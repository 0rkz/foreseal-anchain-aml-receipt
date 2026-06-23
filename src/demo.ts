/**
 * ForeSeal Gate × AnChain-style AML — verify-before-act, end to end.
 *
 *   npm start          (or: node --import tsx src/demo.ts)
 *
 * The whole loop runs locally with NO real USDC (a fake x402 facilitator stands
 * in for settlement):
 *
 *   PROVIDER side — the ForeSeal Gate (`trustMiddleware`) fronts an AML screening
 *                   endpoint: unpaid → 402 (the data is never free), paid → 200 +
 *                   an `X-BYTE-Attestation` receipt (EIP-712) over the EXACT
 *                   verdict bytes.
 *   AGENT    side — before releasing funds to a counterparty, the agent screens
 *                   the address, then runs verify-before-act (`verifyReceipt`):
 *                   it trusts a verdict ONLY if the bytes are intact AND signed
 *                   by the AML provider's attester. Otherwise it fails closed.
 *
 * Why it matters: the field an agent keys on is `sanctioned`. A man-in-the-middle
 * who flips it HIGH→LOW could walk a sanctioned counterparty straight through.
 * ForeSeal makes the verdict tamper-evident and origin-authentic, so the flip is
 * caught before a single dollar moves.
 *
 * Scenarios:
 *   A  genuine HIGH-risk verdict, trusted attester ... ACT ✅ (BLOCK the payout)
 *   B  MITM downgrades sanctioned true→false ......... REFUSE ❌ (hash mismatch)
 *   C  forged receipt (attacker self-signs "clean") .. REFUSE ❌ (untrusted signer)
 *   D  missing receipt ............................... REFUSE ❌ (fail-closed)
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { trustMiddleware } from "@foreseal/gate/express";
import {
  verifyReceipt,
  parseReceiptHeader,
  buildDomain,
  signerFromKey,
  PAYLOAD_ATTESTATION_TYPES,
  type ByteAttestation,
} from "@foreseal/gate/core";
import { startAnchainAmlMock, type AmlVerdict } from "./anchain-aml-mock.js";

// ── throwaway keys (NOT real attester keys) ──────────────────────────────────
const PROVIDER_ATTESTER_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ATTACKER_KEY =
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";
const PAY_TO = "0x07B8C1D531958A3193eA527aea52A9f26bcfE91B" as const;
const NETWORK = "eip155:84532"; // a known net so USDC resolves (no real settle)

// A flagged (illustrative) counterparty address the agent is about to pay.
const COUNTERPARTY = "0x7f367cc41522ce07553e823bf3be79a889debe1b";

// ── tiny ANSI helpers ────────────────────────────────────────────────────────
const useColor = process.stdout.isTTY;
const green = (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s);
const red = (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s);
const dim = (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s);
const bold = (s: string) => (useColor ? `\x1b[1m${s}\x1b[0m` : s);

// ── fake x402 facilitator (the test-harness pattern; approves the forged pay) ─
function startFacilitator(): Promise<{ url: string; close: () => void }> {
  const kinds = [{ x402Version: 2, scheme: "exact", network: NETWORK }];
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.endsWith("/supported"))
        return void res.end(JSON.stringify({ kinds, extensions: [], signers: {} }));
      if (req.url?.endsWith("/verify"))
        return void res.end(JSON.stringify({ isValid: true, payer: "0xPayer" }));
      if (req.url?.endsWith("/settle"))
        return void res.end(
          JSON.stringify({ success: true, transaction: "0xdeadbeef", network: NETWORK, payer: "0xPayer" }),
        );
      res.statusCode = 404;
      res.end("{}");
    });
    srv.listen(0, () => {
      const port = (srv.address() as AddressInfo).port;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => srv.close() });
    });
  });
}

function startApp(handler: express.RequestHandler): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const app = express();
    app.use(express.json());
    app.use("/aml", handler);
    const srv = app.listen(0, () => {
      const port = (srv.address() as AddressInfo).port;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => srv.close() });
    });
  });
}

async function waitFor(pred: () => Promise<boolean>, ms = 6000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (await pred()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return pred();
}

/** Forge a complete x402 v2 payment from a route's own 402 challenge. */
async function paidGet(url: string): Promise<Response> {
  const challenge = await fetch(url);
  const hdr = challenge.headers.get("payment-required");
  if (!hdr) return challenge;
  const { accepts } = JSON.parse(Buffer.from(hdr, "base64").toString("utf8"));
  const accepted = accepts[0];
  const payload = { x402Version: 2, scheme: accepted.scheme, network: accepted.network, accepted, payload: {} };
  return fetch(url, {
    headers: { "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(payload)).toString("base64") },
  });
}

// ── the agent's verify-before-act decision: trust the AML verdict, or fail closed
async function decide(
  label: string,
  receivedBytes: Uint8Array | string,
  receipt: ByteAttestation | null,
  trustedAttester: string,
): Promise<void> {
  console.log(bold(`\n${label}`));

  if (!receipt) {
    const v = await verifyReceipt(receivedBytes, undefined as never);
    console.log(dim(`  verifyReceipt → verified=${v.verified}  (${v.reason})`));
    console.log(`  ${red("REFUSE ❌")} — no receipt; the verdict is unverifiable. Fail closed → HOLD the payout.`);
    return;
  }

  const v = await verifyReceipt(receivedBytes, receipt);
  const signerTrusted =
    !!v.recoveredSigner && v.recoveredSigner.toLowerCase() === trustedAttester.toLowerCase();
  console.log(
    dim(
      `  verifyReceipt → verified=${v.verified}  hashMatch=${v.hashMatch}  ` +
        `signer=${v.recoveredSigner ?? "none"}  trustedAttester? ${signerTrusted}`,
    ),
  );

  const trustworthy = v.verified && signerTrusted;
  if (!trustworthy) {
    console.log(
      `  ${red("REFUSE ❌")} — ${v.verified ? "signer is NOT the AML provider's attester" : v.reason}. ` +
        `Treat as unscreened → HOLD the payout.`,
    );
    return;
  }

  // The verdict is authentic + intact → the agent can ACT on it.
  let verdict: AmlVerdict;
  try {
    verdict = JSON.parse(typeof receivedBytes === "string" ? receivedBytes : Buffer.from(receivedBytes).toString("utf8"));
  } catch {
    console.log(`  ${red("REFUSE ❌")} — verdict is not parseable JSON. HOLD the payout.`);
    return;
  }
  const block = verdict.sanctioned || verdict.riskLevel === "HIGH";
  console.log(
    `  ${green("ACT ✅")} — verdict is authentic (intact + signed by the attester we trust): ` +
      `riskLevel=${verdict.riskLevel}, sanctioned=${verdict.sanctioned}.`,
  );
  console.log(
    block
      ? `         → ${bold("BLOCK the payout")} (sanctioned / HIGH risk). No funds released.`
      : `         → release funds (clean counterparty).`,
  );
}

async function main() {
  console.log(bold("\n══ ForeSeal Gate × AnChain-style AML — verify-before-act ") + dim("(local; no real USDC) ══"));

  const provider = privateKeyToAccount(PROVIDER_ATTESTER_KEY);
  const attacker = signerFromKey(ATTACKER_KEY); // the Gate's Signer (clean EIP-712 typing)
  const trustedAttester = provider.address; // published out-of-band (agent card / well-known)

  // ── PROVIDER: front the AML screening endpoint with the Gate ───────────────
  const aml = await startAnchainAmlMock();
  const fac = await startFacilitator();
  const handler = trustMiddleware({
    upstream: aml.url,
    price: { perCallUsdc: "0.05" }, // a $0.05 counterparty screen
    payTo: PAY_TO,
    network: NETWORK,
    facilitatorUrl: fac.url,
    attestationKey: PROVIDER_ATTESTER_KEY,
  });
  const app = await startApp(handler);

  console.log(dim(`\nAML provider attester address the agent trusts: ${trustedAttester}`));
  console.log(dim(`Counterparty under screening: ${COUNTERPARTY}`));
  await waitFor(async () => (await fetch(`${app.url}/aml/screen?address=${COUNTERPARTY}`)).status === 402);

  // gate engaged: unpaid is 402, never free data.
  const unpaid = await fetch(`${app.url}/aml/screen?address=${COUNTERPARTY}`);
  console.log(
    `Gate engaged: unpaid screen → ${unpaid.status === 402 ? green("402 PAYMENT-REQUIRED") : red(String(unpaid.status))} ` +
      dim("(AML data is never served free)"),
  );

  // pay (fake facilitator) and capture the genuine receipt + exact verdict bytes.
  const paid = await paidGet(`${app.url}/aml/screen?address=${COUNTERPARTY}`);
  const verdictText = await paid.text();
  const genuine = parseReceiptHeader(paid.headers.get("x-byte-attestation")!);
  console.log(
    `Paid screen ($0.05) → ${paid.status === 200 ? green("200 + X-BYTE-Attestation") : red(String(paid.status))}  ` +
      dim(verdictText),
  );

  // ── AGENT: verify-before-act under attack ──────────────────────────────────
  // A — genuine HIGH-risk verdict
  await decide("A  genuine HIGH-risk verdict, trusted attester", verdictText, genuine, trustedAttester);

  // B — MITM downgrades the verdict: flip sanctioned + risk to sneak the address through.
  const downgraded = verdictText
    .replace('"sanctioned":true', '"sanctioned":false')
    .replace('"riskLevel":"HIGH"', '"riskLevel":"LOW"');
  await decide("B  MITM downgrades sanctioned true→false, HIGH→LOW", downgraded, genuine, trustedAttester);

  // C — forged receipt: attacker signs THEIR OWN "clean" verdict with THEIR key.
  const evilVerdict = JSON.stringify({
    address: COUNTERPARTY,
    riskScore: 2,
    riskLevel: "LOW",
    sanctioned: false,
    categories: [],
    asOf: "2026-06-23T00:00:00Z",
    source: "AnChain.AI AML screening (MOCK — illustrative test data, not real)",
  });
  const evilBytes = new TextEncoder().encode(evilVerdict);
  const evilHash = keccak256(evilBytes);
  const dom = buildDomain();
  const evilDeadline = Math.floor(Date.now() / 1000) + 300;
  const evilSig = await attacker.signTypedData({
    domain: dom,
    types: PAYLOAD_ATTESTATION_TYPES,
    primaryType: "PayloadAttestation",
    message: {
      publisher: attacker.address,
      payloadHash: evilHash,
      payloadLength: BigInt(evilBytes.length),
      deadline: BigInt(evilDeadline),
    },
  });
  const forged: ByteAttestation = {
    alg: "EIP712-PayloadAttestation",
    domain: dom,
    publisher: attacker.address, // internally consistent — but NOT the AML attester
    payloadHash: evilHash,
    payloadLength: evilBytes.length,
    deadline: evilDeadline,
    signature: evilSig,
  };
  await decide("C  forged receipt (attacker self-signs a 'clean' verdict)", evilVerdict, forged, trustedAttester);

  // D — missing receipt
  await decide("D  missing / empty receipt", verdictText, null, trustedAttester);

  console.log(
    green("\n✓ verify-before-act complete — only the authentic, intact AML verdict was ACTed on; ") +
      green("every tampered/forged/missing receipt failed closed and HELD the payout.\n"),
  );

  handler.stop();
  aml.close();
  fac.close();
  app.close();
  setTimeout(() => process.exit(0), 50);
}

main().catch((e) => {
  console.error(red("demo failed:"), e);
  process.exit(1);
});
