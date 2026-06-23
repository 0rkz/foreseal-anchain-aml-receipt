# ForeSeal Gate × AnChain-style AML — verifiable receipts on a paid screening call

A small, MIT-licensed example: front an **AML screening endpoint** with the
[ForeSeal Gate](https://www.npmjs.com/package/@foreseal/gate) so every paid
response carries a tamper-evident **EIP-712 receipt** (`X-BYTE-Attestation`) over
the exact verdict bytes — and an agent does **verify-before-act** before it
releases funds to a counterparty.

> **Authenticity, not correctness.** ForeSeal proves a verdict came from the
> provider's attester and wasn't modified in transit. It does **not** judge
> whether the AML screening is *right* — that's the provider's job. ForeSeal
> makes the provider's answer tamper-evident on the wire. The two are additive.

## Why this matters for an AML provider

The field an agent keys its decision on is `sanctioned` (or `riskLevel`). A
man-in-the-middle who flips it `HIGH → LOW` can walk a sanctioned counterparty
straight through an automated payout. With a ForeSeal receipt, the agent verifies
the verdict's hash and signer *before* trusting it — so the flip is caught before
a dollar moves. Your screening verdict becomes something an agent can **prove**,
not just receive.

## What the demo shows

`npm start` runs the whole loop locally with **no real USDC** (a fake x402
facilitator stands in for settlement):

```
PROVIDER  — ForeSeal Gate fronts a $0.05 AML screen:
            unpaid → 402 (data is never free); paid → 200 + X-BYTE-Attestation
            receipt over the EXACT verdict bytes.
AGENT     — before releasing funds, screens the counterparty, then runs
            verify-before-act: trust the verdict ONLY if the bytes are intact
            AND signed by the provider's attester; otherwise fail closed.
```

Four scenarios, each ending in a visible decision:

| # | Scenario | Outcome |
|---|---|---|
| A | genuine HIGH-risk verdict, trusted attester | **ACT ✅** → BLOCK the payout |
| B | MITM downgrades `sanctioned` true→false | **REFUSE ❌** (hash mismatch) → HOLD |
| C | forged receipt (attacker self-signs "clean") | **REFUSE ❌** (untrusted signer) → HOLD |
| D | missing receipt | **REFUSE ❌** (fail-closed) → HOLD |

## Run it

Requires Node 20+.

```bash
npm install
npm start
```

> `@foreseal/gate@0.1.1` must be available on npm for `npm install` to resolve.
> To run against a **local** build of the Gate before it is published, from this
> directory:
>
> ```bash
> npm pack ../../packages/x402-middleware   # produces foreseal-gate-0.1.1.tgz
> npm install ./foreseal-gate-0.1.1.tgz
> npm start
> ```

## How it works

```ts
import { trustMiddleware } from "@foreseal/gate/express";

app.use("/aml", trustMiddleware({
  upstream: "http://localhost:.../screen", // your AML endpoint
  price: { perCallUsdc: "0.05" },           // a $0.05 counterparty screen
  payTo: "0xYourUSDCAddress",
  attestationKey: PROVIDER_ATTESTER_KEY,    // signs the receipt over exact bytes
}));
```

The agent verifies with `verifyReceipt` (shipped in `@foreseal/gate/core`; the
same hash + signer check the [ForeSeal Kit](https://www.npmjs.com/package/@payperbyte/sdk)
`verify()` ships for buyers):

```ts
import { verifyReceipt, parseReceiptHeader } from "@foreseal/gate/core";

const receipt = parseReceiptHeader(res.headers.get("x-byte-attestation"));
const v = await verifyReceipt(bodyBytes, receipt);
const safeToAct = v.verified && v.recoveredSigner?.toLowerCase() === TRUSTED_ATTESTER;
```

## Notes

- **MIT licensed.** This is a standalone example you can copy, modify, and ship.
- **Not affiliated with AnChain.AI.** The AML data here is mock / illustrative
  and screens no real address. AnChain's own `aml-mcp` is AGPL-3.0; this example
  is a **separate** MIT repo and does not modify or open a PR into it.
- Built by [PayPerByte](https://www.payperbyte.io) (the team behind ForeSeal).
