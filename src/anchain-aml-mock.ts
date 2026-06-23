/**
 * A MOCK AnChain-style AML screening endpoint.
 *
 * AnChain.AI ships AML/KYT screening (their `aml-mcp` server exposes it as an
 * MCP tool). x402 + the ForeSeal Gate monetize and authenticate it over HTTP, so
 * this mock serves the SAME shape of verdict an AML tool returns — over a plain
 * HTTP endpoint the Gate can front with pay-per-call + a signed receipt.
 *
 * This is illustrative test data ONLY. It is NOT AnChain data and screens no
 * real address. No affiliation with AnChain.AI is implied.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";

export interface AmlVerdict {
  address: string;
  /** 0–100, higher = riskier. */
  riskScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH";
  /** True if the address hits a sanctions list. The field an agent keys its
   *  release-funds decision on — and exactly what an attacker would flip. */
  sanctioned: boolean;
  categories: string[];
  asOf: string;
  source: string;
}

// A couple of illustrative "dirty" addresses. Anything else screens clean.
const FLAGGED = new Set<string>([
  "0x7f367cc41522ce07553e823bf3be79a889debe1b", // illustrative only
  "0x098b716b8aaf21512996dc57eb0615e2383e2f96", // illustrative only
]);

/** Deterministic mock screening verdict for an address. */
export function screen(address: string): AmlVerdict {
  const a = (address || "").toLowerCase();
  const flagged = FLAGGED.has(a);
  return {
    address: a,
    riskScore: flagged ? 92 : 6,
    riskLevel: flagged ? "HIGH" : "LOW",
    sanctioned: flagged,
    categories: flagged ? ["sanctions", "mixer"] : [],
    asOf: "2026-06-23T00:00:00Z",
    source: "AnChain.AI AML screening (MOCK — illustrative test data, not real)",
  };
}

/** Start the mock AML endpoint. GET /screen?address=0x… → an AmlVerdict JSON. */
export function startAnchainAmlMock(): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://localhost");
      const address =
        u.searchParams.get("address") ??
        "0x0000000000000000000000000000000000000000";
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(screen(address)));
    });
    srv.listen(0, () => {
      const port = (srv.address() as AddressInfo).port;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => srv.close() });
    });
  });
}
