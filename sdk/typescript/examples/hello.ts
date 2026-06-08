/**
 * Minimal LatchGate example — lease, execute, print receipt.
 *
 * Requires a running gate:
 *   latchgate up
 *
 * Run:
 *   npx tsx examples/hello.ts
 */

import { LatchGateClient, LatchGateDenied, LatchGateApprovalRequired } from "../src/index.js";

async function main() {
  // UDS transport (default) — matches latchgate up.
  // publicBaseUrl must match the server's DPoP htu expectation.
  const client = new LatchGateClient({ publicBaseUrl: "http://localhost:3000" });

  try {
    // 1. Obtain a DPoP-bound lease.
    //    maxCalls caps the session budget — the OPA policy denies
    //    further calls once exhausted. Start conservative; the agent
    //    can request a new lease when the budget runs out.
    await client.connect({ agentId: "hello-example", maxCalls: 100 });
    console.log("lease acquired");

    // 2. Execute a protected action.
    let result;
    try {
      result = await client.execute("http_fetch", {
        url: "https://httpbin.org/get",
      });
    } catch (err) {
      if (err instanceof LatchGateDenied) {
        console.log("denied by policy:", err.reason);
        return;
      }
      if (err instanceof LatchGateApprovalRequired) {
        console.log("held for approval:", err.approvalId);
        return;
      }
      throw err;
    }

    console.log("output: ", result.output);
    console.log("receipt:", result.receiptId);
    console.log("verified:", result.verification?.is_fully_successful ?? false);
  } finally {
    await client.close();
  }
}

main().catch(console.error);
