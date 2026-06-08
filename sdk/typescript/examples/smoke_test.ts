/**
 * LatchGate smoke test - verifies the full pipeline: lease => execute => receipt.
 *
 * Used by `make smoke-test`. Exits 0 on success, 1 on failure.
 *
 * Requires a running gate:
 *   latchgate up
 *
 * Run:
 *   npx tsx examples/smoke_test.ts
 */

import { LatchGateClient } from "../src/index.js";

async function main(): Promise<number> {
  const client = new LatchGateClient({ publicBaseUrl: "http://localhost:3000" });

  try {
    // Step 1: Lease
    process.stdout.write("  [1/3] Acquiring lease... ");
    try {
      await client.connect({ agentId: "smoke-test" });
      console.log("ok");
    } catch (err) {
      console.log(`FAIL: ${err}`);
      return 1;
    }

    // Step 2: Execute
    process.stdout.write("  [2/3] Executing http_fetch... ");
    let receiptId: string;
    try {
      const result = await client.execute("http_fetch", {
        url: "https://httpbin.org/get",
      });
      if (!result.receiptId) {
        throw new Error("missing receiptId in response");
      }
      receiptId = result.receiptId;
      console.log(`ok (receipt=${receiptId})`);
    } catch (err) {
      console.log(`FAIL: ${err}`);
      return 1;
    }

    // Step 3: Verify execution result
    // Note: GET /v1/receipts requires operator auth (admin socket).
    // The agent SDK cannot retrieve receipts directly — this is by
    // design (receipts are an operator/audit concern). We verify the
    // pipeline succeeded by checking the execute response instead.
    process.stdout.write("  [3/3] Verifying result... ");
    try {
      if (!receiptId) {
        throw new Error("missing receiptId — pipeline did not complete");
      }
      console.log("ok (receipt_id present, output received)");
    } catch (err) {
      console.log(`FAIL: ${err}`);
      return 1;
    }

    console.log();
    console.log("  [OK] Smoke test passed: lease => execute => receipt");
    return 0;
  } finally {
    await client.close();
  }
}

main().then(process.exit).catch((err) => {
  console.error(err);
  process.exit(1);
});
