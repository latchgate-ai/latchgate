#!/usr/bin/env python3
"""LatchGate smoke test - verifies the full pipeline: lease => execute => receipt.

Used by `make smoke-test`. Exits 0 on success, 1 on failure.

Requires a running gate:
    latchgate up
"""

import asyncio
import sys

from latchgate import LatchGateClient


async def main() -> int:
    errors: list[str] = []

    async with LatchGateClient(public_base_url="http://localhost:3000") as client:
        # Step 1: Lease
        print("  [1/3] Acquiring lease...", end=" ", flush=True)
        try:
            await client.connect(agent_id="smoke-test")
            print("ok")
        except Exception as exc:
            print(f"FAIL: {exc}")
            errors.append(f"lease: {exc}")
            return 1

        # Step 2: Execute
        print("  [2/3] Executing http_fetch...", end=" ", flush=True)
        try:
            result = await client.execute(
                "http_fetch",
                {"url": "https://httpbin.org/get"},
            )
            if not result.receipt_id:
                raise ValueError("missing receipt_id in response")
            print(f"ok (receipt={result.receipt_id})")
        except Exception as exc:
            print(f"FAIL: {exc}")
            errors.append(f"execute: {exc}")
            return 1

        # Step 3: Verify execution result
        # Note: GET /v1/receipts requires operator auth (admin socket).
        # The agent SDK cannot retrieve receipts directly — this is by
        # design (receipts are an operator/audit concern). We verify the
        # pipeline succeeded by checking the execute response instead.
        print("  [3/3] Verifying result...", end=" ", flush=True)
        try:
            if not result.receipt_id:
                raise ValueError("missing receipt_id — pipeline did not complete")
            if not result.output:
                raise ValueError("empty output — provider returned no data")
            print("ok (receipt_id present, output received)")
        except Exception as exc:
            print(f"FAIL: {exc}")
            errors.append(f"verify: {exc}")
            return 1

    print()
    print("  [OK] Smoke test passed: lease => execute => receipt")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
