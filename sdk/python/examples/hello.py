#!/usr/bin/env python3
"""Minimal LatchGate example — lease, execute, print receipt.

Requires a running gate:
    latchgate up      # start gate + dependencies
"""

import asyncio

from latchgate import (
    LatchGateApprovalRequired,
    LatchGateClient,
    LatchGateDenied,
)


async def main() -> None:
    # UDS transport (default) — matches latchgate up.
    # public_base_url must match the server's DPoP htu expectation.
    async with LatchGateClient(public_base_url="http://localhost:3000") as client:
        # 1. Obtain a DPoP-bound lease.
        #    max_calls caps the session budget — the OPA policy denies
        #    further calls once exhausted. Start conservative; the agent
        #    can request a new lease when the budget runs out.
        await client.connect(agent_id="hello-example", max_calls=100)
        print("lease acquired")

        # 2. Execute a protected action.
        try:
            result = await client.execute(
                "http_fetch",
                {"url": "https://httpbin.org/get"},
            )
        except LatchGateDenied as exc:
            print(f"denied by policy: {exc.reason}")
            return
        except LatchGateApprovalRequired as exc:
            print(f"held for approval: {exc.approval_id}")
            return

        print(f"output:  {result.output}")
        print(f"receipt: {result.receipt_id}")
        print(f"verified: {result.verification.get('is_fully_successful', False)}")


if __name__ == "__main__":
    asyncio.run(main())
