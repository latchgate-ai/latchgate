#!/usr/bin/env python3
"""LatchGate agent loop - the agent doesn't know LatchGate exists.

The agent sees tools: "fetch a URL", "post data". It has no idea
that every call is authenticated, policy-checked, sandboxed, and audited.
That's the point - security is transparent to the model.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    uv run agent.py
    uv run agent.py "Fetch the httpbin IP endpoint and post a summary"
    uv run agent.py --base-url http://localhost:3000

Requires:
    - Running gate: LATCHGATE_DEV_MODE=true latchgate serve
    - ANTHROPIC_API_KEY
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

import anthropic

from latchgate import (
    LatchGateApprovalRequired,
    LatchGateClient,
    LatchGateDenied,
)

# ── Styling ──────────────────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"


def banner(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}\n")


def agent_says(msg: str) -> None:
    print(f"  {MAGENTA}agent{RESET} │ {msg}")


def gate_says(msg: str) -> None:
    print(f"  {GREEN}gate {RESET} │ {msg}")


def error_says(msg: str) -> None:
    print(f"  {RED}error{RESET} │ {msg}")


# ── Default task ─────────────────────────────────────────────────────────────
#
# A multi-step task that naturally exercises several actions and policy paths:
#   1. http_fetch to httpbin.org (allowed, real API)
#   2. http_fetch to httpbin.org (allowed, different endpoint)
#   3. http_post to httpbin.org (medium-risk write action)

DEFAULT_TASK = """\
I need you to gather some data and post a summary.

1. First, fetch https://httpbin.org/ip to find our outbound IP address.
2. Then fetch https://httpbin.org/headers to see what headers we send.
3. Finally, POST a JSON summary of both results to https://httpbin.org/post \
   with keys "ip" and "headers".\
"""

# ── Tool definitions ────────────────────────────────────────────────────────
#
# The agent sees generic tools. Nothing here mentions LatchGate, security
# policies, WASM sandboxes, or receipts. The agent just calls tools.
# The operator wires these tools to LatchGate - the agent never knows.

TOOLS = [
    {
        "name": "http_fetch",
        "description": "Fetch data from an HTTP endpoint via GET.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "http_post",
        "description": "Send data to an HTTP endpoint via POST.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to post to.",
                },
                "body": {
                    "type": "string",
                    "description": "The JSON request body.",
                },
            },
            "required": ["url", "body"],
        },
    },
]

# The agent's system prompt says nothing about LatchGate.
# It just has tools. What happens underneath is not its concern.
SYSTEM_PROMPT = """\
You are a helpful assistant with access to tools. Use them when needed \
to accomplish the user's task. Be concise and report results clearly.\
"""


# ── Gate execution ──────────────────────────────────────────────────────────
#
# This is the operator's wiring. The agent calls a tool, and we route it
# through LatchGate. The agent sees a result (or an error). It has no
# visibility into the pipeline that produced it.


async def execute_tool(
    gate: LatchGateClient,
    tool_name: str,
    tool_input: dict,
    receipts: list[str],
    denials: list[str],
    approvals: list[str],
) -> str:
    """Route a tool call through LatchGate. Returns result text for the agent."""

    # ── This output is for the human watching the demo, not the agent ──
    gate_says(f"Executing {BOLD}{tool_name}{RESET} through LatchGate...")
    for k, v in tool_input.items():
        gate_says(f"  {DIM}{k}: {str(v)[:80]}{RESET}")

    try:
        result = await gate.execute(tool_name, tool_input)
        gate_says(f"  {GREEN}✓ allowed{RESET} - receipt: {DIM}{result.receipt_id}{RESET}")
        receipts.append(result.receipt_id)

        # The agent just sees the output. No receipt ID, no grant ID.
        output = result.output
        if isinstance(output, dict):
            return json.dumps(output, indent=2)
        return str(output) if output else "(empty response)"

    except LatchGateDenied as exc:
        gate_says(f"  {RED}✗ denied{RESET} - {exc}")
        denials.append(tool_name)
        # The agent sees a generic error. It doesn't know why.
        return "Error: this action was not permitted."

    except LatchGateApprovalRequired as exc:
        gate_says(f"  {YELLOW}⏳ approval required{RESET} - id: {exc.approval_id}")
        gate_says(f"  Approve: latchgate approvals approve {exc.approval_id}")
        approvals.append(exc.approval_id)
        # The agent sees a hold. It can't do anything about it.
        return "This action requires approval and is pending. Try again later."

    except Exception as exc:
        error_says(f"  {type(exc).__name__}: {exc}")
        return f"Error: {type(exc).__name__}: {exc}"


# ── Agent loop ──────────────────────────────────────────────────────────────


async def agent_loop(task: str, base_url: str, max_turns: int = 15) -> None:
    banner("LatchGate Agent Loop")
    print(f"  {DIM}Task:  {task.splitlines()[0]}{RESET}")
    if len(task.splitlines()) > 1:
        for line in task.splitlines()[1:]:
            if line.strip():
                print(f"  {DIM}       {line.strip()}{RESET}")
    print(f"  {DIM}Gate:  {base_url}{RESET}")
    print(f"  {DIM}Model: claude-haiku-4-5-20251001{RESET}")
    print()
    print(f"  {CYAN}▸ The agent has no idea LatchGate exists.{RESET}")
    print(f"  {CYAN}▸ It just sees tools. Watch what happens underneath.{RESET} ")
    print()

    claude = anthropic.Anthropic()
    receipts: list[str] = []
    denials: list[str] = []
    approvals: list[str] = []
    t0 = time.monotonic()

    async with LatchGateClient(base_url=base_url) as gate:
        gate_says("Acquiring DPoP-bound lease...")
        await gate.connect(agent_id="agent-loop-demo")
        gate_says(f"  {GREEN}✓ lease acquired{RESET}")
        print()

        messages: list[dict] = [{"role": "user", "content": task}]

        for _ in range(max_turns):
            agent_says(f"{DIM}(thinking...){RESET}")

            response = claude.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )

            assistant_content = []
            tool_results = []

            for block in response.content:
                if block.type == "text":
                    agent_says(block.text)
                    assistant_content.append(block)

                elif block.type == "tool_use":
                    agent_says(
                        f"Calling {BOLD}{block.name}{RESET}"
                        f"({DIM}{json.dumps(block.input, separators=(',', ':'))}{RESET})"
                    )
                    assistant_content.append(block)
                    print()

                    result_text = await execute_tool(
                        gate, block.name, block.input,
                        receipts, denials, approvals,
                    )
                    print()

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    })

            messages.append({"role": "assistant", "content": assistant_content})

            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                break

    elapsed = time.monotonic() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    #
    # Everything below is for the human watching the demo.
    # The agent never sees any of this.

    print(f"\n{BOLD}{WHITE}{'═' * 60}{RESET}")
    print(f"{BOLD}{WHITE}  What happened behind the scenes{RESET}")
    print(f"{BOLD}{WHITE}{'═' * 60}{RESET}\n")

    print(f"  {CYAN}▸ The agent completed its task in {elapsed:.1f}s.{RESET}")
    print(f"  {CYAN}▸ It had no idea any of the following happened:{RESET}")
    print()

    total_actions = len(receipts) + len(denials) + len(approvals)
    print(f"  {BOLD}Actions submitted:{RESET}  {total_actions}")
    if receipts:
        print(f"  {GREEN}✓ Allowed + executed:{RESET} {len(receipts)}")
    if denials:
        print(f"  {RED}✗ Denied by policy:{RESET}  {len(denials)}")
    if approvals:
        print(f"  {YELLOW}⏳ Held for approval:{RESET}  {len(approvals)}")
    print()

    if receipts:
        print(f"  {BOLD}Security pipeline (per action):{RESET}")
        print(f"    {DIM}1. DPoP-bound lease validated{RESET}")
        print(f"    {DIM}2. Anti-replay jti checked in Redis{RESET}")
        print(f"    {DIM}3. Input validated against JSON Schema{RESET}")
        print(f"    {DIM}4. OPA policy evaluated (Rego rules){RESET}")
        print(f"    {DIM}5. Budget atomically reserved in Redis{RESET}")
        print(f"    {DIM}6. Ed25519-signed ExecutionGrant issued{RESET}")
        print(f"    {DIM}7. Provider executed in fresh WASM sandbox{RESET}")
        print(f"    {DIM}8. Result verified (http_status / message_id){RESET}")
        print(f"    {DIM}9. Ed25519-signed receipt, hash-chained to ledger{RESET}")
        print()

        print(f"  {BOLD}Receipts (Ed25519-signed, hash-chained):{RESET}")
        for i, rid in enumerate(receipts):
            marker = f"{GREEN}head{RESET}" if i == 0 else f"{DIM}← chain[{i}]{RESET}"
            print(f"    {DIM}{rid}{RESET}  {marker}")
        print()

    if approvals:
        print(f"  {BOLD}Pending approvals:{RESET}")
        for aid in approvals:
            print(f"    {DIM}{aid}{RESET}")
        print(f"    {DIM}Approve: latchgate approvals approve <id>{RESET}")
        print()

    print(f"  {CYAN}▸ The agent saw tool results. It never saw receipts,{RESET}")
    print(f"  {CYAN}▸ grants, policy decisions, or sandbox boundaries.{RESET}")
    print(f"  {CYAN}▸ The security boundary is invisible to the model.{RESET}")
    print(f"  {CYAN}▸ That's the point.{RESET}")
    print(f"\n{BOLD}{WHITE}{'═' * 60}{RESET}\n")


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            f"\n  {RED}ANTHROPIC_API_KEY not set.{RESET}\n\n"
            f"  export ANTHROPIC_API_KEY=sk-ant-...\n"
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="LatchGate agent loop - Claude plans, LatchGate executes"
    )
    parser.add_argument(
        "task",
        nargs="?",
        default=DEFAULT_TASK,
        help="Task for the agent (default: multi-step HTTP fetch + post scenario)",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:3000",
        help="Gate HTTP base URL (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    asyncio.run(agent_loop(args.task, args.base_url))


if __name__ == "__main__":
    main()
