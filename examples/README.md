# Examples

Runnable examples against a live gate.

**Prerequisites:** `make quickstart` (once), then `make serve` in a separate terminal.

## SDK examples

Start here — minimal scripts that show the core SDK surface:

| Example | Language | What it is |
|---|---|---|
| [`sdk/python/examples/hello.py`](../sdk/python/examples/hello.py) | Python | Lease, execute, print receipt. First thing to run. |
| [`sdk/typescript/examples/hello.ts`](../sdk/typescript/examples/hello.ts) | TypeScript | Same flow in TypeScript. |
| [`sdk/python/examples/approval_flow.py`](../sdk/python/examples/approval_flow.py) | Python | Agent submits high-risk action, operator approves, gate executes stored plan. |
| [`sdk/typescript/examples/approval_flow.ts`](../sdk/typescript/examples/approval_flow.ts) | TypeScript | Same flow in TypeScript. |

## Full examples

End-to-end demonstrations that wire the SDK into real systems:

| Example | What it is | Run |
|---|---|---|
| [**orchestrator**](orchestrator/) | Programmatic test harness. Exercises HTTP actions and every policy path: allowed/denied domains, credential injection, human-in-the-loop approval, burst execution, receipt chain. | `cd examples/orchestrator && uv run orchestrator.py` |
| [**agent-loop**](agent-loop/) | Real Claude agent (Haiku) performing a multi-step task. The agent has no idea LatchGate exists — it just sees tools. Requires `ANTHROPIC_API_KEY`. | `cd examples/agent-loop && uv run agent.py` |
| [**mcp-demo**](mcp-demo/) | Tests the `latchgate-mcp` adapter via raw JSON-RPC over stdio. Same protocol as Claude Desktop / Cursor. No MCP host needed. | `cargo build --release -p latchgate-mcp && bash examples/mcp-demo/test_mcp.sh` |
