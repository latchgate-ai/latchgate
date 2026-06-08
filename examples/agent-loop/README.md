# Agent Loop

LatchGate sits between an AI agent and the outside world. This example shows what that looks like in practice: a real Claude agent performing a multi-step task, completely unaware that every tool call is being authenticated, policy-checked, sandboxed, and audited underneath.

## The key idea

The agent's tool descriptions say "fetch a URL" and "post data". The system prompt says "you are a helpful assistant with access to tools." Nothing mentions LatchGate, security policies, WASM sandboxes, or signed receipts. The agent just calls tools and gets results.

The operator wires those tools to LatchGate. The security boundary is invisible to the model — it cannot bypass what it cannot see.

## Prerequisites

- Running gate: `make quickstart` (once), then `make serve`
- `ANTHROPIC_API_KEY` (Claude Haiku is used in the example)

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd examples/agent-loop

# Default scenario: fetch data from two endpoints, post a summary
uv run agent.py

# Custom task
uv run agent.py "Check the GitHub API rate limit"
```

The default task asks the agent to fetch data from two HTTP endpoints and POST a summary to a third. This naturally exercises:

- **http_fetch** twice (allowed domain, real API responses)
- **http_post** once (medium-risk write action)

## What you'll see

The output shows two perspectives side by side:

- **agent** (magenta) — Claude thinking and calling tools. It has no
  idea about the security pipeline.
- **gate** (green) — LatchGate processing each call: auth, policy,
  sandbox, receipt.

After the loop, a summary reveals what happened behind the scenes: how many actions were allowed, denied, or held for approval; the security pipeline each action went through; and the chain of signed receipts the agent never knew existed.
