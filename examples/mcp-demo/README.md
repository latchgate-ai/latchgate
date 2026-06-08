# MCP Demo

The `latchgate-mcp` adapter exposes registered LatchGate actions as MCP tools. Any MCP host (Claude Desktop, Cursor, custom agents) can call tools through it — the full security pipeline runs underneath.

## Quick test (no MCP host needed)

The test script speaks raw JSON-RPC to the adapter over stdio — the same protocol any MCP host uses. No Claude Desktop, no install:

```bash
# Terminal 1 — gate
make quickstart
make serve

# Terminal 2 — build + test
cargo build --release -p latchgate-mcp
cd examples/mcp-demo
./test_mcp.sh
```

This initializes the adapter, discovers tools, and executes `http_fetch` through the full LatchGate pipeline. If it works here, it works in any MCP host.

## Claude Desktop setup

To use LatchGate tools interactively in Claude Desktop:

**1. Build the adapter:**

```bash
cargo build --release -p latchgate-mcp
```

**2. Add to Claude Desktop config:**

| OS | Config path |
|---|---|
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "latchgate": {
      "command": "/absolute/path/to/target/release/latchgate-mcp",
      "args": ["--gate-url", "http://localhost:3000"],
      "env": {
        "LATCHGATE_AGENT_ID": "claude-desktop",
        "RUST_LOG": "warn"
      }
    }
  }
}
```

A reference copy is at `claude_desktop_config.example.json`.

**3. Restart Claude Desktop.** LatchGate tools appear in the tool picker.

**4. Try it:**

- *"Check the httpbin API"* — `http_fetch` => allowed, receipt signed.
- *"POST a test payload to httpbin"* — `http_post` => medium-risk, auto-allowed.

Watch the audit trail: `latchgate audit tail --follow`

## How it works

`latchgate-mcp` is a stdio process. The MCP host starts it, sends JSON-RPC over stdin, reads responses from stdout. The adapter connects to the gate, acquires a DPoP-bound lease, and auto-discovers registered actions as MCP tools. On `tools/call`, the full pipeline runs: auth => policy => WASM sandbox => signed receipt.

## Available tools

The tools available depend on which action manifests are registered. The default dev catalog includes HTTP actions at various risk levels:

| MCP tool | LatchGate action | Risk | What happens |
|---|---|---|---|
| `http_fetch` | `http_fetch` | low | Auto-allowed, sandboxed GET |
| `http_post` | `http_post` | medium | Auto-allowed, sandboxed POST |
| `http_sensitive_read` | `http_sensitive_read` | high | Held for operator approval |
