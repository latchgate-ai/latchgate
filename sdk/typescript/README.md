# latchgate · TypeScript SDK

Async TypeScript client for the [LatchGate](../../README.md) action authorization gateway.

## Install

```bash
npm install latchgate
```

From a local clone:

```bash
npm install ../sdk/typescript
```

From source (before npm release):

```bash
npm install "latchgate@github:latchgate-ai/latchgate#path=sdk/typescript"
```

**Requirements:** Node.js 18+, no native dependencies.

## Quick start

```ts
import { LatchGateClient } from "latchgate";

await using client = new LatchGateClient();
await client.connect({ agentId: "my-agent" });

const result = await client.execute("http_fetch", {
  url: "https://httpbin.org/get",
});

console.log(result.output);     // provider response
console.log(result.receiptId);  // for audit
```

`await using` (TypeScript 5.2+) ensures the socket is cleanly closed. Falls back to `await client.close()` in older runtimes.

## API

### `new LatchGateClient(options?)`

| Option | Default | Description |
|---|---|---|
| `socket` | auto-discovered | Unix domain socket path (see below) |
| `baseUrl` | — | HTTP base URL for TCP transport (tests, Docker) |
| `timeoutMs` | `30000` | Request timeout in milliseconds |
| `dispatcher` | — | Custom undici `Dispatcher` — inject `MockAgent` in tests |

The socket path is resolved automatically: `$XDG_RUNTIME_DIR/latchgate/gate.sock`, falling back to `/tmp/latchgate-{uid}/gate.sock`. This matches the path written by `latchgate up` and `latchgate init`.

```ts
// UDS — auto-discovers socket path (recommended)
const client = new LatchGateClient();

// UDS — explicit path override
const client = new LatchGateClient({ socket: "/custom/path/gate.sock" });

// TCP — Docker / tests
const client = new LatchGateClient({ baseUrl: "http://localhost:8080" });
```

### `await client.connect(options?)`

Generates a fresh P-256 DPoP key pair and obtains a Lease JWT. Must be called before `execute()`. The lease is automatically renewed when fewer than 60 seconds remain before expiry.

```ts
await client.connect({
  agentId: "agent:my-bot",
  maxCalls: 100,           // optional budget
  maxCostUsdCents: 5000,   // optional budget
});
```

### `await client.execute(actionId, params?) => ActionResult`

```ts
const result = await client.execute("http_fetch", { url: "https://example.com" });

result.output       // unknown — provider response
result.receiptId    // string  — durable receipt ID
result.traceId      // string  — correlation ID
result.verification // object  — outcome + isFullySuccessful
```

### `await client.getReceipt(receiptId) => ExecutionReceipt`

```ts
const receipt = await client.getReceipt(result.receiptId);

isFullySuccessful(receipt)           // boolean helper
receipt.verificationOutcome          // { status, evidence }
receipt.normalizedResult             // { kind, summary }
receipt.resultHash                   // SHA-256 of canonical result
```

### `await client.getApprovalStatus(approvalId) => ApprovalStatus`

Polls the status of a pending approval. **Requires operator authentication** — the approval endpoints live on the admin socket (or combined router in dev mode) and use operator DPoP, not the agent lease. See `examples/approval_flow.ts` for the full pattern.

## Error handling

```ts
import {
  LatchGateDenied,            // action denied by policy
  LatchGateApprovalRequired,  // needs human approval — poll approvalId
  LatchGateBudgetExhausted,   // lease budget used up — reconnect
  LatchGateAuthError,         // expired/invalid lease — reconnect
  LatchGateUnavailable,       // OPA/Redis down — retry with backoff
  LatchGateTransportError,    // socket error — retry
  LatchGateNotConnected,      // connect() not called
} from "latchgate";

try {
  const result = await client.execute("http_post", {
    url: "https://httpbin.org/post",
    body: "{}",
  });
} catch (err) {
  if (err instanceof LatchGateApprovalRequired) {
    // action requires human approval
  } else if (err instanceof LatchGateDenied) {
    // policy said no — do not retry as-is
    console.error(err.actionId, err.reason);
  } else if (err instanceof LatchGateBudgetExhausted) {
    await client.connect(); // fresh lease with new budget
  } else if (err instanceof LatchGateAuthError) {
    await client.connect(); // lease expired
  } else if (err instanceof LatchGateUnavailable) {
    // transient — retry with backoff
  }
}
```

## Examples

All examples require a running gate: `make quickstart` (one-time), then `make serve`.

### hello.ts — minimal lease + execute + receipt

```bash
cd sdk/typescript
npx tsx examples/hello.ts
```

Acquires a DPoP-bound lease, executes `http_fetch` against httpbin.org, and prints the output, receipt ID, and verification status.

### approval_flow.ts — full approval lifecycle

```bash
cd sdk/typescript
npx tsx examples/approval_flow.ts
```

Submits `http_sensitive_read` (risk: high) as an agent — the gate holds the action and returns an approval_id. Then switches to the operator role, discovers credentials from `latchgate.toml` + `.latchgate/*.pem`, and approves via DPoP-authenticated admin endpoint. The gate executes the stored plan and returns a signed receipt.

### smoke_test.ts — CI-friendly pipeline check

```bash
cd sdk/typescript
npx tsx examples/smoke_test.ts
```

Verifies the full pipeline (lease => execute => receipt) with structured pass/fail output. Used by `make smoke-test`. Exits 0 on success, 1 on failure.

## Development

```bash
cd sdk/typescript
npm install
npm test          # vitest
npm run typecheck # tsc --noEmit
npm run lint      # eslint
npm run build     # tsc => dist/
```

Or from the repo root:

```bash
make test-sdk-typescript
```
