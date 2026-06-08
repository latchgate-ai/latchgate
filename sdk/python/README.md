# latchgate · Python SDK

Async Python client for the [LatchGate](../../README.md) action authorization gateway.

## Install

```bash
pip install latchgate
```

From a local clone:

```bash
pip install -e sdk/python/
```

From source (before PyPI release):

```bash
pip install "latchgate @ git+https://github.com/latchgate-ai/latchgate.git#subdirectory=sdk/python"
```

**Requirements:** Python 3.10+, no other system dependencies.

## Quick start

```python
from latchgate import LatchGateClient

# Dev mode (TCP — after `make quickstart && make serve`):
async with LatchGateClient(base_url="http://localhost:3000") as client:
    await client.connect(agent_id="my-agent")

    result = await client.execute("http_fetch", {
        "url": "https://httpbin.org/get",
    })

    print(result.output)       # provider response
    print(result.receipt_id)   # for audit

# Production (UDS — auto-discovers socket via $XDG_RUNTIME_DIR):
async with LatchGateClient() as client:
    await client.connect(agent_id="my-agent")
    ...
```

## API

### `LatchGateClient(socket=..., base_url=..., timeout=30.0)`

Connect over a Unix domain socket (default) or TCP:

```python
# UDS — auto-discovers socket path (recommended)
client = LatchGateClient()

# UDS — explicit path override
client = LatchGateClient(socket="/custom/path/gate.sock")

# TCP — useful in tests or Docker environments
client = LatchGateClient(base_url="http://localhost:8080")
```

### `await client.connect(agent_id=..., session_id=..., scopes=..., max_calls=..., max_cost_usd_cents=...)`

Generates a fresh P-256 DPoP key pair and obtains a Lease JWT. Must be called before `execute()`. The lease is automatically renewed when fewer than 60 seconds remain before expiry.

```python
await client.connect(
    agent_id="agent:my-bot",
    max_calls=100,            # optional budget
)
```

### `await client.execute(action_id, params) => ActionResult`

Executes a protected action. Returns an `ActionResult` on success.

```python
result = await client.execute("http_fetch", {"url": "https://example.com"})

result.output        # dict — provider response
result.receipt_id    # str  — durable receipt ID
result.trace_id      # str  — correlation ID
result.verification  # dict — outcome + is_fully_successful
```

### `await client.get_receipt(receipt_id) => ExecutionReceipt`

Retrieves a stored execution receipt by ID.

```python
receipt = await client.get_receipt(result.receipt_id)

receipt.is_fully_successful          # bool
receipt.verification_outcome         # dict with status + evidence
receipt.normalized_result            # dict with kind + summary
receipt.result_hash                  # SHA-256 of canonical result
```

### `await client.get_approval_status(approval_id) => ApprovalStatus`

Polls the status of a pending approval. **Requires operator authentication** — the approval endpoints live on the admin socket (or combined router in dev mode) and use operator DPoP, not the agent lease. See `examples/approval_flow.py` for the full pattern.

## Error handling

```python
from latchgate import (
    LatchGateDenied,           # action denied by policy
    LatchGateApprovalRequired, # needs human approval — poll approval_id
    LatchGateBudgetExhausted,  # lease budget used up — reconnect
    LatchGateAuthError,        # expired/invalid lease — reconnect
    LatchGateUnavailable,      # OPA/Redis down — retry with backoff
    LatchGateTransportError,   # socket error — retry
)

try:
    result = await client.execute("http_post", {"url": "https://httpbin.org/post", "body": "{}"})
except LatchGateApprovalRequired as exc:
    # action requires human approval
    ...
except LatchGateDenied as exc:
    # policy said no — do not retry as-is
    print(exc.action_id, exc.reason)
except LatchGateBudgetExhausted:
    # obtain a new lease with fresh budget
    await client.connect()
except LatchGateAuthError:
    # lease expired — reconnect
    await client.connect()
except LatchGateUnavailable:
    # transient — retry with backoff
    ...
```

## Examples

All examples require a running gate: `make quickstart` (one-time), then `make serve`.

### hello.py — minimal lease + execute + receipt

```bash
cd sdk/python
uv run examples/hello.py
```

Acquires a DPoP-bound lease, executes `http_fetch` against httpbin.org, and prints the output, receipt ID, and verification status.

### approval_flow.py — full approval lifecycle

```bash
cd sdk/python
uv run examples/approval_flow.py
```

Submits `http_sensitive_read` (risk: high) as an agent — the gate holds the action and returns an approval_id. Then switches to the operator role, discovers credentials from `latchgate.toml` + `.latchgate/*.pem`, and approves via DPoP-authenticated admin endpoint. The gate executes the stored plan and returns a signed receipt.

### smoke_test.py — CI-friendly pipeline check

```bash
cd sdk/python
uv run examples/smoke_test.py
```

Verifies the full pipeline (lease => execute => receipt) with structured pass/fail output. Used by `make smoke-test`. Exits 0 on success, 1 on failure.

## Development

```bash
cd sdk/python
uv sync                     # installs all deps including dev group, creates .venv
uv run pytest               # run tests
uv run ruff format .        # format
uv run ruff check --fix .   # lint + sort imports
```

Or from the repo root:

```bash
make test-sdk-python
```
