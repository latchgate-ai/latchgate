# LatchGate WASM Provider Modules

Provider modules are compiled to `wasm32-wasip2` and loaded by the
LatchGate kernel at startup from `wasm_providers_dir`.

## Prerequisites

```bash
rustup target add wasm32-wasip2
```

## Build

From the workspace root:

```bash
make providers
```

Or build individually:

```bash
cd providers/http_api
cargo build --target wasm32-wasip2 --release
```

The compiled `.wasm` files are copied to `target/providers/` by the
Makefile, ready for the kernel to load.

## Provider inventory

| Provider | Imports | Maturity | Description |
|---|---|---|---|
| `http_api` | `latchgate:io/http` | **Production** | HTTP API calls (REST, webhooks). Powers 17/21 built-in actions via template manifests. |
| `fs` | `latchgate:io/fs` | **Production** | Host-mediated filesystem read/write/delete with path validation and SHA-256 evidence. |
| `email` | `latchgate:io/smtp` | Preview | Send email via SMTP |
| `database` | `latchgate:io/database` | Preview | Execute SQL queries (hybrid mode with SQL parsing) |
| `queue` | `latchgate:io/queue` | Preview | Publish to message queues (AMQP) |
| `artifact_store` | `latchgate:io/storage` | Preview | Store objects in S3-compatible storage |

**Production** providers are audited and recommended for production use.
**Preview** providers are functional and tested but not production-audited.
They demonstrate the host I/O architecture for non-HTTP protocols — review
thoroughly before deploying with untrusted input.

## Sample action manifest

```yaml
action_id: check_order_status
provider_module: sha256:<digest of http_api.wasm>
required_imports:
  - latchgate:io/http
verifier_kind: http_status
declared_side_effects:
  - "api.acme.com"
secrets:
  - name: BEARER_TOKEN
resource_limits:
  fuel: 1_000_000
  memory_mb: 64
  timeout_seconds: 30
  max_io_calls: 5
```

## Security model

- Providers **never** see credentials. The host injects them at I/O time.
- Each execution gets a fresh sandbox (no shared state between calls).
- Only manifest-declared imports are linked (capability-based security).
- Resource limits (CPU fuel, memory, timeout, I/O budget) are enforced.
- Target URLs are validated against `declared_side_effects` before every call.
