# Orchestrator

Drives a live LatchGate gate through every policy path. Not a mock - every action hits the real pipeline (auth, schema, policy, sandbox, signed receipts).

This is a programmatic test harness, not an LLM-powered agent. It calls the SDK directly with hardcoded inputs to exercise each path deterministically. Output is split into two streams:

- `[gate]` lines - actual response bodies and exception fields produced by the gate.
- `>` lines - orchestrator narration explaining what the gate did.

Anything claimed in narration is also visible in real gate output - so you can verify the example isn't fabricating behavior.

## Run

```bash
# From the repo root - one-time setup + start infra:
make quickstart

# Start the gate (separate terminal, from repo root):
make serve

# Run the orchestrator:
cd examples/orchestrator
uv sync
uv run orchestrator.py
```

`make quickstart` builds the binary, generates dev credentials under `.latchgate/`, starts Redis + OPA, and compiles WASM providers. On subsequent runs, `make dev` + `make serve` is enough.

The orchestrator auto-discovers operator credentials from `.latchgate/latchgate.toml` and `.latchgate/operators/<name>.pem`.

## What happens

Seven scenarios, each showing the actual gate response:

**1. Lease lifecycle** - generates a P-256 keypair, calls `POST /v1/leases` with a DPoP proof, and acquires a short-lived JWT bound to the keypair.

**2. http_fetch - low risk, auto-allow** - exercises the full pipeline. Shows the `ActionResult` returned by the gate (trace_id, grant_id, receipt_id, verification, runtime).

**3. http_post - medium risk, auto-allow** - same `http_api.wasm` binary as `http_fetch`, configured by a different manifest (POST template, different domain allowlist, different risk level).

**4. http_bearer_get - required secret enforcement** - manifest declares `API_BEARER_TOKEN` as required. Without `sops_secrets_file` configured, the gate denies pre-flight and surfaces the specific cause via `deny_reason`. With SOPS configured, the secret is injected at the host transport layer and never enters the WASM sandbox.

**5. http_fetch - egress containment** - attempts to reach `evil.example.com`, which is not in `http_fetch.allowed_domains`. The domain pre-check forwards the unresolved domain to OPA, which denies. No grant is issued, no WASM dispatch happens. The gate's `deny_reason` is shown verbatim.

**6. http_sensitive_read - high-risk approval flow** - submits a high-risk read. If policy holds it (HTTP 202), the orchestrator approves it via the admin API using DPoP-authed operator credentials. The actual approval response is displayed. If SOPS isn't configured, the post-approval execution fails with the specific gate error - also shown verbatim.

**7. Burst execution** - fires five sequential `http_fetch` calls. Each goes through the full pipeline and atomic budget decrement in Redis. Receipts and grants accumulate in the report.

## Summary output

After all scenarios:

- **Results** - pass/fail/skip per scenario with latency.
- **Evidence trail** - receipt IDs of every successful execution. Verify offline with `latchgate ledger verify`.
- **Execution grants** - grant IDs that authorised each execution.

## Files

| File | Purpose |
|---|---|
| `orchestrator.py` | Test scenarios and main entrypoint |
| `_helpers.py` | Terminal styling, output functions, result tracking |
| `pyproject.toml` | Dependencies (latchgate SDK, httpx, tomli) |
