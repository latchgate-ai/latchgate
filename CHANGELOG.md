# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.2] — 2026-06-05

### Fixed

- Cross-compilation for `aarch64-unknown-linux-gnu`: the 0.1.1 fix installed
  `clang` in the Cross container but did not account for Cross overriding the
  linker to `aarch64-linux-gnu-gcc` via environment variable, which rejects the
  `-fuse-ld=lld` flag from `.cargo/config.toml`. The release workflow now strips
  the conflicting target section before cross builds; `Cross.toml` additionally
  installs `lld` for completeness.
- SBOM generation on virtual workspace: `cargo cyclonedx --top-level` produces
  no output when the workspace root has no `[package]` section. Changed to
  `--manifest-path crates/latchgate-bin/Cargo.toml` to target the shipped
  binary, capturing the full transitive dependency tree.
- OpenSSF Scorecard workflow: updated `github/codeql-action/upload-sarif` from
  a v3 pin (imposter commit `b22c662…` rejected by the scorecard webapp) to
  v4.35.1 (`c10b806…`).
- Dead code warning on aarch64: `BPF_JGE` constant gated with
  `#[cfg(target_arch = "x86_64")]` to match its only usage site (x32 ABI
  guard in seccomp filter).

## [0.1.1] — 2026-06-05

### Fixed

- Cross-platform `O_PATH` handling: macOS builds failed because `libc::O_PATH`
  is Linux-only. Introduced a platform-conditional constant that falls back to
  `O_RDONLY` on non-Linux targets, preserving the same security invariants
  (`O_DIRECTORY`, `O_NOFOLLOW`, `O_CLOEXEC` are enforced on all platforms).
- Cross-compilation for `aarch64-unknown-linux-gnu`: added `Cross.toml` to
  install `clang` in the cross container.
- SBOM generation: replaced removed `--output-file` flag in `cargo-cyclonedx`
  with `--top-level` and deterministic rename.
- OpenSSF Scorecard workflow: corrected `ossf/scorecard-action` commit hash.

### Added

- Minisign signing of release artifacts and `install.sh` in the release
  pipeline; `install.sh` now verifies signatures and fails closed when
  `minisign` is absent (bypassable with `LATCHGATE_SKIP_SIGNATURE_CHECK=1`).
- npm trusted publishing via OIDC (replaces `NPM_TOKEN`).

## [0.1.0] — 2026-06-01

First public release. The security model is production-ready; the API and
manifest format may change in breaking ways before v1.0. Pin to a specific
commit for production use.

### Scope

LatchGate is an execution security kernel for AI agents. The model requests
an action; the kernel decides whether it runs — authenticated, policy-checked,
budgeted, sandboxed, and signed. Credentials never enter the agent process,
and every decision produces a tamper-evident receipt.

v0.1 ships two built-in provider classes — `http_api` (API calls, webhooks,
web reads, service integrations) and `fs` (scoped filesystem reads and
writes) — covering the majority of agent traffic. Additional provider classes
(email/SMTP, database, queue, artifact store) have WIT interfaces and
scaffolding in-tree and will ship in later versions.

### Enforcement pipeline (`latchgate-kernel`)

- Single fail-closed request pipeline; every protected action follows the
  same path or it does not execute. The default decision is deny.
- Ordered stages: pre-auth rate limiting => lease + DPoP authentication =>
  replay/revocation check => action resolution + module-digest verification =>
  canonicalization + `request_hash` => JSON Schema validation => sink/domain/path
  pre-checks => OPA policy evaluation => approval hold (if required) => atomic
  budget reserve => Ed25519 grant issuance => pre-dispatch intent write +
  one-shot grant consumption (single transaction) => WASM dispatch => response
  schema validation => effect verification => signed receipt + ledger write.
- **One-shot execution.** The grant is marked consumed in the same SQLite
  transaction (`BEGIN IMMEDIATE`) as the pre-dispatch intent write, before
  dispatch. A crash, retry, or concurrent request reusing the grant is denied
  — non-idempotent side effects never run twice.
- **Crash recovery.** Pre-dispatch `ExecutionIntent` records detect
  "dispatched but no receipt" states; outcome markers prevent re-claim of
  approvals after partial completion failure.
- **Pre-auth rate limiting.** Bounds CPU cost of DPoP verification, OPA
  evaluation, and WASM instantiation before any cryptographic work; 429
  responses carry `Retry-After`.
- **Drain guard.** Graceful shutdown rejects new work with 503 (retry) rather
  than dropping in-flight evidence.
- Effect verification per action: `http_status` (HTTP response assertions) and
  `fs_hash` (filesystem content digest).
- **Host-observed effects.** During provider I/O, the host independently
  records transport-layer observations (HTTP status, response body hash,
  filesystem content digest). The verifier cross-checks these against the
  provider's self-reported output — a compromised WASM module cannot lie about
  what happened.
- **Template resolution** for parametrised HTTP actions: `{{variable}}`
  placeholders resolved from the schema-validated request body, percent-encoded
  to prevent path injection, fail-closed on unknown variables. Runs inside the
  kernel before WASM dispatch — the provider never sees raw template strings.
- Structured error responses expose a machine-readable `error` code and never
  leak internal detail (paths, OPA rule names, module digests); policy denials
  additionally surface a `deny_reason` for diagnostics.

### Security hardening

- `#![deny(unsafe_code)]` on every crate except `latchgate-sandbox`, where
  syscall-level isolation requires it; that crate enforces
  `#![deny(clippy::undocumented_unsafe_blocks)]`.
- `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]` on
  the security-critical crates (core, crypto, auth, kernel, policy, api,
  sandbox): a naked `unwrap`/`expect` outside tests is a compile error.
  `panic = "abort"` in the release profile.
- Secrets wrapped in `Zeroizing` at the host transport boundary; never placed
  in the WASM sandbox or model context.
- **Explicit insecurity.** Any deviation from secure defaults requires an
  `unsafe_` flag visible in config and the audit trail. Production startup
  rejects dev-mode identity, ephemeral keys, and shared operator credentials,
  and requires `dpop_jkt` on every operator credential.
- Constant-time comparison for tokens and signatures.
- **Input sanitization** at every untrusted boundary: control characters
  (U+0000–U+001F, U+007F, C1 range) replaced with spaces, length-capped in
  bytes with UTF-8-safe truncation. Prevents newline/ANSI injection in logs,
  audit events, metrics labels, and HTTP responses.
- **Path containment.** Symlink-aware canonicalization rejects paths that
  escape the merge root — a manifest in `manifests/` cannot resolve to
  `/etc/shadow` via a symlink.
- **Security constants.** Config fields whose only safe value is the default
  (`replay_ttl`, `opa_timeout`, `max_lease_lifetime`) promoted to compile-time
  constants, removing misconfiguration surface.

### Authentication (`latchgate-auth`)

- DPoP sender-constrained proofs (RFC 9449): `htu`/`htm` binding, `ath`
  access-token binding, `jkt` thumbprint, ES256 / P-256.
- ES256-signed lease JWTs scoped per agent with call and cost ceilings; sender-bound to the
  DPoP key.
- Replay cache with `jti` tracking; fail-closed when the cache is unreachable.
- Revocation epoch kill-switch: bump the epoch to invalidate all outstanding
  leases and grants at once.

### Cryptography & evidence (`latchgate-crypto`, `latchgate-ledger`)

- Ed25519 signing/verification with key rotation; SHA-256 throughout.
- Append-only, hash-chained SQLite ledger. Every decision — allow, deny,
  approval, error — is recorded and Ed25519-signed. Modifying or deleting any
  entry breaks the chain from that point forward (verified by standalone
  tamper-detection tests).
- WAL journaling, busy timeout, and `locking_mode = EXCLUSIVE` for the
  forensic store; transactional receipt finalization (receipt and audit commit
  together or not at all).

### Configuration (`latchgate-config`)

- Layered config: file, environment, and CLI flags with strict precedence;
  boolean env parsing rejects ambiguous values.
- Auto-discovery of config and operator credentials; single-credential dev
  mode needs no flags.
- Dev-mode auto-detection from the source tree (`definitions/manifests/`,
  `definitions/policies/opa/`, `target/providers/`).
- Eleven security presets: `agent`, `blank`, `coding`, `data`, `devops`,
  `lockdown`, `ops`, `permissive`, `quickstart`, `read-only`, `team`.

### Registry & manifests (`latchgate-registry`)

- 87 action manifests across four risk tiers (low / medium / high / critical).
- `provider_module_digest` accepts `sha256:<hex>` (WASM modules, verified at
  load) or `builtin:<name>` (providers compiled into the server binary).
- Per-action declarations: input/output JSON Schemas, egress domain
  allowlists, filesystem path scopes, risk level, and verifier kind.

### Policy (`latchgate-policy`)

- OPA / Rego evaluation outside the model's influence; fail-closed (OPA
  unreachable => deny).
- Decisions: allow, deny, or pending-approval, with per-decision egress and
  secret approvals.
- `latchgate.rego` policy plus a Rego test suite (`test_latchgate.rego`).
- **Approval-bypass allowlist.** Per-(action, principal) entries that skip the
  approval hold while all deny rules (trust, ACL, scope, budget, sink) still
  apply unconditionally. Managed via admin API and audited in the ledger.
- JCS (RFC 8785) canonicalization with SHA-256 hashing; I-JSON subset
  validation and size/depth DoS limits enforced before hashing.

### Budgets & approvals (`latchgate-state`)

- Per-session call and cost ceilings, atomically reserved and debited
  (Redis-backed); exhaustion denies. Rollback on post-debit failure.
- High-risk actions block until a human approves; the kernel stores an
  immutable execution plan and issues no grant until then. Plan-integrity
  checks reject any request mutation between approval and execution.
- **Approval expiry scanner.** Background task polls pending approvals and
  emits `approval.expired` domain events for webhook/notification delivery.
  Duplicate-safe via seen-set; non-fatal errors logged, never propagated.

### Providers (`latchgate-providers`, `providers/`)

- WASM providers run with no filesystem and no network access; only clocks and
  randomness are available. One fresh sandbox instance per call.
- Built-in providers: `http_api` and `fs`. Each WASM module is SHA-256-pinned
  and verified before instantiation.
- **HTTP transport defenses:** port 443 only; `https`/`http` schemes only
  (`file:`, `gopher:`, `ftp:`, `data:` rejected); DNS resolved once and pinned
  for the connection (closes the rebinding TOCTOU window); private/internal IP
  ranges rejected after resolution; per-action domain allowlists validated
  before dispatch.
- **Filesystem path enforcement.** Glob-based allowlists and denylists
  evaluated at the host I/O boundary; deny overrides allow. Shared evaluation
  between host import validation and OPA policy.
- Per-execution I/O call budgets enforced at the host boundary; exceeded
  budgets terminate the sandbox.
- **Runtime domain/path learning.** Operators can approve egress domains and
  filesystem path globs at runtime. Learned entries are per-action, additive
  only (manifest entries are immutable), and fail-closed to the manifest
  baseline on error.
- WIT host interfaces defined for current and forthcoming providers:
  `io-http`, `io-fs`, `io-database`, `io-queue`, `io-smtp`, `io-storage`,
  `io-log`, and the `provider` world.

### Webhooks (`latchgate-webhooks`)

- Push events to Slack, Teams, PagerDuty, or any HTTPS endpoint.
- HMAC-SHA256 signed, asynchronous delivery with retry and a dead-letter
  queue (outbox pattern).

### Agent process sandbox (`latchgate-sandbox`)

- Runs the agent inside Linux namespaces — user, network, mount, PID, UTS,
  IPC, cgroup, time (`CLONE_NEW*`) — with seccomp-BPF and
  `pivot_root`. Requires Linux ≥ 5.8 with unprivileged user namespaces.
- The agent sees an empty filesystem and no network interfaces; only two exits
  exist: the gate UDS and an HTTPS CONNECT proxy.
- Egress proxy accepts CONNECT to allowlisted hosts on port 443 only;
  everything else is refused at the network boundary.

### HTTP API (`latchgate-api`)

- Unix domain socket transport (production) and HTTP (dev mode).
- `/healthz` liveness probe; `/readyz` readiness probe (checks Redis, OPA,
  ledger, approval store, egress proxy, action count; returns
  `ready`/`degraded`/`not_ready`).
- `/.well-known/jwks.json` — public key discovery for lease JWT verification.
- `/metrics` — Prometheus text exposition format (operator-authenticated).
- `/v1/receipts/{id}` — receipt retrieval on both the admin socket
  (operator DPoP) and the client socket (lease DPoP).
- `/v1/receipt-keys` — receipt signing public keys for offline verification.
- `/v1/actions/{id}/schema/request` — request JSON Schema retrieval for
  client-side validation.
- Admin CRUD endpoints for runtime resource management:
  `/v1/admin/domains` (list, add, remove, clear),
  `/v1/admin/paths` (list, add, remove, clear),
  `/v1/admin/policy/allowlist` (add, remove approval-bypass entries),
  `/v1/admin/policy` (show ACL, per-principal detail, grant, revoke),
  `/v1/admin/reload` (hot-reload config and manifests),
  `/v1/admin/drain` (graceful drain), `/v1/admin/status`, `/v1/admin/epoch`.
- **Domain event system.** Security-relevant state changes (action allowed,
  denied, approval pending/approved/denied/expired) emitted as structured
  events. Webhook, metrics, and audit consumers subscribe independently.
- Status-code semantics: 401 auth, 403 policy/trust, 409 grant-consumed/
  conflict, 422 schema, 429 rate-limited, 502 provider, 503 dependency-
  unavailable/draining. 503 still denies — there is no permissive fallback.

### CLI (`latchgate-cli`, `latchgate` binary)

- `latchgate up` — one-command dev/eval setup; manages Redis, OPA, and the
  egress proxy via Docker, generates a dev config, and runs the gate. First
  run launches an interactive setup wizard. `--reset` re-runs the wizard.
- `latchgate down [--prune] [--yes]` — stop Docker dependencies; `--prune`
  also deletes the data directory (audit DB, receipts, cache).
- `latchgate serve` — production server against externally managed
  infrastructure.
- `latchgate sandbox [--workspace DIR] [--allow-host H] [--bind PATH] [--env K]
  -- <cmd>` — launch an agent inside the namespace sandbox.
- `latchgate doctor` — pre-flight checks (config, Redis, OPA, providers,
  manifests, secrets, host WASM capabilities); dev-mode aware.
- `latchgate status` — config, mode, resource counts, dependency health.
- `latchgate tui` — interactive terminal UI (see below).
- `latchgate init [--preset NAME]` — scaffold a project non-interactively.
- `latchgate actions [ACTION]` — list registered actions or show one.
- `latchgate audit` — query the signed ledger (operator-authenticated).
- `latchgate verify` — offline ledger hash-chain integrity check.
- `latchgate revoke [--yes]` — bump the revocation epoch (kill-switch).
- `latchgate approvals {list, show <id>, approve <id> [-y], deny <id>
  [--reason]}` — operator approval workflow.
- `latchgate operator keygen [-o PATH]` — generate a DPoP operator keypair
  (ES256 / P-256).
- `latchgate config {path, resources, get}` — inspect active config and
  built-in vs. user resources.
- `latchgate policy {grant, revoke, show}` — manage policy ACLs.
- `latchgate secrets {init, set, get, list, remove}` — SOPS/age encrypted
  secret management. `init` generates an age keypair and encrypted secrets
  file; `set`/`get`/`remove` operate on individual secrets; `list` shows
  status and which actions require each secret.
- `latchgate domains {list, add, remove, clear, check}` — manage learned
  egress domain allowlists. `check` dry-runs a domain against the effective
  allowlist (manifest + learned) using the same matching logic as the runtime.
- `latchgate completions {bash, zsh, fish, powershell}` — shell completion
  script generation.
- `latchgate domains {list, add}` — manage the learned egress allowlist.
- `latchgate secrets {init, set, get, list, remove}` — operator secret store.
- `latchgate completions <shell>` — shell completion scripts.
- `--operator-key` / `LATCHGATE_OPERATOR_KEY` and `--operator-private-key` /
  `LATCHGATE_OPERATOR_PRIVATE_KEY` for authenticated commands; `--json` for
  scripting and CI.

### Terminal UI (`latchgate-tui`)

- Full-screen operator console (`latchgate tui`) with tabbed navigation
  (`Tab` / `Shift-Tab`): Dashboard, Activity, Approvals, Actions, Domains,
  Policy.
- **Dashboard** — live resource counts, dependency health, throughput
  sparklines, status cards, and meters.
- **Approvals** — review pending approvals with full plan detail; single-
  keypress approve/deny with countdown timers and live polling.
- **Activity** — streaming decision feed (allow/deny/approval/error).
- **Actions** — registered action inventory with digest status.
- **Domains** — learned egress allowlist management.
- **Policy** — policy ACL inspection.
- Interactive setup wizard (shared with `latchgate up` first-run), in-app
  config editing, and editor suspend/resume.

### MCP adapter (`latchgate-mcp`, `latchgate-mcp` binary)

- Bridges MCP-speaking agents to LatchGate over stdio JSON-RPC 2.0
  (MCP 2024-11-05).
- `latchgate-mcp install --ide <cursor|claude|cline|windsurf|codex>` — one-command
  IDE configuration.
- `tools/list` exposes registered actions as MCP tools with `inputSchema`;
  `tools/call` constructs a per-request DPoP proof and maps gate responses.
- UDS transport (default) and TCP/HTTP transport (dev); DPoP + lease lifecycle
  with automatic renewal.

### SDKs

- **Python 3.10+** (`pip install latchgate`) — async client with lazy-connect,
  `LATCHGATE_URL` support, automatic DPoP proof construction, typed results and
  exceptions (denied, approval-required, budget-exhausted, lease-expired,
  replay-detected, unavailable).
- **TypeScript / Node 18+** (`npm install latchgate`) — equivalent async
  client.

### Framework integrations

Published separately at `latchgate-ai/latchgate-integrations`; each auto-discovers
actions and wraps them as native framework tools: LangChain, CrewAI, Vercel
AI SDK, OpenAI Agents, Pydantic AI.

### Egress allowlist generation

- Egress allowlists are derived from action manifests — the single source of
  truth for permitted domains. The `squid-allowlist` Make target and release
  pipeline generate a Squid `dstdomain` list; `egress_sync` renders and
  hot-reloads it for the proxy.
- `egress_runtime_allowlist` config field for operator-controlled domain
  narrowing that intersects with manifest allowlists at runtime.

### Supply chain & build

- Static musl binary, zero runtime dependencies; `--locked` / `--frozen` on
  every build.
- Reproducible release tarballs (`SOURCE_DATE_EPOCH`, sorted tar, `gzip -n`)
  with per-artifact SHA-256 checksums verified before publish.
- Reproducible WASM provider modules built in a pinned container
  (`--remap-path-prefix`); committed digests verified at module load and again
  at image build.
- All container base images pinned by SHA-256 digest (Dependabot-managed).
- SLSA build-provenance and CycloneDX SBOM attestations on every release
  artifact; PyPI and npm published via OIDC trusted publishing
  (`--provenance`).
- CI gate: `cargo fmt --check`, `cargo clippy --lib --bins -D warnings`,
  unit tests (`cargo test --workspace --lib`), a release-build test-hooks
  guard, `cargo deny`, and `cargo audit`. The Docker-dependent suites
  (standalone, integration, conformance) are run locally, not in hosted CI
  for v0.1.0 — see CONTRIBUTING.md.

### Infrastructure & deployment

- `install.sh` — OS/arch detection, tarball download from GitHub Releases,
  SHA-256 verification, and shell-completion install.
- Homebrew tap (`latchgate-ai/tap/latchgate`).
- Multi-arch Docker images (linux/amd64, linux/arm64): the gate
  (`ghcr.io/latchgate-ai/latchgate`) and the egress proxy
  (`ghcr.io/latchgate-ai/latchgate-egress`), running as a non-root user with a
  healthcheck.
- `docker-compose.yml` with profiles for Redis, OPA, Squid egress proxy, and
  Prometheus; `cap_drop` and `security_opt` hardening.
- GitHub Action (`latchgate-ai/latchgate-action@v1`) for gating tool calls in CI.

### Testing & fuzzing

- Six `cargo-fuzz` targets covering security-critical parsers: `canonical_hash`,
  `domain_allowlist_match`, `ip_classification`, `manifest_domain_entry`,
  `parse_host_from_url`, `path_glob_match`.
- Standalone test suites (no external infra): WASM provider isolation, ledger
  tamper detection (direct SQLite manipulation), receipt key rotation across
  simulated restarts, WASM conformance against compiled provider modules,
  webhook delivery, execution-path coverage, compose-port isolation, and
  manifest coverage (risk consistency, secret declarations, egress profiles,
  naming conventions, schema compilation, verifier strength gates).
- Integration test suites (require Docker): end-to-end pipeline through the
  real HTTP surface, resilience (mid-session backend death, embedded-mode
  recovery), and evidence-persistence failure (post-dispatch finalization
  fault injection via test-hooks).

### Documentation

- `RISK_MODEL.md` — four-tier risk classification guide with rationale and
  examples for each level (low, medium, high, critical). Referenced by every
  manifest's `risk_rationale`.
- `SECURITY.md` — vulnerability reporting policy.
- `CONTRIBUTING.md` — development workflow, test commands, and PR checklist.

### Repo layout

- Source tree reorganized for clarity: `wit/` => `providers/wit/`,
  `spec/` => `definitions/`, `policies/` => `definitions/policies/`.
  Install-output layouts (`.latchgate/`, `share/latchgate/`) unchanged.

[0.1.2]: https://github.com/latchgate-ai/latchgate/releases/tag/v0.1.2
[0.1.1]: https://github.com/latchgate-ai/latchgate/releases/tag/v0.1.1
[0.1.0]: https://github.com/latchgate-ai/latchgate/releases/tag/v0.1.0
