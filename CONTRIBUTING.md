# Contributing to LatchGate

LatchGate is an execution security kernel. Contributions touch code that enforces security invariants in production, so the bar for review is high, and the expectations for testing and documentation are explicit. This guide covers everything you need to set up, build, test, and submit changes.

## Reporting bugs and security issues

**Security vulnerabilities** - do not open a public issue. Use GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) or see [SECURITY.md](SECURITY.md). We take every report seriously and will respond within 48 hours.

**Bugs** - open a GitHub issue with your LatchGate version (`cargo pkgid latchgate-api`), Rust version (`rustc --version`), platform, minimal reproduction steps, and expected vs. actual behavior. If the bug is security-adjacent (e.g., a policy evaluation that produces an unexpected allow, a receipt missing fields), please flag that explicitly in the issue title so we can triage it faster.

**Feature requests** - open an issue describing the use case before writing code. For large changes (new crate, new provider, changes to the kernel pipeline, changes to the grant or receipt structure), wait for maintainer feedback before investing significant effort. We may have context on architectural constraints that aren't obvious from the code alone.

## Development setup

**Prerequisites:**

You need Rust 1.88+ (`rustup update stable`), the `wasm32-wasip2` target (`rustup target add wasm32-wasip2`), Docker (for the dev stack and security tests), and `make`. If you're working on the Python SDK you'll also need Python 3.10+ and [`uv`](https://docs.astral.sh/uv/); for TypeScript SDK work, Node.js 18+ and `npm`.

**First-time setup:**

```bash
git clone https://github.com/latchgate-ai/latchgate.git
cd latchgate
make setup          # installs git hooks (pre-commit runs `make check`)
make quickstart     # generates dev config, starts deps, builds providers
```

Or step by step if you want more control:

```bash
make setup
latchgate init --dev
make dev            # starts Redis + OPA + Squid + Prometheus via Docker Compose
make providers      # builds WASM provider modules + updates manifest digests
```

The dev stack exposes Redis on `127.0.0.1:6379` and OPA on `127.0.0.1:8181`, matching the defaults in the generated config. To start the gate: `LATCHGATE_DEV_MODE=true latchgate serve`. To verify everything is wired correctly: `latchgate doctor`.

**Faster linker (optional but recommended):**

The workspace ships with `.cargo/config.toml` configured for `clang` + `lld`. On Linux, install them with `sudo apt install clang lld`. If you want even faster link times, `mold` is noticeably better - install it (`sudo apt install mold`) and add this to your personal `~/.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

This isn't committed to the project config because it breaks on machines without `mold`, but it cuts incremental link times significantly on large workspaces. On Windows, `rust-lld` ships with rustup and is enabled automatically.

**Compilation cache (recommended):**

`sccache` is enabled in `.cargo/config.toml` and caches compiled artifacts across `cargo clean` invocations. Especially impactful for C dependencies (libsqlite3-sys, cranelift) that recompile from source on every clean build. `make setup` installs it automatically, or:

```bash
cargo install sccache --locked
```

## Running the tests

The test suite is stratified by what it exercises and what infrastructure it needs. Here's the full picture:

```bash
make test               # unit + integration tests for all Rust crates (starts Redis)
make test-opa           # OPA policy unit tests (no Gate or Docker stack required)
make test-standalone    # cross-crate security invariant suite (no Docker)
make test-integration   # integration tests (requires Redis + OPA via `make dev`)
make test-conformance   # WASM conformance tests (requires compiled providers + fixtures)
make test-sdk-python    # Python SDK tests (requires uv)
make test-sdk-typescript # TypeScript SDK tests (requires node + npm)
make test-sdk           # both SDK test suites
make test-all           # all of the above

make check              # cargo fmt --check + clippy (no I/O, fast)
make audit              # cargo audit + cargo deny
make ci                 # full local gate: check + test + audit (run before pushing)
```

**What CI enforces.** GitHub Actions runs the fast gate on every push and PR: format, clippy, unit tests (`cargo test --workspace --lib`), a release-build test-hooks guard, dependency audit (`cargo deny` + `cargo audit`), image-digest pin verification, and the SDK suites. The Docker-dependent suites — `make test-standalone`, `make test-integration`, and `make test-conformance` — are **not** run in hosted CI: they require Redis, OPA, and a reproducible WASM provider build that are impractical on the standard GitHub-hosted runners. **You are responsible for running them locally before opening a PR that touches security-sensitive code** (see step 4 below). `make ci` runs the full local gate (`check` + `test` + `audit`); run it before pushing.

**Running a single test:**

```bash
cargo test -p latchgate-auth -- dpop::tests::verify_dpop_proof
```

**Running with logs:**

```bash
RUST_LOG=debug cargo test -p latchgate-kernel 2>&1 | less
```

**Validating provider digests (what CI checks):**

```bash
make providers-verify
```

This runs `deploy/verify-manifest-digests.py`, confirming every manifest's `provider_module_digest` matches the actual `.wasm` binary. A mismatch means the kernel will refuse to load the provider at startup.

## Making changes

1. Fork the repo and create a branch from `main`: `git checkout -b feat/my-feature`.
2. Make your changes. For non-trivial features, add tests. For security-sensitive changes, add regression tests in `tests/standalone/`.
3. Run `make fmt` to auto-format and fix lints.
4. Run `make test` (always). Then, because hosted CI does not run them, run locally as applicable: `make test-standalone` if you touched the kernel pipeline, auth, policy, providers, or the ledger; `make test-integration` and `make test-conformance` for changes to the request pipeline or providers (these need `make dev` for Redis + OPA, and `make providers` for the WASM build); `make test-opa` if you touched `definitions/policies/opa/`; `make test-sdk` if you touched `sdk/`. These suites guard security invariants that the fast CI gate cannot — running them is on you.
5. Commit using [conventional commits](#commit-conventions).
6. Open a PR against `main`.

## Working on the Rust crates

The workspace is organized under `crates/`, with each crate having its own `Cargo.toml` and test module. Internal dependencies use `path = "../crate-name"` with a pinned `version`. The crate dependency graph is intentional and enforced:

`core` has no provider or API dependencies - it defines types, config, canonical forms, grants, receipts, and signers. `kernel` depends on traits, not concrete transports. `providers` host I/O never calls `policy` directly. Effect verifiers never mutate approval or budget state. `api` does not contain business logic - it routes requests and delegates to `kernel`. Provider `.wasm` modules never import kernel internals; they only see `latchgate:io/*` interfaces.

Security-sensitive code (auth, pipeline, policy, grant signing, receipt signing, host I/O, WASM runtime) has inline `// SECURITY:` comments explaining the invariant being maintained. These comments are not decoration - they document the reasoning behind non-obvious code, and they serve as review anchors. **If you change code near a `// SECURITY:` comment, update the comment to reflect the new state.** If you're adding a new security invariant, add a `// SECURITY:` comment explaining what it enforces and how.

## Working on providers

Provider source lives under `providers/`. Each provider is a standalone Rust crate that compiles to `wasm32-wasip2`. To add a new provider:

1. Create a new crate under `providers/` (look at `providers/http_api/` for the pattern).
2. Add it to the `PROVIDERS` list in the Makefile and as a member in `providers/Cargo.toml`.
3. Create a manifest in `definitions/manifests/` with `provider_source: "your_provider.wasm"`.
4. Define request/response JSON Schemas inline in the manifest's `io:` section.
5. Build and rehash: `make providers-rehash` (compiles modules and writes digests into the manifests).
6. Verify: `make providers-verify`.
7. Add WASM conformance test coverage in `tests/standalone/wasm_conformance.rs` if the provider exercises new host I/O patterns.

## Working on OPA policy

Policy lives in `definitions/policies/opa/`. Unit tests are in `definitions/policies/opa/test_*.rego` and run with `make test-opa`. Policy changes must include test coverage for both the allow and deny paths. The default policy ships with the open-source distribution and should remain a reasonable starting point - avoid adding organization-specific logic to the defaults.

## Working on the SDKs

SDKs live in `sdk/python/` and `sdk/typescript/` with independent dependency managers (`uv` and `npm`). When changing the API (adding a field to an endpoint response, renaming an endpoint, changing request structure), update both SDKs and their tests together in the same PR. The SDKs handle DPoP key generation, proof construction, lease management, and receipt retrieval - if you're changing any of these flows in the kernel, coordinate with the SDK code.

**Python SDK:**

```bash
cd sdk/python
uv sync
uv run pytest tests/ -v
uv run ruff format .
uv run ruff check --fix .
uv run mypy latchgate/
```

**TypeScript SDK:**

```bash
cd sdk/typescript
npm ci
npm test
npm run lint
npm run typecheck
```

## Working on action specs

Manifests live in `definitions/manifests/` with schemas defined inline. The registry validates manifests at startup - a gate that fails to load its manifests will not start. Run `make test` to catch manifest or schema errors early. When adding or changing a manifest, also run `make providers` to ensure digests are up to date, followed by `make providers-verify`.

### Domain convention

Generic actions (those usable against any HTTP endpoint) ship with empty `allowed_domains`. Operators configure domains for their environment. Service-specific actions ship with the canonical service domain only.

```
generic actions  (http_*, webhook_notify)    => allowed_domains: []
service actions  (github_*, gmail_*, etc.)   => allowed_domains: ["api.github.com"]
```

Example configurations with pre-populated domains can be copied during setup with `latchgate init --include-examples`.

### Risk classification

Every manifest must declare a `risk_level` and include a `# Risk rationale:` comment that maps to one of the categories in `RISK_MODEL.md`. When adding or changing a manifest, verify the risk level is appropriate:

- **low** — read-only, no auth required, no PII.
- **medium** — write to one external endpoint, or read with auth.
- **high** — multi-recipient, modifies local code, accesses PII/financial data, hard to undo.
- **critical** — destructive, no rollback, financial transactions.

See `RISK_MODEL.md` for the full classification criteria and manifest requirements per level.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat` (new feature), `fix` (bug fix), `security` (security fix - use for any security-relevant change), `refactor`, `test`, `docs`, `chore` (deps, tooling, CI), `perf`.

Scope is optional but helpful: the affected crate or area, e.g. `auth`, `kernel`, `pipeline`, `sdk-python`, `opa`, `api`, `providers`, `cli`.

```
feat(auth): add per-lease budget constraints to Lease JWT

fix(kernel): hold lease lock during renewal to prevent duplicate requests

security(dpop): reject proofs with iat in the future beyond clock skew window

docs: expand deployment hardening guide with UDS permissions
```

Breaking changes must include `BREAKING CHANGE:` in the footer:

```
feat(api): rename /v1/tools to /v1/actions

BREAKING CHANGE: the /v1/tools/* endpoints have been removed.
Use /v1/actions/* instead.
```

## Pull request checklist

Before marking a PR ready for review:

- [ ] `make ci` passes locally
- [ ] `make test-standalone` passes if you touched auth, kernel, policy, providers, or the ledger
- [ ] `make test-integration` + `make test-conformance` pass if you touched the request pipeline or providers (these are **not** run by CI)
- [ ] `make test-opa` passes if you touched `definitions/policies/opa/`
- [ ] `make test-sdk` passes if you touched SDK code or changed the API surface
- [ ] `make providers-verify` passes if you touched manifests or provider source
- [ ] New behavior has tests; new security invariants have regression tests
- [ ] `// SECURITY:` comments are added or updated for any security-sensitive code
- [ ] `CHANGELOG.md` is updated under `[Unreleased]` for user-visible changes
- [ ] PR description explains *why*, not just *what*

## Code style

**Rust:** `make fmt` handles formatting and auto-fixable lints. Clippy is configured to deny warnings - no `#[allow(clippy::...)]` without a comment explaining why. Prefer explicit error types over `anyhow` in library crates. Use `// SECURITY:` comments for any code enforcing a security invariant.

**Python:** `ruff format`, `ruff check --fix`, `mypy`.

**TypeScript:** `eslint`, `tsc --noEmit`.

## Security-sensitive changes

Changes that touch the kernel pipeline, auth, DPoP verification, policy evaluation, WASM runtime, host I/O, grant/receipt signing, or the approval path receive extra scrutiny during review. For these changes:

1. Describe the security impact in the PR description.
2. Reference the relevant security invariant from the [security model](https://docs.latchgate.ai/security-model/) or the `// SECURITY:` comments.
3. Add or update regression tests in `tests/standalone/`.
4. If the change affects the threat model or trust boundaries, update [https://docs.latchgate.ai/security-model/](https://docs.latchgate.ai/security-model/).

We review security-sensitive PRs with at least two pairs of eyes and may ask for additional test coverage before merging.
