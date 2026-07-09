# LatchGate

Execution security kernel for AI agents.

[![CI](https://github.com/latchgate-ai/latchgate/actions/workflows/ci.yml/badge.svg)](https://github.com/latchgate-ai/latchgate/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/latchgate-ai/latchgate)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/latchgate-ai/latchgate/badge)](https://scorecard.dev/viewer/?uri=github.com/latchgate-ai/latchgate)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
![Rust](https://img.shields.io/badge/rust-1.88%2B-orange?style=flat-square)
[![Protected by CVE Lite CLI](https://img.shields.io/badge/Protected_by-CVE_Lite_CLI-brightgreen)](https://github.com/OWASP/cve-lite-cli)

[Website](https://latchgate-ai.pages.dev) · [Docs](https://latchgate-docs.pages.dev) · [Security model](https://latchgate-docs.pages.dev/architecture/security-model/) · [Report a vulnerability](SECURITY.md)

> [!IMPORTANT]
> The security model is production-ready; the API and manifest format may have breaking changes until v1.0. Pin to a specific commit for production use.

---

## The Problem

AI agents hold credentials, run shell commands, and call external APIs, but nothing enforces what they're allowed to do with that access. A single prompt injection, malicious tool, or misrouted action can exfiltrate secrets, mutate production systems, or spend money, and the operator has no cryptographic proof of what actually happened.

Authentication alone doesn't solve this. It proves *who* - not *what*, *how much*, or *whether a human approved it*. Agents need an execution boundary: a fail-closed kernel that sits between intent and side effect, enforces policy before anything runs, and produces tamper-evident evidence of every decision.

## Install

Verify [the script](https://github.com/latchgate-ai/latchgate/blob/main/install.sh) first, or download a tarball from [Releases](https://github.com/latchgate-ai/latchgate/releases).

```bash
curl -fsSL https://raw.githubusercontent.com/latchgate-ai/latchgate/main/install.sh | bash
```

Or via Homebrew:

```bash
brew install latchgate-ai/tap/latchgate
```

Start the gate:

```bash
latchgate up
```

No Docker, Redis, or OPA required. LatchGate runs as a single binary with SQLite state and an embedded policy engine. The first run launches an interactive setup wizard; subsequent runs start immediately.

For production deployments needing HA replay protection and defense-in-depth egress:

```bash
latchgate up --infra   # Redis + OPA + Squid in Docker
```

For non-interactive setup (CI, Docker), see the [deployment guide](https://latchgate-docs.pages.dev/deployment/).

## How it works

The model requests an action. LatchGate decides whether it runs - then signs the evidence.

```
Request in
  │
  ├─ Authenticate    Lease validation · DPoP sender binding · replay check
  ├─ Validate        ActionSpec digest verify · JSON schema · canonicalize
  ├─ Authorize       OPA/Rego policy · approval hold · atomic budget reserve
  ├─ Execute         Ed25519-signed grant · WASM sandbox · effect verification
  ├─ Evidence        Ed25519 receipt · hash-chained ledger · webhook fan-out
  │
  ▼
Response out (only when evidence is durable)
```

Default deny. The model never holds credentials, never has network access. Every protected side effect passes through one fail-closed pipeline, or it doesn't happen. See [Architecture](https://latchgate-docs.pages.dev/architecture/) for the full pipeline breakdown.

## Security model

| Property | How |
|---|---|
| Credential isolation | Secrets injected at the host transport layer - never in agent memory or model context |
| Policy before execution | OPA/Rego evaluates every action outside the model's influence; default deny |
| Constrained providers | WASM sandbox: no filesystem, no network. SHA-256-pinned, verified before instantiation |
| Default-deny egress | Sink-validated host I/O with per-action domain allowlists; proxy restricts to port 443 |
| One-shot execution | Grant consumed atomically before dispatch - no double execution on crash or replay |
| Budgets and approvals | Per-session call/cost limits; high-risk actions require human sign-off |
| Forensic ledger | Append-only, hash-chained SQLite with Ed25519-signed receipts and key rotation |
| Fail-closed | Redis down → deny. OPA down → deny. Budget exhausted → deny. No permissive fallback |
| Agent sandbox | Linux user/network/mount/PID namespaces + Landlock LSM + seccomp-BPF; three exits: gate socket, HTTPS proxy, credential-injecting reverse proxy |

Full threat model: [Security model](https://latchgate-docs.pages.dev/security-model/) · [Security notes](https://latchgate-ai.pages.dev/security-notes)

## Agent sandbox

`latchgate sandbox` runs the agent process inside Linux namespace isolation - user, network, mount, PID, plus Landlock LSM, seccomp-BPF, and `pivot_root`. The agent sees an empty filesystem, no network interfaces, and three controlled exits:

```
Agent process
  │
  ├─ Gate socket         tool calls through the full LatchGate pipeline
  ├─ HTTPS proxy         LLM API traffic only (port 443, allowlisted hosts)
  └─ Credential proxy    API auth injection (keys never enter the sandbox)
```

```bash
latchgate sandbox --profile claude-code
latchgate sandbox --profile aider
latchgate sandbox -- my-custom-agent   # no profile, manual flags or TOML
```

Built-in profiles: `claude-code`, `codex`, `cursor`, `opencode`, `aider`. Profiles work out of the box with subscription/OAuth — the agent authenticates through the CONNECT tunnel. For credential isolation (API key never enters the sandbox), set the provider's env var on the host; the proxy injects it on the agent's behalf. Any BYO-key agent can be sandboxed without a built-in profile via `[sandbox.agent.credentials]` in TOML.

Even if the agent is fully compromised - prompt injection, supply chain attack, malicious plugin - it cannot reach anything outside the namespace boundary. The only side effects it can trigger are those gated through LatchGate.

Guide: [Agent sandbox](https://latchgate-docs.pages.dev/guides/sandbox/) · [Profiles, credential routes, and user-defined routes](https://latchgate-docs.pages.dev/guides/sandbox/#agent-profiles)

## Security Standards

LatchGate's controls map to [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — covering prompt injection blast-radius containment (LLM01), credential isolation (LLM02), supply-chain verification (LLM03), output validation (LLM05), excessive agency (LLM06), and unbounded consumption (LLM10) — and to all four functions of the [NIST AI RMF 1.0](https://www.nist.gov/artificial-intelligence/risk-management-framework) (Govern, Map, Measure, Manage).

Supply-chain assurance: WASM modules and container images pinned by SHA-256 digest. `Cargo.lock` committed, `--locked` enforced. `cargo deny`, `cargo audit`, `pip-audit`, `cve-lite-cli`, Dependabot, CodeQL `security-extended`, and six coverage-guided fuzz targets on trust-boundary parsers.

Full mapping: [Security model](https://latchgate-docs.pages.dev/security-model/) · [Security notes](https://latchgate-ai.pages.dev/security-notes)

## Integrations

### IDE agents (MCP)

```bash
latchgate-mcp install --ide cursor   # or: claude-code, claude, cline, windsurf, codex, opencode, copilot, hermes-agent, openclaw, antigravity
```

Restart the IDE. LatchGate-registered actions appear as MCP tools alongside the IDE's built-in tools - only calls to LatchGate tools go through the gate.

### Frameworks

| Framework | Install |
|---|---|
| LangChain | `pip install latchgate-langchain` |
| CrewAI | `pip install latchgate-crewai` |
| Vercel AI SDK | `npm install @latchgate/ai-sdk` |
| OpenAI Agents | `pip install latchgate-openai-agents` |
| Pydantic AI | `pip install latchgate-pydantic-ai` |

Each integration auto-discovers actions and wraps them as native framework tools. Guides: [docs.latchgate.ai/integrations](https://latchgate-docs.pages.dev/integrations/)

### SDKs

| Language | Install |
|---|---|
| Python 3.10+ | `pip install latchgate` |
| TypeScript / Node 18+ | `npm install latchgate` |

Both support lazy-connect, `LATCHGATE_URL`, and automatic DPoP proof construction.

```python
from latchgate import LatchGateClient

async with LatchGateClient() as client:
    await client.connect(agent_id="my-agent")
    result = await client.execute("http_post", {
        "url": "https://api.example.com/v1/orders",
        "body": body,
    })
    # Token injected at the host layer. Policy checked. Budget enforced. Signed receipt.
```

## Operations

```bash
latchgate status            # config, mode, resource counts, dependency health
latchgate doctor            # full pre-flight check
latchgate actions           # list registered actions
latchgate audit             # query the signed ledger
latchgate verify            # verify ledger hash-chain integrity
latchgate revoke <id>       # revoke a lease or grant
```

## Development

```bash
git clone https://github.com/latchgate-ai/latchgate.git && cd latchgate
make setup              # git hooks (once)
make quickstart         # build + dev config + infra + providers
make serve              # start the gate

make test               # unit tests
make test-all           # unit + standalone + integration + OPA + SDK
make ci                 # full CI gate
make fuzz-smoke         # 60s per fuzz target
```

Dev-mode auto-detection: when CWD is the source repo, the binary resolves manifests, policies, and providers from the working tree. No install step needed.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

Apache-2.0 - see [LICENSE](LICENSE).
