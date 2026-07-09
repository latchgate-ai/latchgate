# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest release | Yes |
| older releases | No |

Only the latest release receives security updates. Pin to a specific version for production and upgrade promptly when a security advisory is published.

## Reporting a Vulnerability

**Do not open a public issue.**

1. **Preferred:** use [GitHub Private Vulnerability Reporting](https://github.com/latchgate-ai/latchgate/security/advisories/new).
2. **Fallback:** email m2papierz@gmail.com with subject `[LatchGate Security]`.

Include:
- Description of the vulnerability and its impact
- Reproduction steps or proof of concept
- Affected version(s) and component(s)
- Severity assessment if known (see classification below)

## Severity Classification

We use [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) for severity assessment:

| Severity | CVSS Score | Response target |
|----------|------------|-----------------|
| Critical | 9.0 -- 10.0 | Fix within 3 days, advisory within 24h of fix |
| High | 7.0 -- 8.9 | Fix within 5 days |
| Medium | 4.0 -- 6.9 | Fix within 14 days |
| Low | 0.1 -- 3.9 | Fix in next scheduled release |

These are targets, not guarantees. Complex issues may take longer. We will communicate progress to the reporter throughout.

## Response Timeline

| Step | Target |
|------|--------|
| Acknowledgement | 48 hours |
| Triage and severity assessment | 3 business days |
| Fix (see severity table above) | 3 -- 14 days |
| Public disclosure | After fix is released |

## Coordinated Disclosure

We follow coordinated disclosure. We ask reporters to keep findings confidential until a fix is released. We will coordinate a disclosure timeline with the reporter and request a CVE where applicable.

We credit reporters in the release notes and security advisory unless anonymity is requested.

## Safe Harbor

We consider security research conducted in good faith to be authorized and will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission of the account holder
- Do not exploit a vulnerability beyond the minimum necessary to demonstrate it
- Report the vulnerability through the channels described above before any public disclosure

## Scope

### In scope

This policy covers all components of the LatchGate security boundary:

- **Server runtime:** `latchgate-api`, `latchgate-kernel`, `latchgate-auth`, `latchgate-policy`, `latchgate-ledger`, `latchgate-providers`, `latchgate-core`
- **MCP adapter:** `latchgate-mcp` (`latchgate-mcp` binary)
- **SDK clients:** Python SDK (`latchgate` on PyPI), TypeScript SDK (`latchgate` on npm)
- **WASM provider interface:** host I/O contracts, sandbox enforcement, module verification
- **Supply chain:** release pipeline, Docker images (`ghcr.io/latchgate-ai/latchgate`), install script, Homebrew tap (`latchgate-ai/tap/latchgate`)
- **Cryptographic operations:** DPoP proof generation/verification, Ed25519 receipt signing, JCS canonicalization, grant integrity

### Out of scope

- Example and demo configurations shipped in `examples/`
- Third-party OPA policies authored by users
- User-authored WASM providers (report to the provider author)
- The documentation site itself (unless it serves executable content)

## Threat Model

See the [Security Model](https://latchgate-docs.pages.dev/security-model/) for trust boundaries, threat model, defense-in-depth layers, fail-closed behavior, and explicit non-goals. See [Architecture](https://latchgate-docs.pages.dev/architecture/) for the system layer diagram, crate layout, and security invariants.
