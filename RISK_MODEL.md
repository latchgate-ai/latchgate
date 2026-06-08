# Risk Model

Risk levels classify actions by their potential for harm. The OPA policy uses risk levels to enforce approval requirements. Every manifest must declare a `risk_level` with a `risk_rationale` comment that maps to one of the categories below.

## Levels

### low

Read-only, no auth required, no PII exposure.

The action retrieves public data with no side effects. No credentials are injected by the host layer, or credentials are optional and the action functions without them. The response cannot contain personally identifiable information or financial data under normal use.

Examples: `http_fetch`, `github_read`, `wikipedia_read`, `hn_top`, `rss_fetch`, `fs_read`.

### medium

Write to one external endpoint, or read with auth.

The action modifies state at a single external service, or reads data that requires authentication (implying access to non-public resources). Budget controls limit call volume. Operator-configured domain allowlists scope the blast radius.

Examples: `http_post`, `http_put`, `http_patch`, `webhook_notify`, `slack_post`, `s3_read`, `gmail_read`.

### high

Sends to multiple recipients, modifies local code, accesses financial/PII data, or is hard to undo.

The action can affect multiple downstream systems, alter the local project in ways that change runtime behavior, read sensitive data that could cause harm if exfiltrated, or perform writes that are difficult to reverse. Human approval is required before execution.

Examples: `fs_write`, `http_delete`, `http_sensitive_read`, `gmail_send`, `github_pr_merge`, `stripe_read`.

### critical

Destructive, no rollback, financial transactions.

The action permanently destroys data, executes financial transactions, or performs operations with no feasible undo path. Human approval is required. Verification must confirm the intended effect occurred.

Examples: `fs_delete`, `stripe_create_invoice`, `github_delete`.

## Manifest requirements by level

| Level    | Verifier required | Response schema | Approval |
|----------|-------------------|-----------------|----------|
| low      | No                | No              | No       |
| medium   | Recommended       | No              | No       |
| high     | Yes               | Yes (non-fs)    | Yes      |
| critical | Yes               | Yes (non-fs)    | Yes      |

Filesystem actions (`builtin:fs`) are exempt from the response schema requirement — they verify via host-observed SHA-256 hashes, not response body inspection.

High/critical write actions using `http_status` verifier must declare `verification_config.required_fields`. A bare 2xx status check is insufficient for destructive or financial operations.

## Review process

Every new or changed manifest must include a `risk_rationale` comment (lines starting with `# Risk rationale:`) that maps to one of the categories above. CI validates that this comment is present and non-empty.

When proposing a risk level change, the PR description must explain why the previous level was insufficient and which category criteria the action now meets.
