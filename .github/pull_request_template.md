## What

<!-- One-line summary of the change. -->

## Why

<!-- Link to issue or describe the motivation. -->

## How

<!-- Key implementation decisions. Skip obvious stuff. -->

## Testing

- [ ] `make check` (fmt + clippy)
- [ ] `make test` (unit + standalone)
- [ ] `make test-integration` — if touching server runtime, provider I/O, or state
- [ ] `make test-conformance` — if touching WASM runtime, host I/O, or provider interface
- [ ] `make test-opa` — if touching policy rules or OPA integration
- [ ] `make test-sdk` — if touching SDK clients or API contract

## Security checklist

If this PR touches auth, policy, isolation, secrets, egress, receipts, or grants:

- [ ] No new `unwrap()`/`expect()` in production code
- [ ] Fail-closed on error (deny, not allow)
- [ ] Negative test added (invalid input => rejection)
- [ ] No secrets in logs, metrics, or error messages
- [ ] Security checklist item covered or N/A noted

<!-- Delete this section if the PR doesn't touch security surface. -->
