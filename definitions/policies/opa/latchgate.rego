# LatchGate execution policy.
#
# Default-deny: every tool execution is denied unless all rules pass.
#
# Evaluation pipeline (else-chain, most restrictive first):
#   1. _deny_untrusted     — reject untrusted action digests
#   2. _deny_acl           — principal must be authorised for this action
#   3. _deny_scope         — lease must carry tools:call + action-required scopes
#   4. _deny_budget        — session must have remaining calls
#   5. _deny_sink          — requested sinks must be within ACL allowlist
#  5b. _skip_approval      — allowlisted (action, principal) pairs bypass approval
#   6. _require_approval   — high/critical risk or sensitive fs path
#  6c.                      — unresolved fs path
#  6d.                      — unresolved egress domain
#   7. _allow              — all checks pass, decrement budget, return sinks
#
# Adding a new check = one helper + one else clause.
#
# Input contract: see PolicyInput in crates/latchgate-policy/src/policy.rs.
# Data contract:  see data.json (acl section).

package latchgate

import rego.v1

# ---------------------------------------------------------------------------
# Decision pipeline — else-chain
# ---------------------------------------------------------------------------

decision := result if {
	result := _deny_untrusted
} else := result if {
	result := _deny_acl
} else := result if {
	result := _deny_scope
} else := result if {
	result := _deny_budget
} else := result if {
	result := _deny_sink
} else := result if {
	result := _skip_approval
} else := result if {
	result := _require_approval
} else := result if {
	result := _allow
}

# Fallback: if no helper fires, deny.
default decision := {
	"allow": false,
	"deny_reason": "no matching allow rule",
}

# ---------------------------------------------------------------------------
# 1. Trust gate — untrusted digest => deny
# ---------------------------------------------------------------------------

_deny_untrusted := {
	"allow": false,
	"deny_reason": "untrusted action: digest verification failed",
} if {
	input.action_trust_verdict != "digest_ok"
}

# ---------------------------------------------------------------------------
# 2. ACL check — principal must have action_id in allowed_actions
# ---------------------------------------------------------------------------

_deny_acl := {
	"allow": false,
	"deny_reason": sprintf("principal '%s' is not authorised for action '%s'", [input.principal, input.action_id]),
} if {
	not _principal_has_tool
}

# ---------------------------------------------------------------------------
# 3. Scope check — tools:call base gate + action-required scopes
# ---------------------------------------------------------------------------

# 3a. Base scope: tools:call must be present.
_deny_scope := {
	"allow": false,
	"deny_reason": sprintf(
		"scope 'tools:call' is required for action execution but is absent from lease scopes: %v",
		[input.scopes],
	),
} if {
	not _has_tools_call_scope
}

# 3b. Required scopes: all action-required scopes must be present.
_deny_scope := {
	"allow": false,
	"deny_reason": sprintf(
		"lease is missing required scope(s) for action '%s': required=%v, present=%v, missing=%v",
		[input.action_id, input.required_scopes, input.scopes, _missing_required_scopes],
	),
} if {
	_has_tools_call_scope
	count(_missing_required_scopes) > 0
}

# ---------------------------------------------------------------------------
# 4. Budget check — calls_remaining must be > 0
# ---------------------------------------------------------------------------

_deny_budget := {
	"allow": false,
	"deny_reason": "budget exhausted: no calls remaining",
} if {
	input.budgets_before.calls_remaining <= 0
}

# ---------------------------------------------------------------------------
# 5. Sink check — all requested sinks must be in ACL allowlist
# ---------------------------------------------------------------------------

_deny_sink := {
	"allow": false,
	"deny_reason": sprintf("disallowed sink(s): %v", [_disallowed_sinks]),
} if {
	count(_disallowed_sinks) > 0
}

# ---------------------------------------------------------------------------
# 5b. Allowlist bypass — skip approval for explicitly allowlisted pairs
#
# Evaluates AFTER all deny rules (trust, ACL, scope, budget, sink) — an
# allowlisted action still fails if the principal lacks ACL access, scopes
# are missing, or budget is exhausted. The allowlist only bypasses the
# approval hold, nothing else.
# ---------------------------------------------------------------------------

_skip_approval := {
	"allow": true,
	"requires_approval": false,
	"budgets_after": _decremented_budgets,
	"allowed_sinks": _principal_allowed_sinks,
	"approved_secrets": _approved_secrets,
	"approved_egress": _approved_egress,
	"policy_version": _policy_version,
} if {
	data.latchgate.allowlist[input.action_id][input.principal]
}

# ---------------------------------------------------------------------------
# 6. Approval gate — high/critical risk OR sensitive fs paths
# ---------------------------------------------------------------------------

# 6a. High or critical risk actions require human approval.
_require_approval := _approval_result if {
	_is_high_risk
}

# 6b. FS sensitive path — defense-in-depth approval gate regardless of risk.
_require_approval := _approval_result if {
	not _is_high_risk
	input.action_category == "fs"
	_fs_path_sensitive
}

# 6c. FS unresolved path — requires approval to learn the path.
_require_approval := _approval_result if {
	not _is_high_risk
	not _fs_path_sensitive
	count(object.get(input, "unresolved_paths", [])) > 0
}

# 6d. Unresolved domain — requires approval to learn the domain.
#
# SECURITY: when a target domain is not in the manifest allowlist or the
# learned allowlist, the pipeline marks it as unresolved. Without this
# rule, low-risk actions with empty allowed_domains silently proceed to
# provider dispatch with zero sinks and fail opaquely. Gating here gives
# the operator a chance to approve + learn the domain, after which it is
# auto-allowed on future requests.
_require_approval := _approval_result if {
	not _is_high_risk
	not _fs_path_sensitive
	count(object.get(input, "unresolved_paths", [])) == 0
	count(object.get(input, "unresolved_domains", [])) > 0
}

_approval_result := {
	"allow": true,
	"requires_approval": true,
	"budgets_after": _decremented_budgets,
	"allowed_sinks": _principal_allowed_sinks,
	"approved_secrets": _approved_secrets,
	"approved_egress": _approved_egress,
	"policy_version": _policy_version,
}

# ---------------------------------------------------------------------------
# 7. Allow — all checks passed, no approval needed
# ---------------------------------------------------------------------------

_allow := {
	"allow": true,
	"requires_approval": false,
	"budgets_after": _decremented_budgets,
	"allowed_sinks": _principal_allowed_sinks,
	"approved_secrets": _approved_secrets,
	"approved_egress": _approved_egress,
	"policy_version": _policy_version,
} if {
	not _is_high_risk
	not _fs_path_sensitive
	count(object.get(input, "unresolved_paths", [])) == 0
	count(object.get(input, "unresolved_domains", [])) == 0
}

# ---------------------------------------------------------------------------
# Helper rules (private)
# ---------------------------------------------------------------------------

_has_tools_call_scope if {
	some s in input.scopes
	s == "tools:call"
}

_missing_required_scopes := {r |
	some r in input.required_scopes
	not _scope_present(r)
}

_scope_present(s) if {
	some present in input.scopes
	present == s
}

# -- ACL: principal ↔ action ------------------------------------------------

# Direct grant — principal's own allowed_actions.
_principal_has_tool if {
	some action in data.acl[input.principal].allowed_actions
	action == input.action_id
}

# Explicit inheritance — principal opts in to wildcard actions.
# Auditable: the flag must be set to `true` in the ACL entry; implicit
# merging never occurs.
_principal_has_tool if {
	data.acl[input.principal].inherits_wildcard == true
	some action in data.acl["*"].allowed_actions
	action == input.action_id
}

# Absent principal — fall back to wildcard unconditionally.
_principal_has_tool if {
	not data.acl[input.principal]
	some action in data.acl["*"].allowed_actions
	action == input.action_id
}

# -- Sinks -------------------------------------------------------------------

_disallowed_sinks := {sink |
	some sink in input.requested_sinks
	not _sink_allowed(sink)
}

# Direct grant.
_sink_allowed(sink) if {
	some allowed in data.acl[input.principal].allowed_sinks
	allowed == sink
}

# Explicit inheritance.
_sink_allowed(sink) if {
	data.acl[input.principal].inherits_wildcard == true
	some allowed in data.acl["*"].allowed_sinks
	allowed == sink
}

# Absent principal.
_sink_allowed(sink) if {
	not data.acl[input.principal]
	some allowed in data.acl["*"].allowed_sinks
	allowed == sink
}

# -- Risk helpers ------------------------------------------------------------

_is_high_risk if {
	input.action_risk_level == "high"
}

_is_high_risk if {
	input.action_risk_level == "critical"
}

# -- FS helpers --

# Sensitive path patterns that always require human approval regardless
# of risk level. Deny-list enforcement happens in the host import;
# these rules add a policy-level approval gate for defense in depth.
_fs_path_sensitive if {
	input.action_category == "fs"
	glob.match("**/.env", [], object.get(input, "fs_path", ""))
}

_fs_path_sensitive if {
	input.action_category == "fs"
	glob.match("**/.env.*", [], object.get(input, "fs_path", ""))
}

_fs_path_sensitive if {
	input.action_category == "fs"
	glob.match("**/secrets/**", [], object.get(input, "fs_path", ""))
}

_fs_path_sensitive if {
	input.action_category == "fs"
	glob.match("**/.ssh/**", [], object.get(input, "fs_path", ""))
}

_fs_path_sensitive if {
	input.action_category == "fs"
	glob.match("**/.aws/credentials", [], object.get(input, "fs_path", ""))
}

# -- Shared result fields --

# Approved secrets: pass-through from input (policy can narrow in future).
# object.get ensures a valid deny decision even if input is malformed.
_approved_secrets := object.get(input, "requested_secrets", [])

# Approved egress: pass-through from input (policy can narrow in future).
_approved_egress := object.get(input, "egress_profile", "none")

_decremented_budgets := {
	"calls_remaining": input.budgets_before.calls_remaining - 1,
}

# -- Allowed sinks for the decision result --
#
# Three cases, mutually exclusive by guard:
#   1. Named principal without inheritance → own sinks only.
#   2. Named principal with inherits_wildcard → union of own + wildcard.
#   3. Absent principal → wildcard sinks.

_principal_allowed_sinks := data.acl[input.principal].allowed_sinks if {
	data.acl[input.principal]
	not data.acl[input.principal].inherits_wildcard
}

_principal_allowed_sinks := sort(own | base) if {
	data.acl[input.principal].inherits_wildcard == true
	own := {s | some s in data.acl[input.principal].allowed_sinks}
	base := {s | some s in data.acl["*"].allowed_sinks}
}

_principal_allowed_sinks := data.acl["*"].allowed_sinks if {
	not data.acl[input.principal]
}

_policy_version := data.policy_version
