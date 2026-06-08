# Unit tests for LatchGate OPA policy.
#
# Run with: opa test /policies -v
# Or via:   make opa-test

package latchgate_test

import rego.v1

import data.latchgate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_base_input := {
	"principal": "agent:test-agent",
	"session_id": "sess-001",
	"action_id": "http_fetch",
	"action_version": "1.0.0",
	"action_risk_level": "low",
	"action_trust_verdict": "digest_ok",
	"request_hash": "abc123",
	"requested_sinks": ["http_read"],
	"requested_secrets": [],
	"egress_profile": "none",
	"budgets_before": {
		"calls_remaining": 10,
	},
	"scopes": ["tools:call"],
	"required_scopes": ["tools:call"],
}

# Merge helper: override specific fields in base input.
_with(overrides) := object.union(_base_input, overrides)

# ---------------------------------------------------------------------------
# Test 1: Default deny (empty input)
# ---------------------------------------------------------------------------

test_default_deny if {
	result := latchgate.decision with input as {}
	result.allow == false
	contains(result.deny_reason, "no matching allow rule")
}

# ---------------------------------------------------------------------------
# Test 2: Allow — known action, valid trust, with budget
# ---------------------------------------------------------------------------

test_allow_known_tool_valid_trust_with_budget if {
	result := latchgate.decision with input as _base_input
	result.allow == true
	result.requires_approval == false
	result.budgets_after.calls_remaining == 9
	result.allowed_sinks == ["http_read", "http_write", "http_delete"]
	result.policy_version == "m0-dev-001"
}

# ---------------------------------------------------------------------------
# Test 3: Deny — unknown action
# ---------------------------------------------------------------------------

test_deny_unknown_action if {
	inp := _with({"action_id": "unknown_action"})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# ---------------------------------------------------------------------------
# Test 4: Deny — untrusted action (digest mismatch)
# ---------------------------------------------------------------------------

test_deny_untrusted_action if {
	inp := _with({"action_trust_verdict": "digest_mismatch"})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "untrusted action")
}

# ---------------------------------------------------------------------------
# Test 5: Deny — budget exhausted
# ---------------------------------------------------------------------------

test_deny_budget_exhausted if {
	inp := _with({"budgets_before": {"calls_remaining": 0}})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "budget exhausted")
}

# ---------------------------------------------------------------------------
# Test 6: Deny — disallowed sink
# ---------------------------------------------------------------------------

test_deny_disallowed_sink if {
	inp := _with({"requested_sinks": ["http_read", "secret_exfil"]})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "disallowed sink")
}

# ---------------------------------------------------------------------------
# Test 7: Deny — unknown principal
# ---------------------------------------------------------------------------

test_deny_unknown_principal if {
	# Use "file_write" — not in the wildcard "*" allowed_actions, so an unknown
	# principal cannot execute it even via the wildcard ACL fallback.
	# Using "http_fetch" would allow the wildcard to resolve the principal and
	# the test would incorrectly pass or fail depending on scope state.
	inp := _with({"principal": "agent:nonexistent", "action_id": "file_write"})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# ---------------------------------------------------------------------------
# Test 8: High risk requires approval
# ---------------------------------------------------------------------------

test_high_risk_requires_approval if {
	inp := _with({"action_risk_level": "high"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# ---------------------------------------------------------------------------
# Test 9: Critical risk requires approval
# ---------------------------------------------------------------------------

test_critical_risk_requires_approval if {
	inp := _with({"action_risk_level": "critical"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# ---------------------------------------------------------------------------
# Test 10: Low risk — no approval needed
# ---------------------------------------------------------------------------

test_low_risk_no_approval if {
	inp := _with({"action_risk_level": "low"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# ---------------------------------------------------------------------------
# Test 11: Budgets decremented on allow
# ---------------------------------------------------------------------------

test_budgets_decremented_on_allow if {
	inp := _with({"budgets_before": {"calls_remaining": 3}})
	result := latchgate.decision with input as inp
	result.allow == true
	result.budgets_after.calls_remaining == 2
	result.policy_version == "m0-dev-001"
}

# ---------------------------------------------------------------------------
# Test 12: Restricted agent denied file_write
# ---------------------------------------------------------------------------

test_restricted_agent_denied_file_write if {
	inp := _with({
		"principal": "agent:restricted",
		"action_id": "file_write",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# ---------------------------------------------------------------------------
# Test 13: Deny — missing tools:call scope (base gate)
# ---------------------------------------------------------------------------

test_deny_missing_tools_call_scope if {
	inp := _with({"scopes": []})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "tools:call")
}

# ---------------------------------------------------------------------------
# Test 14: Deny — wrong scope (audit:read cannot execute actions)
# ---------------------------------------------------------------------------

test_deny_wrong_scope if {
	inp := _with({"scopes": ["audit:read"]})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "tools:call")
}

# ---------------------------------------------------------------------------
# Test 15: Allow — multiple scopes including tools:call
# ---------------------------------------------------------------------------

test_allow_multiple_scopes_including_tools_call if {
	inp := _with({"scopes": ["audit:read", "tools:call"]})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# ---------------------------------------------------------------------------
# Test 16: Allow — action requires only tools:call, lease has tools:call
# ---------------------------------------------------------------------------

test_allow_action_requiring_only_tools_call if {
	inp := _with({
		"scopes": ["tools:call"],
		"required_scopes": ["tools:call"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# ---------------------------------------------------------------------------
# Test 17: Allow — action requires additional scope, lease carries it
# ---------------------------------------------------------------------------

test_allow_when_lease_carries_required_scope if {
	inp := _with({
		"scopes": ["tools:call", "email:send"],
		"required_scopes": ["tools:call", "email:send"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# ---------------------------------------------------------------------------
# Test 18: Deny — lease missing one required scope
# ---------------------------------------------------------------------------

test_deny_lease_missing_required_scope if {
	# Lease only has tools:call, but action also requires email:send.
	inp := _with({
		"scopes": ["tools:call"],
		"required_scopes": ["tools:call", "email:send"],
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "email:send")
}

# ---------------------------------------------------------------------------
# Test 19: Deny — lease missing multiple required scopes
# ---------------------------------------------------------------------------

test_deny_lease_missing_multiple_required_scopes if {
	inp := _with({
		"scopes": ["tools:call"],
		"required_scopes": ["tools:call", "email:send", "file:write"],
	})
	result := latchgate.decision with input as inp
	result.allow == false
	# deny_reason must mention the missing scopes
	contains(result.deny_reason, "missing")
}

# ---------------------------------------------------------------------------
# Test 20: Allow — lease superset of required scopes
# ---------------------------------------------------------------------------

test_allow_lease_superset_of_required_scopes if {
	# Lease carries more scopes than the action requires — this is allowed.
	# Scopes are not a whitelist filter; they are a minimum-capability check.
	inp := _with({
		"scopes": ["tools:call", "email:send", "audit:read", "file:write"],
		"required_scopes": ["tools:call", "email:send"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
}

# ---------------------------------------------------------------------------
# Test 21: Deny — required_scopes present but tools:call absent from lease
#
# Regression: Rule 2b (base scope gate) must fire before Rule 2c so that
# a missing tools:call is reported clearly even if other required scopes
# are present.
# ---------------------------------------------------------------------------

test_deny_required_scopes_present_but_tools_call_missing_from_lease if {
	inp := _with({
		"scopes": ["email:send"],
		"required_scopes": ["tools:call", "email:send"],
	})
	result := latchgate.decision with input as inp
	result.allow == false
	# Rule 2b fires first — error must mention tools:call
	contains(result.deny_reason, "tools:call")
}

# ---------------------------------------------------------------------------
# Test 22: Deny — required_scopes is empty list (pipeline guard regression)
#
# The pipeline must never send an empty required_scopes (manifest validation
# rejects it). But if it somehow arrived, the policy should not silently
# allow a scope-less action call — the base _has_tools_call_scope gate ensures
# tools:call is still required.
# ---------------------------------------------------------------------------

test_deny_empty_required_scopes_still_requires_tools_call if {
	# Lease has no scopes at all — even with empty required_scopes, deny.
	inp := _with({
		"scopes": [],
		"required_scopes": [],
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "tools:call")
}

# ===========================================================================
# Risk => approval mapping tests (action-specific, using real ACL data)
# ===========================================================================

# Low risk actions — auto-allow, no approval.

test_github_read_low_risk_no_approval if {
	inp := _with({"action_id": "github_read", "action_risk_level": "low"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

test_webhook_notify_medium_risk_no_approval if {
	inp := _with({"action_id": "webhook_notify", "action_risk_level": "medium"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

test_api_authenticated_low_risk_no_approval if {
	inp := _with({"action_id": "http_bearer_get", "action_risk_level": "low"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# Medium risk actions — auto-allow, no approval.

test_http_post_medium_risk_no_approval if {
	inp := _with({"action_id": "http_post", "action_risk_level": "medium"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

test_slack_post_message_medium_risk_no_approval if {
	inp := _with({"action_id": "slack_post", "action_risk_level": "medium"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

test_pagerduty_medium_risk_no_approval if {
	inp := _with({"action_id": "pagerduty_event", "action_risk_level": "medium"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# High risk actions — require approval.

test_github_create_issue_high_risk_requires_approval if {
	inp := _with({"action_id": "github_create_issue", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

test_sensitive_api_read_high_risk_requires_approval if {
	inp := _with({"action_id": "http_sensitive_read", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

test_sendgrid_high_risk_requires_approval if {
	inp := _with({"action_id": "sendgrid_send", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

test_stripe_read_high_risk_requires_approval if {
	inp := _with({"action_id": "stripe_read", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# Critical risk — requires approval.

test_github_delete_critical_risk_requires_approval if {
	# github_delete is critical AND only in agent:test-agent ACL.
	inp := _with({"action_id": "github_delete", "action_risk_level": "critical"})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# ===========================================================================
# ACL scoping tests — github_delete restricted to test-agent
# ===========================================================================

test_wildcard_agent_cannot_use_github_delete if {
	# An unknown principal falls back to wildcard "*" ACL.
	# github_delete is NOT in wildcard allowed_actions.
	inp := _with({
		"principal": "agent:some-random-agent",
		"action_id": "github_delete",
		"action_risk_level": "critical",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

test_restricted_agent_cannot_use_github_delete if {
	inp := _with({
		"principal": "agent:restricted",
		"action_id": "github_delete",
		"action_risk_level": "critical",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

test_test_agent_can_use_github_delete if {
	inp := _with({
		"principal": "agent:test-agent",
		"action_id": "github_delete",
		"action_risk_level": "critical",
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# Restricted agent CAN use github_read and api_authenticated (added to their ACL).

test_restricted_agent_can_use_github_read if {
	inp := _with({
		"principal": "agent:restricted",
		"action_id": "github_read",
		"action_risk_level": "low",
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

test_restricted_agent_can_use_api_authenticated if {
	inp := _with({
		"principal": "agent:restricted",
		"action_id": "http_bearer_get",
		"action_risk_level": "low",
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

test_restricted_agent_cannot_use_http_post if {
	inp := _with({
		"principal": "agent:restricted",
		"action_id": "http_post",
		"action_risk_level": "medium",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# db-agent has github_read but not github_create_issue.

test_db_agent_can_use_github_read if {
	inp := _with({
		"principal": "agent:db-agent",
		"action_id": "github_read",
		"action_risk_level": "low",
	})
	result := latchgate.decision with input as inp
	result.allow == true
}

test_db_agent_cannot_use_github_create_issue if {
	inp := _with({
		"principal": "agent:db-agent",
		"action_id": "github_create_issue",
		"action_risk_level": "high",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# ===========================================================================
# Allowlist bypass tests
# ===========================================================================

# High-risk action with allowlist entry — approval bypassed.

test_allowlist_bypasses_approval_for_high_risk if {
	inp := _with({"action_id": "github_create_issue", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"github_create_issue": {"agent:test-agent": true}}
	result.allow == true
	result.requires_approval == false
}

# Critical-risk action with allowlist entry — approval bypassed.

test_allowlist_bypasses_approval_for_critical_risk if {
	inp := _with({
		"action_id": "github_delete",
		"action_risk_level": "critical",
	})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"github_delete": {"agent:test-agent": true}}
	result.allow == true
	result.requires_approval == false
}

# Allowlist does NOT bypass ACL deny — principal must still be authorised.

test_allowlist_does_not_bypass_acl_deny if {
	inp := _with({
		"principal": "agent:restricted",
		"action_id": "http_post",
		"action_risk_level": "medium",
	})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"http_post": {"agent:restricted": true}}
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# Allowlist does NOT bypass budget exhaustion.

test_allowlist_does_not_bypass_budget if {
	inp := _with({
		"action_id": "http_fetch",
		"action_risk_level": "high",
		"budgets_before": {"calls_remaining": 0},
	})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"http_fetch": {"agent:test-agent": true}}
	result.allow == false
	contains(result.deny_reason, "budget exhausted")
}

# Allowlist does NOT bypass scope check.

test_allowlist_does_not_bypass_scope if {
	inp := _with({
		"action_id": "http_fetch",
		"action_risk_level": "high",
		"scopes": [],
	})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"http_fetch": {"agent:test-agent": true}}
	result.allow == false
	contains(result.deny_reason, "tools:call")
}

# Allowlist does NOT bypass trust verification.

test_allowlist_does_not_bypass_trust if {
	inp := _with({
		"action_trust_verdict": "digest_mismatch",
		"action_risk_level": "high",
	})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"http_fetch": {"agent:test-agent": true}}
	result.allow == false
	contains(result.deny_reason, "untrusted")
}

# Allowlist entry for different agent — approval still required.

test_allowlist_wrong_agent_still_requires_approval if {
	inp := _with({"action_id": "github_create_issue", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"github_create_issue": {"agent:other-agent": true}}
	result.allow == true
	result.requires_approval == true
}

# Allowlist entry for different action — approval still required.

test_allowlist_wrong_action_still_requires_approval if {
	inp := _with({"action_id": "github_create_issue", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"http_fetch": {"agent:test-agent": true}}
	result.allow == true
	result.requires_approval == true
}

# Empty allowlist — no effect, approval still required.

test_empty_allowlist_no_effect if {
	inp := _with({"action_id": "github_create_issue", "action_risk_level": "high"})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {}
	result.allow == true
	result.requires_approval == true
}

# Low-risk action with allowlist — allowlist is a no-op (already allowed).

test_allowlist_low_risk_already_allowed if {
	inp := _with({"action_id": "http_fetch", "action_risk_level": "low"})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"http_fetch": {"agent:test-agent": true}}
	result.allow == true
	result.requires_approval == false
}

# Allowlist with budget decrement — budgets still consumed.

test_allowlist_decrements_budget if {
	inp := _with({
		"action_id": "github_create_issue",
		"action_risk_level": "high",
		"budgets_before": {"calls_remaining": 5},
	})
	result := latchgate.decision with input as inp
		with data.latchgate.allowlist as {"github_create_issue": {"agent:test-agent": true}}
	result.allow == true
	result.requires_approval == false
	result.budgets_after.calls_remaining == 4
}

# ===========================================================================
# inherits_wildcard tests
# ===========================================================================

# Named principal with inherits_wildcard: true can use a wildcard action
# not present in its own allowed_actions.

test_inheriting_principal_can_use_wildcard_action if {
	inp := _with({"principal": "agent:inheriting", "action_id": "http_fetch"})
	result := latchgate.decision with input as inp
	result.allow == true
}

# Named principal with inherits_wildcard: true can still use an action
# from its own explicit list.

test_inheriting_principal_can_use_own_action if {
	inp := _with({
		"principal": "agent:inheriting",
		"action_id": "github_delete",
		"action_risk_level": "critical",
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# inherits_wildcard grants access to wildcard sinks not in the principal's
# own allowed_sinks.

test_inheriting_principal_gets_wildcard_sinks if {
	inp := _with({
		"principal": "agent:inheriting",
		"requested_sinks": ["http_write"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
}

# _principal_allowed_sinks returns the sorted union of own + wildcard sinks
# when inherits_wildcard is true.

test_inheriting_principal_allowed_sinks_is_union if {
	inp := _with({"principal": "agent:inheriting"})
	result := latchgate.decision with input as inp
	result.allow == true
	# Own: ["http_read"]. Wildcard: ["http_read", "http_write", "http_delete"].
	# Sorted union:
	result.allowed_sinks == ["http_delete", "http_read", "http_write"]
}

# inherits_wildcard does not grant sinks outside the union — unknown sinks
# are still denied.

test_inheriting_principal_denied_unknown_sink if {
	inp := _with({
		"principal": "agent:inheriting",
		"requested_sinks": ["secret_exfil"],
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "disallowed sink")
}

# Named principal with an empty ACL entry and no inherits_wildcard is denied.
# The presence of the entry blocks wildcard fallback; without inheritance
# the empty allowed_actions list means nothing is reachable.

test_empty_acl_principal_denied if {
	inp := _with({
		"principal": "agent:empty-acl",
		"action_id": "http_fetch",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# Empty-ACL principal is denied even for actions that the wildcard would
# allow — the ACL entry shadows the wildcard without granting anything.

test_empty_acl_principal_denied_despite_wildcard if {
	inp := _with({
		"principal": "agent:empty-acl",
		"action_id": "http_post",
		"action_risk_level": "medium",
	})
	result := latchgate.decision with input as inp
	result.allow == false
	contains(result.deny_reason, "not authorised")
}

# ---------------------------------------------------------------------------
# Unresolved domains — triggers pending approval (rule 6d)
# ---------------------------------------------------------------------------

# Low-risk action with an unresolved domain must require approval so the
# operator can review and learn the domain.

test_unresolved_domain_requires_approval if {
	inp := _with({
		"unresolved_domains": ["example.com"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# When unresolved_domains is empty, low-risk action is auto-allowed.

test_empty_unresolved_domains_allows if {
	inp := _with({
		"unresolved_domains": [],
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == false
}

# Absent unresolved_domains field (omitted by skip_serializing_if) is
# equivalent to empty — auto-allow.

test_absent_unresolved_domains_allows if {
	result := latchgate.decision with input as _base_input
	result.allow == true
	result.requires_approval == false
}

# Multiple unresolved domains still trigger approval (not just single).

test_multiple_unresolved_domains_requires_approval if {
	inp := _with({
		"unresolved_domains": ["a.com", "b.com", "c.com"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}

# High-risk action with unresolved domains: already gated by risk level;
# approval is still required (rule 6a fires before 6d).

test_high_risk_with_unresolved_domains_requires_approval if {
	inp := _with({
		"action_risk_level": "high",
		"unresolved_domains": ["example.com"],
	})
	result := latchgate.decision with input as inp
	result.allow == true
	result.requires_approval == true
}
