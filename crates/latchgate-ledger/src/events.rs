//! Audit event schema and builder for the LatchGate forensic ledger.
//!
//! Every action call (allow, deny, error, timeout) produces an [`AuditEvent`]
//! with full decision context — sufficient for forensic reconstruction:
//! who, what, when, which policy, what outcome.
//!
//! # Sub-struct decomposition
//!
//! Fields are grouped into sub-structs by concern: [`AuditSubject`],
//! [`AuditAction`], [`AuditRequest`], [`AuditPolicy`], [`AuditExecution`],
//! [`AuditApproval`].
//!
//! # Security properties
//!
//! - Secret values (env vars, tokens, private keys) NEVER appear in events.
//! - Request/response bodies are represented only by their canonical hash.
//! - Full JWTs are excluded — only the `jti` claim is recorded.
//! - Internal paths and stack traces are excluded.
//! - Events are hash-chained: each event's `prev_hash` is the SHA-256 of the
//!   previous event's JCS-canonicalized JSON (RFC 8785). Deletion or mutation
//!   of any record is detectable.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ActionCall,
    LeaseIssued,
    LeaseRevoked,
    ApprovalGranted,
    ApprovalDenied,
    /// Operator invoked the global kill-switch (revoke-all / epoch advance).
    ///
    /// SECURITY: kill-switch activation is a first-class security event.
    /// It must be in the tamper-evident ledger, not only in process logs,
    /// so it survives log rotation and is auditable by external parties.
    AdminRevokeAll,
    /// Operator read the current revocation epoch (read-only diagnostic).
    AdminEpochRead,
    /// Operator read the receipt signing key(s).
    AdminReceiptKeysRead,
    /// Operator initiated graceful drain via `POST /v1/admin/drain`.
    ///
    /// Records who triggered the drain and when, so orchestrators and
    /// forensic analysis can attribute shutdown decisions.
    AdminDrain,
    /// Operator triggered a hot-reload of manifests and policy data via
    /// `POST /v1/admin/reload`. Records the resulting action count and
    /// policy version for operational traceability.
    AdminReload,
    /// Operator added a learned domain via the admin API.
    DomainAdd,
    /// Operator removed a learned domain via the admin API.
    DomainRemove,
    /// Operator cleared all learned domains for an action via the admin API.
    DomainClear,
    /// Operator added a learned path glob via the admin API.
    PathAdd,
    /// Operator removed a learned path glob via the admin API.
    PathRemove,
    /// Operator cleared all learned path globs for an action via the admin API.
    PathClear,
    /// Operator granted actions to a principal via the admin API.
    PolicyGrant,
    /// Operator revoked actions from a principal via the admin API.
    PolicyRevoke,
    /// Operator added an allowlist entry (action, agent) via the admin API.
    PolicyAllowlistAdded,
    /// Operator removed an allowlist entry (action, agent) via the admin API.
    PolicyAllowlistRemoved,
    /// A budget debit could not be rolled back after a post-debit failure.
    ///
    /// SECURITY: the operator was charged for an execution that did not
    /// happen and the refund failed. This leaves an orphaned debit that
    /// requires reconciliation. It is recorded in the tamper-evident ledger
    /// — not only in process logs — so the affected session is queryable
    /// and survives log rotation.
    BudgetRollbackFailed,
}

impl EventType {
    /// Snake-case string matching the `#[serde(rename_all = "snake_case")]`
    /// serialization. Used for SQLite column values without the overhead of
    /// `serde_json::to_string` + `trim_matches('"')`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ActionCall => "action_call",
            Self::LeaseIssued => "lease_issued",
            Self::LeaseRevoked => "lease_revoked",
            Self::ApprovalGranted => "approval_granted",
            Self::ApprovalDenied => "approval_denied",
            Self::AdminRevokeAll => "admin_revoke_all",
            Self::AdminEpochRead => "admin_epoch_read",
            Self::AdminReceiptKeysRead => "admin_receipt_keys_read",
            Self::AdminDrain => "admin_drain",
            Self::AdminReload => "admin_reload",
            Self::DomainAdd => "domain_add",
            Self::DomainRemove => "domain_remove",
            Self::DomainClear => "domain_clear",
            Self::PathAdd => "path_add",
            Self::PathRemove => "path_remove",
            Self::PathClear => "path_clear",
            Self::PolicyGrant => "policy_grant",
            Self::PolicyRevoke => "policy_revoke",
            Self::PolicyAllowlistAdded => "policy_allowlist_added",
            Self::PolicyAllowlistRemoved => "policy_allowlist_removed",
            Self::BudgetRollbackFailed => "budget_rollback_failed",
        }
    }
}

/// Enforcement decision for an action call.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    /// Action executed but independent verification failed or was inconclusive.
    ///
    /// The WASM provider ran and returned output, but the post-hoc verifier
    /// could not confirm the output matches expectations (e.g. file not found
    /// for `fs_hash`, HTTP error for `http_status`). Distinguished from `Allow`
    /// so operators can spot unverified executions in the activity view.
    ///
    /// High/critical risk actions with failed verification are denied outright
    /// and recorded as `Deny` — this variant only applies to low/medium risk.
    AllowUnverified,
    Deny,
    PendingApproval,
    Error,
}

impl Decision {
    /// Snake-case string matching `#[serde(rename_all = "snake_case")]`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowUnverified => "allow_unverified",
            Self::Deny => "deny",
            Self::PendingApproval => "pending_approval",
            Self::Error => "error",
        }
    }
}

// Sub-structs

/// Caller identity — who invoked the action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSubject {
    /// Principal identifier (e.g. `"agent:my-agent-01"`).
    pub principal: Arc<str>,
    pub session_id: Arc<str>,
    pub lease_jti: Arc<str>,

    /// How the caller's identity was verified at lease issuance time.
    ///
    /// Values: `"peercred"`, `"peercred:unmapped"`, `"oidc"`, `"mtls"`,
    /// `"none"` (dev only). `None` for action-call events where the
    /// identity method is not separately recorded.
    ///
    /// SECURITY: without this field, forensic analysis cannot distinguish
    /// how a principal was authenticated. A peercred principal has
    /// kernel-guaranteed identity; a none principal does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_method: Option<Arc<str>>,

    /// Owner/responsible person for this agent (from identity config).
    ///
    /// Free-form string, typically email (e.g. `"alice@company.com"`).
    /// Frozen in the Lease JWT at authentication time. `None` when not
    /// configured in the identity mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Arc<str>>,
}

/// Action identification — what was invoked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditAction {
    pub action_id: Arc<str>,
    pub action_version: Option<Arc<str>>,
    pub action_digest: Arc<str>,
    /// `"digest_ok"` | `"mismatch"` | `"not_registered"`
    pub action_trust_verdict: Arc<str>,

    /// Action risk classification from the manifest (`"low"`, `"medium"`,
    /// `"high"`, `"critical"`).
    ///
    /// Captured at registry lookup time. `None` for lifecycle events
    /// (LeaseIssued, AdminReload, etc.) where no action is involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<Arc<str>>,
}

/// Request context — the input being processed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRequest {
    /// SHA-256 of JCS-canonicalized request (from `canonical_hash()`).
    pub request_hash: Arc<str>,
    pub request_schema_id: Option<Arc<str>>,
}

/// Policy evaluation outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPolicy {
    pub policy_version: Option<Arc<str>>,
    pub decision: Decision,
    pub deny_reason: Option<Arc<str>>,
    /// Sinks approved by OPA for this execution. Empty on deny.
    #[serde(default)]
    pub allowed_sinks: Vec<Arc<str>>,
}

/// Runtime execution details — populated only when the action was actually run
/// (i.e. `decision == Allow`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAudit {
    pub module_digest: Arc<str>,
    pub egress_profile: Arc<str>,
    pub duration_ms: u64,
    pub exit_code: i64,
    pub timeout_hit: bool,
    pub fuel_consumed: u64,
    pub io_calls_made: u32,
}

/// Provider dispatch and verification outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditExecution {
    /// Runtime details (only when decision == Allow).
    pub runtime: Option<RuntimeAudit>,

    pub response_hash: Option<Arc<str>>,
    pub response_bytes: Option<usize>,

    /// ExecutionGrant ID. Present when the pipeline progressed past policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<Arc<str>>,
    /// ExecutionReceipt ID. Present when provider dispatch completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<Arc<str>>,
    /// Verifier outcome tag: "verified", "verification_failed",
    /// "unverifiable_declared", "provider_failed_before_verification", "skipped".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_outcome: Option<Arc<str>>,
}

/// Operator approval attribution — who approved or denied, and how.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditApproval {
    /// Approval identifier linking the pending and terminal audit events.
    ///
    /// Present on `pending_approval`, `approval_granted`, and `approval_denied`
    /// events. `None` for auto-allowed actions (no human in the loop).
    /// The TUI uses this to consolidate the pending row with its resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<Arc<str>>,

    /// Operator identity that approved or denied the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<Arc<str>>,

    /// How the operator authenticated when approving or denying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_authn_method: Option<Arc<str>>,

    /// JWK thumbprint (DPoP sender binding) of the operator who approved/denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_sender_binding: Option<Arc<str>>,

    /// `jti` from the operator's DPoP proof (forensic correlation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_proof_jti: Option<Arc<str>>,
}

// AuditEvent

/// Complete audit record for a single pipeline invocation.
///
/// Fields are grouped into sub-structs by concern. All sub-structs use
/// `#[serde(flatten)]` so the JSON representation is flat — identical to
/// the pre-decomposition layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    // -- Identification --
    pub trace_id: Arc<str>,
    /// ISO 8601 with milliseconds (e.g. `2026-02-26T12:34:56.789Z`).
    pub timestamp: String,
    pub event_type: EventType,

    // -- Subject --
    #[serde(flatten)]
    pub subject: AuditSubject,

    // -- Action --
    #[serde(flatten)]
    pub action: AuditAction,

    // -- Request --
    #[serde(flatten)]
    pub request: AuditRequest,

    // -- Policy --
    #[serde(flatten)]
    pub policy: AuditPolicy,

    // -- Budgets --
    pub budgets_before: Option<serde_json::Value>,
    pub budgets_after: Option<serde_json::Value>,

    // -- Execution --
    #[serde(flatten)]
    pub execution: AuditExecution,

    // -- Approval attribution --
    #[serde(flatten)]
    pub approval: AuditApproval,

    // -- Integrity (hash-chain) --
    /// SHA-256 of the previous event's JCS-canonicalized (RFC 8785) JSON.
    /// `None` for the first event in the ledger. Set by `LedgerStore` at
    /// write time — the builder always leaves this as `None`.
    pub prev_hash: Option<String>,

    // -- Flags --
    pub dev_mode: bool,
    pub sandbox_degraded: bool,
}

// AuditEventBuilder

/// Incremental builder for [`AuditEvent`].
///
/// The pipeline constructs an event step by step — each enforcement stage
/// adds its own fields. `build()` stamps the current UTC time and returns
/// the finished event.
///
/// Required fields: `trace_id` and `event_type` (set at construction).
/// All other fields default to empty/false/None and are filled in by the
/// pipeline as it progresses.
///
/// **Note:** `prev_hash` is NOT set by the builder. It is filled in by
/// `LedgerStore::write_event` at persistence time, because only the store
/// knows the current chain head.
#[must_use = "builder must be consumed via build() — dropping one silently discards an audit event"]
pub struct AuditEventBuilder {
    trace_id: Arc<str>,
    event_type: EventType,

    principal: Arc<str>,
    session_id: Arc<str>,
    lease_jti: Arc<str>,
    identity_method: Option<Arc<str>>,
    owner: Option<Arc<str>>,

    action_id: Arc<str>,
    action_version: Option<Arc<str>>,
    action_digest: Arc<str>,
    action_trust_verdict: Arc<str>,
    risk_level: Option<Arc<str>>,

    request_hash: Arc<str>,
    request_schema_id: Option<Arc<str>>,

    policy_version: Option<Arc<str>>,
    decision: Decision,
    deny_reason: Option<Arc<str>>,
    allowed_sinks: Vec<Arc<str>>,

    budgets_before: Option<serde_json::Value>,
    budgets_after: Option<serde_json::Value>,

    runtime: Option<RuntimeAudit>,

    response_hash: Option<Arc<str>>,
    response_bytes: Option<usize>,

    grant_id: Option<Arc<str>>,
    receipt_id: Option<Arc<str>>,
    verification_outcome: Option<Arc<str>>,

    approved_by: Option<Arc<str>>,
    operator_authn_method: Option<Arc<str>>,
    operator_sender_binding: Option<Arc<str>>,
    operator_proof_jti: Option<Arc<str>>,
    approval_id: Option<Arc<str>>,

    dev_mode: bool,
    sandbox_degraded: bool,
}

impl AuditEventBuilder {
    /// Start building an event for the given trace and type.
    pub fn new(trace_id: impl Into<Arc<str>>, event_type: EventType) -> Self {
        Self {
            trace_id: trace_id.into(),
            event_type,

            principal: Arc::from(""),
            session_id: Arc::from(""),
            lease_jti: Arc::from(""),
            identity_method: None,
            owner: None,

            action_id: Arc::from(""),
            action_version: None,
            action_digest: Arc::from(""),
            action_trust_verdict: Arc::from(""),
            risk_level: None,

            request_hash: Arc::from(""),
            request_schema_id: None,

            policy_version: None,
            decision: Decision::Error,
            deny_reason: None,
            allowed_sinks: Vec::new(),

            budgets_before: None,
            budgets_after: None,

            runtime: None,

            response_hash: None,
            response_bytes: None,

            grant_id: None,
            receipt_id: None,
            verification_outcome: None,

            approved_by: None,
            operator_authn_method: None,
            operator_sender_binding: None,
            operator_proof_jti: None,
            approval_id: None,

            dev_mode: false,
            sandbox_degraded: false,
        }
    }

    /// Set subject identity fields (from Lease JWT claims).
    pub fn principal(
        mut self,
        principal: impl Into<Arc<str>>,
        session_id: impl Into<Arc<str>>,
        lease_jti: impl Into<Arc<str>>,
    ) -> Self {
        self.principal = principal.into();
        self.session_id = session_id.into();
        self.lease_jti = lease_jti.into();
        self
    }

    /// Set the identity verification method used at lease issuance.
    ///
    /// Records how the principal was authenticated: `"peercred"`
    /// (kernel-guaranteed), `"oidc"`, `"mtls"`, or `"none"` (dev).
    /// Empty string is treated as None.
    pub fn identity_method(mut self, method: impl Into<Arc<str>>) -> Self {
        let method: Arc<str> = method.into();
        if !method.is_empty() {
            self.identity_method = Some(method);
        }
        self
    }

    /// Set the owner/responsible person for this agent.
    ///
    /// Propagated from `AuthContext.owner` (which originates in the
    /// identity config and is frozen in the Lease JWT).
    pub fn owner(mut self, owner: Option<Arc<str>>) -> Self {
        self.owner = owner;
        self
    }

    /// Set action identification fields (from registry lookup / trust check).
    pub fn action(
        mut self,
        action_id: impl Into<Arc<str>>,
        action_version: Option<Arc<str>>,
        action_digest: impl Into<Arc<str>>,
        trust_verdict: impl Into<Arc<str>>,
    ) -> Self {
        self.action_id = action_id.into();
        self.action_version = action_version;
        self.action_digest = action_digest.into();
        self.action_trust_verdict = trust_verdict.into();
        self
    }

    /// Set request hash and optional schema identifier.
    pub fn request(mut self, hash: impl Into<Arc<str>>, schema_id: Option<Arc<str>>) -> Self {
        self.request_hash = hash.into();
        self.request_schema_id = schema_id;
        self
    }

    /// Set the action's risk level from the manifest.
    ///
    /// Accepts the `RiskLevel::as_str()` value (`"low"`, `"medium"`,
    /// `"high"`, `"critical"`). Empty string is treated as None.
    pub fn risk_level(mut self, level: impl Into<Arc<str>>) -> Self {
        let level: Arc<str> = level.into();
        if !level.is_empty() {
            self.risk_level = Some(level);
        }
        self
    }

    /// Set policy evaluation outcome.
    ///
    /// SECURITY: `deny_reason` is sanitized before storage because it may be
    /// derived from attacker-controlled request fields that OPA reflected
    /// back. Even though the kernel sanitizes reasons at construction of
    /// `PolicyError::Denied`, this is defense in depth — any caller passing
    /// a raw string through this builder (auth errors serialized via
    /// `format!("auth: {e}")`, future call sites) is covered here as well.
    pub fn policy(
        mut self,
        decision: Decision,
        policy_version: Option<Arc<str>>,
        deny_reason: Option<String>,
    ) -> Self {
        const REASON_MAX_BYTES: usize = 500;
        self.decision = decision;
        self.policy_version = policy_version;
        self.deny_reason = deny_reason
            .map(|r| Arc::from(latchgate_core::sanitize_for_log(&r, REASON_MAX_BYTES).as_ref()));
        self
    }

    /// Set the decision for a lifecycle event that is not a policy outcome.
    ///
    /// The builder defaults to [`Decision::Error`] so that any event reaching
    /// the ledger without an explicit decision is conspicuous. Lifecycle
    /// events (e.g. `LeaseIssued`) that succeed must set [`Decision::Allow`]
    /// via this method; use [`Self::policy`] for genuine policy decisions.
    pub fn decision(mut self, decision: Decision) -> Self {
        self.decision = decision;
        self
    }

    /// Set the sinks approved by OPA policy for this execution.
    pub fn allowed_sinks(mut self, sinks: Vec<Arc<str>>) -> Self {
        self.allowed_sinks = sinks;
        self
    }

    /// Set budget snapshots (before and after execution).
    pub fn budgets(
        mut self,
        before: Option<serde_json::Value>,
        after: Option<serde_json::Value>,
    ) -> Self {
        self.budgets_before = before;
        self.budgets_after = after;
        self
    }

    /// Set runtime execution details (only meaningful when decision is Allow).
    pub fn runtime(mut self, runtime: RuntimeAudit) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Set response hash and byte count.
    pub fn response(mut self, hash: impl Into<Arc<str>>, bytes: usize) -> Self {
        self.response_hash = Some(hash.into());
        self.response_bytes = Some(bytes);
        self
    }

    /// Set the ExecutionGrant identifier (present when grant was issued).
    pub fn grant(mut self, grant_id: impl Into<Arc<str>>) -> Self {
        self.grant_id = Some(grant_id.into());
        self
    }

    /// Set the ExecutionReceipt identifier and verification outcome
    /// (present when provider dispatch completed and verifier ran).
    pub fn receipt(
        mut self,
        receipt_id: impl Into<Arc<str>>,
        verification_outcome: impl Into<Arc<str>>,
    ) -> Self {
        self.receipt_id = Some(receipt_id.into());
        self.verification_outcome = Some(verification_outcome.into());
        self
    }

    /// Set the operator identity that approved or denied the request.
    ///
    /// Must be called on approval and denial paths to record per-operator
    /// accountability as a structured, queryable field — not embedded in
    /// free-text `deny_reason`.
    pub fn approved_by(mut self, operator_id: impl Into<Arc<str>>) -> Self {
        self.approved_by = Some(operator_id.into());
        self
    }

    /// Set the approval identifier linking pending and terminal events.
    pub fn approval_id(mut self, id: impl Into<Arc<str>>) -> Self {
        self.approval_id = Some(id.into());
        self
    }

    /// Set how the operator authenticated (e.g. "operator_dpop").
    pub fn operator_authn_method(mut self, method: impl Into<Arc<str>>) -> Self {
        self.operator_authn_method = Some(method.into());
        self
    }

    /// Set the operator's DPoP sender binding (JWK thumbprint).
    ///
    /// SECURITY (04.4): records the cryptographic binding between the operator
    /// action and their key. Empty string is treated as None.
    pub fn operator_sender_binding(mut self, binding: impl Into<Arc<str>>) -> Self {
        let binding: Arc<str> = binding.into();
        if !binding.is_empty() {
            self.operator_sender_binding = Some(binding);
        }
        self
    }

    /// Set the operator's DPoP proof jti (for forensic correlation).
    pub fn operator_proof_jti(mut self, jti: impl Into<Arc<str>>) -> Self {
        let jti: Arc<str> = jti.into();
        if !jti.is_empty() {
            self.operator_proof_jti = Some(jti);
        }
        self
    }

    /// Set operational flags.
    pub fn flags(mut self, dev_mode: bool, sandbox_degraded: bool) -> Self {
        self.dev_mode = dev_mode;
        self.sandbox_degraded = sandbox_degraded;
        self
    }

    /// Consume the builder and produce a finished [`AuditEvent`].
    ///
    /// The `timestamp` is set to the current UTC time at the moment of this
    /// call, formatted as ISO 8601 with millisecond precision.
    ///
    /// `prev_hash` is always `None` — it is set later by `LedgerStore::write_event`.
    pub fn build(self) -> AuditEvent {
        let timestamp = now_iso8601();
        AuditEvent {
            trace_id: self.trace_id,
            timestamp,
            event_type: self.event_type,

            subject: AuditSubject {
                principal: self.principal,
                session_id: self.session_id,
                lease_jti: self.lease_jti,
                identity_method: self.identity_method,
                owner: self.owner,
            },

            action: AuditAction {
                action_id: self.action_id,
                action_version: self.action_version,
                action_digest: self.action_digest,
                action_trust_verdict: self.action_trust_verdict,
                risk_level: self.risk_level,
            },

            request: AuditRequest {
                request_hash: self.request_hash,
                request_schema_id: self.request_schema_id,
            },

            policy: AuditPolicy {
                policy_version: self.policy_version,
                decision: self.decision,
                deny_reason: self.deny_reason,
                allowed_sinks: self.allowed_sinks,
            },

            budgets_before: self.budgets_before,
            budgets_after: self.budgets_after,

            execution: AuditExecution {
                runtime: self.runtime,
                response_hash: self.response_hash,
                response_bytes: self.response_bytes,
                grant_id: self.grant_id,
                receipt_id: self.receipt_id,
                verification_outcome: self.verification_outcome,
            },

            approval: AuditApproval {
                approval_id: self.approval_id,
                approved_by: self.approved_by,
                operator_authn_method: self.operator_authn_method,
                operator_sender_binding: self.operator_sender_binding,
                operator_proof_jti: self.operator_proof_jti,
            },

            prev_hash: None,

            dev_mode: self.dev_mode,
            sandbox_degraded: self.sandbox_degraded,
        }
    }
}

/// UTC timestamp with millisecond precision in ISO 8601 format.
fn now_iso8601() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- as_str() ↔ serde sync --

    /// `EventType::as_str()` must return the same string as serde JSON
    /// serialization (minus the quotes). If a variant is added and the
    /// match arm is wrong, this test catches it.
    #[test]
    fn event_type_as_str_matches_serde() {
        let variants = [
            EventType::ActionCall,
            EventType::LeaseIssued,
            EventType::LeaseRevoked,
            EventType::ApprovalGranted,
            EventType::ApprovalDenied,
            EventType::AdminRevokeAll,
            EventType::AdminEpochRead,
            EventType::AdminReceiptKeysRead,
            EventType::AdminDrain,
            EventType::AdminReload,
            EventType::DomainAdd,
            EventType::DomainRemove,
            EventType::DomainClear,
            EventType::PathAdd,
            EventType::PathRemove,
            EventType::PathClear,
            EventType::PolicyGrant,
            EventType::PolicyRevoke,
        ];
        for v in &variants {
            let serde_str = serde_json::to_string(v).unwrap();
            let serde_str = serde_str.trim_matches('"');
            assert_eq!(
                v.as_str(),
                serde_str,
                "EventType::{v:?} as_str() out of sync with serde"
            );
        }
    }

    /// Same for `Decision`.
    #[test]
    fn decision_as_str_matches_serde() {
        let variants = [
            Decision::Allow,
            Decision::AllowUnverified,
            Decision::Deny,
            Decision::PendingApproval,
            Decision::Error,
        ];
        for v in &variants {
            let serde_str = serde_json::to_string(v).unwrap();
            let serde_str = serde_str.trim_matches('"');
            assert_eq!(
                v.as_str(),
                serde_str,
                "Decision::{v:?} as_str() out of sync with serde"
            );
        }
    }

    // -- Serialization roundtrip --

    #[test]
    fn audit_event_serializes_to_json_and_back() {
        let event = AuditEventBuilder::new("trace-001", EventType::ActionCall)
            .principal("agent:test", "sess-001", "jti-001")
            .action(
                "http_fetch",
                Some("1.0.0".into()),
                "sha256:abcdef",
                "digest_ok",
            )
            .request("sha256:req123", Some("schema-v1".into()))
            .policy(Decision::Allow, Some("policy-v2".into()), None)
            .runtime(RuntimeAudit {
                module_digest: "sha256:ctr-abc123".into(),
                egress_profile: "none".into(),
                duration_ms: 450,
                exit_code: 0,
                timeout_hit: false,
                fuel_consumed: 50_000,
                io_calls_made: 1,
            })
            .response("sha256:resp456", 1024)
            .flags(false, false)
            .build();

        let json_str = serde_json::to_string(&event).expect("serialize");
        let restored: AuditEvent = serde_json::from_str(&json_str).expect("deserialize");

        assert_eq!(event, restored);
    }

    // -- JSON shape is flat (serde(flatten) works) --

    #[test]
    fn json_shape_is_flat() {
        let event = AuditEventBuilder::new("trace-flat", EventType::ActionCall)
            .principal("agent:x", "sess", "jti")
            .action("t", None, "d", "digest_ok")
            .build();

        let json_val = serde_json::to_value(&event).unwrap();
        let obj = json_val.as_object().unwrap();

        // Sub-struct fields must appear at top level, not nested.
        assert!(obj.contains_key("principal"), "principal must be top-level");
        assert!(obj.contains_key("action_id"), "action_id must be top-level");
        assert!(obj.contains_key("decision"), "decision must be top-level");
        assert!(
            !obj.contains_key("subject"),
            "subject wrapper must not appear in JSON"
        );
        assert!(
            !obj.contains_key("action"),
            "action wrapper must not appear in JSON"
        );
        assert!(
            !obj.contains_key("policy"),
            "policy wrapper must not appear in JSON"
        );
    }

    // -- Builder sets timestamp --

    #[test]
    fn builder_sets_timestamp_on_build() {
        let event = AuditEventBuilder::new("trace-ts", EventType::ActionCall).build();
        assert!(!event.timestamp.is_empty(), "timestamp must be non-empty");
        assert!(
            event.timestamp.ends_with('Z'),
            "timestamp must be UTC (ends with Z)"
        );
        assert!(
            event.timestamp.contains('T'),
            "timestamp must be ISO 8601 (contains T)"
        );
    }

    #[test]
    fn builder_generates_millisecond_precision() {
        let event = AuditEventBuilder::new("trace-ms", EventType::ActionCall).build();
        let parts: Vec<&str> = event.timestamp.split('.').collect();
        assert_eq!(parts.len(), 2, "timestamp must have fractional part");
        assert_eq!(parts[1].len(), 4, "fractional part must be 3 digits + Z");
    }

    // -- Decision serialization --

    #[test]
    fn decision_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::AllowUnverified).unwrap(),
            "\"allow_unverified\""
        );
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");
        assert_eq!(
            serde_json::to_string(&Decision::PendingApproval).unwrap(),
            "\"pending_approval\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn decision_deserializes_snake_case() {
        assert_eq!(
            serde_json::from_str::<Decision>("\"allow\"").unwrap(),
            Decision::Allow
        );
        assert_eq!(
            serde_json::from_str::<Decision>("\"allow_unverified\"").unwrap(),
            Decision::AllowUnverified
        );
        assert_eq!(
            serde_json::from_str::<Decision>("\"pending_approval\"").unwrap(),
            Decision::PendingApproval
        );
    }

    // -- EventType serialization --

    #[test]
    fn event_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::ActionCall).unwrap(),
            "\"action_call\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::LeaseIssued).unwrap(),
            "\"lease_issued\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::LeaseRevoked).unwrap(),
            "\"lease_revoked\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::ApprovalGranted).unwrap(),
            "\"approval_granted\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::ApprovalDenied).unwrap(),
            "\"approval_denied\""
        );
    }

    #[test]
    fn admin_event_types_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::AdminRevokeAll).unwrap(),
            "\"admin_revoke_all\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::AdminEpochRead).unwrap(),
            "\"admin_epoch_read\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::AdminReceiptKeysRead).unwrap(),
            "\"admin_receipt_keys_read\""
        );
    }

    #[test]
    fn path_event_types_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::PathAdd).unwrap(),
            "\"path_add\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::PathRemove).unwrap(),
            "\"path_remove\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::PathClear).unwrap(),
            "\"path_clear\""
        );
    }

    #[test]
    fn policy_event_types_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::PolicyGrant).unwrap(),
            "\"policy_grant\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::PolicyRevoke).unwrap(),
            "\"policy_revoke\""
        );
    }

    // -- Secret values structurally excluded from event --

    #[test]
    fn audit_event_schema_has_no_raw_content_fields() {
        // SECURITY: verify that AuditEvent stores only hashes, IDs, and
        // verdicts — never raw request/response bodies, full JWTs, env
        // vars, or key material. The builder API makes it structurally
        // difficult to accidentally log secrets because no such field
        // exists. This test codifies that invariant.

        let event = AuditEventBuilder::new("trace-struct", EventType::ActionCall)
            .principal("agent:test", "sess-01", "jti-only")
            .action(
                "http_fetch",
                Some("1.0.0".into()),
                "sha256:abcdef1234567890",
                "digest_ok",
            )
            .request("sha256:req_hash_only", Some("http_fetch:request".into()))
            .policy(
                Decision::Deny,
                Some("v1.2.3".into()),
                Some("budget exhausted".into()),
            )
            .response("sha256:resp_hash_only", 1024)
            .flags(false, false)
            .build();

        let json_val = serde_json::to_value(&event).unwrap();
        let obj = json_val.as_object().unwrap();

        // No field name should suggest raw content or secret storage.
        let forbidden_patterns = [
            "raw_",
            "body",
            "payload",
            "token",
            "secret",
            "key",
            "password",
            "env_",
            "jwt",
            "credential",
        ];
        for field in obj.keys() {
            let lower = field.to_lowercase();
            for pat in &forbidden_patterns {
                assert!(
                    !lower.contains(pat),
                    "field '{field}' suggests raw/secret storage (contains '{pat}')"
                );
            }
        }

        // Request and response are represented only by their hashes.
        assert!(
            event.request.request_hash.starts_with("sha256:"),
            "request_hash must be a hash, not raw body"
        );
        assert!(
            event
                .execution
                .response_hash
                .as_ref()
                .unwrap()
                .starts_with("sha256:"),
            "response_hash must be a hash, not raw body"
        );

        // lease_jti stores the jti claim only — must not look like a JWT.
        assert!(
            !event.subject.lease_jti.contains('.'),
            "lease_jti looks like a full JWT (contains '.'); only the jti claim should be stored"
        );
    }

    #[test]
    fn deny_reason_does_not_contain_env_values() {
        // SECURITY: deny_reason is a free-text field populated from error
        // messages. Verify that pipeline-level deny reasons use generic
        // descriptions, not interpolated secret values.
        let event = AuditEventBuilder::new("trace-deny-reason", EventType::ActionCall)
            .policy(Decision::Deny, None, Some("budget exhausted".into()))
            .build();

        let json_str = serde_json::to_string(&event).unwrap();
        // These patterns should never appear in audit output.
        assert!(!json_str.contains("sk-live"));
        assert!(!json_str.contains("BEGIN PRIVATE KEY"));
        assert!(!json_str.contains("Bearer ey"));
    }

    // -- RuntimeAudit is optional --

    #[test]
    fn runtime_audit_optional_for_deny() {
        let event = AuditEventBuilder::new("trace-deny", EventType::ActionCall)
            .policy(Decision::Deny, None, Some("budget exhausted".into()))
            .build();

        assert!(event.execution.runtime.is_none());
        let json_str = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert!(restored.execution.runtime.is_none());
        assert_eq!(restored.policy.decision, Decision::Deny);
        assert_eq!(
            restored.policy.deny_reason.as_deref(),
            Some("budget exhausted")
        );
    }

    // -- Budgets are optional --

    #[test]
    fn budgets_are_optional() {
        let event = AuditEventBuilder::new("trace-no-budget", EventType::ActionCall).build();
        assert!(event.budgets_before.is_none());
        assert!(event.budgets_after.is_none());
    }

    #[test]
    fn budgets_roundtrip() {
        let before = json!({"calls_remaining": 10});
        let after = json!({"calls_remaining": 9});
        let event = AuditEventBuilder::new("trace-budget", EventType::ActionCall)
            .budgets(Some(before.clone()), Some(after.clone()))
            .build();

        let json_str = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(restored.budgets_before, Some(before));
        assert_eq!(restored.budgets_after, Some(after));
    }

    // -- Flags --

    #[test]
    fn dev_mode_flag_serialized() {
        let event = AuditEventBuilder::new("trace-dev", EventType::ActionCall)
            .flags(true, false)
            .build();

        assert!(event.dev_mode);
        assert!(!event.sandbox_degraded);

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("\"dev_mode\":true"));
    }

    #[test]
    fn sandbox_degraded_flag_serialized() {
        let event = AuditEventBuilder::new("trace-degraded", EventType::ActionCall)
            .flags(false, true)
            .build();

        assert!(!event.dev_mode);
        assert!(event.sandbox_degraded);

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("\"sandbox_degraded\":true"));
    }

    // -- Approved-by attribution --

    #[test]
    fn approved_by_roundtrips() {
        let event = AuditEventBuilder::new("trace-ab", EventType::ActionCall)
            .approved_by("alice")
            .build();

        assert_eq!(event.approval.approved_by.as_deref(), Some("alice"));

        let json_str = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(restored.approval.approved_by.as_deref(), Some("alice"));
    }

    #[test]
    fn approved_by_omitted_from_json_when_none() {
        let event = AuditEventBuilder::new("trace-ab-none", EventType::ActionCall).build();
        assert!(event.approval.approved_by.is_none());
        let json_str = serde_json::to_string(&event).unwrap();
        assert!(
            !json_str.contains("approved_by"),
            "approved_by must be omitted when None"
        );
    }

    // -- Defaults --

    #[test]
    fn builder_defaults_are_safe() {
        let event = AuditEventBuilder::new("trace-default", EventType::ActionCall).build();

        assert_eq!(event.policy.decision, Decision::Error);
        assert!(!event.dev_mode);
        assert!(!event.sandbox_degraded);
        assert!(event.action.risk_level.is_none());
        assert!(event.execution.runtime.is_none());
        assert!(event.execution.response_hash.is_none());
        assert!(event.execution.response_bytes.is_none());
        assert!(event.policy.deny_reason.is_none());
        assert!(event.approval.approved_by.is_none());
        assert!(event.subject.identity_method.is_none());
        assert!(event.subject.owner.is_none());
        assert!(
            event.prev_hash.is_none(),
            "prev_hash must be None from builder (store sets it)"
        );
    }

    // -- Timestamp sanity --

    #[test]
    fn timestamp_is_plausible() {
        let event = AuditEventBuilder::new("trace-time", EventType::ActionCall).build();
        assert!(event.timestamp.starts_with("20"));
        assert_eq!(event.timestamp.len(), 24);
    }

    // -- prev_hash --

    #[test]
    fn prev_hash_defaults_to_none_from_builder() {
        let event = AuditEventBuilder::new("trace-ph", EventType::ActionCall).build();
        assert!(event.prev_hash.is_none());
    }

    #[test]
    fn prev_hash_roundtrip() {
        let mut event = AuditEventBuilder::new("trace-ph-rt", EventType::ActionCall).build();
        event.prev_hash = Some("sha256:abc123def456".into());

        let json_str = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(restored.prev_hash.as_deref(), Some("sha256:abc123def456"));
    }

    // -- Full event has all fields --

    #[test]
    fn full_event_has_all_fields() {
        let mut event = AuditEventBuilder::new("trace-full", EventType::ActionCall)
            .principal("agent:x", "sess", "jti")
            .identity_method("peercred")
            .owner(Some("alice@company.com".into()))
            .action("t", Some("1.0".into()), "sha256:d", "digest_ok")
            .risk_level("high")
            .request("sha256:r", Some("s".into()))
            .policy(Decision::Allow, Some("pv".into()), None)
            .budgets(Some(json!({})), Some(json!({})))
            .runtime(RuntimeAudit {
                module_digest: "sha256:c".into(),
                egress_profile: "none".into(),
                duration_ms: 100,
                exit_code: 0,
                timeout_hit: false,
                fuel_consumed: 10_000,
                io_calls_made: 0,
            })
            .response("sha256:resp", 512)
            .approved_by("alice")
            .flags(false, false)
            .build();
        event.prev_hash = Some("sha256:prev".into());

        let json_val: serde_json::Value = serde_json::to_value(&event).unwrap();
        let obj = json_val.as_object().unwrap();

        let expected_keys = [
            "trace_id",
            "timestamp",
            "event_type",
            "principal",
            "session_id",
            "lease_jti",
            "identity_method",
            "owner",
            "action_id",
            "action_version",
            "action_digest",
            "action_trust_verdict",
            "risk_level",
            "request_hash",
            "request_schema_id",
            "policy_version",
            "decision",
            "deny_reason",
            "allowed_sinks",
            "budgets_before",
            "budgets_after",
            "runtime",
            "response_hash",
            "response_bytes",
            "approved_by",
            "prev_hash",
            "dev_mode",
            "sandbox_degraded",
        ];
        for key in &expected_keys {
            assert!(obj.contains_key(*key), "missing field: {key}");
        }
        assert_eq!(obj.len(), expected_keys.len());
    }

    // -- Identity method attribution --

    #[test]
    fn identity_method_roundtrips() {
        let event = AuditEventBuilder::new("trace-im", EventType::LeaseIssued)
            .principal("agent-jira", "sess-001", "")
            .identity_method("peercred")
            .build();

        assert_eq!(event.subject.identity_method.as_deref(), Some("peercred"));

        let json_str = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(
            restored.subject.identity_method.as_deref(),
            Some("peercred")
        );
    }

    #[test]
    fn identity_method_omitted_from_json_when_none() {
        let event = AuditEventBuilder::new("trace-im-none", EventType::ActionCall).build();
        assert!(event.subject.identity_method.is_none());
        let json_str = serde_json::to_string(&event).unwrap();
        assert!(
            !json_str.contains("identity_method"),
            "identity_method must be omitted when None"
        );
    }

    #[test]
    fn identity_method_empty_string_treated_as_none() {
        let event = AuditEventBuilder::new("trace-im-empty", EventType::LeaseIssued)
            .identity_method(String::new())
            .build();
        assert!(
            event.subject.identity_method.is_none(),
            "empty string must be treated as None"
        );
    }

    // -- Owner attribution --

    #[test]
    fn owner_roundtrips_through_json() {
        let event = AuditEventBuilder::new("trace-owner", EventType::ActionCall)
            .principal("agent:deploy-bot", "sess-001", "jti-001")
            .owner(Some("alice@company.com".into()))
            .build();

        assert_eq!(event.subject.owner.as_deref(), Some("alice@company.com"));

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("\"owner\":\"alice@company.com\""));

        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(restored.subject.owner.as_deref(), Some("alice@company.com"));
    }

    #[test]
    fn owner_omitted_from_json_when_none() {
        let event = AuditEventBuilder::new("trace-owner-none", EventType::ActionCall).build();
        assert!(event.subject.owner.is_none());
        let json_str = serde_json::to_string(&event).unwrap();
        assert!(
            !json_str.contains("\"owner\""),
            "owner must be omitted from JSON when None"
        );
    }

    #[test]
    fn owner_deserialized_as_none_when_absent() {
        // Simulate an old audit event JSON without the owner field.
        let json_str = r#"{
            "trace_id":"t","timestamp":"2026-01-01T00:00:00.000Z","event_type":"action_call",
            "principal":"agent:x","session_id":"s","lease_jti":"j",
            "action_id":"a","action_version":null,"action_digest":"d",
            "action_trust_verdict":"digest_ok","request_hash":"h",
            "request_schema_id":null,"policy_version":null,"decision":"allow",
            "deny_reason":null,"allowed_sinks":[],"budgets_before":null,
            "budgets_after":null,"runtime":null,"response_hash":null,
            "response_bytes":null,"prev_hash":null,"dev_mode":false,
            "sandbox_degraded":false
        }"#;
        let event: AuditEvent = serde_json::from_str(json_str).unwrap();
        assert!(
            event.subject.owner.is_none(),
            "owner must default to None for old events without the field"
        );
    }

    // -- Risk level --

    #[test]
    fn risk_level_roundtrips_through_json() {
        let event = AuditEventBuilder::new("trace-rl", EventType::ActionCall)
            .action("act", Some("1.0".into()), "sha256:d", "digest_ok")
            .risk_level("high")
            .build();

        assert_eq!(event.action.risk_level.as_deref(), Some("high"));

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("\"risk_level\":\"high\""));

        let restored: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(restored.action.risk_level.as_deref(), Some("high"));
    }

    #[test]
    fn risk_level_omitted_from_json_when_none() {
        let event = AuditEventBuilder::new("trace-rl-none", EventType::ActionCall).build();
        assert!(event.action.risk_level.is_none());
        let json_str = serde_json::to_string(&event).unwrap();
        assert!(
            !json_str.contains("risk_level"),
            "risk_level must be omitted from JSON when None"
        );
    }

    #[test]
    fn risk_level_empty_string_treated_as_none() {
        let event = AuditEventBuilder::new("trace-rl-empty", EventType::ActionCall)
            .risk_level("")
            .build();
        assert!(
            event.action.risk_level.is_none(),
            "empty string must be treated as None"
        );
    }

    #[test]
    fn risk_level_deserialized_as_none_when_absent() {
        // Simulate a pre-risk_level audit event JSON.
        let json_str = r#"{
            "trace_id":"t","timestamp":"2026-01-01T00:00:00.000Z","event_type":"action_call",
            "principal":"agent:x","session_id":"s","lease_jti":"j",
            "action_id":"a","action_version":null,"action_digest":"d",
            "action_trust_verdict":"digest_ok","request_hash":"h",
            "request_schema_id":null,"policy_version":null,"decision":"allow",
            "deny_reason":null,"allowed_sinks":[],"budgets_before":null,
            "budgets_after":null,"runtime":null,"response_hash":null,
            "response_bytes":null,"prev_hash":null,"dev_mode":false,
            "sandbox_degraded":false
        }"#;
        let event: AuditEvent = serde_json::from_str(json_str).unwrap();
        assert!(
            event.action.risk_level.is_none(),
            "risk_level must default to None for old events without the field"
        );
    }
}
