//! Public types for the approval lifecycle.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use latchgate_core::ApprovedExecutionPlan;

// Error

/// Errors from the approval store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// The approval already exists (duplicate creation attempt).
    ///
    /// SECURITY: prevents silent overwrite of an in-flight approval.
    #[error("approval already exists: {approval_id}")]
    AlreadyExists { approval_id: String },

    /// The approval was not found (never created, already expired and purged).
    #[error("approval not found or expired: {approval_id}")]
    NotFound { approval_id: String },

    /// The approval is already claimed by another operator/request.
    ///
    /// SECURITY: prevents double execution. The first claim wins.
    #[error("approval already claimed: {approval_id}")]
    AlreadyClaimed { approval_id: String },

    /// The approval has already reached a terminal state.
    #[error("approval already completed: {approval_id}")]
    AlreadyCompleted { approval_id: String },

    /// The claim token does not match the stored one.
    ///
    /// SECURITY: prevents a stale or forged claim from completing.
    #[error("claim token mismatch for approval: {approval_id}")]
    TokenMismatch { approval_id: String },

    /// The approval is not in `Claimed` state.
    #[error("approval not in claimed state: {approval_id}")]
    NotClaimed { approval_id: String },

    /// Redis is unavailable. SECURITY: fail-closed => pipeline maps to 503.
    #[error("approval store unavailable: {0}")]
    Unavailable(String),

    /// Redis URL is malformed (configuration error).
    #[error("invalid Redis URL: {0}")]
    InvalidUrl(String),

    /// Serialization/deserialization failure (corrupted data).
    #[error("approval data corrupted: {0}")]
    DataCorrupted(String),
}

// ApprovalState

/// State machine for the approval lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Awaiting operator decision.
    Pending,
    /// Claimed by an operator for execution.
    Claimed,
    /// Terminal: approved and executed.
    Approved,
    /// Terminal: denied by operator.
    Denied,
    /// Terminal: approved but execution failed.
    ///
    /// SECURITY: prevents silent re-execution of non-idempotent actions.
    Failed,
}

impl ApprovalState {
    /// Returns `true` if this is a terminal state (no further transitions).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ApprovalState::Approved | ApprovalState::Denied | ApprovalState::Failed
        )
    }

    /// Canonical string representation used in SQLite and Redis.
    ///
    /// Inverse of [`from_db_str`](Self::from_db_str). All storage backends
    /// MUST use this for writes — hand-written string literals are a
    /// consistency hazard.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }

    /// Parse a state string as stored in SQLite or Redis.
    ///
    /// Returns `None` for unrecognised values. Callers should map `None`
    /// to `ApprovalError::DataCorrupted` — an unknown state string in the
    /// database indicates data corruption or a schema migration bug.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "claimed" => Some(Self::Claimed),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

// Shared state-machine precondition: require Claimed + matching token

/// Verify that an approval is in `Claimed` state with a matching claim token.
///
/// SECURITY: this is the **single** in-process implementation of the
/// complete/write-outcome precondition check. Both the in-memory and SQLite
/// backends call this function. The Redis backend performs an equivalent
/// check inside a Lua script (server-side, no client-observable timing).
///
/// The token comparison uses `constant_time_eq` to prevent timing
/// side-channel leakage of stored claim tokens. Claim tokens are bearer
/// secrets: anyone who presents the correct token can complete (approve,
/// deny, or fail) an approval. Variable-time comparison would let an
/// attacker iteratively guess the token byte-by-byte.
pub(crate) fn require_claimed_with_token(
    state: ApprovalState,
    stored_token: Option<&str>,
    given_token: &str,
    approval_id: &str,
) -> Result<(), ApprovalError> {
    if state != ApprovalState::Claimed {
        if state.is_terminal() {
            return Err(ApprovalError::AlreadyCompleted {
                approval_id: approval_id.to_string(),
            });
        }
        return Err(ApprovalError::NotClaimed {
            approval_id: approval_id.to_string(),
        });
    }

    let token_matches = match stored_token {
        Some(stored) => latchgate_core::constant_time_eq(stored.as_bytes(), given_token.as_bytes()),
        None => false,
    };

    if !token_matches {
        return Err(ApprovalError::TokenMismatch {
            approval_id: approval_id.to_string(),
        });
    }

    Ok(())
}

/// Validate that the current approval state allows claiming.
///
/// SECURITY: this is the single Rust implementation of the claim transition
/// guard. Both the InMemory and SQLite backends delegate to this function.
/// The Redis backend implements equivalent logic in its Lua script
/// (`LUA_CLAIM`) for server-side atomicity — changes here MUST be mirrored
/// in the Lua script.
///
/// # State machine
///
/// - `Pending` → Claimable.
/// - `Claimed` with outcome marker → `AlreadyCompleted` (durable marker
///   takes precedence, even if the `state` field hasn't been advanced yet).
/// - `Claimed` with unexpired claim → `AlreadyClaimed`.
/// - `Claimed` with expired claim → Claimable (crash recovery re-claim).
/// - `Approved | Denied | Failed` → `AlreadyCompleted`.
pub(crate) fn validate_claim_transition(
    state: ApprovalState,
    has_outcome_marker: bool,
    claim_expires_at: Option<i64>,
    now: i64,
    approval_id: &str,
) -> Result<(), ApprovalError> {
    match state {
        ApprovalState::Pending => Ok(()),
        ApprovalState::Claimed => {
            // SECURITY (02): outcome marker takes absolute precedence.
            if has_outcome_marker {
                return Err(ApprovalError::AlreadyCompleted {
                    approval_id: approval_id.to_string(),
                });
            }
            match claim_expires_at {
                Some(exp) if now < exp => Err(ApprovalError::AlreadyClaimed {
                    approval_id: approval_id.to_string(),
                }),
                Some(_) => Ok(()), // Expired claim — allow re-claim.
                None => Err(ApprovalError::AlreadyClaimed {
                    approval_id: approval_id.to_string(),
                }),
            }
        }
        ApprovalState::Approved | ApprovalState::Denied | ApprovalState::Failed => {
            Err(ApprovalError::AlreadyCompleted {
                approval_id: approval_id.to_string(),
            })
        }
    }
}

/// Build [`CompletionInfo`] from the key/value detail pair.
///
/// Shared between InMemory and SQLite backends so the detail-key dispatch
/// (receipt_id, deny_reason, error_code) is consistent.
pub(crate) fn build_completion_info(
    completed_at: &str,
    trace_id: &str,
    detail_key: &str,
    detail_value: &str,
) -> CompletionInfo {
    let mut info = CompletionInfo {
        completed_at: completed_at.to_string(),
        trace_id: trace_id.to_string(),
        receipt_id: None,
        deny_reason: None,
        error_code: None,
    };
    match detail_key {
        "receipt_id" if !detail_value.is_empty() => {
            info.receipt_id = Some(detail_value.to_string());
        }
        "deny_reason" if !detail_value.is_empty() => {
            info.deny_reason = Some(detail_value.to_string());
        }
        "error_code" if !detail_value.is_empty() => {
            info.error_code = Some(detail_value.to_string());
        }
        _ => {}
    }
    info
}

// ClaimInfo — grouped claim metadata

/// Operator claim metadata. Present when state ≥ `Claimed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimInfo {
    pub claimed_by: String,
    pub claimed_at: String,
    /// Opaque token that must be presented to complete the claim.
    pub claim_token: String,
    pub claim_expires_at_unix: i64,
}

// OutcomeMarker — write-ahead crash-recovery marker

/// Durable outcome marker written BEFORE the terminal state transition.
///
/// SECURITY (02): once this marker exists, the approval can never be
/// re-claimed — even if the main `state` field remains `Claimed` due to
/// a failed `complete_*()` call. This is the primary defense against
/// double-execution after partial completion failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeMarker {
    /// `"approved"`, `"denied"`, or `"failed"`.
    pub kind: String,
    pub at: String,
    /// State-specific detail: receipt_id / reason / error_code.
    pub detail: String,
}

// CompletionInfo — terminal state data

/// Terminal state data. Present when a `complete_*()` call succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionInfo {
    pub completed_at: String,
    /// Trace ID of the terminal execution (audit correlation).
    pub trace_id: String,
    /// Receipt ID from the executed grant (Approved only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Operator-provided denial reason (Denied only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// Error classification (Failed only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

// ApprovalRecord — the full envelope stored in Redis/SQLite

/// Storage envelope for an approval lifecycle.
///
/// Contains the immutable `PendingApproval` payload plus lifecycle metadata
/// grouped by phase: claim => outcome marker => completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    #[serde(rename = "status")]
    pub state: ApprovalState,
    pub payload: PendingApproval,

    /// Claim metadata. Present once an operator claims the approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<ClaimInfo>,

    /// Durable outcome marker (write-ahead for crash recovery).
    /// Written BEFORE the terminal state transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_marker: Option<OutcomeMarker>,

    /// Terminal completion data. Written by `complete_*()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<CompletionInfo>,
}

impl ApprovalRecord {
    /// Create a new record in `Pending` state.
    pub fn new_pending(payload: PendingApproval) -> Self {
        Self {
            state: ApprovalState::Pending,
            payload,
            claim: None,
            outcome_marker: None,
            completion: None,
        }
    }

    /// Compute the effective state, considering the outcome marker.
    ///
    /// When main `state` is still `Claimed` but an `outcome_marker` is
    /// present (partial completion failure), synthesize the terminal state.
    ///
    /// SECURITY: this is the **single** implementation of effective-state
    /// synthesis. All code paths must call this — never inline the logic.
    pub fn effective_state(&self) -> ApprovalState {
        if self.state == ApprovalState::Claimed {
            if let Some(ref marker) = self.outcome_marker {
                return match marker.kind.as_str() {
                    "approved" => ApprovalState::Approved,
                    "denied" => ApprovalState::Denied,
                    "failed" => ApprovalState::Failed,
                    _ => self.state,
                };
            }
        }
        self.state
    }

    /// Build an [`ApprovalStatus`] (detail view) from this record.
    ///
    /// Synthesizes receipt_id / deny_reason / error_code from the outcome
    /// marker when the main completion fields weren't written (crash recovery).
    pub fn to_status(&self) -> ApprovalStatus {
        let effective = self.effective_state();

        // Primary source: completion info. Fallback: outcome marker.
        let receipt_id = self
            .completion
            .as_ref()
            .and_then(|c| c.receipt_id.clone())
            .or_else(|| self.marker_detail_if("approved"));
        let deny_reason = self
            .completion
            .as_ref()
            .and_then(|c| c.deny_reason.clone())
            .or_else(|| self.marker_detail_if("denied"));
        let error_code = self
            .completion
            .as_ref()
            .and_then(|c| c.error_code.clone())
            .or_else(|| self.marker_detail_if("failed"));
        let completed_at = self
            .completion
            .as_ref()
            .map(|c| c.completed_at.clone())
            .or_else(|| self.outcome_marker.as_ref().map(|m| m.at.clone()));

        ApprovalStatus {
            state: effective,
            approval_id: self.payload.approval_id.clone(),
            action_id: Arc::clone(&self.payload.action_id),
            principal: Arc::clone(&self.payload.auth_context.principal),
            session_id: Arc::clone(&self.payload.auth_context.session_id),
            request_hash: Arc::clone(&self.payload.request_hash),
            policy_version: self.payload.policy_version.clone(),
            created_at: self.payload.created_at.clone(),
            claimed_by: self.claim.as_ref().map(|c| c.claimed_by.clone()),
            claimed_at: self.claim.as_ref().map(|c| c.claimed_at.clone()),
            completed_at,
            receipt_id,
            deny_reason,
            error_code,
        }
    }

    /// Build an [`ApprovalSummary`] (lightweight list view) from this record.
    pub fn to_summary(&self) -> ApprovalSummary {
        ApprovalSummary {
            approval_id: self.payload.approval_id.clone(),
            state: self.effective_state(),
            action_id: Arc::clone(&self.payload.action_id),
            action_version: Arc::clone(&self.payload.plan.action_version),
            principal: Arc::clone(&self.payload.auth_context.principal),
            session_id: Arc::clone(&self.payload.auth_context.session_id),
            owner: self.payload.auth_context.owner.clone(),
            risk_level: self.payload.plan.risk_level,
            request_hash: Arc::clone(&self.payload.request_hash),
            created_at: self.payload.created_at.clone(),
            expires_at: self.payload.plan.core.expires_at.to_rfc3339(),
            claimed_by: self.claim.as_ref().map(|c| c.claimed_by.clone()),
        }
    }

    /// Extract outcome marker detail if the marker kind matches.
    fn marker_detail_if(&self, kind: &str) -> Option<String> {
        self.outcome_marker
            .as_ref()
            .filter(|m| m.kind == kind)
            .map(|m| m.detail.clone())
    }
}

// ClaimedApproval — return type from claim_pending

/// Successful result of `claim_pending()`.
#[derive(Debug, Clone)]
pub struct ClaimedApproval {
    pub pending: PendingApproval,
    pub claim_token: String,
    pub claimed_at: String,
    pub claimed_by: String,
}

// ApprovalStatus — detail view for GET endpoint

/// Current status of an approval (detail view).
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalStatus {
    #[serde(rename = "status")]
    pub state: ApprovalState,
    pub approval_id: String,
    pub action_id: Arc<str>,
    pub principal: Arc<str>,
    pub session_id: Arc<str>,
    pub request_hash: Arc<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<Arc<str>>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

// ApprovalSummary — lightweight list view

/// Lightweight summary for approval list views.
///
/// Contains enough context for an operator to identify and prioritize
/// pending approvals. Rich review data is available via the detail endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalSummary {
    pub approval_id: String,
    #[serde(rename = "status")]
    pub state: ApprovalState,
    pub action_id: Arc<str>,
    pub action_version: Arc<str>,
    pub principal: Arc<str>,
    pub session_id: Arc<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Arc<str>>,
    pub risk_level: latchgate_core::RiskLevel,
    pub request_hash: Arc<str>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<String>,
}

// StoredAuthContext

/// Reduced auth context stored alongside pending approvals.
///
/// SECURITY: deliberately omits full JWT, DPoP key material, and secrets.
/// Contains only identifiers needed for audit attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthContext {
    pub principal: Arc<str>,
    pub session_id: Arc<str>,
    pub lease_jti: Arc<str>,
    /// JWK thumbprint (cnf.jkt) of the agent's DPoP key.
    ///
    /// SECURITY: carried through the approval flow so the post-approval
    /// grant is bound to the original caller's key — not the operator's.
    pub sender_thumbprint: Arc<str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Arc<str>>,
}

// PendingApproval

/// Full context of an action call awaiting human approval.
///
/// Persisted as JSON inside an `ApprovalRecord`. Contains the immutable
/// execution plan capturing the exact security-relevant state at decision time.
///
/// SECURITY: the `plan` field is the single source of truth for what was
/// approved. The approve endpoint MUST use `plan.approved_targets`,
/// `plan.approved_secrets`, `plan.provider_module_digest`, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub approval_id: String,
    pub trace_id: Arc<str>,
    pub action_id: Arc<str>,
    pub auth_context: StoredAuthContext,
    pub request_hash: Arc<str>,
    pub request_body: Arc<serde_json::Value>,
    pub policy_version: Option<Arc<str>>,
    pub created_at: String,
    /// Immutable execution plan captured at pending-approval time.
    ///
    /// SECURITY: binds the exact execution contract the operator approves.
    pub plan: ApprovedExecutionPlan,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_paths: Vec<String>,
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers

    fn test_plan() -> ApprovedExecutionPlan {
        ApprovedExecutionPlan::test_default()
    }

    fn test_auth_context() -> StoredAuthContext {
        StoredAuthContext {
            principal: "agent:test".into(),
            session_id: "sess-001".into(),
            lease_jti: "jti-abc".into(),
            sender_thumbprint: "thumb-xyz".into(),
            owner: None,
        }
    }

    fn test_pending() -> PendingApproval {
        PendingApproval {
            approval_id: "apr-001".into(),
            trace_id: "trace-001".into(),
            action_id: "http_fetch".into(),
            auth_context: test_auth_context(),
            request_hash: "sha256:deadbeef".into(),
            request_body: Arc::new(serde_json::json!({"url": "https://example.com"})),
            policy_version: Some("v1.2.3".into()),
            created_at: "2025-01-15T12:00:00Z".into(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        }
    }

    fn pending_record() -> ApprovalRecord {
        ApprovalRecord::new_pending(test_pending())
    }

    fn claimed_record(claim_token: &str) -> ApprovalRecord {
        let mut r = pending_record();
        r.state = ApprovalState::Claimed;
        r.claim = Some(ClaimInfo {
            claimed_by: "alice".into(),
            claimed_at: "2025-01-15T12:01:00Z".into(),
            claim_token: claim_token.into(),
            claim_expires_at_unix: 9999999999,
        });
        r
    }

    // ApprovalState: serde + is_terminal

    #[test]
    fn state_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_value(ApprovalState::Pending).unwrap(),
            "pending"
        );
        assert_eq!(
            serde_json::to_value(ApprovalState::Claimed).unwrap(),
            "claimed"
        );
        assert_eq!(
            serde_json::to_value(ApprovalState::Approved).unwrap(),
            "approved"
        );
        assert_eq!(
            serde_json::to_value(ApprovalState::Denied).unwrap(),
            "denied"
        );
        assert_eq!(
            serde_json::to_value(ApprovalState::Failed).unwrap(),
            "failed"
        );
    }

    #[test]
    fn state_roundtrips_through_json() {
        for state in [
            ApprovalState::Pending,
            ApprovalState::Claimed,
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Failed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let restored: ApprovalState = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, state);
        }
    }

    #[test]
    fn is_terminal_correct_for_all_variants() {
        assert!(!ApprovalState::Pending.is_terminal());
        assert!(!ApprovalState::Claimed.is_terminal());
        assert!(ApprovalState::Approved.is_terminal());
        assert!(ApprovalState::Denied.is_terminal());
        assert!(ApprovalState::Failed.is_terminal());
    }

    // ApprovalState::from_db_str

    #[test]
    fn from_db_str_parses_all_known_states() {
        assert_eq!(
            ApprovalState::from_db_str("pending"),
            Some(ApprovalState::Pending)
        );
        assert_eq!(
            ApprovalState::from_db_str("claimed"),
            Some(ApprovalState::Claimed)
        );
        assert_eq!(
            ApprovalState::from_db_str("approved"),
            Some(ApprovalState::Approved)
        );
        assert_eq!(
            ApprovalState::from_db_str("denied"),
            Some(ApprovalState::Denied)
        );
        assert_eq!(
            ApprovalState::from_db_str("failed"),
            Some(ApprovalState::Failed)
        );
    }

    #[test]
    fn from_db_str_rejects_unknown_values() {
        assert!(ApprovalState::from_db_str("unknown").is_none());
        assert!(ApprovalState::from_db_str("PENDING").is_none());
        assert!(ApprovalState::from_db_str("").is_none());
    }

    #[test]
    fn as_str_returns_canonical_strings() {
        assert_eq!(ApprovalState::Pending.as_str(), "pending");
        assert_eq!(ApprovalState::Claimed.as_str(), "claimed");
        assert_eq!(ApprovalState::Approved.as_str(), "approved");
        assert_eq!(ApprovalState::Denied.as_str(), "denied");
        assert_eq!(ApprovalState::Failed.as_str(), "failed");
    }

    #[test]
    fn as_str_from_db_str_roundtrip() {
        for state in [
            ApprovalState::Pending,
            ApprovalState::Claimed,
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Failed,
        ] {
            assert_eq!(
                ApprovalState::from_db_str(state.as_str()),
                Some(state),
                "roundtrip failed for {state:?}"
            );
        }
    }

    // require_claimed_with_token — shared precondition guard

    #[test]
    fn require_claimed_accepts_matching_token() {
        let result = super::require_claimed_with_token(
            ApprovalState::Claimed,
            Some("tok-secret-123"),
            "tok-secret-123",
            "apr-001",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn require_claimed_rejects_mismatched_token() {
        let result = super::require_claimed_with_token(
            ApprovalState::Claimed,
            Some("tok-secret-123"),
            "tok-wrong-456",
            "apr-001",
        );
        assert!(
            matches!(result, Err(ApprovalError::TokenMismatch { .. })),
            "mismatched token must return TokenMismatch, got: {result:?}"
        );
    }

    #[test]
    fn require_claimed_rejects_absent_stored_token() {
        let result =
            super::require_claimed_with_token(ApprovalState::Claimed, None, "tok-any", "apr-001");
        assert!(
            matches!(result, Err(ApprovalError::TokenMismatch { .. })),
            "absent stored token must return TokenMismatch, got: {result:?}"
        );
    }

    #[test]
    fn require_claimed_rejects_pending_state() {
        let result = super::require_claimed_with_token(
            ApprovalState::Pending,
            Some("tok"),
            "tok",
            "apr-001",
        );
        assert!(
            matches!(result, Err(ApprovalError::NotClaimed { .. })),
            "pending state must return NotClaimed, got: {result:?}"
        );
    }

    #[test]
    fn require_claimed_rejects_terminal_states() {
        for state in [
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Failed,
        ] {
            let result = super::require_claimed_with_token(state, Some("tok"), "tok", "apr-001");
            assert!(
                matches!(result, Err(ApprovalError::AlreadyCompleted { .. })),
                "terminal state {state:?} must return AlreadyCompleted, got: {result:?}"
            );
        }
    }

    // ApprovalRecord::effective_state — outcome marker synthesis

    #[test]
    fn effective_state_pending_without_marker() {
        let r = pending_record();
        assert_eq!(r.effective_state(), ApprovalState::Pending);
    }

    #[test]
    fn effective_state_claimed_without_marker() {
        let r = claimed_record("tok");
        assert_eq!(r.effective_state(), ApprovalState::Claimed);
    }

    #[test]
    fn effective_state_synthesizes_approved_from_marker() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "approved".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "rcpt-001".into(),
        });
        assert_eq!(r.effective_state(), ApprovalState::Approved);
    }

    #[test]
    fn effective_state_synthesizes_denied_from_marker() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "denied".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "too risky".into(),
        });
        assert_eq!(r.effective_state(), ApprovalState::Denied);
    }

    #[test]
    fn effective_state_synthesizes_failed_from_marker() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "failed".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "provider_timeout".into(),
        });
        assert_eq!(r.effective_state(), ApprovalState::Failed);
    }

    #[test]
    fn effective_state_unknown_marker_kind_falls_through() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "unknown_value".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "???".into(),
        });
        assert_eq!(
            r.effective_state(),
            ApprovalState::Claimed,
            "unknown marker kind must not synthesize a terminal state"
        );
    }

    #[test]
    fn effective_state_marker_on_pending_is_ignored() {
        // Outcome marker should only affect Claimed state.
        let mut r = pending_record();
        r.outcome_marker = Some(OutcomeMarker {
            kind: "approved".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "rcpt-001".into(),
        });
        assert_eq!(
            r.effective_state(),
            ApprovalState::Pending,
            "marker on non-Claimed state must be ignored"
        );
    }

    #[test]
    fn effective_state_already_terminal_ignores_marker() {
        let mut r = claimed_record("tok");
        r.state = ApprovalState::Approved;
        r.outcome_marker = Some(OutcomeMarker {
            kind: "denied".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "conflicting".into(),
        });
        assert_eq!(
            r.effective_state(),
            ApprovalState::Approved,
            "already-terminal state must not be overridden by marker"
        );
    }

    // ApprovalRecord::to_status — detail view + fallback logic

    #[test]
    fn to_status_pending_has_no_claim_or_completion() {
        let status = pending_record().to_status();
        assert_eq!(status.state, ApprovalState::Pending);
        assert_eq!(status.approval_id, "apr-001");
        assert_eq!(&*status.action_id, "http_fetch");
        assert!(status.claimed_by.is_none());
        assert!(status.completed_at.is_none());
        assert!(status.receipt_id.is_none());
        assert!(status.deny_reason.is_none());
    }

    #[test]
    fn to_status_claimed_has_operator() {
        let status = claimed_record("tok").to_status();
        assert_eq!(status.state, ApprovalState::Claimed);
        assert_eq!(status.claimed_by.as_deref(), Some("alice"));
    }

    #[test]
    fn to_status_falls_back_to_marker_receipt_id() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "approved".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "rcpt-marker".into(),
        });
        // No completion info set — should fall back to marker detail.
        let status = r.to_status();
        assert_eq!(status.state, ApprovalState::Approved);
        assert_eq!(status.receipt_id.as_deref(), Some("rcpt-marker"));
        assert_eq!(status.completed_at.as_deref(), Some("2025-01-15T12:02:00Z"));
    }

    #[test]
    fn to_status_falls_back_to_marker_deny_reason() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "denied".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "too_risky".into(),
        });
        let status = r.to_status();
        assert_eq!(status.deny_reason.as_deref(), Some("too_risky"));
    }

    #[test]
    fn to_status_falls_back_to_marker_error_code() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "failed".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "provider_timeout".into(),
        });
        let status = r.to_status();
        assert_eq!(status.error_code.as_deref(), Some("provider_timeout"));
    }

    #[test]
    fn to_status_prefers_completion_over_marker() {
        let mut r = claimed_record("tok");
        r.state = ApprovalState::Approved;
        r.outcome_marker = Some(OutcomeMarker {
            kind: "approved".into(),
            at: "2025-01-15T12:02:00Z".into(),
            detail: "rcpt-from-marker".into(),
        });
        r.completion = Some(CompletionInfo {
            completed_at: "2025-01-15T12:03:00Z".into(),
            trace_id: "trace-complete".into(),
            receipt_id: Some("rcpt-from-completion".into()),
            deny_reason: None,
            error_code: None,
        });
        let status = r.to_status();
        assert_eq!(
            status.receipt_id.as_deref(),
            Some("rcpt-from-completion"),
            "completion info must take precedence over marker detail"
        );
        assert_eq!(
            status.completed_at.as_deref(),
            Some("2025-01-15T12:03:00Z"),
            "completion timestamp must take precedence over marker timestamp"
        );
    }

    // ApprovalRecord::to_summary

    #[test]
    fn to_summary_carries_plan_fields() {
        let summary = pending_record().to_summary();
        assert_eq!(&*summary.action_id, "http_fetch");
        assert_eq!(&*summary.principal, "agent:test");
        assert_eq!(summary.state, ApprovalState::Pending);
        assert_eq!(&*summary.action_version, "1.0.0");
        assert_eq!(summary.risk_level, latchgate_core::RiskLevel::Low);
        assert!(!summary.expires_at.is_empty());
    }

    #[test]
    fn to_summary_uses_effective_state() {
        let mut r = claimed_record("tok");
        r.outcome_marker = Some(OutcomeMarker {
            kind: "denied".into(),
            at: "now".into(),
            detail: "reason".into(),
        });
        let summary = r.to_summary();
        assert_eq!(
            summary.state,
            ApprovalState::Denied,
            "summary must use effective_state, not raw state"
        );
    }

    #[test]
    fn to_summary_includes_owner_when_present() {
        let mut r = pending_record();
        r.payload.auth_context.owner = Some("alice@corp.com".into());
        let summary = r.to_summary();
        assert_eq!(summary.owner.as_deref(), Some("alice@corp.com"));
    }

    #[test]
    fn to_summary_owner_none_when_absent() {
        let summary = pending_record().to_summary();
        assert!(summary.owner.is_none());
    }

    // StoredAuthContext serde

    #[test]
    fn auth_context_roundtrips_through_json() {
        let ctx = test_auth_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: StoredAuthContext = serde_json::from_str(&json).unwrap();
        assert_eq!(&*restored.principal, "agent:test");
        assert_eq!(&*restored.sender_thumbprint, "thumb-xyz");
        assert!(restored.owner.is_none());
    }

    #[test]
    fn auth_context_owner_omitted_when_none() {
        let ctx = test_auth_context();
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(
            !json.contains("owner"),
            "owner field must be omitted when None"
        );
    }

    #[test]
    fn auth_context_owner_roundtrips_when_present() {
        let mut ctx = test_auth_context();
        ctx.owner = Some("alice@corp.com".into());
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: StoredAuthContext = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.owner.as_deref(), Some("alice@corp.com"));
    }

    // PendingApproval serde

    #[test]
    fn pending_approval_roundtrips_through_json() {
        let pending = test_pending();
        let json = serde_json::to_string(&pending).unwrap();
        let restored: PendingApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.approval_id, "apr-001");
        assert_eq!(&*restored.action_id, "http_fetch");
        assert_eq!(&*restored.request_hash, "sha256:deadbeef");
        assert_eq!(restored.policy_version.as_deref(), Some("v1.2.3"));
    }

    #[test]
    fn pending_approval_omits_empty_unresolved_vecs() {
        let pending = test_pending();
        let json = serde_json::to_string(&pending).unwrap();
        assert!(
            !json.contains("unresolved_domains"),
            "empty unresolved_domains must be omitted"
        );
        assert!(
            !json.contains("unresolved_paths"),
            "empty unresolved_paths must be omitted"
        );
    }

    #[test]
    fn pending_approval_preserves_unresolved_domains() {
        let mut pending = test_pending();
        pending.unresolved_domains = vec!["newsite.com".into()];
        let json = serde_json::to_string(&pending).unwrap();
        let restored: PendingApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.unresolved_domains, vec!["newsite.com"]);
    }

    // ApprovalRecord serde

    #[test]
    fn record_new_pending_is_in_pending_state() {
        let r = pending_record();
        assert_eq!(r.state, ApprovalState::Pending);
        assert!(r.claim.is_none());
        assert!(r.outcome_marker.is_none());
        assert!(r.completion.is_none());
    }

    #[test]
    fn record_roundtrips_through_json() {
        let r = pending_record();
        let json = serde_json::to_string(&r).unwrap();
        let restored: ApprovalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.state, ApprovalState::Pending);
        assert_eq!(restored.payload.approval_id, "apr-001");
    }

    #[test]
    fn record_omits_none_fields_in_json() {
        let r = pending_record();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("claim_token"));
        assert!(!json.contains("outcome_marker"));
        assert!(!json.contains("completion"));
    }

    // ApprovalError display — no secret leakage

    #[test]
    fn error_display_contains_only_approval_id() {
        // Error messages carry the approval_id for diagnostics but must
        // never include claim tokens, request bodies, or secret values.
        // The struct only holds `approval_id`, so the display string
        // cannot leak anything else — this test guards the invariant.
        let err = ApprovalError::TokenMismatch {
            approval_id: "apr-secret-test".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("apr-secret-test"));
        // The only variable interpolated must be the approval_id.
        // If the struct ever gains a `token` field, this test must be
        // updated to verify it is NOT included in Display output.
    }

    #[test]
    fn error_variants_are_distinguishable() {
        let errors = [
            ApprovalError::AlreadyExists {
                approval_id: "a".into(),
            },
            ApprovalError::NotFound {
                approval_id: "a".into(),
            },
            ApprovalError::AlreadyClaimed {
                approval_id: "a".into(),
            },
            ApprovalError::AlreadyCompleted {
                approval_id: "a".into(),
            },
            ApprovalError::TokenMismatch {
                approval_id: "a".into(),
            },
            ApprovalError::NotClaimed {
                approval_id: "a".into(),
            },
            ApprovalError::Unavailable("conn refused".into()),
            ApprovalError::InvalidUrl("bad".into()),
            ApprovalError::DataCorrupted("garbled".into()),
        ];

        let messages: Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
        let unique: std::collections::HashSet<&String> = messages.iter().collect();
        assert_eq!(
            unique.len(),
            messages.len(),
            "every error variant must produce a distinct message"
        );
    }

    // CompletionInfo optional fields

    #[test]
    fn completion_info_omits_none_optional_fields() {
        let c = CompletionInfo {
            completed_at: "2025-01-15T12:03:00Z".into(),
            trace_id: "trace-1".into(),
            receipt_id: None,
            deny_reason: None,
            error_code: None,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("receipt_id"));
        assert!(!json.contains("deny_reason"));
        assert!(!json.contains("error_code"));
    }

    #[test]
    fn completion_info_includes_present_optional_fields() {
        let c = CompletionInfo {
            completed_at: "2025-01-15T12:03:00Z".into(),
            trace_id: "trace-1".into(),
            receipt_id: Some("rcpt-1".into()),
            deny_reason: None,
            error_code: None,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("rcpt-1"));
        assert!(!json.contains("deny_reason"));
    }

    // validate_claim_transition

    #[test]
    fn claim_transition_pending_allowed() {
        assert!(validate_claim_transition(ApprovalState::Pending, false, None, 1000, "a").is_ok());
    }

    #[test]
    fn claim_transition_terminal_rejected() {
        for state in [
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Failed,
        ] {
            assert!(matches!(
                validate_claim_transition(state, false, None, 1000, "a"),
                Err(ApprovalError::AlreadyCompleted { .. })
            ));
        }
    }

    #[test]
    fn claim_transition_claimed_with_outcome_rejected() {
        assert!(matches!(
            validate_claim_transition(ApprovalState::Claimed, true, Some(9999), 1000, "a"),
            Err(ApprovalError::AlreadyCompleted { .. })
        ));
    }

    #[test]
    fn claim_transition_claimed_unexpired_rejected() {
        assert!(matches!(
            validate_claim_transition(ApprovalState::Claimed, false, Some(2000), 1000, "a"),
            Err(ApprovalError::AlreadyClaimed { .. })
        ));
    }

    #[test]
    fn claim_transition_claimed_expired_allowed() {
        assert!(
            validate_claim_transition(ApprovalState::Claimed, false, Some(500), 1000, "a").is_ok()
        );
    }

    #[test]
    fn claim_transition_claimed_no_expiry_rejected() {
        assert!(matches!(
            validate_claim_transition(ApprovalState::Claimed, false, None, 1000, "a"),
            Err(ApprovalError::AlreadyClaimed { .. })
        ));
    }

    // build_completion_info

    #[test]
    fn build_completion_receipt_id() {
        let c = build_completion_info("2025-01-01T00:00:00Z", "t1", "receipt_id", "r1");
        assert_eq!(c.receipt_id.as_deref(), Some("r1"));
        assert!(c.deny_reason.is_none());
    }

    #[test]
    fn build_completion_deny_reason() {
        let c = build_completion_info("2025-01-01T00:00:00Z", "t1", "deny_reason", "bad");
        assert_eq!(c.deny_reason.as_deref(), Some("bad"));
        assert!(c.receipt_id.is_none());
    }

    #[test]
    fn build_completion_empty_value_ignored() {
        let c = build_completion_info("2025-01-01T00:00:00Z", "t1", "receipt_id", "");
        assert!(c.receipt_id.is_none());
    }
}
