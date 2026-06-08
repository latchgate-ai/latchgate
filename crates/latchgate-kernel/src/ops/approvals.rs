//! Approval lifecycle management — kernel facade.
//!
//! Wraps `ApprovalStore` and `LedgerStore` approval operations so the API
//! layer never imports `latchgate-state` or constructs audit events directly.

use std::sync::Arc;

use tracing::warn;

use crate::{AppState, PipelineError};

// Re-export types the API needs for deserialization and response building.
pub use latchgate_state::approvals::{ApprovalError, ApprovalStatus, ClaimedApproval};
pub use latchgate_state::ApprovalState;

/// Map `ApprovalError` to `PipelineError`, distinguishing unavailable (503)
/// from logical not-found (404) from conflict (409=>404 for no-leak posture).
pub fn map_approval_err(e: ApprovalError) -> PipelineError {
    match e {
        ApprovalError::Unavailable(msg) => {
            PipelineError::StoreUnavailable(format!("approval store unavailable: {msg}"))
        }
        ApprovalError::AlreadyExists { approval_id } => PipelineError::Conflict {
            detail: format!("approval already exists: {approval_id}"),
        },
        ApprovalError::NotFound { approval_id } => PipelineError::ActionNotFound {
            action_id: Arc::from(format!("approval:{approval_id}")),
        },
        // SECURITY: AlreadyClaimed / AlreadyCompleted / TokenMismatch =>
        // 404 (no-leak posture). GET exposes real status to authed operators.
        ApprovalError::AlreadyClaimed { approval_id }
        | ApprovalError::AlreadyCompleted { approval_id }
        | ApprovalError::TokenMismatch { approval_id }
        | ApprovalError::NotClaimed { approval_id } => PipelineError::ActionNotFound {
            action_id: Arc::from(format!("approval:{approval_id}")),
        },
        ApprovalError::DataCorrupted(msg) => {
            PipelineError::Internal(format!("approval data corrupted: {msg}"))
        }
        ApprovalError::InvalidUrl(msg) => {
            PipelineError::Internal(format!("approval store invalid URL: {msg}"))
        }
    }
}

/// Claim a pending approval atomically. Returns the claimed approval on
/// success or a typed error.
pub async fn claim_pending(
    state: &AppState,
    approval_id: &str,
    operator_id: &str,
) -> Result<ClaimedApproval, ApprovalError> {
    state
        .enforcement
        .approval_store
        .claim_pending(approval_id, operator_id)
        .await
}

/// Get the status of an approval.
pub async fn get_status(
    state: &AppState,
    approval_id: &str,
) -> Result<Option<ApprovalStatus>, ApprovalError> {
    state
        .enforcement
        .approval_store
        .get_status(approval_id)
        .await
}

/// Get the full pending approval payload (for operator review enrichment).
pub async fn get_pending(
    state: &AppState,
    approval_id: &str,
) -> Result<Option<latchgate_state::approvals::PendingApproval>, ApprovalError> {
    state
        .enforcement
        .approval_store
        .get_pending(approval_id)
        .await
}

/// Retrieve the approval payload regardless of lifecycle state.
///
/// Used by the operator detail endpoint where plan review fields must be
/// visible throughout the approval lifecycle (pending, claimed, terminal).
pub async fn get_payload(
    state: &AppState,
    approval_id: &str,
) -> Result<Option<latchgate_state::approvals::PendingApproval>, ApprovalError> {
    state
        .enforcement
        .approval_store
        .get_payload(approval_id)
        .await
}

/// List approval summaries with optional state filter.
pub async fn list_approvals(
    state: &AppState,
    status: Option<ApprovalState>,
    limit: usize,
) -> Result<Vec<latchgate_state::approvals::ApprovalSummary>, ApprovalError> {
    state
        .enforcement
        .approval_store
        .list_approvals(status, limit)
        .await
}

/// Terminal outcome kind for approval finalization.
#[derive(Debug, Clone, Copy)]
pub enum OutcomeKind {
    Approved,
    Denied,
    Failed,
}

impl OutcomeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// Two-phase finalize: durable outcome marker + terminal state transition.
///
/// Phase 1 (critical): `write_outcome_marker` — blocks re-claim.
/// Phase 2 (best-effort): `complete_*` — full terminal state.
pub async fn finalize_outcome(
    state: &AppState,
    approval_id: &str,
    claim_token: &str,
    trace_id: &str,
    kind: OutcomeKind,
    detail: &str,
) {
    let store = &state.enforcement.approval_store;

    // Phase 1: durable outcome marker (critical).
    if let Err(e) = store
        .write_outcome_marker(approval_id, claim_token, kind.as_str(), detail)
        .await
    {
        warn!(
            trace_id = %trace_id,
            approval_id = %approval_id,
            outcome = kind.as_str(),
            error = %e,
            "CRITICAL: failed to write outcome marker — \
             re-execution risk if claim expires before terminal write"
        );
    }

    // Phase 2: full terminal state transition (best-effort).
    let complete_result = match kind {
        OutcomeKind::Approved => {
            store
                .complete_approved(approval_id, claim_token, trace_id, detail)
                .await
        }
        OutcomeKind::Denied => {
            store
                .complete_denied(approval_id, claim_token, trace_id, detail)
                .await
        }
        OutcomeKind::Failed => {
            store
                .complete_failed(approval_id, claim_token, trace_id, detail)
                .await
        }
    };
    if let Err(e) = complete_result {
        warn!(
            trace_id = %trace_id,
            approval_id = %approval_id,
            outcome = kind.as_str(),
            error = %e,
            "failed to complete approval record — outcome marker protects against re-execution"
        );
    }
}

/// Write a durable approval outcome to SQLite.
pub async fn write_durable_outcome(
    state: &AppState,
    approval_id: &str,
    outcome: &str,
    detail: &str,
) {
    let ledger = Arc::clone(&state.ledger);
    let aid = approval_id.to_string();
    let out = outcome.to_string();
    let det = detail.to_string();
    if let Err(e) =
        tokio::task::spawn_blocking(move || ledger.write_approval_outcome(&aid, &out, &det))
            .await
            .unwrap_or_else(|e| {
                Err(latchgate_ledger::LedgerError::Io(std::io::Error::other(
                    format!("{e}"),
                )))
            })
    {
        warn!(
            approval_id = %approval_id,
            error = %e,
            "failed to write durable approval outcome to SQLite"
        );
    }
}

/// Check if a durable outcome already exists in SQLite.
pub async fn has_durable_outcome(state: &AppState, approval_id: &str) -> bool {
    let ledger = Arc::clone(&state.ledger);
    let aid = approval_id.to_string();
    tokio::task::spawn_blocking(move || ledger.has_approval_outcome(&aid))
        .await
        .unwrap_or(Ok(false))
        .unwrap_or(false)
}

/// Retrieve a durable outcome for idempotent terminal responses.
///
/// Returns `(outcome, detail, completed_at)` if found.
pub async fn get_durable_outcome(
    state: &AppState,
    approval_id: &str,
) -> Option<(String, String, String)> {
    let ledger = Arc::clone(&state.ledger);
    let aid = approval_id.to_string();
    tokio::task::spawn_blocking(move || ledger.get_approval_outcome(&aid))
        .await
        .unwrap_or(Ok(None))
        .unwrap_or(None)
}

/// Typed terminal response from a durable SQLite outcome.
///
/// Used by the API layer for idempotent retry responses when the Redis
/// record has expired but a SQLite outcome exists.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DurableOutcomeResponse {
    pub decision: &'static str,
    pub approval_id: String,
    pub state: String,
    pub completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub source: &'static str,
}

/// Build a terminal response from a durable outcome.
pub fn durable_outcome_response(
    approval_id: &str,
    outcome: &str,
    detail: &str,
    completed_at: &str,
) -> DurableOutcomeResponse {
    let decision = match outcome {
        "approved" => "already_approved",
        "denied" => "already_denied",
        "failed" => "already_failed",
        _ => "already_completed",
    };
    DurableOutcomeResponse {
        decision,
        approval_id: approval_id.to_string(),
        state: outcome.to_string(),
        completed_at: completed_at.to_string(),
        receipt_id: if outcome == "approved" {
            Some(detail.to_string())
        } else {
            None
        },
        deny_reason: if outcome == "denied" {
            Some(detail.to_string())
        } else {
            None
        },
        error_code: if outcome == "failed" {
            Some(detail.to_string())
        } else {
            None
        },
        source: "durable_outcome",
    }
}

/// SQLite fallback response for `GET /v1/approvals/{id}`.
///
/// Mirrors [`DurableOutcomeResponse`] but omits the `decision` verb: a GET is
/// a status read, not an operator action, so there is no "already_*" decision
/// to report. Co-located with its builder so the durable-outcome wire shapes
/// live in one place rather than being re-derived in the API layer.
#[derive(serde::Serialize)]
pub struct DurableGetOutcomeResponse {
    pub approval_id: String,
    pub state: String,
    pub completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub source: &'static str,
}

/// Build the GET-shaped response from a durable outcome.
pub fn durable_get_outcome_response(
    approval_id: &str,
    outcome: &str,
    detail: &str,
    completed_at: &str,
) -> DurableGetOutcomeResponse {
    DurableGetOutcomeResponse {
        approval_id: approval_id.to_string(),
        state: outcome.to_string(),
        completed_at: completed_at.to_string(),
        receipt_id: (outcome == "approved").then(|| detail.to_string()),
        deny_reason: (outcome == "denied").then(|| detail.to_string()),
        error_code: (outcome == "failed").then(|| detail.to_string()),
        source: "durable_outcome",
    }
}

/// Fail an orphaned approval after detecting a durable outcome collision.
pub async fn fail_already_executed(state: &AppState, approval_id: &str, claim_token: &str) {
    let _ = state
        .enforcement
        .approval_store
        .complete_failed(approval_id, claim_token, "reconcile", "already_executed")
        .await;
}
