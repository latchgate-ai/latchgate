//! Approval endpoints: approve or deny pending action calls.
//!
//! When OPA returns `PendingApproval`, the pipeline stores the full request
//! context in Redis and returns 202 with an `approval_id`. An operator can
//! then approve or deny the request via these endpoints.
//!
//! # Security properties
//!
//! - **Atomic lifecycle**: approve and deny atomically claim the approval
//!   before executing. Parallel requests race on the claim — exactly one
//!   wins, all others get 404 (no-leak posture).
//! - **One-shot execution**: a claimed approval cannot be re-claimed until
//!   the claim TTL expires (crash recovery). Completed approvals (approved
//!   or denied) can never be re-claimed.
//! - **Request integrity**: on approve, the request hash is recomputed from
//!   the stored body and compared with the hash stored at creation time.
//! - **No re-auth**: the original Lease may have expired by the time the
//!   operator approves. Approval is a separate authorization act.
//! - **Audit trail**: both approve and deny produce audit events with full
//!   context (trace_id, action_id, principal, decision).
//! - **Forensics**: completed records remain visible via GET for
//!   `forensics_ttl` before Redis purges them.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::json_response::JsonResponse as ApiError;
use latchgate_kernel::ops::approvals::{ApprovalError, ApprovalState, OutcomeKind};
use latchgate_kernel::ops::operator_auth::OperatorAuthHeaders;
use latchgate_kernel::{AppState, PipelineError};

/// Idempotent terminal response when an approval has already been completed.
///
/// Used by both `approve_call` and `deny_call` to return a consistent
/// response when the approval has already reached a terminal state.
#[derive(Serialize)]
struct ApprovalTerminalResponse {
    decision: &'static str,
    approval_id: String,
    #[serde(rename = "status")]
    state: ApprovalState,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_reason: Option<String>,
}

#[derive(Serialize)]
struct DenyResponse {
    decision: &'static str,
    trace_id: String,
    action_id: String,
    approval_id: String,
    denied_by: String,
    deny_reason: String,
}

#[derive(Serialize)]
pub(crate) struct ApprovalListResponse {
    approvals: Vec<latchgate_state::approvals::ApprovalSummary>,
    count: usize,
}

/// Response for `GET /v1/approvals/{id}` with optional plan review enrichment.
///
/// All `Option` fields omit the key when absent (`skip_serializing_if`).
/// Lifecycle fields (claimed_by, completed_at, etc.) are absent until
/// the approval reaches that lifecycle phase. Plan enrichment fields
/// are absent when the full payload is unavailable.
#[derive(Serialize)]
struct ApprovalDetailResponse {
    approval_id: String,
    #[serde(rename = "status")]
    state: ApprovalState,
    action_id: Arc<str>,
    principal: Arc<str>,
    session_id: Arc<str>,
    request_hash: Arc<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_version: Option<Arc<str>>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    // Plan review fields — present when the full payload is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    action_version: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_level: Option<latchgate_core::RiskLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_targets: Option<Vec<Arc<str>>>,
    /// SECURITY: only secret NAMES, never values.
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_secrets: Option<Vec<Arc<str>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_egress: Option<latchgate_core::EgressProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_kind: Option<latchgate_core::VerifierKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_module_digest: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_snapshot: Option<BudgetSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database_review: Option<DatabaseReviewInfo>,
}

#[derive(Serialize)]
struct BudgetSnapshot {
    calls_remaining: i64,
    policy_approved_calls_after: i64,
}

#[derive(Serialize)]
struct DatabaseReviewInfo {
    database_mode: latchgate_kernel::ops::actions::DatabaseMode,
    statement_mode: &'static str,
    operation_class: latchgate_kernel::ops::actions::OperationClass,
    tables: Vec<String>,
    params_preview: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    statement_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_shape: Option<String>,
}

#[derive(Serialize)]
struct DurableGetOutcomeResponse {
    approval_id: String,
    #[serde(rename = "status")]
    state: String,
    completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    source: &'static str,
}

#[derive(Debug, Deserialize, Default)]
pub struct DenyBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Verify operator DPoP proof-of-possession and return the full auth context.
///
/// Used by `approve_call` and `deny_call` which return `PipelineError` and
/// need the unmodified kernel error for correct HTTP status mapping.
///
/// `list_approvals` and `get_approval` use `admin::require_operator_auth`
/// instead, which maps errors to `(StatusCode, Json<Value>)` tuples.
async fn verify_operator_dpop(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    request_method: &str,
    request_path: &str,
) -> Result<latchgate_auth::OperatorAuthContext, PipelineError> {
    let auth_headers = OperatorAuthHeaders {
        authorization: headers.get("authorization").and_then(|v| v.to_str().ok()),
        dpop: headers.get("dpop").and_then(|v| v.to_str().ok()),
    };
    latchgate_kernel::ops::operator_auth::verify(state, &auth_headers, request_method, request_path)
        .await
}

/// Re-use the kernel's approval error mapping.
fn map_approval_err(e: ApprovalError) -> PipelineError {
    latchgate_kernel::ops::approvals::map_approval_err(e)
}

/// Check SQLite for a durable approval outcome and return an idempotent
/// terminal response if one exists. Used when Redis is unavailable or has
/// lost the approval record.
async fn sqlite_outcome_response(state: &AppState, approval_id: &str) -> Option<serde_json::Value> {
    let (outcome, detail, completed_at) =
        latchgate_kernel::ops::approvals::get_durable_outcome(state, approval_id).await?;
    let resp = latchgate_kernel::ops::approvals::durable_outcome_response(
        approval_id,
        &outcome,
        &detail,
        &completed_at,
    );
    serde_json::to_value(resp).ok()
}

/// SQLite fallback for the GET /v1/approvals/{id} endpoint.
/// Returns a synthesized response from the durable outcome.
async fn sqlite_get_outcome_response(
    state: &AppState,
    approval_id: &str,
) -> Option<serde_json::Value> {
    let (outcome, detail, completed_at) =
        latchgate_kernel::ops::approvals::get_durable_outcome(state, approval_id).await?;

    let resp = DurableGetOutcomeResponse {
        approval_id: approval_id.to_string(),
        state: outcome.clone(),
        completed_at,
        receipt_id: if outcome == "approved" {
            Some(detail.clone())
        } else {
            None
        },
        deny_reason: if outcome == "denied" {
            Some(detail.clone())
        } else {
            None
        },
        error_code: if outcome == "failed" {
            Some(detail)
        } else {
            None
        },
        source: "durable_outcome",
    };
    // Convert to Value to fit the shared return path.
    serde_json::to_value(resp).ok()
}

/// Result of the claim-or-short-circuit flow.
enum ClaimOutcome {
    /// Successfully claimed the approval. Proceed with execution or denial.
    Claimed {
        pending: Box<latchgate_state::PendingApproval>,
        claim_token: String,
    },
    /// The approval already has a terminal state. Return this idempotent response.
    Terminal(Json<serde_json::Value>),
}

/// Atomically claim a pending approval with idempotent retry and SQLite fallback.
///
/// SECURITY: handles every terminal and failure case from the approval store:
/// - `AlreadyCompleted` → return the terminal status (idempotent retry).
/// - `AlreadyClaimed` → 409 Conflict (concurrent operator).
/// - `Unavailable` → check SQLite for durable outcome, else 503.
/// - `NotFound` → check SQLite for durable outcome, else 404.
///
/// After a successful claim, checks SQLite for a prior durable outcome to
/// guard against re-execution when Redis lost its terminal state (restart,
/// claim TTL expiry). This is the **single** re-execution guard for both
/// the approve and deny paths.
async fn claim_or_short_circuit(
    state: &AppState,
    approval_id: &str,
    operator_id: &str,
) -> Result<ClaimOutcome, PipelineError> {
    let claimed = match latchgate_kernel::ops::approvals::claim_pending(
        state,
        approval_id,
        operator_id,
    )
    .await
    {
        Ok(c) => c,
        Err(ApprovalError::AlreadyCompleted { .. }) => {
            // Idempotent retry: return terminal status.
            if let Ok(Some(status)) = state
                .enforcement
                .approval_store
                .get_status(approval_id)
                .await
            {
                return terminal_from_status(approval_id, status);
            }
            return Err(map_approval_err(ApprovalError::AlreadyCompleted {
                approval_id: approval_id.to_string(),
            }));
        }
        Err(ApprovalError::AlreadyClaimed { .. }) => {
            return Err(PipelineError::Conflict {
                detail: "approval already claimed — execution in progress".into(),
            });
        }
        Err(ApprovalError::Unavailable(_)) => {
            if let Some(resp) = sqlite_outcome_response(state, approval_id).await {
                return Ok(ClaimOutcome::Terminal(Json(resp)));
            }
            return Err(map_approval_err(ApprovalError::Unavailable(
                "approval store unavailable and no durable outcome found".into(),
            )));
        }
        Err(ApprovalError::NotFound { .. }) => {
            if let Some(resp) = sqlite_outcome_response(state, approval_id).await {
                return Ok(ClaimOutcome::Terminal(Json(resp)));
            }
            return Err(map_approval_err(ApprovalError::NotFound {
                approval_id: approval_id.to_string(),
            }));
        }
        Err(e) => return Err(map_approval_err(e)),
    };

    // SECURITY: guard against acting on an already-executed approval when
    // Redis lost its terminal state but the claim succeeded because Redis
    // no longer remembers the approval was completed.
    let already_executed =
        latchgate_kernel::ops::approvals::has_durable_outcome(state, approval_id).await;

    if already_executed {
        latchgate_kernel::ops::approvals::fail_already_executed(
            state,
            approval_id,
            &claimed.claim_token,
        )
        .await;
        return Err(PipelineError::Conflict {
            detail: "approval already executed (durable outcome exists)".into(),
        });
    }

    Ok(ClaimOutcome::Claimed {
        pending: Box::new(claimed.pending),
        claim_token: claimed.claim_token,
    })
}

/// Build an idempotent terminal response from an existing approval status.
fn terminal_from_status(
    approval_id: &str,
    status: latchgate_state::ApprovalStatus,
) -> Result<ClaimOutcome, PipelineError> {
    let resp = serde_json::to_value(ApprovalTerminalResponse {
        decision: match status.state {
            ApprovalState::Approved => "already_approved",
            ApprovalState::Denied => "already_denied",
            ApprovalState::Failed => "already_failed",
            _ => "already_completed",
        },
        approval_id: approval_id.to_string(),
        state: status.state,
        completed_at: status.completed_at,
        receipt_id: status.receipt_id,
        deny_reason: status.deny_reason,
    })
    .map_err(|e| PipelineError::Internal(format!("failed to serialize terminal response: {e}")))?;
    Ok(ClaimOutcome::Terminal(Json(resp)))
}

/// Write a durable outcome to SQLite and finalize the approval in Redis.
///
/// Two-phase protocol: SQLite first (crash-safe authority), then Redis
/// terminal state transition. See `finalize_outcome` for the two-phase
/// protocol details.
async fn write_outcome_and_finalize(
    state: &AppState,
    approval_id: &str,
    claim_token: &str,
    trace_id: &str,
    kind: OutcomeKind,
    detail: &str,
) {
    let outcome_str = match kind {
        OutcomeKind::Approved => "approved",
        OutcomeKind::Denied => "denied",
        OutcomeKind::Failed => "failed",
    };
    latchgate_kernel::ops::approvals::write_durable_outcome(
        state,
        approval_id,
        outcome_str,
        detail,
    )
    .await;
    latchgate_kernel::ops::approvals::finalize_outcome(
        state,
        approval_id,
        claim_token,
        trace_id,
        kind,
        detail,
    )
    .await;
}

/// Query parameters for `POST /v1/approvals/{id}/approve`.
#[derive(serde::Deserialize, Default)]
pub struct ApproveQuery {
    /// Domain to learn for future use by this action's egress allowlist.
    pub learn_domain: Option<String>,
    /// Filesystem path glob to learn for future use by this action's
    /// `allowed_paths`. Validated by `validate_path_glob` before persistence.
    pub learn_path: Option<String>,
}

/// Validate the `learn_domain` query parameter.
///
/// SECURITY: called BEFORE claiming the approval so invalid input gets a
/// clean 400 without side effects (no execution, no claim). The ledger
/// also validates (defense in depth), but catching it here produces a
/// clean API error instead of a post-execution warning.
///
/// Path validation is deferred to [`resolve_learn_path`] because absolute
/// paths from the agent must be relativized against the session's `fs_root`
/// (which requires the pending approval's `session_id`, available only
/// after the claim).
fn validate_learn_domain(query: &ApproveQuery) -> Result<(), PipelineError> {
    if let Some(ref domain) = query.learn_domain {
        if let Err(e) = latchgate_core::net::validate_domain_entry(domain, false) {
            return Err(PipelineError::BadRequest {
                reason: format!("invalid learn_domain '{domain}': {e}"),
            });
        }
    }
    Ok(())
}

/// Resolve the effective learn path, relativizing absolute paths against
/// the session's filesystem root.
///
/// The agent's request body contains absolute file paths (e.g.
/// `/home/user/projects/foo/AGENTS.md`). Learned path globs are stored
/// relative to the session's `fs_root` (e.g. `projects/foo/AGENTS.md`).
/// This function bridges the gap.
///
/// Precedence: explicit `learn_path` query param > first unresolved path
/// from the pending approval > `None`.
///
/// SECURITY:
/// - Absolute paths MUST be under `session_fs_root`; paths outside the
///   agent's containment boundary are rejected.
/// - Absolute paths without a configured `session_fs_root` are rejected
///   (no root to relativize against).
/// - The returned path is validated by `validate_path_glob_entry` after
///   this function returns.
fn resolve_learn_path(
    explicit: Option<&str>,
    fallback: Option<&str>,
    session_fs_root: Option<&std::path::Path>,
) -> Result<Option<String>, PipelineError> {
    let raw = match explicit.or(fallback) {
        Some(p) => p,
        None => return Ok(None),
    };

    let path = std::path::Path::new(raw);
    if !path.is_absolute() {
        // Already relative — pass through for glob validation.
        return Ok(Some(raw.to_owned()));
    }

    // Absolute path: must relativize against session fs_root.
    let root = session_fs_root.ok_or_else(|| PipelineError::BadRequest {
        reason: format!("learn_path '{raw}' is absolute but no session fs_root is configured"),
    })?;

    latchgate_core::fs_path::relativize_to_root(raw, root)
        .ok_or_else(|| PipelineError::BadRequest {
            reason: format!(
                "learn_path '{raw}' is not under session fs_root '{}'",
                root.display()
            ),
        })
        .map(Some)
}

/// Persist a learned domain after successful execution.
///
/// SECURITY: only called when execution succeeded. A failed execution does
/// not teach the system — the operator must re-approve.
async fn persist_learned_domain(
    state: &AppState,
    action_id: &str,
    approval_id: &str,
    operator_id: &str,
    domain: &str,
) -> Option<String> {
    match latchgate_kernel::ops::domains::add(
        state,
        action_id,
        domain,
        operator_id,
        latchgate_kernel::ops::domains::DomainAddSource::Approval,
        Some(approval_id),
    )
    .await
    {
        Ok(_) => {
            info!(
                approval_id = %approval_id,
                action_id = %action_id,
                domain = %domain,
                "learned domain persisted via approval"
            );
            Some(domain.to_string())
        }
        Err(e) => {
            warn!(
                approval_id = %approval_id,
                domain = %domain,
                error = %e,
                "failed to persist learned domain — approval succeeded but domain not saved"
            );
            None
        }
    }
}

/// Persist a learned path glob after successful execution.
///
/// SECURITY: only called when execution succeeded. The path glob is
/// validated by `validate_path_glob_entry` before this function is called.
async fn persist_learned_path(
    state: &AppState,
    action_id: &str,
    approval_id: &str,
    operator_id: &str,
    path_glob: &str,
) -> Option<String> {
    match latchgate_kernel::ops::paths::add(
        state,
        action_id,
        path_glob,
        operator_id,
        latchgate_kernel::ops::paths::PathAddSource::Approval,
        Some(approval_id),
    )
    .await
    {
        Ok(_) => {
            info!(
                approval_id = %approval_id,
                action_id = %action_id,
                path_glob = %path_glob,
                "learned path persisted via approval"
            );
            Some(path_glob.to_string())
        }
        Err(e) => {
            warn!(
                approval_id = %approval_id,
                path_glob = %path_glob,
                error = %e,
                "failed to persist learned path — approval succeeded but path not saved"
            );
            None
        }
    }
}

/// Sync live egress allowlist after domain learning.
async fn sync_egress_if_needed(state: &AppState) {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let registry = state.registry.load();
        match latchgate_embed::egress_sync::sync(&state.config, &registry, &state.ledger) {
            Ok(latchgate_embed::egress_sync::SyncOutcome::Written { domain_count, path }) => {
                info!(
                    path = %path,
                    domain_count = domain_count,
                    "live egress allowlist synced after domain learning"
                );
            }
            Ok(latchgate_embed::egress_sync::SyncOutcome::Disabled) => {}
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to sync live egress allowlist after domain learning"
                );
            }
        }
    })
    .await
    .ok();
}

/// SECURITY: does NOT re-authenticate (Lease may have expired). The operator's
/// approve action is the authorization. The original principal, session, and
/// trace are preserved in the audit trail.
#[tracing::instrument(
    name = "pipeline.approve",
    skip(state, headers, query),
    fields(approval_id = %approval_id),
)]
pub async fn approve_call(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<ApproveQuery>,
) -> Result<Json<serde_json::Value>, PipelineError> {
    // SECURITY: operator must authenticate before approving.
    let operator_ctx = verify_operator_dpop(
        &state,
        &headers,
        "POST",
        &format!("/v1/approvals/{approval_id}/approve"),
    )
    .await?;
    let operator_id = operator_ctx.operator_id.clone();
    let operator_authn_method = operator_ctx.authn_method;

    if state.draining() {
        return Err(PipelineError::Draining);
    }

    if !state.config.dev_mode() && !state.lifecycle.operator_rate_limiter.check() {
        return Err(PipelineError::Throttled {
            scope: "operator_write",
        });
    }

    validate_learn_domain(&query)?;

    // SECURITY: atomically claim with idempotent retry + durable outcome guard.
    let (pending, claim_token) =
        match claim_or_short_circuit(&state, &approval_id, &operator_id).await? {
            ClaimOutcome::Claimed {
                pending,
                claim_token,
            } => (pending, claim_token),
            ClaimOutcome::Terminal(resp) => return Ok(resp),
        };

    // SECURITY: fresh trace_id — the original was consumed by the
    // PendingApproval audit event, and audit_events has UNIQUE(trace_id).
    let trace_id = latchgate_core::TraceId::new().to_string();
    let pipeline_start = Instant::now();

    // Kernel enforcement: all security checks + AuthorizedExecution build.
    let operator = latchgate_kernel::OperatorContext {
        operator_id: operator_id.clone(),
        authn_method: operator_authn_method,
        sender_binding: operator_ctx.sender_binding.clone(),
        proof_jti: operator_ctx.proof_jti.clone(),
    };

    // Persist learned domain/path BEFORE execution so that
    // `resolve_effective_sinks` (called inside `prepare_approved_execution`)
    // finds the newly-learned entry via the in-memory cache.
    //
    // SECURITY: the operator's approval IS the authorization. Persisting
    // the learned entry before execution is correct — the operator already
    // reviewed the domain/path. If execution fails for an unrelated reason
    // (timeout, provider bug), the domain remains learned, which matches
    // the operator's intent and avoids a chicken-and-egg deadlock where
    // execution needs the domain to succeed but the domain needs execution
    // to succeed.
    //
    // Auto-learn: when the caller does not specify `learn_domain` / `learn_path`
    // explicitly, fall back to the unresolved entries stored in the pending
    // approval. The operator approved THIS request — the domains/paths that
    // caused the hold are exactly the ones that should be learned.
    let effective_domain: Option<Cow<'_, str>> = match &query.learn_domain {
        Some(d) => Some(Cow::Borrowed(d.as_str())),
        None => pending
            .unresolved_domains
            .first()
            .map(|d| Cow::Owned(d.clone())),
    };

    // Resolve + relativize the learn path against the session's fs_root.
    //
    // SECURITY: the agent sends absolute file paths (e.g.
    // `/home/user/projects/foo/README.md`) but learned path globs must be
    // relative. Absolute paths are stripped of the session's fs_root prefix
    // so the glob stays within the agent's containment boundary. Paths
    // outside the fs_root or absolute paths without a configured root are
    // rejected.
    let session_fs_root: Option<std::path::PathBuf> = state
        .runtime
        .session_fs_roots
        .get(&*pending.auth_context.session_id)
        .map(|entry| entry.canonical.clone());
    let effective_path: Option<String> = resolve_learn_path(
        query.learn_path.as_deref(),
        pending.unresolved_paths.first().map(String::as_str),
        session_fs_root.as_deref(),
    )?;

    // Validate the (now-relative) path glob.
    if let Some(ref path_glob) = effective_path {
        if let Err(e) = latchgate_core::fs_path::validate_path_glob_entry(path_glob) {
            return Err(PipelineError::BadRequest {
                reason: format!("invalid learn_path '{path_glob}': {e}"),
            });
        }
    }

    let mut learned_domain = None;
    let mut learned_path = None;
    if let Some(ref domain) = effective_domain {
        learned_domain = persist_learned_domain(
            &state,
            &pending.action_id,
            &approval_id,
            &operator_id,
            domain,
        )
        .await;
    }
    if let Some(ref path_glob) = effective_path {
        learned_path = persist_learned_path(
            &state,
            &pending.action_id,
            &approval_id,
            &operator_id,
            path_glob,
        )
        .await;
    }
    if learned_domain.is_some() {
        sync_egress_if_needed(&state).await;
    }

    // SECURITY: both prepare and execute failures must transition the
    // approval to terminal `failed` state. Without this, a prepare failure
    // (e.g. module not found, trust mismatch) leaves the approval in
    // `claimed` state — blocking idempotent retry and preventing the
    // operator from seeing the terminal status.
    let exec_ctx = match latchgate_kernel::prepare_approved_execution(
        &state,
        &pending,
        &operator,
        &approval_id,
        &trace_id,
        pipeline_start,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(e) => {
            write_outcome_and_finalize(
                &state,
                &approval_id,
                &claim_token,
                &trace_id,
                OutcomeKind::Failed,
                &format!("{e}"),
            )
            .await;
            return Err(e);
        }
    };

    let result = latchgate_kernel::execute_authorized_plan(&state, exec_ctx).await;

    // Two-phase durable outcome: SQLite then Redis.
    {
        let (kind, detail) = match &result {
            Ok(resp) => (OutcomeKind::Approved, resp.receipt_id.to_string()),
            Err(ref e) => (OutcomeKind::Failed, format!("{e}")),
        };
        write_outcome_and_finalize(&state, &approval_id, &claim_token, &trace_id, kind, &detail)
            .await;
    }

    match result {
        Ok(mut response) => {
            response.learned_domain = learned_domain;
            response.learned_path = learned_path;
            let value = serde_json::to_value(&response).map_err(|e| {
                PipelineError::Internal(format!("failed to serialize execution response: {e}"))
            })?;
            Ok(Json(value))
        }
        Err(e) => Err(e),
    }
}

/// Deny a pending action call. The action is NOT executed.
///
/// Atomically claims and denies the approval. The record stays in Redis
/// for `forensics_ttl` so operators can query its status.
#[tracing::instrument(
    name = "pipeline.deny_approval",
    skip(state, headers, body),
    fields(approval_id = %approval_id),
)]
pub async fn deny_call(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    body: Option<Json<DenyBody>>,
) -> Result<Json<serde_json::Value>, PipelineError> {
    // SECURITY: operator must authenticate before denying.
    let operator_ctx = verify_operator_dpop(
        &state,
        &headers,
        "POST",
        &format!("/v1/approvals/{approval_id}/deny"),
    )
    .await?;
    let operator_id = operator_ctx.operator_id.clone();
    let operator_authn_method = operator_ctx.authn_method;

    // NOTE: no `state.draining()` guard here — intentional. Unlike
    // `approve_call`, denials never dispatch WASM providers, so they are
    // safe to accept during graceful shutdown. Allowing denials to drain
    // prevents pending approvals from timing out while the instance is
    // shutting down.
    if !state.config.dev_mode() && !state.lifecycle.operator_rate_limiter.check() {
        return Err(PipelineError::Throttled {
            scope: "operator_write",
        });
    }

    // SECURITY: atomically claim with idempotent retry + durable outcome guard.
    let (pending, claim_token) =
        match claim_or_short_circuit(&state, &approval_id, &operator_id).await? {
            ClaimOutcome::Claimed {
                pending,
                claim_token,
            } => (pending, claim_token),
            ClaimOutcome::Terminal(resp) => return Ok(resp),
        };

    let reason = body
        .and_then(|b| b.reason.clone())
        .unwrap_or_else(|| "operator_denied".to_string());

    // Audit: denied by operator.
    let deny_trace_id = latchgate_core::TraceId::new().to_string();
    latchgate_kernel::ops::audit::write_approval_deny_audit(
        &state,
        latchgate_kernel::ops::audit::ApprovalDenyAudit {
            trace_id: deny_trace_id.clone(),
            principal: pending.auth_context.principal.clone(),
            session_id: pending.auth_context.session_id.clone(),
            lease_jti: pending.auth_context.lease_jti.clone(),
            action_id: pending.action_id.clone(),
            request_hash: pending.request_hash.clone(),
            policy_version: pending.policy_version.clone(),
            approval_id: approval_id.clone(),
            reason: reason.clone(),
            operator_id: operator_id.clone(),
            operator_authn_method,
            sender_binding: Some(operator_ctx.sender_binding.clone()),
            proof_jti: Some(operator_ctx.proof_jti.clone()),
            risk_level: Some(pending.plan.risk_level.as_str().to_owned()),
        },
    )
    .await;

    state.metrics.record_call(&pending.action_id, "deny");
    state.metrics.record_policy_decision("deny");

    // Two-phase durable outcome: SQLite then Redis.
    write_outcome_and_finalize(
        &state,
        &approval_id,
        &claim_token,
        &deny_trace_id,
        OutcomeKind::Denied,
        &reason,
    )
    .await;

    info!(
        trace_id = %pending.trace_id,
        action_id = %pending.action_id,
        approval_id = %approval_id,
        reason = %reason,
        "approval denied by operator"
    );

    state.emit(latchgate_core::DomainEvent::ApprovalDenied {
        approval_id: Arc::from(approval_id.as_str()),
        action_id: pending.action_id.clone(),
        denied_by: Arc::clone(&operator_id),
        reason: Arc::from(reason.as_str()),
        trace_id: pending.trace_id.clone(),
    });

    Ok(Json(
        serde_json::to_value(DenyResponse {
            decision: "deny",
            trace_id: pending.trace_id.to_string(),
            action_id: pending.action_id.to_string(),
            approval_id: approval_id.clone(),
            denied_by: operator_id.to_string(),
            deny_reason: reason,
        })
        .map_err(|e| PipelineError::Internal(format!("failed to serialize deny response: {e}")))?,
    ))
}

/// Query parameters for `GET /v1/approvals`.
#[derive(Debug, Deserialize, Default)]
pub struct ListApprovalsQuery {
    /// Filter by lifecycle state: `pending`, `claimed`, `approved`, `denied`, `failed`.
    /// If omitted, all non-expired approvals are returned.
    #[serde(default)]
    pub status: Option<ApprovalState>,

    /// Maximum number of results to return. Default 50, capped at 200.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// List approvals visible to the operator.
///
/// Returns a bounded, newest-first list of approval summaries. Supports
/// optional state filtering via `?status=pending`. Each summary contains
/// enough context for an operator to identify and prioritize work without
/// fetching the full detail view.
///
/// # Security
///
/// Requires operator authentication. This is a read-only operation.
#[tracing::instrument(name = "api.list_approvals", skip(state, headers, params))]
pub async fn list_approvals(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ListApprovalsQuery>,
) -> Result<Json<ApprovalListResponse>, ApiError> {
    let _operator_ctx =
        crate::admin::require_operator_auth(&state, &headers, "GET", "/v1/approvals").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let limit = params.limit.unwrap_or(50).min(200);

    let summaries = latchgate_kernel::ops::approvals::list_approvals(&state, params.status, limit)
        .await
        .map_err(|e| {
            warn!(error = %e, "list_approvals: store error");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_store_unavailable",
            )
        })?;

    let count = summaries.len();
    Ok(Json(ApprovalListResponse {
        approvals: summaries,
        count,
    }))
}

/// Build database-specific review data from the pending approval's plan.
///
/// Returns `None` when the plan has no `database_config` or when the
/// stored config cannot be deserialized (graceful degradation).
fn build_database_review(pending: &latchgate_state::PendingApproval) -> Option<DatabaseReviewInfo> {
    let config_value = pending.plan.database_config.as_deref()?;
    let db_config = serde_json::from_value::<latchgate_kernel::ops::actions::DatabaseConfig>(
        config_value.clone(),
    )
    .ok()?;

    use latchgate_kernel::ops::actions::*;

    let statement_id = pending
        .request_body
        .get("statement_id")
        .and_then(|v| v.as_str());
    let query = pending.request_body.get("query").and_then(|v| v.as_str());
    let params: Vec<String> = pending
        .request_body
        .get("params")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();

    let (sql, stmt_mode, resolved_id): (String, &'static str, Option<&str>) =
        if let Some(sid) = statement_id {
            match db_config.resolve_statement(sid) {
                Some(stmt) => (stmt.sql.clone(), "predeclared", Some(sid)),
                None => (String::new(), "predeclared", Some(sid)),
            }
        } else if let Some(q) = query {
            (q.to_string(), "parameterized", None)
        } else {
            (String::new(), "unknown", None)
        };

    let op = if sql.is_empty() {
        OperationClass::Unknown
    } else {
        classify_sql(&sql)
    };
    let tables = if sql.is_empty() {
        vec![]
    } else {
        extract_tables(&sql)
    };

    // Redact long/suspicious param values for review.
    let params_preview: Vec<String> = params
        .iter()
        .map(|p| {
            if p.len() <= 32
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                p.clone()
            } else {
                format!("[{} chars]", p.len())
            }
        })
        .collect();

    Some(DatabaseReviewInfo {
        database_mode: db_config.mode,
        statement_mode: stmt_mode,
        operation_class: op,
        tables,
        params_preview,
        statement_id: resolved_id.map(str::to_string),
        query_shape: if stmt_mode == "parameterized" && !sql.is_empty() {
            Some(sql)
        } else {
            None
        },
    })
}

/// Enrich an `ApprovalDetailResponse` with plan review fields from the
/// pending approval's immutable plan.
fn enrich_with_plan(resp: &mut ApprovalDetailResponse, pending: &latchgate_state::PendingApproval) {
    resp.action_version = Some(Arc::clone(&pending.plan.action_version));
    resp.risk_level = Some(pending.plan.risk_level);
    resp.approved_targets = Some(pending.plan.core.approved_targets.clone());
    resp.approved_secrets = Some(pending.plan.core.approved_secrets.clone());
    resp.approved_egress = Some(pending.plan.core.approved_egress.clone());
    resp.verifier_kind = Some(pending.plan.verifier_kind);
    resp.provider_module_digest = Some(Arc::clone(&pending.plan.core.provider_module_digest));
    resp.plan_hash = Some(pending.plan.plan_hash.clone());
    resp.expires_at = Some(pending.plan.core.expires_at.to_rfc3339());
    resp.unresolved_domains = if pending.unresolved_domains.is_empty() {
        None
    } else {
        Some(pending.unresolved_domains.clone())
    };
    resp.unresolved_paths = if pending.unresolved_paths.is_empty() {
        None
    } else {
        Some(pending.unresolved_paths.clone())
    };
    resp.budget_snapshot = Some(BudgetSnapshot {
        calls_remaining: pending.plan.budget_calls_remaining,
        policy_approved_calls_after: pending.plan.policy_approved_calls_after,
    });
    resp.database_review = build_database_review(pending);
}

/// Get the full detail of an approval for operator review.
///
/// Returns lifecycle metadata (state, claimed_by, completed_at) alongside
/// the immutable execution plan fields that the operator needs to make a
/// safe approval decision. Plan fields reflect the state at decision time,
/// not the current live manifest.
///
/// # Review fields from the immutable plan
///
/// - `action_version`, `risk_level` — what was evaluated
/// - `approved_targets` — which sinks will be contacted
/// - `approved_secrets` — which secret names will be injected (names only, never values)
/// - `approved_egress` — network egress profile
/// - `budget_snapshot` — calls/cost remaining at plan creation
/// - `expires_at` — when the plan expires
/// - `verifier_kind` — how the effect will be verified
/// - `provider_module_digest` — exact WASM binary hash
/// - `plan_hash` — tamper-evident hash of the entire plan
///
/// SECURITY: secret values are never returned. Only secret names are
/// exposed so the operator knows which credentials will be used.
#[tracing::instrument(name = "api.get_approval", skip(state, headers), fields(%approval_id))]
pub async fn get_approval(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // SECURITY: operator must authenticate to view pending approvals.
    crate::admin::require_operator_auth(
        &state,
        &headers,
        "GET",
        &format!("/v1/approvals/{approval_id}"),
    )
    .await
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Fetch lifecycle metadata. If Redis is unavailable or the key expired,
    // fall back to the durable SQLite outcome (if one exists).
    let status = match latchgate_kernel::ops::approvals::get_status(&state, &approval_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            if let Some(resp) = sqlite_get_outcome_response(&state, &approval_id).await {
                return Ok(Json(resp));
            }
            return Err(StatusCode::NOT_FOUND);
        }
        Err(e) => {
            warn!(approval_id = %approval_id, error = %e, "get_approval: store error");
            if let Some(resp) = sqlite_get_outcome_response(&state, &approval_id).await {
                return Ok(Json(resp));
            }
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // Fetch full payload for plan review data. Unlike get_pending (which
    // filters by state == "pending"), get_payload returns the plan for any
    // lifecycle state so the operator can review risk_level, targets, etc.
    // even while the approval is claimed or after resolution.
    let pending = latchgate_kernel::ops::approvals::get_payload(&state, &approval_id)
        .await
        .map_err(|e| {
            warn!(approval_id = %approval_id, error = %e, "get_approval: payload fetch error");
            StatusCode::SERVICE_UNAVAILABLE
        })?;

    let mut response = ApprovalDetailResponse {
        approval_id: status.approval_id,
        state: status.state,
        action_id: status.action_id,
        principal: status.principal,
        session_id: status.session_id,
        request_hash: status.request_hash,
        policy_version: status.policy_version,
        created_at: status.created_at,
        claimed_by: status.claimed_by,
        claimed_at: status.claimed_at,
        completed_at: status.completed_at,
        receipt_id: status.receipt_id,
        deny_reason: status.deny_reason,
        error_code: status.error_code,
        action_version: None,
        risk_level: None,
        approved_targets: None,
        approved_secrets: None,
        approved_egress: None,
        verifier_kind: None,
        provider_module_digest: None,
        plan_hash: None,
        expires_at: None,
        unresolved_domains: None,
        unresolved_paths: None,
        budget_snapshot: None,
        database_review: None,
    };

    if let Some(ref p) = pending {
        enrich_with_plan(&mut response, p);
    }

    serde_json::to_value(response)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Lightweight approval status response for agent polling.
///
/// Contains only lifecycle state. On terminal states (approved, denied,
/// failed), includes the relevant detail field. The agent re-executes
/// the action after approval to get fresh output under its own grant.
///
/// SECURITY: no plan detail, no request body, no policy info.
#[derive(Serialize)]
pub(crate) struct ApprovalPollResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
}

/// Agent-accessible approval polling endpoint.
///
/// Uses agent DPoP auth (not operator auth). Validates that the caller's
/// session_id matches the approval's session_id — agents can only poll
/// their own approvals.
///
/// Returns minimal lifecycle data. On `approved`, includes the receipt_id
/// from the operator's execution. The agent re-executes the action to get
/// fresh output under its own grant (the domain/path was learned during
/// approval, so re-execution auto-allows).
#[tracing::instrument(name = "api.poll_approval", skip(state, headers))]
pub async fn poll_approval_status(
    State(state): State<AppState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ApprovalPollResponse>, StatusCode> {
    // Agent DPoP auth — same mechanism as action_call.
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
    let dpop = headers.get("dpop").and_then(|v| v.to_str().ok());
    let request_path = format!("/v1/approvals/{approval_id}/poll");

    // SECURITY: htu must be the full URI (scheme + authority + path), not a
    // bare path. The MCP adapter signs its DPoP proof against the full URI
    // (`{public_base_url}/v1/approvals/{id}/poll`); the server must match.
    // Mirrors the pattern in `operator_auth::verify`.
    let htu = format!(
        "{}{}",
        state.config.listener.public_base_url.trim_end_matches('/'),
        request_path,
    );

    let auth_ctx = latchgate_auth::authenticate(
        authorization,
        dpop,
        "GET",
        &htu,
        state.auth.issuer.jwks(),
        &state.auth.replay_cache,
        &state.auth.dpop_key_cache,
    )
    .await
    .map_err(|e| {
        warn!(error = %e, "poll_approval: agent auth failed");
        StatusCode::UNAUTHORIZED
    })?;

    // Fetch approval status from Redis.
    let status = match latchgate_kernel::ops::approvals::get_status(&state, &approval_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            warn!(approval_id = %approval_id, error = %e, "poll_approval: store error");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // SECURITY: agents may only poll their own approvals.
    if *auth_ctx.session_id != *status.session_id {
        warn!(
            caller_session = %auth_ctx.session_id,
            approval_session = %status.session_id,
            approval_id = %approval_id,
            "poll_approval: session_id mismatch"
        );
        return Err(StatusCode::NOT_FOUND);
    }

    let response = match status.state {
        latchgate_state::ApprovalState::Pending => ApprovalPollResponse {
            status: "pending",
            receipt_id: None,
            reason: None,
            retry_after_seconds: Some(2),
        },
        latchgate_state::ApprovalState::Claimed => ApprovalPollResponse {
            status: "pending",
            receipt_id: None,
            reason: None,
            retry_after_seconds: Some(1),
        },
        latchgate_state::ApprovalState::Approved => ApprovalPollResponse {
            status: "approved",
            receipt_id: status.receipt_id,
            reason: None,
            retry_after_seconds: None,
        },
        latchgate_state::ApprovalState::Denied => ApprovalPollResponse {
            status: "denied",
            receipt_id: None,
            reason: status.deny_reason.or(Some("no reason provided".into())),
            retry_after_seconds: None,
        },
        latchgate_state::ApprovalState::Failed => ApprovalPollResponse {
            status: "failed",
            receipt_id: None,
            reason: status.error_code.or(Some("execution_failed".into())),
            retry_after_seconds: None,
        },
    };

    Ok(Json(response))
}

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::module_inception)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{
        body_json, operator_headers, redis_available, test_redis_url, test_state,
        test_state_with_operator, TEST_OPERATOR_KEY,
    };

    /// Helper: produce DPoP auth headers for a given method and path.
    fn auth(method: &str, path: &str) -> (String, String) {
        operator_headers(method, path)
    }

    /// Helper: build a minimal valid `ApprovedExecutionPlan` for tests.
    fn test_plan() -> latchgate_core::ApprovedExecutionPlan {
        let expires = chrono::Utc::now() + chrono::Duration::minutes(5);
        let mut plan = latchgate_core::ApprovedExecutionPlan {
            core: latchgate_core::ExecutionPlanCore {
                action_id: "http_fetch".into(),
                action_digest:
                    "sha256:f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0".into(),
                provider_module_digest:
                    "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
                request_hash: "sha256:test".into(),
                approved_targets: vec![],
                approved_secrets: vec![],
                approved_egress: latchgate_core::EgressProfile::None,
                policy_version: Some("v1".into()),
                expires_at: expires,
            },
            action_version: "1.0.0".into(),
            required_imports: vec![],
            resource_limits: latchgate_core::ResourceLimits::default(),
            verifier_kind: latchgate_core::VerifierKind::None,
            verification_config: None,
            risk_level: latchgate_core::RiskLevel::Low,
            max_response_bytes: 1024 * 1024,
            secret_declarations: vec![],
            budget_calls_remaining: i64::MAX,
            policy_approved_calls_after: i64::MAX - 1,
            trust_verdict: std::sync::Arc::new(latchgate_core::TrustVerdict::DigestOk),
            database_config: None,
            fs: None,
            plan_hash: String::new(),
        };
        plan.finalize();
        plan
    }

    #[tokio::test]
    async fn approve_without_auth_returns_401() {
        let app = crate::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approvals/any-id/approve")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deny_without_auth_returns_401() {
        let app = crate::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approvals/any-id/deny")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_approval_without_auth_returns_401() {
        let app = crate::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/approvals/any-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn approve_with_wrong_key_returns_401() {
        let app = crate::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approvals/any-id/approve")
                    .header("authorization", "DPoP wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn approve_with_invalid_scheme_returns_401() {
        let app = crate::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approvals/any-id/approve")
                    .header("authorization", format!("Basic {TEST_OPERATOR_KEY}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Redis down => 503 (fail-closed, not 500).
    #[tokio::test]
    async fn get_approval_redis_down_returns_503() {
        use crate::test_support::TEST_OPERATOR;
        let config = latchgate_config::Config {
            operator_credentials: std::collections::HashMap::from([(
                "test-operator".to_string(),
                TEST_OPERATOR.credential(),
            )]),
            ..latchgate_config::Config::default()
        };
        let issuer = latchgate_auth::issuer::Issuer::new(
            config.policy.lease_ttl_seconds,
            latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
        )
        .unwrap();
        // Point approval store to a dead Redis.
        let state = latchgate_kernel::AppState::new(latchgate_kernel::AppStateInit {
            config: config.clone(),
            registry: latchgate_registry::RegistryStore::empty(),
            embedded_manifests: vec![],
            ledger: latchgate_ledger::LedgerStore::open_in_memory(None).unwrap(),
            metrics: latchgate_ledger::Metrics::new().unwrap(),
            auth: latchgate_kernel::AuthServicesInit {
                issuer,
                replay_cache: latchgate_auth::ReplayCache::in_memory(
                    std::time::Duration::from_secs(180),
                ),
                identity_provider: Box::new(latchgate_auth::identity::NoneProvider),
            },
            crypto: latchgate_kernel::CryptoServicesInit {
                receipt_signer: latchgate_crypto::ReceiptSigner::generate(),
                grant_signer: latchgate_crypto::GrantSigner::generate(),
                verifying_key_store: latchgate_crypto::VerifyingKeyStore::single(
                    &latchgate_crypto::ReceiptSigner::generate(),
                ),
            },
            enforcement: latchgate_kernel::EnforcementServicesInit {
                policy: latchgate_policy::PolicyClient::new(
                    config
                        .policy
                        .opa_url
                        .as_deref()
                        .unwrap_or("http://127.0.0.1:8181"),
                    std::time::Duration::from_millis(
                        latchgate_core::security_constants::OPA_TIMEOUT_MS,
                    ),
                ),
                budget_manager: latchgate_state::BudgetManager::in_memory_for_tests(),
                approval_store: latchgate_state::approvals::ApprovalStore::new(
                    "redis://127.0.0.1:1",
                    std::time::Duration::from_secs(300),
                )
                .unwrap(),
            },
            runtime: latchgate_kernel::RuntimeServicesInit {
                wasm_runtime: latchgate_providers::WasmRuntime::new(4).expect("WASM runtime init"),
                secrets_manager: latchgate_providers::SecretsManager::new("sops", None),
                verifier_registry: latchgate_kernel::VerifierRegistry::new(),
                fs_root_fd: None,
                fs_root_canonical: None,
                session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
            },
            lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
        });

        let (authz, dpop) = auth("GET", "/v1/approvals/any-id");
        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/approvals/any-id")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "approval store down must return 503, not 500"
        );
    }

    #[tokio::test]
    async fn approval_lifecycle_deny() {
        let state = test_state();
        let approval_id = uuid::Uuid::now_v7().to_string();

        let pending = latchgate_state::approvals::PendingApproval {
            approval_id: approval_id.clone(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: "http_fetch".into(),
            auth_context: latchgate_state::approvals::StoredAuthContext {
                principal: "agent-test".into(),
                session_id: "sess-lifecycle".into(),
                lease_jti: "jti-lifecycle".into(),
                sender_thumbprint: "thumb-test".into(),
                owner: None,
            },
            request_hash: "sha256:test".into(),
            request_body: std::sync::Arc::new(serde_json::json!({"url": "https://example.com"})),
            policy_version: Some("v1".into()),
            created_at: chrono::Utc::now().to_rfc3339(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        };
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        // GET — should find it.
        let (authz, dpop) = auth("GET", &format!("/v1/approvals/{approval_id}"));
        let resp = crate::router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/v1/approvals/{approval_id}"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["approval_id"], approval_id);
        assert_eq!(json["action_id"], "http_fetch");
        // SECURITY: request_body must NOT be exposed in GET.
        assert!(json.get("request_body").is_none());

        // DENY
        let (authz, dpop) = auth("POST", &format!("/v1/approvals/{approval_id}/deny"));
        let resp = crate::router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{approval_id}/deny"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"reason": "test deny"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["deny_reason"], "test deny");

        // GET after deny — record stays visible for forensics.
        let (authz, dpop) = auth("GET", &format!("/v1/approvals/{approval_id}"));
        let resp = crate::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/v1/approvals/{approval_id}"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(
            json["status"], "denied",
            "completed records show terminal state"
        );
    }

    /// Deny produces an audit event.
    #[tokio::test]
    async fn deny_writes_audit_event() {
        let state = test_state();
        let approval_id = uuid::Uuid::now_v7().to_string();

        let pending = latchgate_state::approvals::PendingApproval {
            approval_id: approval_id.clone(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: "http_fetch".into(),
            auth_context: latchgate_state::approvals::StoredAuthContext {
                principal: "agent-audit".into(),
                session_id: "sess-audit".into(),
                lease_jti: "jti-audit".into(),
                sender_thumbprint: "thumb-test".into(),
                owner: None,
            },
            request_hash: "sha256:audit".into(),
            request_body: std::sync::Arc::new(serde_json::json!({})),
            policy_version: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        };
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        let (authz, dpop) = auth("POST", &format!("/v1/approvals/{approval_id}/deny"));
        let _resp = crate::router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{approval_id}/deny"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        let deny_events: Vec<_> = events
            .iter()
            .filter(|e| e.policy.decision == latchgate_ledger::Decision::Deny)
            .collect();
        assert!(!deny_events.is_empty(), "deny must produce an audit event");
    }

    /// Expired pending approval => 404 on approve attempt.
    ///
    /// This test requires a real Redis instance — it relies on server-side
    /// key TTL expiry which the in-memory store does not replicate.
    #[tokio::test]
    async fn approve_expired_returns_404() {
        if !redis_available().await {
            eprintln!("SKIP: approve_expired_returns_404 requires Redis for TTL expiry");
            return;
        }
        let state = test_state();

        let short_store = latchgate_state::approvals::ApprovalStore::new(
            &test_redis_url(),
            std::time::Duration::from_secs(1),
        )
        .unwrap();

        let approval_id = uuid::Uuid::now_v7().to_string();
        let pending = latchgate_state::approvals::PendingApproval {
            approval_id: approval_id.clone(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: "http_fetch".into(),
            auth_context: latchgate_state::approvals::StoredAuthContext {
                principal: "agent-ttl".into(),
                session_id: "sess-ttl".into(),
                lease_jti: "jti-ttl".into(),
                sender_thumbprint: "thumb-test".into(),
                owner: None,
            },
            request_hash: "sha256:ttl".into(),
            request_body: std::sync::Arc::new(serde_json::json!({})),
            policy_version: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        };
        short_store.create_pending(&pending).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let (authz, dpop) = auth("POST", &format!("/v1/approvals/{approval_id}/approve"));
        let resp = crate::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{approval_id}/approve"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "expired approval must return 404"
        );
    }

    /// Deny with no body (no reason) => defaults to "operator_denied".
    #[tokio::test]
    async fn deny_without_body_uses_default_reason() {
        let state = test_state();
        let approval_id = uuid::Uuid::now_v7().to_string();

        let pending = latchgate_state::approvals::PendingApproval {
            approval_id: approval_id.clone(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: "http_fetch".into(),
            auth_context: latchgate_state::approvals::StoredAuthContext {
                principal: "agent".into(),
                session_id: "sess".into(),
                lease_jti: "jti".into(),
                sender_thumbprint: "thumb-test".into(),
                owner: None,
            },
            request_hash: "sha256:x".into(),
            request_body: std::sync::Arc::new(serde_json::json!({})),
            policy_version: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        };
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        let (authz, dpop) = auth("POST", &format!("/v1/approvals/{approval_id}/deny"));
        let resp = crate::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{approval_id}/deny"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deny_reason"], "operator_denied");
    }

    /// Named operator key is accepted and operator_id is recorded in response.
    #[tokio::test]
    async fn named_operator_key_accepted_and_identity_recorded() {
        let (state, alice_op) = test_state_with_operator("alice", "key-alice-secret");

        let approval_id = uuid::Uuid::now_v7().to_string();
        let pending = latchgate_state::approvals::PendingApproval {
            approval_id: approval_id.clone(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: "http_fetch".into(),
            auth_context: latchgate_state::approvals::StoredAuthContext {
                principal: "agent".into(),
                session_id: "sess".into(),
                lease_jti: "jti".into(),
                sender_thumbprint: "thumb-test".into(),
                owner: None,
            },
            request_hash: "sha256:x".into(),
            request_body: std::sync::Arc::new(serde_json::json!({})),
            policy_version: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        };
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        let deny_path = format!("/v1/approvals/{approval_id}/deny");
        let (authz, dpop) = alice_op.headers_with_key("key-alice-secret", "POST", &deny_path);
        let resp = crate::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&deny_path)
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(
            json["denied_by"], "alice",
            "named key must record operator identity"
        );

        // Unknown key is still rejected.
        let (state2, _) = test_state_with_operator("alice", "key-alice-secret");
        let app2 = crate::router(state2);
        let resp2 = app2
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/approvals/any/deny")
                    .header("authorization", "DPoP key-bob-wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    }

    fn create_test_pending(action_id: &str) -> latchgate_state::approvals::PendingApproval {
        let mut plan = test_plan();
        plan.core.action_id = action_id.into();
        plan.core.approved_targets = vec!["https://example.com".into()];
        plan.core.approved_secrets = vec!["API_KEY".into()];
        plan.finalize();
        latchgate_state::approvals::PendingApproval {
            approval_id: uuid::Uuid::now_v7().to_string(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: action_id.into(),
            auth_context: latchgate_state::approvals::StoredAuthContext {
                principal: "agent-review".into(),
                session_id: "sess-review".into(),
                lease_jti: "jti-review".into(),
                sender_thumbprint: "thumb-review".into(),
                owner: None,
            },
            request_hash: "sha256:review".into(),
            request_body: std::sync::Arc::new(serde_json::json!({"test": true})),
            policy_version: Some("policy-v1".into()),
            created_at: chrono::Utc::now().to_rfc3339(),
            plan,
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        }
    }

    #[tokio::test]
    async fn list_approvals_requires_auth() {
        let app = crate::router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_approvals_returns_valid_response() {
        let app = crate::router(test_state());
        let (authz, dpop) = auth("GET", "/v1/approvals");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/approvals")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["approvals"].is_array(), "must return approvals array");
        assert!(json["count"].is_number(), "must return count field");
        assert_eq!(
            json["count"].as_u64().unwrap(),
            json["approvals"].as_array().unwrap().len() as u64,
            "count must match array length"
        );
    }

    #[tokio::test]
    async fn list_approvals_returns_created_approval() {
        let state = test_state();
        let pending = create_test_pending("list_test_action");
        let id = pending.approval_id.clone();
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        let app = crate::router(state);
        let (authz, dpop) = auth("GET", "/v1/approvals");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/approvals")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let approvals = json["approvals"].as_array().unwrap();

        // At least our approval must be present (Redis may have others from
        // parallel test runs, so we search by ID).
        let found = approvals
            .iter()
            .find(|a| a["approval_id"].as_str() == Some(&id));
        assert!(
            found.is_some(),
            "created approval must appear in list: {approvals:?}"
        );
        let a = found.unwrap();
        assert_eq!(a["action_id"], "list_test_action");
        assert_eq!(a["status"], "pending");
        assert_eq!(a["principal"], "agent-review");
    }

    #[tokio::test]
    async fn list_approvals_filters_by_status() {
        let state = test_state();
        let pending = create_test_pending("filter_test");
        let id = pending.approval_id.clone();
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        // Claim and deny => terminal.
        let claimed = state
            .enforcement
            .approval_store
            .claim_pending(&id, "alice")
            .await
            .unwrap();
        state
            .enforcement
            .approval_store
            .complete_denied(&id, &claimed.claim_token, "t1", "operator_denied")
            .await
            .unwrap();

        let app = crate::router(state);
        let (authz, dpop) = auth("GET", "/v1/approvals?status=pending");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/approvals?status=pending")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let approvals = json["approvals"].as_array().unwrap();

        // The denied approval must not appear in pending filter.
        let found = approvals
            .iter()
            .find(|a| a["approval_id"].as_str() == Some(&id));
        assert!(
            found.is_none(),
            "denied approval must not appear in pending filter"
        );
    }

    #[tokio::test]
    async fn get_approval_returns_plan_review_fields() {
        let state = test_state();
        let pending = create_test_pending("review_action");
        let id = pending.approval_id.clone();
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        let app = crate::router(state);
        let (authz, dpop) = auth("GET", &format!("/v1/approvals/{id}"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/approvals/{id}"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;

        // Lifecycle fields (always present).
        assert_eq!(json["approval_id"], id.as_str());
        assert_eq!(json["status"], "pending");
        assert_eq!(json["action_id"], "review_action");
        assert_eq!(json["principal"], "agent-review");

        // Plan review fields (present when payload available).
        assert_eq!(
            json["action_version"], "1.0.0",
            "action_version must come from immutable plan"
        );
        assert_eq!(json["risk_level"], "low");
        assert!(
            json["approved_targets"].is_array(),
            "approved_targets must be present"
        );
        assert_eq!(json["approved_targets"][0], "https://example.com");

        // SECURITY: secret names only, never values.
        assert!(json["approved_secrets"].is_array());
        assert_eq!(json["approved_secrets"][0], "API_KEY");

        assert!(json["plan_hash"].is_string(), "plan_hash must be exposed");
        assert!(
            json["provider_module_digest"].is_string(),
            "provider_module_digest must be exposed"
        );
        assert!(json["expires_at"].is_string(), "expires_at must be exposed");
        assert!(
            json["budget_snapshot"].is_object(),
            "budget_snapshot must be exposed"
        );
        assert!(
            json["budget_snapshot"]["calls_remaining"].is_number(),
            "calls_remaining must be in budget_snapshot"
        );
        assert!(
            json["verifier_kind"].is_string(),
            "verifier_kind must be exposed"
        );
    }

    #[tokio::test]
    async fn get_approval_detail_does_not_leak_secret_values() {
        let state = test_state();
        let pending = create_test_pending("secret_leak_test");
        let id = pending.approval_id.clone();
        state
            .enforcement
            .approval_store
            .create_pending(&pending)
            .await
            .unwrap();

        let app = crate::router(state);
        let (authz, dpop) = auth("GET", &format!("/v1/approvals/{id}"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/approvals/{id}"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        let body_str = serde_json::to_string(&json).unwrap();

        // The response must contain the secret NAME but must NOT contain
        // any secret value. Since our test plan has no actual secret values
        // (they're injected at execution time by the host I/O layer), we
        // verify the response does not contain fields that would indicate
        // value leakage.
        assert!(
            body_str.contains("API_KEY"),
            "secret name must be present for operator review"
        );
        assert!(
            !body_str.contains("decrypted_secrets"),
            "response must not contain decrypted_secrets field"
        );
        assert!(
            !body_str.contains("secret_value"),
            "response must not contain secret_value field"
        );
    }

    #[tokio::test]
    async fn get_approval_exposes_unresolved_domains_when_present() {
        let state = test_state();

        // Pending with unresolved domain (agent hit unknown URL).
        let mut pending_with = create_test_pending("web_read");
        pending_with.unresolved_domains = vec!["newsite.com".into()];
        let id_with = pending_with.approval_id.clone();
        state
            .enforcement
            .approval_store
            .create_pending(&pending_with)
            .await
            .unwrap();

        // Pending without unresolved domain (normal action).
        let pending_without = create_test_pending("http_fetch");
        let id_without = pending_without.approval_id.clone();
        state
            .enforcement
            .approval_store
            .create_pending(&pending_without)
            .await
            .unwrap();

        let app = crate::router(state);

        // With domain: response must include unresolved_domains.
        let (authz, dpop) = auth("GET", &format!("/v1/approvals/{id_with}"));
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/approvals/{id_with}"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(
            json["unresolved_domains"][0], "newsite.com",
            "unresolved_domains must be exposed for operator review"
        );

        // Without domain: field must be absent (not empty array).
        let (authz, dpop) = auth("GET", &format!("/v1/approvals/{id_without}"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/approvals/{id_without}"))
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(
            json.get("unresolved_domains").is_none(),
            "unresolved_domains must be absent when empty — not an empty array"
        );
    }
}
