//! Gate enforcement pipeline: top-level error type and orchestrator.
//!
//! # Responsibilities
//!
//! This module owns three things:
//!
//! 1. [`PipelineError`] — the top-level error type every step returns.
//!    The HTTP mapping (`IntoResponse`) is gated behind the `http`
//!    feature so the kernel compiles without axum when used standalone.
//! 2. [`ApprovalResponse`] — the 202 payload emitted when OPA defers
//!    to a human operator. Carried as `PipelineError::Approval` so
//!    `run_action_call` can short-circuit through `Result::Err`.
//! 3. [`run_action_call`] — the orchestrator that drives the fail-closed
//!    request pipeline step by step.
//!
//! # HTTP status semantics
//!
//! - 400 — bad request; operator input failed validation.
//! - 401 — auth failure; client must re-authenticate.
//! - 403 — policy/trust denial; client must not retry this request as-is.
//! - 409 — conflict; resource already exists or is being processed.
//! - 422 — schema violation; client must fix the request payload.
//! - 429 — rate limited; client must respect `Retry-After`.
//! - 502 — provider error; WASM execution failed (Gate is healthy).
//! - 503 — dependency unavailable (OPA/Redis down); client should retry.
//!
//! SECURITY: 503 responses still deny the request. The client signal is
//! "transient failure, retry with backoff" — not "approved". Fail-closed is
//! non-negotiable.

use std::sync::Arc;

#[cfg(feature = "http")]
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[cfg(feature = "http")]
use crate::json_response::JsonResponse;

use latchgate_auth::AuthError;
use latchgate_core::TrustError;
use latchgate_core::{ApprovalId, TraceId};
use latchgate_policy::{PolicyDecision, PolicyError};
use latchgate_providers::ProviderError;
use latchgate_registry::SchemaError;
use latchgate_state::BudgetError;

use crate::state::AppState;
use crate::steps;

/// Data returned to the client when a action call requires human approval.
///
/// Not a true error — modelled as `PipelineError::Approval` so the pipeline
/// can short-circuit with a 202 response via `Result::Err`.
#[derive(Debug, Clone)]
pub struct ApprovalResponse {
    pub approval_id: ApprovalId,
    pub request_hash: Arc<str>,
    pub trace_id: TraceId,
}

/// Top-level error type for the Gate enforcement pipeline.
///
/// Each variant wraps the typed error from its pipeline step. `IntoResponse`
/// maps variants to HTTP status codes without leaking internal details.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// Step 2–3: Lease JWT or DPoP proof rejected.
    #[error("auth: {0}")]
    Auth(#[from] AuthError),

    /// Step 5: Request or response schema validation failed.
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),

    /// Step 6: OPA policy evaluation rejected the request.
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),

    /// Step 4: Action trust verification failed (not registered / digest mismatch).
    #[error("trust: {0}")]
    Trust(#[from] TrustError),

    /// Step 7: Provider (WASM) execution failed.
    #[error("provider: {0}")]
    Provider(#[from] ProviderError),

    /// Budget check failed (exhausted, session not found, or Redis down).
    #[error("budget: {0}")]
    Budget(#[from] BudgetError),

    /// OPA returned PendingApproval — not an error, but modelled as one
    /// because the pipeline returns `Result` and we need to short-circuit
    /// with a 202 response.
    #[error("pending approval: {}", .0.approval_id)]
    Approval(ApprovalResponse),

    /// Action ID not found in registry. 404.
    #[error("action not found: {action_id}")]
    ActionNotFound { action_id: Arc<str> },

    /// Operator-supplied input failed validation. 400.
    ///
    /// Used when an operator provides structurally invalid parameters
    /// (e.g. malformed `learn_domain` or `learn_path` on approve). The
    /// reason is surfaced in the response body so the operator can fix
    /// the input without reading server logs.
    #[error("bad request: {reason}")]
    BadRequest { reason: String },

    /// Internal pipeline error (manifest parse, canonical hash, etc.). 500.
    ///
    /// SECURITY: message is logged but never exposed to the client. The HTTP
    /// response body contains only `{"error": "internal_error"}`.
    #[error("internal: {0}")]
    Internal(String),

    /// Grant integrity check failed before dispatch: grant expired, revoked,
    /// signature invalid, or required approval missing.
    ///
    /// SECURITY: these are post-issuance invariant failures — the grant was
    /// valid at creation but failed verification at dispatch time. Logged
    /// server-side with the specific reason; client sees only 500.
    #[error("grant integrity: {reason}")]
    GrantIntegrity { reason: &'static str },

    /// Execution plan integrity check failed on the approval path: plan hash
    /// mismatch, plan expired, or request body tampered since approval was
    /// created.
    #[error("plan integrity: {reason}")]
    PlanIntegrity { reason: &'static str },

    /// State store (Redis, SQLite) is unreachable or returned a non-logical
    /// error. Maps to 503 — distinguished from Internal (500) because
    /// transient infrastructure failures may resolve on retry.
    #[error("store unavailable: {0}")]
    StoreUnavailable(String),

    /// Secret injection or URL template resolution failed for non-policy
    /// reasons (I/O error, missing SOPS key, malformed template).
    #[error("secret resolution: {0}")]
    SecretResolution(String),

    /// Canonical JSON hash computation failed.
    #[error("canonical hash: {0}")]
    CanonicalHash(String),

    /// Runtime configuration constraint violated (e.g.
    /// `response_schema_enforcement = Warn` outside dev mode, operator auth
    /// not configured).
    #[error("config constraint: {reason}")]
    ConfigConstraint { reason: &'static str },

    /// Gate is in drain mode — rejecting new requests. 503.
    ///
    /// Set by `POST /v1/admin/drain`. In-flight requests that were accepted
    /// before the drain started will complete normally.
    #[error("gate is draining — not accepting new requests")]
    Draining,

    /// Side effect may have occurred but durable evidence (receipt + audit)
    /// could not be persisted. The client MUST NOT treat this as success.
    ///
    /// The execution intent was written before dispatch, so operators can
    /// detect this state and investigate whether the side effect occurred.
    #[error("evidence persistence failed: trace_id={trace_id} grant_id={grant_id}")]
    EvidencePersistenceFailed {
        trace_id: Arc<str>,
        grant_id: Arc<str>,
    },

    /// The grant was already consumed by a prior execution. Dispatch is
    /// denied to enforce the one-shot execution invariant. This guard is
    /// independent of the budget system — it fires even for sessions with
    /// unbounded budgets.
    #[error("grant already consumed: {grant_id}")]
    GrantConsumed { grant_id: Arc<str> },

    /// A resource already exists and cannot be overwritten (e.g. duplicate
    /// approval creation). 409.
    #[error("conflict: {detail}")]
    Conflict { detail: String },

    /// Execute-path rate limit exceeded. Applied before any cryptographic
    /// verification so abusive callers cannot burn CPU.
    ///
    /// SECURITY: fail-closed — the request is denied, not deferred. The
    /// client should respect the `Retry-After` header.
    #[error("execute rate limit exceeded")]
    RateLimited,

    /// Operator-path rate limit exceeded. Distinguished from `RateLimited`
    /// (execute path) so operators see 429 instead of a misleading 500,
    /// and `error!`-level logs are reserved for genuine server faults.
    ///
    /// SECURITY: fail-closed — the request is denied, not deferred.
    #[error("operator rate limited: {scope}")]
    Throttled { scope: &'static str },
}

#[cfg(feature = "http")]
impl IntoResponse for PipelineError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            // Auth failures => 401 ─────────────────────────────────────────
            // 401 signals "re-authenticate", not "denied forever".
            // Clients should obtain a fresh Lease / proof and retry.
            PipelineError::Auth(AuthError::LeaseExpired) => {
                (StatusCode::UNAUTHORIZED, "lease_expired")
            }
            PipelineError::Auth(AuthError::InvalidLease { .. }) => {
                (StatusCode::UNAUTHORIZED, "invalid_lease")
            }
            PipelineError::Auth(AuthError::InvalidDPoP { ref reason, .. }) => {
                const DPOP_REASON_MAX_BYTES: usize = 300;
                let safe = latchgate_core::sanitize_for_log(reason, DPOP_REASON_MAX_BYTES);
                return JsonResponse::new(StatusCode::UNAUTHORIZED, "invalid_dpop")
                    .field("deny_reason", &safe)
                    .into_response();
            }
            PipelineError::Auth(AuthError::ReplayDetected { .. }) => {
                (StatusCode::UNAUTHORIZED, "replay_detected")
            }
            PipelineError::Auth(AuthError::MissingHeader { .. }) => {
                (StatusCode::UNAUTHORIZED, "missing_auth_header")
            }

            // Operator-specific auth failures => 401 ──────────────────────
            // Distinct codes so operators and SOC/SIEM can distinguish
            // misconfiguration from attack signals (replay, key tampering).
            PipelineError::Auth(AuthError::InvalidAuthScheme) => {
                (StatusCode::UNAUTHORIZED, "invalid_auth_scheme")
            }
            PipelineError::Auth(AuthError::InvalidOperatorToken) => {
                (StatusCode::UNAUTHORIZED, "invalid_operator_token")
            }
            PipelineError::Auth(AuthError::MissingDpopHeader) => {
                (StatusCode::UNAUTHORIZED, "missing_dpop_header")
            }
            PipelineError::Auth(AuthError::KeyBindingFailed { ref deny_reason }) => {
                return JsonResponse::new(StatusCode::UNAUTHORIZED, "key_binding_failed")
                    .field("deny_reason", deny_reason)
                    .into_response();
            }

            // Clock / cache unavailable => 503 ────────────────────────────────
            // Still fail-closed (request denied), but signals host problem.
            PipelineError::Auth(AuthError::ClockError) => {
                (StatusCode::SERVICE_UNAVAILABLE, "clock_error")
            }
            PipelineError::Auth(AuthError::ReplayCacheUnavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "replay_cache_unavailable")
            }

            // Policy / trust => 403 ────────────────────────────────────────
            // 403 signals "denied for this request". The client should not
            // retry the same request without a policy or trust change.
            PipelineError::Policy(PolicyError::Denied {
                ref reason,
                ref principal,
                ref action_id,
            }) => {
                const BODY_REASON_MAX_BYTES: usize = 500;
                let safe_reason = latchgate_core::sanitize_for_log(reason, BODY_REASON_MAX_BYTES);
                let mut remediation = String::with_capacity(40 + principal.len() + action_id.len());
                remediation.push_str("Run: latchgate policy grant ");
                remediation.push_str(principal);
                remediation.push(' ');
                remediation.push_str(action_id);
                return JsonResponse::new(StatusCode::FORBIDDEN, "policy_denied")
                    .field("deny_reason", &safe_reason)
                    .field("principal", principal)
                    .field("action_id", action_id)
                    .field("remediation", &remediation)
                    .into_response();
            }
            PipelineError::Trust(TrustError::NotRegistered { .. }) => {
                (StatusCode::FORBIDDEN, "action_not_registered")
            }
            PipelineError::Trust(TrustError::DigestMismatch { .. }) => {
                (StatusCode::FORBIDDEN, "action_digest_mismatch")
            }

            // Schema violation => 422 ──────────────────────────────────────
            // Client must fix the request payload. Retrying as-is fails again.
            PipelineError::Schema(_) => (StatusCode::UNPROCESSABLE_ENTITY, "schema_violation"),

            // Dependency unavailable => 503 ─────────────────────────────────
            // SECURITY: fail-closed — request still DENIED. 503 tells the
            // client to retry with backoff, not that the request was allowed.
            PipelineError::Policy(PolicyError::OpaUnavailable(_)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "policy_engine_unavailable")
            }
            PipelineError::Policy(PolicyError::OpaTimeout) => {
                (StatusCode::SERVICE_UNAVAILABLE, "policy_engine_timeout")
            }
            PipelineError::Policy(PolicyError::OpaResponseInvalid(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_engine_invalid_response",
            ),

            // Provider failure => 502 ─────────────────────────────────────────
            // The action provider failed; the Gate itself is healthy. The
            // client may retry, but repeated failures indicate an action problem.
            PipelineError::Provider(_) => (StatusCode::BAD_GATEWAY, "action_execution_failed"),

            // Budget failures => 403 or 503 ───────────────────────────────
            PipelineError::Budget(BudgetError::Exhausted { .. }) => {
                (StatusCode::FORBIDDEN, "budget_exhausted")
            }
            PipelineError::Budget(BudgetError::AlreadyInitialised { .. }) => {
                (StatusCode::CONFLICT, "budget_already_initialised")
            }
            PipelineError::Budget(BudgetError::SessionNotFound { .. }) => {
                (StatusCode::FORBIDDEN, "budget_session_not_found")
            }
            PipelineError::Budget(BudgetError::Unavailable(_)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "budget_store_unavailable")
            }

            // Approval => 202 (not a true error) ─────────────────────────
            // Short-circuit: return structured 202 with approval_id so the
            // client/operator can approve or deny later.
            PipelineError::Approval(ref resp) => {
                return JsonResponse::with_key(
                    StatusCode::ACCEPTED,
                    "decision",
                    "pending_approval",
                )
                .field("approval_id", resp.approval_id.as_str())
                .field("request_hash", &resp.request_hash)
                .field("trace_id", resp.trace_id.as_str())
                .into_response();
            }

            // Tool not found => 404 ─────────────────────────────────────────
            PipelineError::ActionNotFound { .. } => (StatusCode::NOT_FOUND, "action_not_found"),

            // Draining => 503 ──────────────────────────────────────────────
            // Gate is shutting down gracefully. Client should retry against
            // a different instance or wait for the replacement.
            PipelineError::Draining => (StatusCode::SERVICE_UNAVAILABLE, "draining"),

            // Bad request => 400 ────────────────────────────────────────
            // Operator input failed validation. The reason is surfaced so
            // the operator can fix the input without reading server logs.
            PipelineError::BadRequest { ref reason } => {
                return JsonResponse::new(StatusCode::BAD_REQUEST, "bad_request")
                    .field("deny_reason", reason)
                    .into_response();
            }

            // Internal => 500 ───────────────────────────────────────────────
            // SECURITY: internal details logged server-side, never in body.
            PipelineError::Internal(_) => {
                tracing::error!(error = %self, "internal pipeline error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }

            // Grant / plan integrity => 500 ─────────────────────────────────
            PipelineError::GrantIntegrity { .. }
            | PipelineError::PlanIntegrity { .. }
            | PipelineError::CanonicalHash(_)
            | PipelineError::SecretResolution(_)
            | PipelineError::ConfigConstraint { .. } => {
                tracing::error!(error = %self, "internal pipeline error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }

            // Store unavailable => 503 ──────────────────────────────────────
            // State store (Redis, SQLite) is unreachable. Transient — the
            // client may retry. Distinguished from Internal (500) which
            // indicates a logic bug, not an infrastructure issue.
            PipelineError::StoreUnavailable(_) => {
                tracing::error!(error = %self, "state store unavailable");
                (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable")
            }

            // Evidence persistence failed => 500 ─────────────────────────
            // Side effect may have occurred but durable evidence was not
            // written. The client must not treat this as success.
            PipelineError::EvidencePersistenceFailed { .. } => {
                tracing::error!(error = %self, "evidence persistence failed after dispatch");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "evidence_persistence_failed",
                )
            }

            // Grant already consumed => 409 ──────────────────────────────
            // One-shot invariant: the grant was dispatched in a prior
            // execution. Retrying is not possible. The client should
            // request a fresh authorization cycle.
            PipelineError::GrantConsumed { .. } => (StatusCode::CONFLICT, "grant_consumed"),

            // Resource conflict => 409 ────────────────────────────────────
            PipelineError::Conflict { .. } => (StatusCode::CONFLICT, "conflict"),

            // Execute rate limit => 429 ──────────────────────────────────
            // SECURITY: 429 signals "slow down". Retry-After tells the
            // client when to retry. Applied pre-auth so CPU-expensive
            // steps (DPoP, OPA, WASM) are never reached.
            PipelineError::RateLimited => {
                return JsonResponse::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
                    .header("retry-after", "1")
                    .into_response();
            }

            // Operator rate limit => 429 ──────────────────────────────────
            // Same semantics as RateLimited but for the operator write path
            // (approve/deny). Distinguished so metrics and logs can separate
            // execute-path pressure from operator-path pressure.
            PipelineError::Throttled { .. } => {
                return JsonResponse::new(StatusCode::TOO_MANY_REQUESTS, "operator_throttled")
                    .header("retry-after", "2")
                    .into_response();
            }
        };

        // SECURITY: structured body with a machine-readable `error` code only.
        // Never include: stack traces, internal paths, OPA rule names,
        // module digests, or any other implementation detail.
        JsonResponse::new(status, code).into_response()
    }
}

/// Execute the full Gate enforcement pipeline for a action call.
///
/// This is the core enforcement path — every step is fail-closed. The function
/// accepts pre-extracted HTTP inputs (no axum types) so the gate layer has no
/// HTTP framework dependency.
///
/// * `peer_id` — opaque transport-level identifier for the connecting peer
///   (e.g. stringified UID on UDS, remote IP on TCP). Used as the rate-limit
///   shard key when no session hint is parseable from the Authorization header.
/// * `body` — raw request body bytes (may be empty for no-arg actions).
#[tracing::instrument(
    name = "pipeline.run_action_call",
    skip(state, authorization, dpop, body),
    fields(action_id = %action_id),
)]
pub async fn run_action_call(
    state: AppState,
    action_id: &str,
    authorization: Option<&str>,
    dpop: Option<&str>,
    peer_id: crate::rate_limit::PeerId,
    body: &[u8],
) -> Result<crate::execution::ExecutionResponse, PipelineError> {
    // ---- Pre-step: execute-path rate limit ----------------------------------
    //
    // SECURITY: applied before ANY cryptographic verification. A compromised
    // or misbehaving agent can flood the gate with requests that fail auth,
    // trust, or policy — each one consuming CPU for DPoP verification, OPA
    // evaluation, and WASM instantiation. The rate limiter bounds this cost.
    //
    // The session hint is extracted from the JWT *without* signature
    // verification — this is intentional. The hint selects a rate-limit
    // bucket, not a security principal. Forging a session_id merely selects
    // a different (independently bounded) bucket.
    {
        let key = crate::rate_limit::extract_limiter_key(authorization, peer_id);
        if !state.lifecycle.execute_rate_limiters.check(&key) {
            state.metrics.record_call(action_id, "rate_limited");
            tracing::warn!(
                ?key,
                action_id = %action_id,
                "execute rate limit exceeded"
            );
            return Err(PipelineError::RateLimited);
        }
    }

    // Request-scoped context. Every step reads or mutates fields on `ctx`;
    // audit, budget-debit state, and both identifiers travel here instead
    // of through positional argument lists. See `request` module for rationale.
    let trace_id = TraceId::new();
    let mut ctx = crate::request::RequestCtx::new(
        Arc::from(trace_id.as_str()),
        Arc::from(action_id),
        state.config.dev_mode(),
    );

    // ---- Step 0: drain guard ------------------------------------------------
    steps::step_drain_guard(&state, &ctx).await?;

    // ---- Step 1: authentication --------------------------------------------
    let auth_ctx = steps::step_authenticate(&state, &mut ctx, authorization, dpop).await?;

    // ---- Step 2: registry lookup -------------------------------------------
    //
    // Snapshot the registry once per pipeline run via `load_full()`. This is
    // one atomic increment — the resulting Arc lives on the stack and all
    // borrowed manifest references are tied to it.
    let registry = state.registry.load_full();
    let steps::ResolveActionOutput {
        manifest,
        egress_profile,
    } = steps::step_resolve_action(&state, &mut ctx, &registry).await?;

    // ---- Step 3: trust verification ----------------------------------------
    let (verdict_out, trust_verdict) = steps::step_verify_trust(&state, &mut ctx, manifest).await?;
    let trust_verdict_str = verdict_out.trust_verdict_str;

    // ---- Step 4: parse + validate + canonical hash -------------------------
    let steps::ValidateAndHashOutput {
        request_body,
        request_hash,
        schema_id,
    } = steps::step_validate_and_hash(&state, &mut ctx, manifest, body).await?;

    // ---- Steps 5 + 5b: domain and path pre-checks (parallel) ----------------
    //
    // Both pre-checks read shared state (ledger, manifest, request_body) and
    // perform independent I/O (learned-domain lookup vs learned-path lookup).
    // Running them concurrently halves the wall-clock latency of this phase.
    let (
        steps::DomainPrecheckOutput { unresolved_domains },
        steps::PathPrecheckOutput {
            fs_path,
            unresolved_paths,
            compiled_allowed,
            compiled_denied,
        },
    ) = tokio::join!(
        steps::step_domain_precheck(&state, &ctx, manifest, &request_body, &egress_profile),
        steps::step_path_precheck(&state, &ctx.action_id, manifest, &request_body),
    );

    // ---- Step 6: budget snapshot + OPA evaluation --------------------------
    let steps::EvaluatePolicyOutput {
        decision,
        budgets_before,
        budgets_after_opa,
    } = steps::step_evaluate_policy(
        &state,
        &mut ctx,
        &auth_ctx,
        manifest,
        steps::EvaluatePolicyInput {
            trust_verdict: Arc::clone(&trust_verdict),
            request_hash: &request_hash,
            request_body: &request_body,
            egress_profile: &egress_profile,
            unresolved_domains: &unresolved_domains,
            fs_path,
            unresolved_paths: &unresolved_paths,
        },
    )
    .await?;

    // ---- Policy branch: Allow vs PendingApproval ---------------------------
    //
    // The Deny case is handled terminally inside `step_evaluate_policy` and
    // arrives here only as an `Err`. The two remaining variants diverge
    // sharply: PendingApproval stores an immutable plan and returns 202;
    // Allow debits the budget, builds a grant, and dispatches the provider.
    let (policy_approved, policy_version) = match decision {
        PolicyDecision::Allow {
            allowed_sinks,
            approved_secrets,
            approved_egress,
            policy_version,
            ..
        } => (
            steps::PolicyApproved {
                allowed_sinks,
                approved_secrets,
                approved_egress,
            },
            policy_version,
        ),

        PolicyDecision::PendingApproval {
            approval_id,
            allowed_sinks: policy_allowed_sinks,
            approved_secrets: policy_approved_secrets,
            approved_egress: policy_approved_egress,
            budgets_after: policy_budgets_after,
            policy_version,
        } => {
            // Terminal: returns PipelineError::Approval (202 at the API boundary).
            return Err(steps::step_store_pending_approval(
                &state,
                &mut ctx,
                &auth_ctx,
                manifest,
                steps::StorePendingApprovalInput {
                    request_hash,
                    request_body,
                    budgets_before,
                    trust_verdict,
                    approval_id: approval_id.to_arc_str(),
                    policy: steps::PolicyApproved {
                        allowed_sinks: policy_allowed_sinks,
                        approved_secrets: policy_approved_secrets,
                        approved_egress: policy_approved_egress,
                    },
                    policy_budgets_after,
                    policy_version,
                    unresolved_domains,
                    unresolved_paths,
                },
            )
            .await);
        }

        PolicyDecision::Deny { .. } => {
            // SECURITY: unreachable — step_evaluate_policy handles Deny
            // terminally, writes its audit event and returns `Err`. This
            // branch exists only to make the match exhaustive; if reached,
            // something violated the step contract and we refuse to
            // continue into debit/dispatch.
            return Err(PipelineError::Internal(
                "policy decision Deny propagated past step_evaluate_policy".into(),
            ));
        }
    };

    let steps::DebitBudgetOutput { budgets_after } = steps::step_debit_budget(
        &state,
        &mut ctx,
        &auth_ctx,
        manifest,
        &budgets_before,
        &budgets_after_opa,
    )
    .await?;

    let build_result = steps::step_build_run_task(
        &state,
        &mut ctx,
        &auth_ctx,
        manifest,
        steps::BuildRunTaskInput {
            request_body: &request_body,
            request_hash: &request_hash,
            policy: &policy_approved,
            budgets_before: &budgets_before,
            budgets_after: &budgets_after,
            policy_version: policy_version.as_ref().map(Arc::clone),
            compiled_fs_allowed: compiled_allowed,
            compiled_fs_denied: compiled_denied,
        },
    )
    .await;

    let steps::BuildRunTaskOutput {
        grant,
        task,
        concrete_sinks,
    } = match build_result {
        Ok(out) => out,
        Err(e) => {
            // SECURITY: rollback the debit from Step 7. Without this, the
            // operator is charged for an execution that never happened.
            crate::pipeline_audit::rollback_budget_if_debited(
                &state,
                &auth_ctx.session_id,
                ctx.budget_debited,
                &ctx.trace_id,
                "build_run_task_error",
            )
            .await;
            return Err(e);
        }
    };

    // ---- Step 9: dispatch via shared execution tail ------------------------
    //
    // Both auto-allow (here) and human-approved (approved_execution.rs) paths converge
    // on `execute_authorized_plan`. That function owns grant validation,
    // provider dispatch, response schema, verifier, receipt, and evidence
    // write. No other code path dispatches WASM providers.
    let exec_ctx = crate::execution::AuthorizedExecution {
        identity: crate::execution::ExecutionIdentity {
            trace_id: Arc::clone(&ctx.trace_id),
            principal: Arc::clone(&auth_ctx.principal),
            owner: auth_ctx.owner.clone(),
            session_id: Arc::clone(&auth_ctx.session_id),
            lease_jti: Arc::clone(&auth_ctx.lease_jti),
        },
        grant,
        task,
        action: crate::execution::ActionMetadata {
            action_id: Arc::clone(&ctx.action_id),
            action_version: Arc::clone(&manifest.version),
            provider_module_digest: Arc::clone(&manifest.provider_module_digest),
            trust_verdict_str: Arc::from(trust_verdict_str),
            risk_level: manifest.risk_level,
            verifier_kind: manifest.verifier_kind,
            verification_config: manifest.verification_config.clone(),
            max_response_bytes: manifest.io.max_response_bytes,
        },
        request: crate::execution::RequestContext {
            request_hash,
            schema_id,
            policy_version,
            allowed_sinks: concrete_sinks,
            // SECURITY (01.2): policy-approved egress, not manifest-declared.
            egress_profile: policy_approved.approved_egress,
        },
        budget: crate::execution::BudgetContext {
            budgets_before,
            budgets_after,
            budget_debited: ctx.budget_debited,
        },
        decision_source: crate::execution::DecisionSource::AutoAllow,
        pipeline_start: ctx.pipeline_start,
    };

    crate::execution::execute_authorized_plan(&state, exec_ctx).await
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    async fn status_and_code(err: PipelineError) -> (StatusCode, String) {
        let resp = err.into_response();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 512)
            .await
            .expect("response body must be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("response body must be valid JSON");
        let code = json["error"]
            .as_str()
            .expect("response body must contain string 'error' field")
            .to_string();
        (status, code)
    }

    /// Every PipelineError variant maps to a specific (StatusCode, error_code)
    /// pair. This single test covers the entire mapping exhaustively.
    #[tokio::test]
    async fn error_to_status_mapping() {
        let cases: Vec<(PipelineError, StatusCode, &str)> = vec![
            // Auth => 401
            (
                PipelineError::Auth(AuthError::LeaseExpired),
                StatusCode::UNAUTHORIZED,
                "lease_expired",
            ),
            (
                PipelineError::Auth(AuthError::invalid_lease("x")),
                StatusCode::UNAUTHORIZED,
                "invalid_lease",
            ),
            (
                PipelineError::Auth(AuthError::InvalidDPoP {
                    kind: latchgate_auth::dpop::verify::DpopRejectKind::BadSig,
                    reason: "x".into(),
                }),
                StatusCode::UNAUTHORIZED,
                "invalid_dpop",
            ),
            (
                PipelineError::Auth(AuthError::ReplayDetected { jti: "j".into() }),
                StatusCode::UNAUTHORIZED,
                "replay_detected",
            ),
            (
                PipelineError::Auth(AuthError::MissingHeader {
                    name: "Authorization".into(),
                }),
                StatusCode::UNAUTHORIZED,
                "missing_auth_header",
            ),
            // Auth dependency => 503 (fail-closed)
            (
                PipelineError::Auth(AuthError::ClockError),
                StatusCode::SERVICE_UNAVAILABLE,
                "clock_error",
            ),
            (
                PipelineError::Auth(AuthError::ReplayCacheUnavailable),
                StatusCode::SERVICE_UNAVAILABLE,
                "replay_cache_unavailable",
            ),
            // Trust => 403
            (
                PipelineError::Trust(TrustError::NotRegistered {
                    action_id: "x".into(),
                }),
                StatusCode::FORBIDDEN,
                "action_not_registered",
            ),
            (
                PipelineError::Trust(TrustError::DigestMismatch {
                    action_id: "x".into(),
                    expected: "a".into(),
                    actual: "b".into(),
                }),
                StatusCode::FORBIDDEN,
                "action_digest_mismatch",
            ),
            // Schema => 422
            (
                PipelineError::Schema(SchemaError::ValidationFailed { reason: "x".into() }),
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
            ),
            // Policy dependency => 503
            (
                PipelineError::Policy(PolicyError::OpaTimeout),
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_engine_timeout",
            ),
            (
                PipelineError::Policy(PolicyError::OpaUnavailable("down".into())),
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_engine_unavailable",
            ),
            (
                PipelineError::Policy(PolicyError::OpaResponseInvalid("x".into())),
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_engine_invalid_response",
            ),
            // Provider => 502
            (
                PipelineError::Provider(ProviderError::WasmTimeout),
                StatusCode::BAD_GATEWAY,
                "action_execution_failed",
            ),
            // Budget => 403 / 503
            (
                PipelineError::Budget(BudgetError::Exhausted { reason: "x".into() }),
                StatusCode::FORBIDDEN,
                "budget_exhausted",
            ),
            (
                PipelineError::Budget(BudgetError::SessionNotFound {
                    session_id: "s".into(),
                }),
                StatusCode::FORBIDDEN,
                "budget_session_not_found",
            ),
            (
                PipelineError::Budget(BudgetError::Unavailable("x".into())),
                StatusCode::SERVICE_UNAVAILABLE,
                "budget_store_unavailable",
            ),
            // Action not found => 404
            (
                PipelineError::ActionNotFound {
                    action_id: "x".into(),
                },
                StatusCode::NOT_FOUND,
                "action_not_found",
            ),
            // BadRequest => 400
            (
                PipelineError::BadRequest {
                    reason: "invalid learn_domain".into(),
                },
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            // Internal => 500
            (
                PipelineError::Internal("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            // GrantIntegrity => 500
            (
                PipelineError::GrantIntegrity {
                    reason: "grant expired",
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            // PlanIntegrity => 500
            (
                PipelineError::PlanIntegrity {
                    reason: "hash mismatch",
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            // StoreUnavailable => 503
            (
                PipelineError::StoreUnavailable("redis down".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
            ),
            // SecretResolution => 500
            (
                PipelineError::SecretResolution("sops key missing".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            // CanonicalHash => 500
            (
                PipelineError::CanonicalHash("depth exceeded".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            // ConfigConstraint => 500
            (
                PipelineError::ConfigConstraint {
                    reason: "warn mode requires dev",
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            (
                PipelineError::EvidencePersistenceFailed {
                    trace_id: "t".into(),
                    grant_id: "g".into(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_persistence_failed",
            ),
            // Drain => 503
            (
                PipelineError::Draining,
                StatusCode::SERVICE_UNAVAILABLE,
                "draining",
            ),
            // Rate limited => 429
            (
                PipelineError::RateLimited,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            ),
            // Operator throttled => 429
            (
                PipelineError::Throttled {
                    scope: "operator_write",
                },
                StatusCode::TOO_MANY_REQUESTS,
                "operator_throttled",
            ),
            // GrantConsumed => 409
            (
                PipelineError::GrantConsumed {
                    grant_id: "g".into(),
                },
                StatusCode::CONFLICT,
                "grant_consumed",
            ),
            // Conflict => 409
            (
                PipelineError::Conflict {
                    detail: "already claimed".into(),
                },
                StatusCode::CONFLICT,
                "conflict",
            ),
        ];

        for (error, expected_status, expected_code) in cases {
            let label = format!("{error}");
            let (status, code) = status_and_code(error).await;
            assert_eq!(status, expected_status, "status mismatch for: {label}");
            assert_eq!(code, expected_code, "code mismatch for: {label}");
        }
    }

    /// SECURITY: policy deny surfaces deny_reason to callers (for diagnostics),
    /// but all other error bodies contain only the `error` code — no internals.
    #[tokio::test]
    async fn policy_denied_surfaces_deny_reason() {
        let resp = PipelineError::Policy(PolicyError::denied(
            "action not in ACL for principal 'agent-1'",
            Arc::from("agent-1"),
            Arc::from("web_read"),
        ))
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), 1024)
            .await
            .expect("response body must be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("response body must be valid JSON");
        assert_eq!(json["error"], "policy_denied");
        assert_eq!(
            json["deny_reason"], "action not in ACL for principal 'agent-1'",
            "deny_reason must be surfaced to the caller"
        );
        assert_eq!(json["principal"], "agent-1");
        assert_eq!(json["action_id"], "web_read");
        assert!(
            json["remediation"]
                .as_str()
                .unwrap()
                .contains("latchgate policy grant"),
            "remediation must contain a copy-pasteable command"
        );
    }

    /// PendingApproval returns 202 with structured payload (not a true error).
    #[tokio::test]
    async fn approval_returns_202_with_fields() {
        let resp = PipelineError::Approval(ApprovalResponse {
            approval_id: "appr-001".into(),
            request_hash: Arc::from("sha256:abc"),
            trace_id: "trace-001".into(),
        })
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = to_bytes(resp.into_body(), 512)
            .await
            .expect("response body must be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("response body must be valid JSON");
        assert_eq!(json["decision"], "pending_approval");
        assert_eq!(json["approval_id"], "appr-001");
        assert_eq!(json["request_hash"], "sha256:abc");
        assert_eq!(json["trace_id"], "trace-001");
    }

    /// SECURITY: error responses must not leak internal details.
    /// Standard error bodies contain exactly one key: `error`.
    #[tokio::test]
    async fn error_body_contains_only_error_code() {
        let resp = PipelineError::Auth(AuthError::LeaseExpired).into_response();
        let body = to_bytes(resp.into_body(), 512)
            .await
            .expect("response body must be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("response body must be valid JSON");
        let obj = json
            .as_object()
            .expect("response body must be a JSON object");
        assert!(obj.contains_key("error"), "body must have 'error' key");
        assert_eq!(obj.len(), 1, "body must contain only 'error' key");
    }

    /// SECURITY: 429 responses MUST include a Retry-After header so
    /// well-behaved clients back off rather than hammering the gate.
    #[tokio::test]
    async fn rate_limited_includes_retry_after_header() {
        let resp = PipelineError::RateLimited.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("429 response must include Retry-After header")
            .to_str()
            .expect("Retry-After header must be valid UTF-8");
        assert_eq!(retry_after, "1");
    }

    /// SECURITY: operator throttle responses include Retry-After so
    /// CLI/automation clients back off instead of busy-looping.
    #[tokio::test]
    async fn operator_throttled_includes_retry_after_header() {
        let resp = PipelineError::Throttled {
            scope: "operator_write",
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("429 response must include Retry-After header")
            .to_str()
            .expect("Retry-After header must be valid UTF-8");
        assert_eq!(retry_after, "2");
    }

    /// BadRequest surfaces the reason to the caller so operators can fix
    /// their input without reading server logs.
    #[tokio::test]
    async fn bad_request_surfaces_reason() {
        let resp = PipelineError::BadRequest {
            reason: "invalid learn_domain '*.com': wildcard suffix too short".into(),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 1024)
            .await
            .expect("response body must be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("response body must be valid JSON");
        assert_eq!(json["error"], "bad_request");
        assert!(
            json["deny_reason"].as_str().is_some(),
            "bad_request must include deny_reason for operator diagnostics"
        );
    }
}
