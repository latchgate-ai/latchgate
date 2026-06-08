//! Shared execution tail — the single path for all authorized side effects.
//!
//! Both the auto-allow pipeline and the human-approval pipeline converge here
//! after their respective authorization steps.
//!
//! **There is no other execution path.** If code dispatches a provider outside
//! this function, it is a bug.
//!
//! # Evidence durability contract
//!
//! The success response to the client is gated on durable evidence: receipt and
//! final audit event are written atomically in a single SQLite transaction. If
//! the transaction fails, the client receives `evidence_persistence_failed` —
//! never a false success. The pre-dispatch `ExecutionIntent` allows operators to
//! detect "dispatch occurred but evidence was not finalized" states.

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::verification::VerificationInput;
use latchgate_auth::OperatorAuthnMethod;
use latchgate_core::BudgetSnapshot;
use latchgate_core::ExecutionGrant;
use latchgate_core::{crypto::canonical, EgressProfile, RiskLevel, VerifierKind};
use latchgate_core::{ExecutionReceipt, FailureClass, NormalizedResult, VerificationOutcome};
use latchgate_crypto::{GrantExt, ReceiptExt};
use latchgate_ledger::{AuditEventBuilder, Decision, EventType, ExecutionIntent, RuntimeAudit};
use latchgate_providers::{ProviderError, RunTask};
use latchgate_registry::schema::{self, SchemaError, ValidationLimits};

use crate::pipeline::PipelineError;
use crate::pipeline_audit;
use crate::state::AppState;

/// How this execution was authorized.
///
/// Recorded in the audit trail and response so operators can distinguish
/// auto-allowed actions from human-approved ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    /// Policy auto-allowed the execution (no human in the loop).
    AutoAllow,
    /// A human operator approved the execution.
    HumanApproved {
        approval_id: Arc<str>,
        approved_by: Arc<str>,
        /// How the operator authenticated (e.g. `OperatorAuthnMethod::Dpop`).
        operator_authn_method: OperatorAuthnMethod,
        /// JWK thumbprint of the operator's DPoP key (sender binding).
        operator_sender_binding: Arc<str>,
        /// `jti` from the operator's DPoP proof (forensic correlation).
        operator_proof_jti: Arc<str>,
    },
}

/// Structured response from a successful action execution.
///
/// Every field is statically guaranteed to be present — enrichment cannot
/// silently degrade for non-object provider output. Downstream consumers
/// (API handlers, approval finalization) access typed fields instead of
/// indexing into `serde_json::Value`.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionResponse {
    /// Explicit response discriminator. Always `"executed"` for this type.
    /// The approval path emits `"pending_approval"` in its own response.
    /// Downstream consumers (MCP adapter, CLI) match on this field instead
    /// of inferring shape from field presence.
    pub decision: &'static str,
    pub trace_id: Arc<str>,
    pub action_id: Arc<str>,
    pub grant_id: Arc<str>,
    pub receipt_id: Arc<str>,
    pub output: Arc<serde_json::Value>,
    pub verification_outcome: Arc<str>,
    pub verification: VerificationInfo,
    pub runtime: RuntimeInfo,
    /// Approval provenance — present only for human-approved executions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalProvenance>,
    /// Learned domain — set by the approval endpoint when `learn_domain`
    /// was requested and the execution succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learned_domain: Option<String>,
    /// Learned path — set by the approval endpoint when `learn_path`
    /// was requested and the execution succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learned_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationInfo {
    pub outcome: Arc<str>,
    pub is_fully_successful: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub duration_ms: u64,
    pub exit_code: i64,
    pub fuel_consumed: u64,
}

/// Provenance record for human-approved executions. Included in the
/// response so clients and operators see approval context without a
/// separate query.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalProvenance {
    pub decision: Arc<str>,
    pub approval_id: Arc<str>,
    pub approved_by: Arc<str>,
    pub approval_hash: Option<Arc<str>>,
    pub operator_authn_method: OperatorAuthnMethod,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub operator_sender_binding: Arc<str>,
}

/// Trace and caller identity for the execution.
///
/// Fields are `Arc<str>` because identity values originate as `Arc<str>` in
/// `AuthContext` and `RequestCtx`, are cloned into audit events, domain
/// events, and the execution intent (5+ clones per request). `Arc<str>`
/// makes each clone a refcount bump instead of a heap allocation.
#[derive(Debug)]
pub struct ExecutionIdentity {
    pub trace_id: Arc<str>,
    pub principal: Arc<str>,
    /// Owner/responsible person for this agent, frozen at lease time.
    pub owner: Option<Arc<str>>,
    pub session_id: Arc<str>,
    pub lease_jti: Arc<str>,
}

/// Static metadata from the action manifest, frozen at grant time.
///
/// String fields are `Arc<str>` to avoid per-clone heap allocations when
/// these values are forwarded into audit events, domain events, and the
/// execution response (5+ clones per request on the success path).
#[derive(Debug)]
pub struct ActionMetadata {
    pub action_id: Arc<str>,
    pub action_version: Arc<str>,
    pub provider_module_digest: Arc<str>,
    pub trust_verdict_str: Arc<str>,
    pub risk_level: RiskLevel,
    pub verifier_kind: VerifierKind,
    pub verification_config: Option<Arc<serde_json::Value>>,
    pub max_response_bytes: usize,
}

/// Request-scoped context: hashes, policy version, egress profile.
#[derive(Debug)]
pub struct RequestContext {
    pub request_hash: Arc<str>,
    pub schema_id: Option<String>,
    pub policy_version: Option<Arc<str>>,
    pub allowed_sinks: Vec<Arc<str>>,
    pub egress_profile: EgressProfile,
}

/// Budget state before and after the debit, plus whether the debit occurred.
#[derive(Debug)]
pub struct BudgetContext {
    pub budgets_before: BudgetSnapshot,
    pub budgets_after: BudgetSnapshot,
    pub budget_debited: bool,
}

/// Everything needed to execute an authorized action.
///
/// Built by the caller (auto-allow branch or approval endpoint) after
/// their respective authorization steps. The shared execution tail does
/// NOT re-authorize — it validates, dispatches, verifies, and records.
#[derive(Debug)]
pub struct AuthorizedExecution {
    pub identity: ExecutionIdentity,
    pub grant: ExecutionGrant,
    pub task: RunTask,
    pub action: ActionMetadata,
    pub request: RequestContext,
    pub budget: BudgetContext,
    pub decision_source: DecisionSource,
    pub pipeline_start: Instant,
}

/// Immutable context for building audit events during execution.
///
/// Borrows the execution context's sub-structs individually so that
/// `task` can be moved to the WASM runtime while audit methods remain
/// callable on the remaining fields.
struct AuditCtx<'a> {
    identity: &'a ExecutionIdentity,
    action: &'a ActionMetadata,
    request: &'a RequestContext,
    budget: &'a BudgetContext,
    decision_source: &'a DecisionSource,
    owner: &'a Option<Arc<str>>,
    dev_mode: bool,
}

impl<'a> AuditCtx<'a> {
    /// Build an audit event populated with the execution's common fields.
    fn event(&self, decision: Decision, reason: Option<String>) -> AuditEventBuilder {
        let builder =
            AuditEventBuilder::new(Arc::clone(&self.identity.trace_id), EventType::ActionCall)
                .principal(
                    Arc::clone(&self.identity.principal),
                    Arc::clone(&self.identity.session_id),
                    Arc::clone(&self.identity.lease_jti),
                )
                .owner(self.owner.as_ref().map(Arc::clone))
                .action(
                    Arc::clone(&self.action.action_id),
                    Some(Arc::clone(&self.action.action_version)),
                    Arc::clone(&self.action.provider_module_digest),
                    Arc::clone(&self.action.trust_verdict_str),
                )
                .request(
                    Arc::clone(&self.request.request_hash),
                    self.request.schema_id.as_deref().map(Arc::from),
                )
                .budgets(
                    Some(pipeline_audit::serialize_budgets(
                        &self.budget.budgets_before,
                    )),
                    Some(pipeline_audit::serialize_budgets(
                        &self.budget.budgets_after,
                    )),
                )
                .policy(decision, self.request.policy_version.clone(), reason)
                .risk_level(self.action.risk_level.as_str())
                .flags(self.dev_mode, false);

        if let DecisionSource::HumanApproved {
            ref approval_id,
            ref approved_by,
            ref operator_authn_method,
            ref operator_sender_binding,
            ref operator_proof_jti,
        } = self.decision_source
        {
            builder
                .approval_id(Arc::clone(approval_id))
                .approved_by(Arc::clone(approved_by))
                .operator_authn_method(operator_authn_method.as_str())
                .operator_sender_binding(Arc::clone(operator_sender_binding))
                .operator_proof_jti(Arc::clone(operator_proof_jti))
        } else {
            builder
        }
    }

    /// Rollback budget, record deny metrics, and write a deny audit event.
    ///
    /// Used for all pre-dispatch deny paths where no side effect has
    /// occurred and budget refund is safe.
    async fn deny_pre_dispatch(
        &self,
        state: &AppState,
        reason: &str,
        rollback_label: &'static str,
    ) {
        crate::pipeline_audit::rollback_budget_if_debited(
            state,
            &self.identity.session_id,
            self.budget.budget_debited,
            &self.identity.trace_id,
            rollback_label,
        )
        .await;
        state.metrics.record_call(&self.action.action_id, "deny");
        let audit = self.event(Decision::Deny, Some(reason.into()));
        pipeline_audit::write_audit(&state.ledger, &state.metrics, audit).await;
    }

    /// Emit an `ActionFailed` domain event with the execution's identity.
    fn emit_action_failed(&self, state: &AppState, error_class: &str) {
        state.emit(latchgate_core::DomainEvent::ActionFailed {
            action_id: Arc::clone(&self.action.action_id),
            principal: Arc::clone(&self.identity.principal),
            owner: self.owner.clone(),
            error_class: Arc::from(error_class),
            trace_id: Arc::clone(&self.identity.trace_id),
        });
    }
}

/// Execute an authorized plan through the full security pipeline.
///
/// SECURITY: this is the **only** function that dispatches WASM providers.
/// Both the auto-allow path and the approval path MUST call this function.
/// Any code that bypasses it is a security violation.
///
/// Steps: validate grant (1–3) => write intent + consume grant (3a) => dispatch
/// WASM (4) => validate response schema (5) => run verifier (6) => build receipt
/// (7/7a) => finalize evidence (8) => return result (9).
#[tracing::instrument(
    name = "kernel.execute_authorized",
    skip(state, ctx),
    fields(
        trace_id = %ctx.identity.trace_id,
        action_id = %ctx.action.action_id,
        grant_id = %ctx.grant.grant_id,
    ),
)]
pub async fn execute_authorized_plan(
    state: &AppState,
    ctx: AuthorizedExecution,
) -> Result<ExecutionResponse, PipelineError> {
    // Destructure so `task` can move to the WASM runtime independently
    // while the other sub-structs remain borrowable for audit and response.
    let AuthorizedExecution {
        identity,
        grant,
        task,
        action,
        request,
        budget,
        decision_source,
        pipeline_start,
    } = ctx;

    let owner = identity.owner.clone();
    let audit = AuditCtx {
        identity: &identity,
        action: &action,
        request: &request,
        budget: &budget,
        decision_source: &decision_source,
        owner: &owner,
        dev_mode: state.config.dev_mode(),
    };
    let trace_id = &identity.trace_id;
    let action_id = &action.action_id;
    let grant_id = &grant.grant_id;
    validate_grant_pre_dispatch(state, &audit, &grant, &action).await?;
    // SECURITY: both writes in a single BEGIN IMMEDIATE transaction.
    // The intent is a pre-dispatch durability record; the consumed-grant
    // marker enforces the one-shot execution invariant.
    //
    // Timestamp captured once and reused for both the intent record and
    // the receipt's `started_at`. The `write_intent_and_consume` call
    // between here and WASM dispatch is a single SQLite transaction
    // (~1 ms) — a shared timestamp is accurate for both purposes and
    // avoids a redundant `clock_gettime` syscall.
    let dispatch_start = chrono::Utc::now();

    let intent = ExecutionIntent {
        trace_id: trace_id.to_string(),
        grant_id: grant_id.to_string(),
        action_id: action_id.to_string(),
        principal: identity.principal.to_string(),
        provider_module_digest: action.provider_module_digest.to_string(),
        request_hash: request.request_hash.to_string(),
        approved_by: match &decision_source {
            DecisionSource::HumanApproved { approved_by, .. } => Some(approved_by.to_string()),
            DecisionSource::AutoAllow => None,
        },
        started_at: dispatch_start.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };

    if let Err(e) = write_intent_and_consume(state, &intent, action_id, &identity.principal).await {
        let is_duplicate = matches!(
            e,
            latchgate_ledger::LedgerError::GrantAlreadyConsumed { .. }
        );
        if is_duplicate {
            warn!(
                trace_id = %trace_id, action_id = %action_id, grant_id = %grant_id,
                "SECURITY: grant already consumed — refusing dispatch (one-shot invariant)"
            );
        } else {
            warn!(
                trace_id = %trace_id, action_id = %action_id, grant_id = %grant_id,
                error = %e,
                "SECURITY: pre-dispatch persistence failed — denying before dispatch"
            );
        }
        audit
            .deny_pre_dispatch(
                state,
                &format!("pre-dispatch guard: {e}"),
                "pre_dispatch_persistence",
            )
            .await;
        return Err(if is_duplicate {
            PipelineError::GrantConsumed {
                grant_id: grant_id.to_arc_str(),
            }
        } else {
            PipelineError::StoreUnavailable("pre-dispatch persistence failed".into())
        });
    }
    let run_output = match state.runtime.wasm_runtime.execute(task).await {
        Ok(output) => output,
        Err(e) => {
            // SECURITY: budget intentionally NOT refunded — side effect may
            // have occurred before the error.
            let elapsed = pipeline_start.elapsed();
            state.metrics.record_duration(action_id, elapsed);
            let error_type = classify_provider_error(&e);
            state.metrics.record_provider_error(action_id, error_type);
            if matches!(e, ProviderError::WasmTimeout) {
                state.metrics.record_provider_timeout(action_id);
            }
            state.metrics.record_call(action_id, "error");
            // Surface the provider failure reason to the structured log, not
            // just the audit ledger, so operators can diagnose failures from
            // logs alone. The error string is already persisted to the ledger
            // below; ProviderError carries no secrets, so logging the same
            // sanitized text adds no new exposure.
            warn!(
                trace_id = %trace_id,
                action_id = %action_id,
                error_type,
                error = %e,
                "provider execution failed"
            );
            let ev = audit.event(Decision::Error, Some(format!("provider: {e}")));
            pipeline_audit::write_audit(&state.ledger, &state.metrics, ev).await;
            audit.emit_action_failed(state, error_type);
            return Err(PipelineError::Provider(e));
        }
    };
    enforce_response_schema(state, &audit, action_id, trace_id, &run_output.stdout).await?;
    let verification_input = VerificationInput {
        action_id: Arc::clone(action_id),
        provider_output: Arc::clone(&run_output.stdout),
        exit_code: run_output.exit_code,
        approved_targets: &grant.core.approved_targets,
        verification_config: action.verification_config.clone(),
        host_observed: &run_output.host_observed,
    };
    let verification_outcome = match state
        .runtime
        .verifier_registry
        .verify(action.verifier_kind, &verification_input)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!(trace_id = %trace_id, action_id = %action_id, error = %e,
                "verifier failed to execute");
            VerificationOutcome::VerificationFailed {
                reason: format!("verifier error: {e}"),
            }
        }
    };
    let verification_tag = verification_outcome_tag(&verification_outcome);
    info!(
        trace_id = %trace_id, action_id = %action_id,
        verifier = %state.runtime.verifier_registry.verifier_name(action.verifier_kind),
        outcome = verification_tag, "verification complete"
    );
    let receipt_id = latchgate_core::ReceiptId::new();
    let receipt = build_signed_receipt(
        &grant,
        &action,
        &run_output,
        dispatch_start,
        &verification_outcome,
        &receipt_id,
        state,
    );

    if matches!(action.risk_level, RiskLevel::High | RiskLevel::Critical)
        && !matches!(action.verifier_kind, VerifierKind::None)
        && verification_outcome.is_failed()
    {
        return Err(deny_high_risk_verification_failure(
            state,
            &audit,
            &action,
            &receipt,
            &receipt_id,
            verification_tag,
            trace_id,
            action_id,
        )
        .await);
    }
    finalize_evidence(
        state,
        &audit,
        &grant,
        &request,
        &decision_source,
        &run_output,
        &receipt,
        &receipt_id,
        verification_tag,
    )
    .await?;

    // Webhooks: emitted after evidence is durable.
    state.emit(latchgate_core::DomainEvent::ActionExecuted {
        action_id: Arc::clone(action_id),
        principal: Arc::clone(&identity.principal),
        owner: owner.clone(),
        receipt_id: receipt_id.to_arc_str(),
        verification_outcome: Arc::from(verification_tag),
        trace_id: Arc::clone(trace_id),
    });
    if let DecisionSource::HumanApproved {
        ref approval_id,
        ref approved_by,
        ..
    } = decision_source
    {
        state.emit(latchgate_core::DomainEvent::ApprovalGranted {
            approval_id: Arc::clone(approval_id),
            action_id: Arc::clone(action_id),
            approved_by: Arc::clone(approved_by),
            receipt_id: receipt_id.to_arc_str(),
            trace_id: Arc::clone(trace_id),
        });
    }
    let elapsed = pipeline_start.elapsed();
    let metrics_decision = if verification_tag == "verified" || verification_tag == "not_applicable"
    {
        "allow"
    } else {
        "allow_unverified"
    };
    state.metrics.record_call(action_id, metrics_decision);
    state.metrics.record_policy_decision(metrics_decision);
    state.metrics.record_duration(action_id, elapsed);
    info!(
        trace_id = %trace_id, action_id = %action_id, grant_id = %grant_id,
        receipt_id = %receipt_id, exit_code = run_output.exit_code,
        verification = verification_tag,
        duration_ms = run_output.duration.as_millis() as u64,
        "action execution complete"
    );

    Ok(assemble_execution_response(
        identity,
        grant,
        action,
        decision_source,
        run_output,
        receipt,
        receipt_id,
        verification_tag,
    ))
}

/// Steps 1–3: Validate grant expiry, signature, and approval-hash invariants.
///
/// All checks happen before any side effect — budget rollback is safe.
async fn validate_grant_pre_dispatch(
    state: &AppState,
    audit: &AuditCtx<'_>,
    grant: &ExecutionGrant,
    action: &ActionMetadata,
) -> Result<(), PipelineError> {
    let trace_id = &audit.identity.trace_id;
    let action_id = &audit.action.action_id;
    let grant_id = &grant.grant_id;

    // Step 1: expiry + revocation epoch.
    if !grant.is_valid(chrono::Utc::now(), state.current_revocation_epoch()) {
        audit
            .deny_pre_dispatch(
                state,
                "grant expired or revoked before dispatch",
                "grant_validation_failure",
            )
            .await;
        return Err(PipelineError::GrantIntegrity {
            reason: "grant expired or revoked before dispatch",
        });
    }

    // Step 2: signature verification.
    if !grant.verify_signature(&state.crypto.grant_verifying_key_store) {
        warn!(
            trace_id = %trace_id, action_id = %action_id, grant_id = %grant_id,
            "SECURITY: grant signature verification failed — possible tampering"
        );
        audit
            .deny_pre_dispatch(
                state,
                "grant signature verification failed",
                "grant_signature_failure",
            )
            .await;
        return Err(PipelineError::GrantIntegrity {
            reason: "grant signature verification failed",
        });
    }

    // Step 3: high-risk actions require approval_hash.
    if matches!(action.risk_level, RiskLevel::High | RiskLevel::Critical)
        && grant.approval_hash.is_none()
    {
        warn!(
            trace_id = %trace_id, action_id = %action_id,
            risk_level = ?action.risk_level,
            "SECURITY: high-risk action auto-allowed without approval — denying"
        );
        audit
            .deny_pre_dispatch(
                state,
                "high-risk action missing approval_hash — policy bypass detected",
                "approval_hash_assertion",
            )
            .await;
        return Err(PipelineError::GrantIntegrity {
            reason: "high-risk action executed without required approval",
        });
    }

    Ok(())
}

/// Classify a provider error for metrics recording.
fn classify_provider_error(e: &ProviderError) -> &'static str {
    match e {
        ProviderError::WasmTimeout => "wasm_timeout",
        ProviderError::ModuleNotFound { .. } => "module_not_found",
        ProviderError::DigestMismatch { .. } => "digest_mismatch",
        ProviderError::FuelExhausted => "fuel_exhausted",
        ProviderError::MemoryLimitExceeded => "memory_limit",
        ProviderError::IoBudgetExceeded => "io_budget_exceeded",
        ProviderError::ImportNotDeclared { .. } => "import_not_declared",
        ProviderError::ExecutionFailed { .. } => "execution_failed",
        ProviderError::PathTraversal { .. } => "path_traversal",
        _ => "unknown_provider_error",
    }
}

/// Map a `VerificationOutcome` to its string tag for logging and audit.
fn verification_outcome_tag(outcome: &VerificationOutcome) -> &'static str {
    match outcome {
        VerificationOutcome::Verified { .. } => "verified",
        VerificationOutcome::VerificationFailed { .. } => "verification_failed",
        VerificationOutcome::UnverifiableDeclared => "unverifiable_declared",
        VerificationOutcome::ProviderFailedBeforeVerification => {
            "provider_failed_before_verification"
        }
        VerificationOutcome::Skipped => "skipped",
    }
}

/// Step 5: Enforce response schema validation policy.
///
/// In `Deny` mode, a schema violation fails the execution (budget retained —
/// dispatch already occurred). In `Warn` mode outside dev, fail-closed as a
/// defense-in-depth measure against configuration bypass.
async fn enforce_response_schema(
    state: &AppState,
    audit: &AuditCtx<'_>,
    action_id: &str,
    trace_id: &str,
    provider_stdout: &Arc<serde_json::Value>,
) -> Result<(), PipelineError> {
    let response_limits = ValidationLimits {
        max_bytes: audit.action.max_response_bytes,
        max_depth: 10,
        max_items: 100,
    };

    let schema_err = match schema::validate_response(
        state.registry.load().get_response_validator(action_id),
        provider_stdout,
        &response_limits,
    ) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };

    state.metrics.record_response_schema_violation(action_id);
    warn!(
        trace_id = %trace_id, action_id = %action_id, error = %schema_err,
        enforcement = ?state.config.response_schema_enforcement,
        "action response failed schema validation"
    );

    // SECURITY: Warn mode outside dev_mode is treated as Deny (fail-closed).
    if state.config.response_schema_enforcement == latchgate_config::ResponseSchemaEnforcement::Warn
        && !state.config.dev_mode()
    {
        warn!(
            trace_id = %trace_id, action_id = %action_id,
            "SECURITY: response_schema_enforcement = Warn observed in non-dev \
             context — startup validation bypassed; treating as Deny"
        );
        state.metrics.record_call(action_id, "deny");
        let ev = audit.event(
            Decision::Deny,
            Some(format!(
                "response schema violation (Warn mode rejected outside dev_mode): {schema_err}"
            )),
        );
        pipeline_audit::write_audit(&state.ledger, &state.metrics, ev).await;
        audit.emit_action_failed(state, "response_schema_warn_mode_non_dev");
        return Err(PipelineError::ConfigConstraint {
            reason: "response_schema_enforcement = Warn is not permitted outside dev_mode",
        });
    }

    if state.config.response_schema_enforcement == latchgate_config::ResponseSchemaEnforcement::Deny
    {
        state.metrics.record_call(action_id, "deny");
        let ev = audit.event(
            Decision::Deny,
            Some(format!("response schema violation: {schema_err}")),
        );
        pipeline_audit::write_audit(&state.ledger, &state.metrics, ev).await;
        audit.emit_action_failed(state, "response_schema_violation");
        return Err(PipelineError::Schema(SchemaError::ResponseValidation(
            schema_err.to_string(),
        )));
    }

    Ok(())
}

/// Step 7: Construct, hash, and sign the `ExecutionReceipt`.
fn build_signed_receipt(
    grant: &ExecutionGrant,
    action: &ActionMetadata,
    run_output: &latchgate_providers::RunOutput,
    dispatch_start: chrono::DateTime<chrono::Utc>,
    verification_outcome: &VerificationOutcome,
    receipt_id: &latchgate_core::ReceiptId,
    state: &AppState,
) -> ExecutionReceipt {
    let normalized_result = if run_output.exit_code == 0 {
        NormalizedResult::Success {
            summary: "provider completed successfully".into(),
        }
    } else {
        NormalizedResult::ProviderFailure {
            reason: format!("exit code {}", run_output.exit_code),
        }
    };

    let failure_class = if !normalized_result.is_success() {
        Some(FailureClass::ProviderError)
    } else if verification_outcome.is_failed() {
        Some(FailureClass::VerificationFailed)
    } else {
        None
    };

    let mut receipt = ExecutionReceipt {
        receipt_id: receipt_id.clone(),
        grant_id: grant.grant_id.clone(),
        provider_module_digest: Arc::clone(&action.provider_module_digest),
        provider_receipt: Arc::clone(&run_output.stdout),
        normalized_result,
        verification_outcome: verification_outcome.clone(),
        effect_evidence: vec![],
        result_hash: String::new(),
        receipt_signature: None,
        signing_key_id: None,
        started_at: dispatch_start,
        finished_at: chrono::Utc::now(),
        failure_class,
    };
    receipt.result_hash = receipt.compute_result_hash();
    receipt.sign(&state.crypto.receipt_signer);
    receipt
}

/// Step 8: Write receipt + final audit event transactionally.
///
/// SECURITY: the success response is gated on durable evidence. Receipt
/// and final audit event are written atomically in a single SQLite
/// transaction. If the transaction fails, the client receives an error
/// instead of a false success.
#[allow(clippy::too_many_arguments)]
async fn finalize_evidence(
    state: &AppState,
    audit: &AuditCtx<'_>,
    grant: &ExecutionGrant,
    request: &RequestContext,
    decision_source: &DecisionSource,
    run_output: &latchgate_providers::RunOutput,
    receipt: &ExecutionReceipt,
    receipt_id: &latchgate_core::ReceiptId,
    verification_tag: &'static str,
) -> Result<(), PipelineError> {
    let trace_id = &audit.identity.trace_id;
    let action_id = &audit.action.action_id;

    // SECURITY: scope canonical limits to the action's declared
    // max_response_bytes — not the canonicalizer default (64 KiB). Responses
    // up to the declared limit must produce a real hash. Failure is a hard
    // error: synthetic hashes ("sha256:error") would break the evidence
    // integrity invariant for successful executions.
    let response_hash_limits = canonical::Limits {
        max_bytes: audit.action.max_response_bytes,
        max_depth: 32,
    };
    let (response_hash, response_bytes) =
        canonical::canonical_hash_with_len(&run_output.stdout, &response_hash_limits).map_err(
            |e| {
                warn!(
                    trace_id = %trace_id, action_id = %action_id,
                    error = %e, "response canonical hash failed"
                );
                state.metrics.record_call(action_id, "error");
                audit.emit_action_failed(state, "response_hash_failed");
                PipelineError::EvidencePersistenceFailed {
                    trace_id: Arc::clone(&audit.identity.trace_id),
                    grant_id: grant.grant_id.to_arc_str(),
                }
            },
        )?;

    let duration_ms = run_output.duration.as_millis() as u64;
    #[allow(unreachable_patterns)]
    let egress_str = match &request.egress_profile {
        EgressProfile::None => "none",
        EgressProfile::ProxyAllowlist { .. } => "proxy_allowlist",
        _ => "unknown",
    };

    let policy_reason = match decision_source {
        DecisionSource::AutoAllow => None,
        DecisionSource::HumanApproved { approval_id, .. } => {
            Some(format!("approved via {approval_id}"))
        }
    };

    let decision = if verification_tag == "verified" || verification_tag == "not_applicable" {
        Decision::Allow
    } else {
        Decision::AllowUnverified
    };

    let final_audit = audit
        .event(decision, policy_reason)
        .allowed_sinks(request.allowed_sinks.clone())
        .runtime(RuntimeAudit {
            module_digest: Arc::clone(&audit.action.provider_module_digest),
            egress_profile: Arc::from(egress_str),
            duration_ms,
            exit_code: run_output.exit_code,
            timeout_hit: false,
            fuel_consumed: run_output.fuel_consumed,
            io_calls_made: run_output.io_calls_made,
        })
        .response(response_hash, response_bytes)
        .grant(grant.grant_id.to_arc_str())
        .receipt(receipt_id.to_arc_str(), verification_tag);

    if !write_evidence(state, receipt, final_audit).await {
        warn!(
            trace_id = %trace_id, action_id = %action_id,
            grant_id = %grant.grant_id, receipt_id = %receipt_id,
            "SECURITY: evidence finalization failed after dispatch — budget \
             retained to prevent re-execution; operator must correlate \
             ExecutionIntent without matching receipt and remediate manually"
        );
        state.metrics.record_call(action_id, "error");
        state.metrics.record_audit_write_error();
        audit.emit_action_failed(state, "evidence_persistence_failed");
        return Err(PipelineError::EvidencePersistenceFailed {
            trace_id: Arc::clone(&audit.identity.trace_id),
            grant_id: grant.grant_id.to_arc_str(),
        });
    }

    Ok(())
}

/// SECURITY: deny execution when a verifier fails for a high- or critical-risk
/// action.
///
/// Writes the receipt for forensics and emits audit/metrics before returning
/// the denial error. Budget is intentionally retained — the call was attempted
/// and the budget debit is correct.
#[allow(clippy::too_many_arguments)]
async fn deny_high_risk_verification_failure(
    state: &AppState,
    audit: &AuditCtx<'_>,
    action: &ActionMetadata,
    receipt: &ExecutionReceipt,
    receipt_id: &latchgate_core::ReceiptId,
    verification_tag: &'static str,
    trace_id: &str,
    action_id: &str,
) -> PipelineError {
    let _ = write_receipt(state, receipt).await;
    warn!(
        trace_id = %trace_id, action_id = %action_id,
        risk_level = ?action.risk_level,
        verifier = %state.runtime.verifier_registry.verifier_name(action.verifier_kind),
        outcome = verification_tag,
        "SECURITY: verifier failed for high-risk action — denying"
    );
    state.metrics.record_call(action_id, "deny");
    let ev = audit
        .event(
            Decision::Deny,
            Some(format!(
                "verifier failed for high-risk action: {verification_tag}"
            )),
        )
        .receipt(receipt_id.to_arc_str(), verification_tag);
    pipeline_audit::write_audit(&state.ledger, &state.metrics, ev).await;
    audit.emit_action_failed(
        state,
        &format!("verification_failed_high_risk:{verification_tag}"),
    );
    PipelineError::GrantIntegrity {
        reason: "verifier failed for high-risk action — execution denied",
    }
}

/// Step 9: Assemble the structured execution response.
///
/// Called only after evidence is durably persisted.
#[allow(clippy::too_many_arguments)]
fn assemble_execution_response(
    identity: ExecutionIdentity,
    grant: ExecutionGrant,
    action: ActionMetadata,
    decision_source: DecisionSource,
    run_output: latchgate_providers::RunOutput,
    receipt: ExecutionReceipt,
    receipt_id: latchgate_core::ReceiptId,
    verification_tag: &'static str,
) -> ExecutionResponse {
    let approval = match &decision_source {
        DecisionSource::HumanApproved {
            approval_id,
            approved_by,
            operator_authn_method,
            operator_sender_binding,
            ..
        } => Some(ApprovalProvenance {
            decision: Arc::from("allow"),
            approval_id: Arc::clone(approval_id),
            approved_by: Arc::clone(approved_by),
            approval_hash: grant.approval_hash.clone(),
            operator_authn_method: *operator_authn_method,
            operator_sender_binding: Arc::clone(operator_sender_binding),
        }),
        DecisionSource::AutoAllow => None,
    };

    let duration_ms = run_output.duration.as_millis() as u64;
    let verification_arc: Arc<str> = Arc::from(verification_tag);

    ExecutionResponse {
        decision: "executed",
        trace_id: identity.trace_id,
        action_id: action.action_id,
        grant_id: grant.grant_id.to_arc_str(),
        receipt_id: receipt_id.to_arc_str(),
        output: run_output.stdout,
        verification_outcome: Arc::clone(&verification_arc),
        verification: VerificationInfo {
            outcome: verification_arc,
            is_fully_successful: receipt.is_fully_successful(),
        },
        runtime: RuntimeInfo {
            duration_ms,
            exit_code: run_output.exit_code,
            fuel_consumed: run_output.fuel_consumed,
        },
        approval,
        learned_domain: None,
        learned_path: None,
    }
}

async fn write_intent_and_consume(
    state: &AppState,
    intent: &ExecutionIntent,
    action_id: &Arc<str>,
    principal: &Arc<str>,
) -> Result<(), latchgate_ledger::LedgerError> {
    let ledger = Arc::clone(&state.ledger);
    let intent = intent.clone();
    let action_id = Arc::clone(action_id);
    let principal = Arc::clone(principal);
    let result = tokio::task::spawn_blocking(move || {
        ledger.write_intent_and_consume_grant(&intent, &action_id, &principal)
    })
    .await;
    match result {
        Ok(inner) => inner,
        Err(e) => {
            warn!(error = %e, "write_intent_and_consume task panicked");
            Err(latchgate_ledger::LedgerError::Io(std::io::Error::other(
                "write_intent_and_consume task panicked",
            )))
        }
    }
}

/// Atomically persist receipt + final audit event. Returns `true` on success.
///
/// SECURITY: this is the evidence finalization gate. The success response to
/// the client is only sent if this returns `true`. On failure, the client
/// receives `EvidencePersistenceFailed` instead of a false success.
async fn write_evidence(
    state: &AppState,
    receipt: &ExecutionReceipt,
    builder: AuditEventBuilder,
) -> bool {
    let ledger = Arc::clone(&state.ledger);
    let receipt = receipt.clone();
    let mut event = builder.build();
    let trace_id = event.trace_id.clone();

    let result =
        tokio::task::spawn_blocking(move || ledger.finalize_evidence(&receipt, &mut event)).await;
    match result {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::error!(
                trace_id = %trace_id,
                error = %e,
                "evidence finalization failed — receipt + audit not durable"
            );
            false
        }
        Err(e) => {
            tracing::error!(
                trace_id = %trace_id,
                error = %e,
                "evidence finalization task panicked"
            );
            false
        }
    }
}

/// Persist receipt standalone (best-effort). Used only for forensic writes
/// on deny paths (e.g. verifier failure for high-risk actions) where the
/// receipt records what happened even though the caller receives a denial.
///
/// Not used on the success path — use [`write_evidence`] instead.
async fn write_receipt(state: &AppState, receipt: &ExecutionReceipt) -> bool {
    let ledger = Arc::clone(&state.ledger);
    let receipt = receipt.clone();
    let result = tokio::task::spawn_blocking(move || ledger.write_receipt(&receipt)).await;
    match result {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            warn!(error = %e, "forensic receipt write failed");
            state.metrics.record_audit_write_error();
            false
        }
        Err(e) => {
            warn!(error = %e, "forensic receipt write task panicked");
            state.metrics.record_audit_write_error();
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Instant;

    use chrono::Utc;

    use latchgate_core::types::GrantId;
    use latchgate_core::{BudgetReservation, ExecutionGrantBuilder};
    use latchgate_core::{BudgetSnapshot, EgressProfile, RiskLevel, VerifierKind};
    use latchgate_crypto::GrantBuilderExt;
    use latchgate_crypto::GrantSigner;

    use crate::test_support::test_app_state;

    /// Build a valid, signed grant that passes all pre-dispatch checks.
    fn valid_grant(signer: &GrantSigner) -> ExecutionGrant {
        let now = Utc::now();
        ExecutionGrantBuilder::new(
            GrantId::new(),
            latchgate_core::GrantIdentity {
                subject: "test:agent".into(),
                sender_binding: "thumbprint:test".into(),
            },
            latchgate_core::ExecutionPlanCore {
                action_id: "test_action".into(),
                action_digest: "sha256:action_digest".into(),
                provider_module_digest: "sha256:provider_digest".into(),
                request_hash: "sha256:request".into(),
                policy_version: Some("policy-v1".into()),
                approved_targets: vec!["https://api.example.com".into()],
                approved_secrets: vec![],
                approved_egress: EgressProfile::None,
                expires_at: now + chrono::Duration::minutes(5),
            },
            BudgetReservation {
                calls_before: 10,
                calls_after: 9,
            },
            now,
            0, // revocation_epoch
        )
        .build_and_sign(signer)
    }

    /// Build an `AuthorizedExecution` from a grant with sensible defaults.
    fn test_execution(grant: ExecutionGrant) -> AuthorizedExecution {
        AuthorizedExecution {
            identity: ExecutionIdentity {
                trace_id: "test-trace-001".into(),
                principal: "test:agent".into(),
                owner: None,
                session_id: "session-001".into(),
                lease_jti: "jti-001".into(),
            },
            action: ActionMetadata {
                action_id: grant.core.action_id.clone(),
                action_version: "1.0.0".into(),
                provider_module_digest: grant.core.provider_module_digest.clone(),
                trust_verdict_str: "trusted".into(),
                risk_level: RiskLevel::Low,
                verifier_kind: VerifierKind::None,
                verification_config: None,
                max_response_bytes: 1_000_000,
            },
            request: RequestContext {
                request_hash: Arc::clone(&grant.core.request_hash),
                schema_id: None,
                policy_version: Some("policy-v1".into()),
                allowed_sinks: vec!["https://api.example.com".into()],
                egress_profile: EgressProfile::None,
            },
            budget: BudgetContext {
                budgets_before: BudgetSnapshot {
                    calls_remaining: 10,
                },
                budgets_after: BudgetSnapshot { calls_remaining: 9 },
                budget_debited: false,
            },
            decision_source: DecisionSource::AutoAllow,
            task: latchgate_providers::RunTask {
                trace_id: Arc::from("test-trace-001"),
                module_digest: grant.core.provider_module_digest.clone(),
                args_json: "{}".into(),
                allowed_sinks: vec![],
                allowed_imports: vec![],
                approved_secrets: vec![],
                decrypted_secrets: Default::default(),
                resource_limits: latchgate_core::ResourceLimits::default(),
                database_config: None,
                egress_proxy_url: None,
                fs_config: None,
            },
            grant,
            pipeline_start: Instant::now(),
        }
    }

    // ===================================================================
    // Step 1: Grant expiry and revocation
    // ===================================================================

    #[tokio::test]
    async fn expired_grant_is_denied() {
        let (state, signer) = test_app_state();
        let now = Utc::now();

        // Grant that expired 1 minute ago.
        let grant = ExecutionGrantBuilder::new(
            GrantId::new(),
            latchgate_core::GrantIdentity {
                subject: "test:agent".into(),
                sender_binding: "thumbprint:test".into(),
            },
            latchgate_core::ExecutionPlanCore {
                action_id: "test_action".into(),
                action_digest: "sha256:ad".into(),
                provider_module_digest: "sha256:pd".into(),
                request_hash: "sha256:req".into(),
                policy_version: Some("pv1".into()),
                approved_targets: vec![],
                approved_secrets: vec![],
                approved_egress: EgressProfile::None,
                expires_at: now - chrono::Duration::minutes(1), // already expired
            },
            BudgetReservation {
                calls_before: 1,
                calls_after: 0,
            },
            now - chrono::Duration::minutes(10),
            0,
        )
        .build_and_sign(&signer);

        let ctx = test_execution(grant);
        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantIntegrity { .. }),
            "expected expiry denial, got: {err}"
        );
    }

    #[tokio::test]
    async fn revoked_grant_is_denied() {
        let (state, signer) = test_app_state();

        // Advance the global revocation epoch past the grant's epoch.
        state
            .lifecycle
            .revocation_epoch
            .store(5, std::sync::atomic::Ordering::Release);

        let now = Utc::now();
        let grant = ExecutionGrantBuilder::new(
            GrantId::new(),
            latchgate_core::GrantIdentity {
                subject: "test:agent".into(),
                sender_binding: "thumbprint:test".into(),
            },
            latchgate_core::ExecutionPlanCore {
                action_id: "test_action".into(),
                action_digest: "sha256:ad".into(),
                provider_module_digest: "sha256:pd".into(),
                request_hash: "sha256:req".into(),
                policy_version: Some("pv1".into()),
                approved_targets: vec![],
                approved_secrets: vec![],
                approved_egress: EgressProfile::None,
                expires_at: now + chrono::Duration::minutes(5),
            },
            BudgetReservation {
                calls_before: 1,
                calls_after: 0,
            },
            now,
            0, // grant epoch 0 < global epoch 5 => revoked
        )
        .build_and_sign(&signer);

        let ctx = test_execution(grant);
        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantIntegrity { .. }),
            "expected revocation denial, got: {err}"
        );
    }

    // ===================================================================
    // Step 2: Grant signature verification
    // ===================================================================

    #[tokio::test]
    async fn tampered_grant_is_denied() {
        let (state, signer) = test_app_state();
        let mut grant = valid_grant(&signer);

        // Corrupt the signature after signing.
        if let Some(ref mut sig) = grant.grant_signature {
            sig.replace_range(..4, "ffff");
        }

        let ctx = test_execution(grant);
        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantIntegrity { .. }),
            "expected signature failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn grant_signed_by_unknown_key_is_denied() {
        let (state, _signer) = test_app_state();

        // Sign with a different key not in the verifying key store.
        let rogue_signer = GrantSigner::generate();
        let grant = valid_grant(&rogue_signer);

        let ctx = test_execution(grant);
        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantIntegrity { .. }),
            "expected unknown-key denial, got: {err}"
        );
    }

    // ===================================================================
    // Step 3: High-risk without approval_hash
    // ===================================================================

    #[tokio::test]
    async fn high_risk_without_approval_hash_is_denied() {
        let (state, signer) = test_app_state();
        let grant = valid_grant(&signer);

        // Grant has no approval_hash (auto-allow), but risk is High.
        assert!(grant.approval_hash.is_none());
        let mut ctx = test_execution(grant);
        ctx.action.risk_level = RiskLevel::High;

        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantIntegrity { .. }),
            "expected high-risk denial, got: {err}"
        );
    }

    #[tokio::test]
    async fn critical_risk_without_approval_hash_is_denied() {
        let (state, signer) = test_app_state();
        let grant = valid_grant(&signer);
        let mut ctx = test_execution(grant);
        ctx.action.risk_level = RiskLevel::Critical;

        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantIntegrity { .. }),
            "expected critical-risk denial, got: {err}"
        );
    }

    // ===================================================================
    // Step 3.6: One-shot grant consumption (duplicate prevention)
    // ===================================================================

    #[tokio::test]
    async fn grant_consumed_twice_is_denied() {
        let (state, signer) = test_app_state();
        let grant = valid_grant(&signer);

        // First execution: passes grant consumption but fails at WASM dispatch
        // (no module loaded). That's fine — the grant is already consumed.
        let ctx1 = test_execution(grant.clone());
        let result1 = execute_authorized_plan(&state, ctx1).await;
        // Expect provider error (ModuleNotFound) since no WASM is loaded.
        assert!(result1.is_err(), "first call should fail at WASM dispatch");

        // Second execution with the same grant_id: must be denied at the
        // one-shot guard (step 3.6), NOT at WASM dispatch.
        let ctx2 = test_execution(grant);
        let err = execute_authorized_plan(&state, ctx2).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::GrantConsumed { ref grant_id } if !grant_id.is_empty()),
            "expected GrantConsumed for duplicate grant, got: {err}"
        );
    }

    // ===================================================================
    // Low-risk auto-allow passes pre-dispatch checks
    // ===================================================================

    #[tokio::test]
    async fn valid_grant_passes_pre_dispatch_checks() {
        let (state, signer) = test_app_state();
        let grant = valid_grant(&signer);
        let ctx = test_execution(grant);

        // A valid grant with Low risk and correct signature should pass
        // all pre-dispatch checks (steps 1–3.6). It will fail at WASM
        // dispatch (step 4) because no provider module is loaded — but
        // the point is it REACHES step 4, proving all guards passed.
        let err = execute_authorized_plan(&state, ctx).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::Provider(_)),
            "expected provider error (no module), not a pre-dispatch denial: {err}"
        );
    }

    // ===================================================================
    // DecisionSource serialization
    // ===================================================================

    #[test]
    fn decision_source_auto_allow_serializes() {
        let ds = DecisionSource::AutoAllow;
        let json = serde_json::to_value(&ds).unwrap();
        assert_eq!(json, "auto_allow");
    }

    #[test]
    fn decision_source_human_approved_serializes() {
        let ds = DecisionSource::HumanApproved {
            approval_id: Arc::from("apr-001"),
            approved_by: Arc::from("operator@example.com"),
            operator_authn_method: OperatorAuthnMethod::Dpop,
            operator_sender_binding: Arc::from("thumb:abc"),
            operator_proof_jti: Arc::from("jti-proof"),
        };
        let json = serde_json::to_value(&ds).unwrap();
        let inner = &json["human_approved"];
        assert_eq!(inner["approval_id"], "apr-001");
        assert_eq!(inner["approved_by"], "operator@example.com");
    }
}
