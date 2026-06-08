//! Kernel-level approval enforcement: prepare an approved execution.
//!
//! This module owns the **entire** enforcement pipeline for approved action
//! calls. The API layer (`api/approvals.rs`) handles HTTP concerns (operator
//! auth, claim lifecycle, Redis/SQLite persistence) and then delegates ALL
//! security enforcement to [`prepare_approved_execution`].
//!
//! # Security invariant
//!
//! There is exactly ONE code path that transforms a `PendingApproval` into an
//! `AuthorizedExecution`.

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use tracing::{info, warn};

use latchgate_auth::OperatorAuthnMethod;
use latchgate_core::crypto::canonical;
use latchgate_core::types::GrantId;
use latchgate_core::BudgetReservation;
use latchgate_core::TrustError;
use latchgate_core::TrustVerdict;
use latchgate_crypto::GrantBuilderExt;
use latchgate_ledger::{AuditEventBuilder, Decision, EventType};
use latchgate_policy::PolicyError;
use latchgate_providers::RunTask;
use latchgate_state::approvals::PendingApproval;

use crate::execution::{
    ActionMetadata, AuthorizedExecution, BudgetContext, DecisionSource, ExecutionIdentity,
    RequestContext,
};
use crate::pipeline::PipelineError;
use crate::pipeline_audit::{self, PipelineAudit};
use crate::state::AppState;

/// Operator identity and authentication context, extracted by the API layer
/// before calling into the kernel.
///
/// The kernel does not perform operator authentication — that is an HTTP/API
/// concern. The kernel trusts that the API layer verified these fields.
#[derive(Debug, Clone)]
pub struct OperatorContext {
    pub operator_id: Arc<str>,
    pub authn_method: OperatorAuthnMethod,
    pub sender_binding: Arc<str>,
    pub proof_jti: Arc<str>,
}

/// Transform a claimed `PendingApproval` into an `AuthorizedExecution`.
///
/// This function performs every enforcement step that the auto-allow pipeline
/// performs between policy evaluation and dispatch:
///
/// 1. Plan hash verification (tamper detection)
/// 2. Plan expiry check
/// 3. Trust re-verification (against the plan's digest, not the live manifest)
/// 4. Request integrity (canonical hash recompute)
/// 5. Secret resolution (policy-approved subset only)
/// 6. Budget debit (atomic, same path as auto-allow)
/// 7. ExecutionGrant construction (with approval binding)
/// 8. Concrete sink resolution + learned domain merge
/// 9. RunTask construction
/// 10. AuthorizedExecution assembly
///
/// On any enforcement failure, this function writes the appropriate audit
/// event and returns `Err(PipelineError)`. The API layer does NOT need to
/// write enforcement audit events — only orchestration-level events (claim,
/// persist outcome, etc.).
///
/// # Arguments
///
/// * `state` — shared application state (registry, ledger, secrets, budgets, etc.)
/// * `pending` — the claimed pending approval (immutable execution plan + request context)
/// * `operator` — authenticated operator identity
/// * `approval_id` — the approval identifier (for grant binding and audit)
/// * `trace_id` — fresh trace ID for this execution (distinct from the original request's trace)
/// * `pipeline_start` — timestamp for duration metrics
#[tracing::instrument(
    name = "kernel.prepare_approved_execution",
    skip(state, pending, operator),
    fields(
        %approval_id,
        %trace_id,
        action_id = %pending.action_id,
    ),
)]

/// Transform a claimed `PendingApproval` into an `AuthorizedExecution`.
///
/// Performs every enforcement step that the auto-allow pipeline performs
/// between policy evaluation and dispatch:
///
/// 1–4. Plan hash, expiry, trust, request integrity (via `validate_approved_plan`)
/// 5. Manifest resolution (schema validators)
/// 6. Secret resolution (policy-approved subset only)
/// 7. Budget debit (atomic, same path as auto-allow)
/// 8–11. Grant construction, sink resolution, RunTask, AuthorizedExecution
///
/// On any enforcement failure, writes the appropriate audit event and
/// returns `Err(PipelineError)`. The API layer does NOT need to write
/// enforcement audit events.
#[tracing::instrument(
    name = "kernel.prepare_approved_execution",
    skip(state, pending, operator),
    fields(
        %approval_id,
        %trace_id,
        action_id = %pending.action_id,
    ),
)]
pub async fn prepare_approved_execution(
    state: &AppState,
    pending: &PendingApproval,
    operator: &OperatorContext,
    approval_id: &str,
    trace_id: &str,
    pipeline_start: Instant,
) -> Result<AuthorizedExecution, PipelineError> {
    let trust_verdict_str = validate_approved_plan(state, pending).await?;

    // Audit context for the remainder of the function. All fields are known
    // after plan validation: identity from stored auth_context, action from
    // the immutable plan, trust verdict from the re-check above.
    let audit = PipelineAudit::from_pending(pending, trust_verdict_str, state.config.dev_mode());

    // Step 5: Resolve action manifest (before hash integrity check so
    // canonical limits can be scoped to the action's max_request_bytes).
    // SECURITY: the registry is consulted for response schema validators,
    // I/O config, and request-size limits for canonical hashing. All other
    // security-relevant execution parameters come from the immutable plan.
    let registry = state.registry.load();
    let manifest =
        registry
            .get_action(&pending.action_id)
            .ok_or_else(|| PipelineError::ActionNotFound {
                action_id: pending.action_id.clone(),
            })?;

    // SECURITY: re-hash the stored request body with action-scoped limits
    // and compare to the stored hash. Using the action's max_request_bytes
    // instead of the canonicalizer default (64 KiB) ensures bodies that
    // were accepted at request time can be re-verified on approval.
    let canonical_limits = canonical::Limits {
        max_bytes: manifest.io.max_request_bytes,
        max_depth: 32,
    };
    let request_hash = canonical::canonical_hash(&pending.request_body, &canonical_limits)
        .map_err(|e| PipelineError::CanonicalHash(e.to_string()))?;

    if request_hash != *pending.request_hash {
        state.metrics.record_call(&pending.action_id, "deny");
        audit
            .write(
                &state.ledger,
                &state.metrics,
                Decision::Deny,
                pending.policy_version.clone(),
                Some("request hash mismatch: stored data may be tampered".into()),
            )
            .await;
        return Err(PipelineError::PlanIntegrity {
            reason: "request hash mismatch on approval",
        });
    }

    let schema_id: Option<String> = registry
        .get_request_validator(&pending.action_id)
        .map(|_| format!("{}:request", pending.action_id));
    let decrypted_secrets = resolve_approved_secrets(state, pending, &audit, trace_id).await?;
    let has_budgets = pending.plan.budget_calls_remaining != i64::MAX;
    let budgets_before = latchgate_core::BudgetSnapshot {
        calls_remaining: pending.plan.budget_calls_remaining,
    };
    let mut budget_debited = false;

    let budgets_after = if has_budgets {
        match state
            .enforcement
            .budget_manager
            .get_and_debit(&pending.auth_context.session_id)
            .await
        {
            Ok(snap) => {
                budget_debited = true;
                snap
            }
            Err(e) => {
                state.metrics.record_call(&pending.action_id, "deny");
                audit
                    .write(
                        &state.ledger,
                        &state.metrics,
                        Decision::Deny,
                        pending.policy_version.clone(),
                        Some(format!("budget: {e}")),
                    )
                    .await;
                return Err(PipelineError::Budget(e));
            }
        }
    } else {
        budgets_before
    };
    // SECURITY: every early exit between budget debit (above) and a
    // successful return MUST rollback. The async block + match gate
    // enforces this structurally.
    let request_hash: Arc<str> = request_hash.into();

    let build = build_authorized_execution(
        state,
        pending,
        operator,
        approval_id,
        trace_id,
        trust_verdict_str,
        schema_id,
        decrypted_secrets,
        budgets_before,
        budgets_after,
        budget_debited,
        request_hash,
        pipeline_start,
    )
    .await;

    match build {
        Ok(exec) => Ok(exec),
        Err(e) => {
            crate::pipeline_audit::rollback_budget_if_debited(
                state,
                &pending.auth_context.session_id,
                budget_debited,
                trace_id,
                "approval_enforcement_error",
            )
            .await;

            state.metrics.record_call(&pending.action_id, "error");
            audit
                .write(
                    &state.ledger,
                    &state.metrics,
                    Decision::Error,
                    pending.policy_version.clone(),
                    Some(format!("{e}")),
                )
                .await;

            Err(e)
        }
    }
}

/// Build a deny audit event with the pending approval's context.
fn build_plan_deny_audit(
    pending: &PendingApproval,
    state: &AppState,
    trust_str: &str,
    reason: &str,
) -> AuditEventBuilder {
    AuditEventBuilder::new(&*pending.trace_id, EventType::ActionCall)
        .principal(
            pending.auth_context.principal.clone(),
            pending.auth_context.session_id.clone(),
            pending.auth_context.lease_jti.clone(),
        )
        .action(
            pending.action_id.clone(),
            Some(pending.plan.action_version.clone()),
            Arc::clone(&pending.plan.core.provider_module_digest),
            trust_str,
        )
        .risk_level(pending.plan.risk_level.as_str())
        .approval_id(pending.approval_id.as_str())
        .policy(
            Decision::Deny,
            pending.policy_version.clone(),
            Some(reason.to_string()),
        )
        .flags(state.config.dev_mode(), false)
}

/// Steps 1–3: Verify plan hash, expiry, and trust digest.
///
/// Returns the trust verdict string on success (needed by later steps).
async fn validate_approved_plan(
    state: &AppState,
    pending: &PendingApproval,
) -> Result<&'static str, PipelineError> {
    // Step 1: Plan hash verification.
    if !pending.plan.verify_hash() {
        state.metrics.record_call(&pending.action_id, "deny");
        let audit = build_plan_deny_audit(
            pending,
            state,
            "plan_hash_failed",
            "execution plan hash verification failed — possible tampering",
        );
        pipeline_audit::write_audit(&state.ledger, &state.metrics, audit).await;
        return Err(PipelineError::PlanIntegrity {
            reason: "execution plan hash verification failed",
        });
    }

    // Step 2: Plan expiry.
    if Utc::now() >= pending.plan.core.expires_at {
        state.metrics.record_call(&pending.action_id, "deny");
        let audit = build_plan_deny_audit(pending, state, "expired", "execution plan expired");
        pipeline_audit::write_audit(&state.ledger, &state.metrics, audit).await;
        return Err(PipelineError::PlanIntegrity {
            reason: "execution plan expired before approval",
        });
    }

    // Step 3: Trust re-verification against the plan's digest.
    let trust_verdict = state.registry.load().verify_digest(
        &pending.action_id,
        &pending.plan.core.provider_module_digest,
    );
    let trust_verdict_str = match &trust_verdict {
        TrustVerdict::DigestOk => "digest_ok",
        TrustVerdict::DigestMismatch { .. } => "mismatch",
        TrustVerdict::NotRegistered => "not_registered",
    };

    if let Err(e) = TrustError::from_verdict(&pending.action_id, &trust_verdict) {
        state.metrics.record_call(&pending.action_id, "deny");
        let audit = build_plan_deny_audit(
            pending,
            state,
            trust_verdict_str,
            &format!("trust changed since approval: {e}"),
        );
        pipeline_audit::write_audit(&state.ledger, &state.metrics, audit).await;
        return Err(PipelineError::Trust(e));
    }

    Ok(trust_verdict_str)
}

/// Step 6: Resolve secrets approved in the execution plan.
async fn resolve_approved_secrets(
    state: &AppState,
    pending: &PendingApproval,
    audit: &PipelineAudit,
    trace_id: &str,
) -> Result<std::collections::HashMap<String, zeroize::Zeroizing<String>>, PipelineError> {
    match state
        .runtime
        .secrets_manager
        .resolve_approved(
            &pending.plan.core.approved_secrets,
            &pending.plan.secret_declarations,
            state.config.secrets.sops_secrets_file.as_deref(),
        )
        .await
    {
        Ok(secrets) => {
            if !secrets.is_empty() {
                let key_list: Vec<&str> = secrets.keys().map(|k| k.as_str()).collect();
                info!(
                    trace_id = %trace_id,
                    action_id = %pending.action_id,
                    injected_secrets = ?key_list,
                    "secrets decrypted for approved execution"
                );
            }
            Ok(secrets)
        }
        Err(e) => {
            let err_msg = e.to_string();
            warn!(
                trace_id = %trace_id,
                action_id = %pending.action_id,
                error = %err_msg,
                "secret resolution failed for approved execution"
            );
            state.metrics.record_call(&pending.action_id, "error");
            audit
                .write(
                    &state.ledger,
                    &state.metrics,
                    Decision::Error,
                    pending.policy_version.clone(),
                    Some(err_msg.clone()),
                )
                .await;

            let pipeline_err = match e {
                latchgate_providers::SecretsError::RequiredSecretsButNoSopsFile { .. } => {
                    PipelineError::Policy(PolicyError::denied(
                        err_msg,
                        pending.auth_context.principal.clone(),
                        pending.action_id.clone(),
                    ))
                }
                _ => PipelineError::SecretResolution(format!("secret injection: {err_msg}")),
            };
            Err(pipeline_err)
        }
    }
}

/// Steps 8–11: Construct grant, resolve sinks, build RunTask, assemble output.
///
/// Wrapped in a separate function so the rollback guard in the caller
/// catches any `?` exit structurally — no per-call-site bookkeeping.
#[allow(clippy::too_many_arguments)]
async fn build_authorized_execution(
    state: &AppState,
    pending: &PendingApproval,
    operator: &OperatorContext,
    approval_id: &str,
    trace_id: &str,
    trust_verdict_str: &str,
    schema_id: Option<String>,
    decrypted_secrets: std::collections::HashMap<String, zeroize::Zeroizing<String>>,
    budgets_before: latchgate_core::BudgetSnapshot,
    budgets_after: latchgate_core::BudgetSnapshot,
    budget_debited: bool,
    request_hash: Arc<str>,
    pipeline_start: Instant,
) -> Result<AuthorizedExecution, PipelineError> {
    // Fault injection for regression tests.
    #[cfg(feature = "test-hooks")]
    {
        let armed = state
            .lifecycle
            .fault_after_budget_debit
            .swap(false, std::sync::atomic::Ordering::AcqRel);
        if armed {
            return Err(PipelineError::Internal(
                "fault-injected after budget debit (test-hooks)".into(),
            ));
        }
    }

    // Step 8: Construct ExecutionGrant with approval binding.
    let grant_id = GrantId::new();
    let grant_issued_at = Utc::now();
    let grant_expires_at = grant_issued_at
        + chrono::Duration::seconds(pending.plan.resource_limits.timeout_seconds as i64 + 30);

    let operator_binding: Option<Arc<str>> = if operator.sender_binding.is_empty() {
        None
    } else {
        Some(Arc::from(&*operator.sender_binding))
    };

    let grant_core = latchgate_core::ExecutionPlanCore {
        expires_at: grant_expires_at,
        ..pending.plan.core.clone()
    };

    let grant = latchgate_core::ExecutionGrantBuilder::new(
        grant_id.clone(),
        latchgate_core::GrantIdentity {
            subject: pending.auth_context.principal.clone(),
            sender_binding: pending.auth_context.sender_thumbprint.clone(),
        },
        grant_core,
        BudgetReservation {
            calls_before: budgets_before.calls_remaining,
            calls_after: budgets_after.calls_remaining,
        },
        grant_issued_at,
        state.current_revocation_epoch(),
    )
    .approved_by(&*operator.operator_id)
    .operator_binding(operator_binding)
    .with_approval_for(approval_id, &*pending.plan.plan_hash)
    .build_and_sign(&state.crypto.grant_signer);

    info!(
        trace_id = %trace_id,
        approval_id = %approval_id,
        grant_id = %grant_id,
        approval_hash = ?grant.approval_hash,
        plan_hash = %pending.plan.plan_hash,
        "execution grant issued for approved request"
    );

    // Step 9: Resolve concrete sinks.
    let concrete_sinks = crate::learned_allowlist::resolve_effective_sinks(
        &state.ledger,
        &state.config,
        &pending.action_id,
        trace_id,
        &pending.plan.core.approved_egress,
    )
    .await;

    // Resolve the provider module digest. The plan stores the manifest value
    // (e.g. `builtin:http_api`); the module cache is keyed by the concrete
    // content SHA, so an unresolved `builtin:` label would miss and surface
    // as a spurious ModuleNotFound at dispatch. Resolve through the same
    // single source of truth the direct pipeline uses.
    let module_digest: Arc<str> = state
        .runtime
        .wasm_runtime
        .resolve_module_digest(&pending.plan.core.provider_module_digest)
        .map_err(PipelineError::Provider)?
        .into();

    // Resolve the filesystem host config from the immutable plan — never the
    // live manifest. The plan stores the manifest `fs` block as opaque JSON;
    // deserialize it and build through the same single source of truth the
    // auto-allow path uses. `precompiled = None` forces a fresh compile that
    // merges currently-learned paths; a gate without a configured fs root
    // yields `None` (provider permits nothing), failing closed.
    let fs_config = match pending.plan.fs.as_deref() {
        Some(fs_value) => {
            let parsed: latchgate_registry::manifest::FsConfig =
                serde_json::from_value(fs_value.clone()).map_err(|e| {
                    PipelineError::Internal(format!("deserialise approved fs config: {e}"))
                })?;
            let session_fs_root: Option<std::path::PathBuf> = state
                .runtime
                .session_fs_roots
                .get(&*pending.auth_context.session_id)
                .map(|entry| entry.canonical.clone());
            crate::learned_allowlist::build_fs_host_config(
                state,
                &pending.action_id,
                &parsed,
                None,
                session_fs_root.as_deref(),
            )
            .await
        }
        None => None,
    };

    // Step 10: Build RunTask.
    let args_json = serde_json::to_string(&pending.request_body)
        .map_err(|e| PipelineError::Internal(format!("serialise args: {e}")))?;

    let task = RunTask {
        module_digest: module_digest.clone(),
        args_json,
        allowed_imports: pending.plan.required_imports.clone(),
        resource_limits: pending.plan.resource_limits.clone(),
        allowed_sinks: concrete_sinks.clone(),
        approved_secrets: pending.plan.core.approved_secrets.clone(),
        decrypted_secrets,
        trace_id: Arc::from(trace_id),
        database_config: pending.plan.database_config.as_deref().and_then(|v| {
            serde_json::from_value::<latchgate_providers::DatabaseConfig>(v.clone()).ok()
        }),
        egress_proxy_url: state
            .config
            .egress
            .egress_proxy_url
            .as_deref()
            .map(Arc::from),
        fs_config,
    };

    // Step 11: Assemble AuthorizedExecution.
    Ok(AuthorizedExecution {
        identity: ExecutionIdentity {
            trace_id: Arc::from(trace_id),
            principal: pending.auth_context.principal.clone(),
            owner: pending.auth_context.owner.as_deref().map(Arc::from),
            session_id: pending.auth_context.session_id.clone(),
            lease_jti: pending.auth_context.lease_jti.clone(),
        },
        grant,
        task,
        action: ActionMetadata {
            action_id: pending.action_id.clone(),
            action_version: pending.plan.action_version.clone(),
            provider_module_digest: pending.plan.core.provider_module_digest.clone(),
            trust_verdict_str: Arc::from(trust_verdict_str),
            risk_level: pending.plan.risk_level,
            verifier_kind: pending.plan.verifier_kind,
            verification_config: pending.plan.verification_config.clone(),
            max_response_bytes: pending.plan.max_response_bytes,
        },
        request: RequestContext {
            request_hash,
            schema_id,
            policy_version: pending.policy_version.clone(),
            allowed_sinks: concrete_sinks,
            egress_profile: pending.plan.core.approved_egress.clone(),
        },
        budget: BudgetContext {
            budgets_before,
            budgets_after,
            budget_debited,
        },
        decision_source: DecisionSource::HumanApproved {
            approval_id: Arc::from(approval_id),
            approved_by: Arc::clone(&operator.operator_id),
            operator_authn_method: operator.authn_method,
            operator_sender_binding: Arc::clone(&operator.sender_binding),
            operator_proof_jti: Arc::clone(&operator.proof_jti),
        },
        pipeline_start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;

    use latchgate_core::ApprovedExecutionPlan;
    use latchgate_state::approvals::{PendingApproval, StoredAuthContext};

    /// Construct a minimal `AppState` with all in-memory backends.
    fn test_app_state() -> AppState {
        let (state, _signer) = crate::test_support::test_app_state();
        state
    }

    fn test_operator() -> OperatorContext {
        OperatorContext {
            operator_id: Arc::from("test-operator"),
            authn_method: OperatorAuthnMethod::Dpop,
            sender_binding: Arc::from("thumb:op"),
            proof_jti: Arc::from("jti-op-proof"),
        }
    }

    fn test_pending(plan: ApprovedExecutionPlan) -> PendingApproval {
        PendingApproval {
            approval_id: "apr-test-001".into(),
            trace_id: "trace-test-001".into(),
            action_id: plan.core.action_id.clone(),
            auth_context: StoredAuthContext {
                principal: "test:agent".into(),
                session_id: "session-001".into(),
                lease_jti: "jti-001".into(),
                sender_thumbprint: "thumb:agent".into(),
                owner: None,
            },
            request_hash: plan.core.request_hash.clone(),
            request_body: Arc::new(serde_json::json!({"url": "https://example.com"})),
            policy_version: plan.core.policy_version.clone(),
            created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            plan,
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        }
    }

    // ===================================================================
    // Step 1: Plan hash verification (tamper detection)
    // ===================================================================

    #[tokio::test]
    async fn tampered_plan_is_denied() {
        let state = test_app_state();
        let mut plan = ApprovedExecutionPlan::test_default();

        // Tamper after finalize: widen approved_targets.
        plan.core.approved_targets.push("https://evil.com".into());
        // plan_hash is stale — verify_hash() will return false.

        let pending = test_pending(plan);
        let operator = test_operator();

        let err = prepare_approved_execution(
            &state,
            &pending,
            &operator,
            "apr-001",
            "trace-001",
            Instant::now(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, PipelineError::PlanIntegrity { .. }),
            "expected plan hash failure, got: {err}"
        );
    }

    // ===================================================================
    // Step 2: Plan expiry
    // ===================================================================

    #[tokio::test]
    async fn expired_plan_is_denied() {
        let state = test_app_state();
        let mut plan = ApprovedExecutionPlan::test_default();

        // Set expiry in the past.
        plan.core.expires_at = Utc::now() - chrono::Duration::minutes(1);
        plan.finalize();

        let pending = test_pending(plan);
        let operator = test_operator();

        let err = prepare_approved_execution(
            &state,
            &pending,
            &operator,
            "apr-001",
            "trace-001",
            Instant::now(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, PipelineError::PlanIntegrity { .. }),
            "expected expiry denial, got: {err}"
        );
    }

    // ===================================================================
    // Valid plan passes hash + expiry checks
    // ===================================================================

    #[tokio::test]
    async fn valid_plan_passes_hash_and_expiry() {
        let state = test_app_state();
        let plan = ApprovedExecutionPlan::test_default();
        let pending = test_pending(plan);
        let operator = test_operator();

        // A valid plan should pass steps 1-2. It will fail at step 3
        // (trust re-verification) because no manifest is loaded in the
        // registry — but that proves hash and expiry checks passed.
        let err = prepare_approved_execution(
            &state,
            &pending,
            &operator,
            "apr-001",
            "trace-001",
            Instant::now(),
        )
        .await
        .unwrap_err();

        // Should NOT be a hash or expiry error.
        let msg = err.to_string();
        assert!(
            !msg.contains("hash") && !msg.contains("expired"),
            "valid plan should pass hash+expiry; got: {msg}"
        );
    }
}
