//! Steps 7a–9: pending-approval storage, budget debit, and run-task assembly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use latchgate_auth::AuthContext;
use latchgate_core::BudgetSnapshot;
use latchgate_crypto::GrantBuilderExt;
use latchgate_ledger::Decision;
use latchgate_policy::PolicyError;
use latchgate_providers::RunTask;
use latchgate_registry::{ActionSpec, SchemaError};
use latchgate_state::approvals::StoredAuthContext;
use latchgate_state::{BudgetError, PendingApproval};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::deny_and_audit;
use super::types::{
    BuildRunTaskInput, BuildRunTaskOutput, DebitBudgetOutput, StorePendingApprovalInput,
};
use crate::learned_allowlist;
use crate::pipeline::{ApprovalResponse, PipelineError};
use crate::request::RequestCtx;
use crate::state::AppState;

/// Store the immutable execution plan for later operator approval and
/// return `PipelineError::Approval` (a 202 response at the API boundary).
///
/// SECURITY: the plan persisted here is the single source of truth for
/// what was approved. On approve, the kernel uses fields from the
/// stored plan — NEVER the live manifest. This prevents a manifest
/// update between pending and approve from silently changing provider
/// behavior.
pub(crate) async fn step_store_pending_approval(
    state: &AppState,
    ctx: &mut RequestCtx,
    auth_ctx: &AuthContext,
    manifest: &ActionSpec,
    input: StorePendingApprovalInput,
) -> PipelineError {
    state
        .metrics
        .record_call(&ctx.action_id, "pending_approval");
    state.metrics.record_policy_decision("pending_approval");

    // SECURITY: build immutable execution plan NOW from the
    // policy-narrowed decision. approved_targets / approved_secrets /
    // approved_egress come from the POLICY decision, not the manifest —
    // the policy engine may have narrowed any of these.
    let plan_expires_at = chrono::Utc::now()
        + chrono::Duration::from_std(state.enforcement.approval_store.default_ttl())
            .unwrap_or_else(|_| chrono::Duration::minutes(5));

    let mut plan = latchgate_core::ApprovedExecutionPlan {
        core: latchgate_core::ExecutionPlanCore {
            action_id: Arc::clone(&ctx.action_id),
            action_digest: Arc::from(manifest.content_digest.as_str()),
            provider_module_digest: Arc::clone(&manifest.provider_module_digest),
            request_hash: Arc::clone(&input.request_hash),
            approved_targets: input.policy.allowed_sinks,
            approved_secrets: input.policy.approved_secrets,
            approved_egress: input.policy.approved_egress,
            policy_version: input.policy_version.clone(),
            expires_at: plan_expires_at,
        },
        action_version: Arc::clone(&manifest.version),
        required_imports: manifest.required_imports.clone(),
        resource_limits: manifest.resource_limits.clone(),
        verifier_kind: manifest.verifier_kind,
        verification_config: manifest.verification_config.clone(),
        risk_level: manifest.risk_level,
        max_response_bytes: manifest.io.max_response_bytes,
        secret_declarations: manifest.secrets.clone(),
        budget_calls_remaining: input.budgets_before.calls_remaining,
        policy_approved_calls_after: input.policy_budgets_after.calls_remaining,
        trust_verdict: input.trust_verdict,
        database_config: manifest.database_config.clone(),
        fs: manifest
            .fs
            .as_ref()
            .map(|f| Arc::new(serde_json::to_value(f).unwrap_or(serde_json::Value::Null))),
        plan_hash: String::new(),
    };
    plan.finalize();

    info!(
        trace_id = %ctx.trace_id,
        action_id = %ctx.action_id,
        plan_hash = %plan.plan_hash,
        "immutable execution plan captured for pending approval"
    );

    // Move owned fields into PendingApproval rather than cloning.
    // After `create_pending(&pending)` borrows it, the fields are moved
    // out of `pending` into the DomainEvent — zero-copy for Vec<String>
    // and String fields that would otherwise require heap clones.
    let pending = PendingApproval {
        approval_id: input.approval_id.to_string(),
        trace_id: Arc::clone(&ctx.trace_id),
        action_id: Arc::clone(&ctx.action_id),
        auth_context: StoredAuthContext {
            principal: Arc::clone(&auth_ctx.principal),
            session_id: Arc::clone(&auth_ctx.session_id),
            lease_jti: Arc::clone(&auth_ctx.lease_jti),
            sender_thumbprint: Arc::clone(&auth_ctx.sender_thumbprint),
            owner: auth_ctx.owner.clone(),
        },
        request_hash: Arc::clone(&input.request_hash),
        request_body: Arc::clone(&input.request_body),
        policy_version: input.policy_version.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        plan,
        unresolved_domains: input.unresolved_domains,
        unresolved_paths: input.unresolved_paths,
    };

    if let Err(e) = state
        .enforcement
        .approval_store
        .create_pending(&pending)
        .await
    {
        warn!(
            trace_id = %ctx.trace_id,
            error = %e,
            "failed to persist pending approval"
        );
        // SECURITY: fail-closed — if we can't persist the plan, deny.
        return deny_and_audit(
            state,
            ctx,
            Decision::Error,
            "error",
            input.policy_version.clone(),
            format!("approval store unavailable: {e}"),
            PipelineError::StoreUnavailable(format!("approval store: {e}")),
        )
        .await;
    }

    ctx.audit.set_approval_id(&pending.approval_id);
    ctx.audit
        .write(
            &state.ledger,
            &state.metrics,
            Decision::PendingApproval,
            input.policy_version,
            None,
        )
        .await;

    state.emit(latchgate_core::DomainEvent::ApprovalPending(
        latchgate_core::ApprovalPendingEvent {
            approval_id: Arc::from(pending.approval_id.as_str()),
            action_id: Arc::clone(&ctx.action_id),
            principal: Arc::clone(&auth_ctx.principal),
            owner: auth_ctx.owner.clone(),
            risk_level: Arc::from(manifest.risk_level.as_str()),
            request_hash: Arc::clone(&input.request_hash),
            expires_at: Arc::from(plan_expires_at.to_rfc3339()),
            request_body: Arc::unwrap_or_clone(input.request_body),
            secret_names: manifest
                .secrets
                .iter()
                .map(|s| s.name.to_string())
                .collect::<Vec<_>>(),
            unresolved_domains: pending.unresolved_domains,
            unresolved_paths: pending.unresolved_paths,
            trace_id: Arc::clone(&ctx.trace_id),
        },
    ));

    PipelineError::Approval(ApprovalResponse {
        approval_id: pending.approval_id.into(),
        request_hash: input.request_hash,
        trace_id: ctx.trace_id.to_string().into(),
    })
}

/// Debit the per-session budget for this request and flip
/// `ctx.budget_debited = true` on success.
///
/// SECURITY: after this returns `Ok`, every error path in the remaining
/// pipeline MUST rollback via `state.enforcement.budget_manager.rollback` to avoid
/// charging the operator for an execution that never happened. The
/// orchestrator owns this responsibility — steps after debit do not
/// rollback themselves (they don't know whether the caller will retry
/// at a higher level).
pub(crate) async fn step_debit_budget(
    state: &AppState,
    ctx: &mut RequestCtx,
    auth_ctx: &AuthContext,
    _manifest: &ActionSpec,
    budgets_before: &BudgetSnapshot,
    _budgets_after_opa: &BudgetSnapshot,
) -> Result<DebitBudgetOutput, PipelineError> {
    let has_budgets = auth_ctx.budgets.is_some();
    let budgets_after = if has_budgets {
        let redis_start = Instant::now();
        let debit_result = state
            .enforcement
            .budget_manager
            .get_and_debit(&auth_ctx.session_id)
            .await;
        state
            .metrics
            .record_redis_duration("budget_debit", redis_start.elapsed());
        match debit_result {
            Ok(snap) => {
                ctx.budget_debited = true;
                snap
            }
            Err(e) => {
                state.metrics.record_call(&ctx.action_id, "deny");
                ctx.audit
                    .write(
                        &state.ledger,
                        &state.metrics,
                        Decision::Deny,
                        None,
                        Some(format!("budget: {e}")),
                    )
                    .await;
                if matches!(e, BudgetError::Exhausted { .. }) {
                    state.emit(latchgate_core::DomainEvent::BudgetExhausted {
                        action_id: Arc::clone(&ctx.action_id),
                        principal: Arc::clone(&auth_ctx.principal),
                        owner: auth_ctx.owner.clone(),
                        session_id: Arc::clone(&auth_ctx.session_id),
                    });
                }
                return Err(PipelineError::Budget(e));
            }
        }
    } else {
        *budgets_before
    };

    Ok(DebitBudgetOutput { budgets_after })
}

/// After debit has succeeded, construct the signed `ExecutionGrant`,
/// decrypt approved secrets, resolve the request template if any, and
/// assemble the `RunTask` for provider dispatch.
///
/// SECURITY:
/// - The grant is constructed via [`ExecutionGrantBuilder::build_and_sign`]
///   — signature is applied before the grant becomes visible to the rest
///   of the pipeline.
/// - Secret resolution errors are classified: `RequiredSecretsButNoSopsFile`
///   => policy denial (operator approved a posture the gate can't honor);
///   anything else => internal error.
/// - All errors here owe a budget rollback. The orchestrator MUST call
///   `state.enforcement.budget_manager.rollback(session_id)` on
///   `Err` from this step, gated on `ctx.budget_debited`.
pub(crate) async fn step_build_run_task(
    state: &AppState,
    ctx: &mut RequestCtx,
    auth_ctx: &AuthContext,
    manifest: &ActionSpec,
    input: BuildRunTaskInput<'_>,
) -> Result<BuildRunTaskOutput, PipelineError> {
    // --- Grant construction ------------------------------------------------
    let grant_id = latchgate_core::GrantId::new();
    let grant_issued_at = chrono::Utc::now();
    let grant_expires_at = grant_issued_at
        + chrono::Duration::seconds(manifest.resource_limits.timeout_seconds as i64 + 30);

    let resolved_policy_version = input.policy_version.unwrap_or_else(|| {
        warn!(
            trace_id = %ctx.trace_id,
            "OPA returned allow without policy_version — approval_hash binding weakened"
        );
        "unknown".into()
    });

    let grant_core = latchgate_core::ExecutionPlanCore {
        action_id: Arc::clone(&ctx.action_id),
        action_digest: Arc::from(manifest.content_digest.as_str()),
        provider_module_digest: Arc::clone(&manifest.provider_module_digest),
        request_hash: Arc::from(input.request_hash),
        policy_version: Some(resolved_policy_version),
        approved_targets: input.policy.allowed_sinks.to_vec(),
        approved_secrets: input.policy.approved_secrets.to_vec(),
        approved_egress: input.policy.approved_egress.clone(),
        expires_at: grant_expires_at,
    };

    let grant = latchgate_core::ExecutionGrantBuilder::new(
        grant_id,
        latchgate_core::GrantIdentity {
            subject: Arc::clone(&auth_ctx.principal),
            sender_binding: Arc::clone(&auth_ctx.sender_thumbprint),
        },
        grant_core,
        latchgate_core::BudgetReservation {
            calls_before: input.budgets_before.calls_remaining,
            calls_after: input.budgets_after.calls_remaining,
        },
        grant_issued_at,
        state.current_revocation_epoch(),
    )
    .build_and_sign(&state.crypto.grant_signer);

    // --- Secret resolution --------------------------------------------------
    let decrypted_secrets = resolve_approved_secrets(
        state,
        ctx,
        auth_ctx,
        manifest,
        &input.policy.approved_secrets,
    )
    .await?;

    // --- Template / args resolution -----------------------------------------
    let args_json = resolve_args_json(state, ctx, manifest, input.request_body).await?;

    // --- Provider module digest resolution ----------------------------------
    let module_digest = resolve_provider_module(state, ctx, manifest).await?;

    // --- Concrete sinks: policy-approved + learned + narrowed ---------------
    let concrete_sinks = learned_allowlist::resolve_effective_sinks(
        &state.ledger,
        &state.config,
        &ctx.action_id,
        &ctx.trace_id,
        &input.policy.approved_egress,
    )
    .await;

    // --- RunTask assembly -------------------------------------------------
    let task = RunTask {
        module_digest: Arc::from(module_digest),
        args_json,
        allowed_imports: manifest.required_imports.clone(),
        resource_limits: manifest.resource_limits.clone(),
        allowed_sinks: concrete_sinks.clone(),
        // SECURITY (01.2): policy-approved secrets, not manifest-declared.
        approved_secrets: input.policy.approved_secrets.to_vec(),
        decrypted_secrets,
        trace_id: Arc::clone(&ctx.trace_id),
        database_config: manifest.database_config.as_deref().and_then(|v| {
            serde_json::from_value::<latchgate_providers::DatabaseConfig>(v.clone()).ok()
        }),
        egress_proxy_url: state
            .config
            .egress
            .egress_proxy_url
            .as_deref()
            .map(Arc::from),
        // Construct FsHostConfig via the shared builder so the auto-allow and
        // approval paths cannot diverge on filesystem scope. Pre-compiled
        // patterns from step_path_precheck are reused when available, avoiding
        // a redundant learned-path query and glob compilation on the hot path.
        fs_config: match &manifest.fs {
            Some(fs_conf) => {
                let precompiled = match (input.compiled_fs_allowed, input.compiled_fs_denied) {
                    (Some(a), Some(d)) => Some((a, d)),
                    _ => None,
                };
                let session_fs_root: Option<std::path::PathBuf> = state
                    .runtime
                    .session_fs_roots
                    .get(&*auth_ctx.session_id)
                    .map(|entry| entry.canonical.clone());
                learned_allowlist::build_fs_host_config(
                    state,
                    &ctx.action_id,
                    fs_conf,
                    precompiled,
                    session_fs_root.as_deref(),
                )
                .await
            }
            None => None,
        },
    };

    Ok(BuildRunTaskOutput {
        grant,
        task,
        concrete_sinks,
    })
}

/// Decrypt policy-approved secrets via the SecretsManager.
///
/// SECURITY: `RequiredSecretsButNoSopsFile` is classified as a policy denial
/// — the operator approved a posture the gate cannot honor. All other
/// failures are internal errors. Both paths write an audit event before
/// returning.
async fn resolve_approved_secrets(
    state: &AppState,
    ctx: &mut RequestCtx,
    auth_ctx: &AuthContext,
    manifest: &ActionSpec,
    approved_secrets: &[Arc<str>],
) -> Result<HashMap<String, Zeroizing<String>>, PipelineError> {
    match state
        .runtime
        .secrets_manager
        .resolve_approved(
            approved_secrets,
            &manifest.secrets,
            state.config.secrets.sops_secrets_file.as_deref(),
        )
        .await
    {
        Ok(secrets) => {
            if !secrets.is_empty() {
                let key_list: Vec<&str> = secrets.keys().map(|k| k.as_str()).collect();
                info!(
                    trace_id = %ctx.trace_id,
                    action_id = %ctx.action_id,
                    injected_secrets = ?key_list,
                    "secrets decrypted for host-layer injection"
                );
            }
            Ok(secrets)
        }
        Err(e) => {
            let err_msg = e.to_string();
            warn!(
                trace_id = %ctx.trace_id,
                action_id = %ctx.action_id,
                error = %err_msg,
                "secret resolution failed"
            );
            let pipeline_err = match e {
                latchgate_providers::secrets::SecretsError::RequiredSecretsButNoSopsFile {
                    ..
                } => PipelineError::Policy(PolicyError::denied(
                    err_msg.clone(),
                    Arc::clone(&auth_ctx.principal),
                    Arc::clone(&ctx.action_id),
                )),
                _ => PipelineError::SecretResolution(format!("secret injection: {err_msg}")),
            };
            Err(deny_and_audit(
                state,
                ctx,
                Decision::Error,
                "error",
                None,
                err_msg,
                pipeline_err,
            )
            .await)
        }
    }
}

/// Resolve the request body through the manifest template (if any) and
/// serialise to JSON.
///
/// SECURITY: every error path records a `Decision::Error` audit event
/// before returning — a user-reachable failure must never be invisible
/// to operators.
async fn resolve_args_json(
    state: &AppState,
    ctx: &mut RequestCtx,
    manifest: &ActionSpec,
    request_body: &serde_json::Value,
) -> Result<String, PipelineError> {
    let value = match &manifest.template {
        Some(template) => match crate::template::resolve_template(template, request_body) {
            Ok(v) => v,
            Err(e) => {
                let err_msg = format!("template resolution failed: {e}");
                return Err(deny_and_audit(
                    state,
                    ctx,
                    Decision::Error,
                    "error",
                    None,
                    err_msg.clone(),
                    PipelineError::Schema(SchemaError::ValidationFailed { reason: err_msg }),
                )
                .await);
            }
        },
        None => request_body.clone(),
    };

    match serde_json::to_string(&value) {
        Ok(s) => Ok(s),
        Err(e) => {
            let err_msg = format!("serialise args: {e}");
            Err(deny_and_audit(
                state,
                ctx,
                Decision::Error,
                "error",
                None,
                err_msg.clone(),
                PipelineError::SecretResolution(err_msg),
            )
            .await)
        }
    }
}

/// Resolve the provider module digest, mapping builtin aliases to their
/// registered digests.
///
/// SECURITY: an unregistered digest is an operator misconfiguration (the
/// manifest references a provider module the runtime doesn't have). The
/// audit event ensures operators can correlate the failure.
async fn resolve_provider_module(
    state: &AppState,
    ctx: &mut RequestCtx,
    manifest: &ActionSpec,
) -> Result<String, PipelineError> {
    match state
        .runtime
        .wasm_runtime
        .resolve_module_digest(&manifest.provider_module_digest)
    {
        Ok(digest) => Ok(digest),
        Err(e) => {
            let digest = manifest.provider_module_digest.to_string();
            let err_msg = format!("builtin provider module not registered: {digest}");
            Err(deny_and_audit(
                state,
                ctx,
                Decision::Error,
                "error",
                None,
                err_msg,
                PipelineError::Provider(e),
            )
            .await)
        }
    }
}
