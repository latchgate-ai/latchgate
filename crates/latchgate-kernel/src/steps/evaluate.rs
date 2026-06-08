//! Step 6: budget snapshot + OPA policy evaluation.

use std::sync::Arc;
use std::time::Instant;

use latchgate_auth::AuthContext;
use latchgate_core::BudgetSnapshot;
use latchgate_ledger::Decision;
use latchgate_policy::{
    PolicyAction, PolicyDecision, PolicyError, PolicyIdentity, PolicyInput, PolicyRequest,
    PolicyResolution,
};
use latchgate_registry::ActionSpec;
use latchgate_state::BudgetError;

use super::deny_and_audit;
use super::types::{EvaluatePolicyInput, EvaluatePolicyOutput};
use crate::pipeline::PipelineError;
use crate::request::RequestCtx;
use crate::state::AppState;

/// Snapshot budgets, evaluate OPA policy, and return the policy decision.
///
/// SECURITY:
/// - Budget store unavailable => 503 (transient, client can retry).
/// - Budget exhausted => deny (not 503 — the denial is authoritative).
/// - OPA timeout / unavailable => deny (fail-closed).
/// - Handles the `Deny` decision terminally by writing audit + emitting
///   `ActionDenied` before returning `Err`. The caller never sees a
///   `PolicyDecision::Deny` variant in `Ok`.
pub(crate) async fn step_evaluate_policy(
    state: &AppState,
    ctx: &mut RequestCtx,
    auth_ctx: &AuthContext,
    manifest: &ActionSpec,
    input: EvaluatePolicyInput<'_>,
) -> Result<EvaluatePolicyOutput, PipelineError> {
    let has_budgets = auth_ctx.budgets.is_some();

    let budgets_before = if has_budgets {
        match state
            .enforcement
            .budget_manager
            .get_snapshot(&auth_ctx.session_id)
            .await
        {
            Ok(snap) => snap,
            Err(BudgetError::Unavailable(ref msg)) => {
                return Err(deny_and_audit(
                    state,
                    ctx,
                    Decision::Error,
                    "error",
                    None,
                    format!("budget store unavailable: {msg}"),
                    PipelineError::StoreUnavailable(format!("budget store: {msg}")),
                )
                .await);
            }
            Err(e) => {
                let reason = format!("budget: {e}");
                return Err(deny_and_audit(
                    state,
                    ctx,
                    Decision::Deny,
                    "deny",
                    None,
                    reason,
                    PipelineError::Budget(e),
                )
                .await);
            }
        }
    } else {
        BudgetSnapshot {
            calls_remaining: i64::MAX,
        }
    };

    let policy_input = PolicyInput {
        identity: PolicyIdentity {
            principal: Arc::clone(&auth_ctx.principal),
            session_id: Arc::clone(&auth_ctx.session_id),
            scopes: &auth_ctx.scopes,
            required_scopes: &manifest.required_scopes,
        },
        action: PolicyAction {
            action_id: Arc::clone(&ctx.action_id),
            action_version: &manifest.version,
            action_risk_level: manifest.risk_level,
            action_trust_verdict: input.trust_verdict,
            action_category: if manifest.fs.is_some() { "fs" } else { "" },
        },
        request: PolicyRequest {
            request_hash: input.request_hash,
            requested_sinks: &manifest.declared_side_effects,
            requested_secrets: &manifest.secret_names,
            egress_profile: input.egress_profile,
            provider_context: latchgate_providers::build_policy_context(
                &manifest.provider_module_digest,
                manifest.database_config.as_deref(),
                input.request_body,
            ),
            fs_path: input.fs_path.as_deref(),
        },
        budgets_before,
        resolution: PolicyResolution {
            unresolved_domains: input.unresolved_domains,
            unresolved_paths: input.unresolved_paths,
        },
    };

    ctx.audit.set_budgets_before(&budgets_before);

    let opa_result = {
        let opa_start = Instant::now();
        let result = state.enforcement.policy.evaluate(&policy_input).await;
        state
            .metrics
            .record_opa_duration("evaluate", opa_start.elapsed());
        result
    };

    let policy_decision = match opa_result {
        Ok(d) => d,
        Err(e) => {
            let decision = match &e {
                PolicyError::Denied { .. } => Decision::Deny,
                _ => Decision::Error,
            };
            let decision_str = match &decision {
                Decision::Deny => "deny",
                _ => "error",
            };
            state.metrics.record_call(&ctx.action_id, decision_str);
            state.metrics.record_policy_decision(decision_str);
            ctx.audit
                .write(
                    &state.ledger,
                    &state.metrics,
                    decision,
                    None,
                    Some(format!("{e}")),
                )
                .await;
            return Err(PipelineError::Policy(e));
        }
    };

    // Terminal Deny: emit ActionDenied before returning.
    if let PolicyDecision::Deny { ref reason } = policy_decision {
        state.metrics.record_call(&ctx.action_id, "deny");
        state.metrics.record_policy_decision("deny");
        ctx.audit
            .write(
                &state.ledger,
                &state.metrics,
                Decision::Deny,
                None,
                Some(reason.clone()),
            )
            .await;
        state.emit(latchgate_core::DomainEvent::ActionDenied {
            action_id: Arc::clone(&ctx.action_id),
            principal: Arc::clone(&auth_ctx.principal),
            owner: auth_ctx.owner.clone(),
            deny_reason: Arc::from(reason.as_str()),
            trace_id: Arc::clone(&ctx.trace_id),
        });
        return Err(PipelineError::Policy(PolicyError::denied(
            reason.clone(),
            Arc::clone(&auth_ctx.principal),
            Arc::clone(&ctx.action_id),
        )));
    }

    let budgets_after_opa = match &policy_decision {
        PolicyDecision::Allow { budgets_after, .. }
        | PolicyDecision::PendingApproval { budgets_after, .. } => *budgets_after,
        PolicyDecision::Deny { .. } => {
            return Err(PipelineError::Internal(
                "policy Deny decision observed after terminal handler — step contract violation"
                    .into(),
            ));
        }
    };

    Ok(EvaluatePolicyOutput {
        decision: policy_decision,
        budgets_before,
        budgets_after_opa,
    })
}
