//! Steps 2–3: registry lookup and trust verification.

use std::sync::Arc;

use latchgate_core::{TrustError, TrustVerdict};
use latchgate_ledger::Decision;
use latchgate_registry::{ActionSpec, RegistryStore};

use super::deny_and_audit;
use super::types::{ResolveActionOutput, VerifyTrustOutput};
use crate::pipeline::PipelineError;
use crate::request::RequestCtx;
use crate::state::AppState;

/// Load the action manifest from the registry and derive its egress profile.
///
/// SECURITY: `ActionNotFound` is a deny, not a 404 — it signals that the
/// caller requested an action the operator has not declared. Writing
/// an audit event here preserves visibility into probe/reconnaissance.
///
/// The `registry` parameter is a snapshot (`Arc<RegistryStore>`) captured
/// once per pipeline run. The returned manifest borrows from it, keeping
/// the hot path allocation-free.
pub(crate) async fn step_resolve_action<'a>(
    state: &AppState,
    ctx: &mut RequestCtx,
    registry: &'a RegistryStore,
) -> Result<ResolveActionOutput<'a>, PipelineError> {
    let manifest = match registry.get_action(&ctx.action_id) {
        Some(m) => m,
        None => {
            return Err(deny_and_audit(
                state,
                ctx,
                Decision::Deny,
                "deny",
                None,
                "action_not_found".into(),
                PipelineError::ActionNotFound {
                    action_id: Arc::clone(&ctx.action_id),
                },
            )
            .await);
        }
    };

    let egress_profile = manifest
        .egress_profile()
        .map_err(|e| PipelineError::Internal(format!("manifest egress config: {e}")))?;

    Ok(ResolveActionOutput {
        manifest,
        egress_profile,
    })
}

/// Verify the manifest's provider_module_digest digest is registered as trusted.
///
/// SECURITY: the registry's digest store is the source of truth for
/// "is this provider module allowed to run". A mismatch or unregistered
/// module is a deny — executing untrusted code is never the answer.
pub(crate) async fn step_verify_trust(
    state: &AppState,
    ctx: &mut RequestCtx,
    manifest: &ActionSpec,
) -> Result<(VerifyTrustOutput, Arc<TrustVerdict>), PipelineError> {
    let trust_verdict = Arc::new(
        state
            .registry
            .load()
            .verify_digest(&ctx.action_id, &manifest.provider_module_digest),
    );
    let trust_verdict_str: &'static str = match &*trust_verdict {
        TrustVerdict::DigestOk => "digest_ok",
        TrustVerdict::DigestMismatch { .. } => "mismatch",
        TrustVerdict::NotRegistered => "not_registered",
    };

    ctx.audit.set_action(
        Arc::clone(&ctx.action_id),
        Some(Arc::clone(&manifest.version)),
        Arc::clone(&manifest.provider_module_digest),
        Arc::from(trust_verdict_str),
    );
    ctx.audit.set_risk_level(manifest.risk_level);

    if let Err(e) = TrustError::from_verdict(&ctx.action_id, &trust_verdict) {
        let reason = format!("trust: {e}");
        return Err(deny_and_audit(
            state,
            ctx,
            Decision::Deny,
            "deny",
            None,
            reason,
            PipelineError::Trust(e),
        )
        .await);
    }

    Ok((VerifyTrustOutput { trust_verdict_str }, trust_verdict))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use latchgate_core::{EgressProfile, TrustVerdict};

    use super::*;
    use crate::request::RequestCtx;
    use crate::test_support::{
        registry_with_test_action, test_app_state, test_app_state_with_registry, TEST_ACTION_YAML,
    };

    fn ctx(action_id: &str) -> RequestCtx {
        RequestCtx::new(Arc::from("trace-test-001"), Arc::from(action_id), true)
    }

    #[tokio::test]
    async fn resolve_action_not_found_in_empty_registry() {
        let (state, _) = test_app_state();
        let mut c = ctx("nonexistent_action");
        let registry = state.registry.load();
        let err = step_resolve_action(&state, &mut c, &registry)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PipelineError::ActionNotFound { .. }),
            "missing action must return ActionNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn resolve_action_succeeds_when_registered() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let mut c = ctx("test_action");
        let registry = state.registry.load();
        let out = step_resolve_action(&state, &mut c, &registry)
            .await
            .unwrap();
        assert_eq!(out.manifest.action_id, "test_action");
        assert_eq!(&*out.manifest.version, "1.0.0");
    }

    #[tokio::test]
    async fn resolve_action_returns_egress_profile() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let mut c = ctx("test_action");
        let registry = state.registry.load();
        let out = step_resolve_action(&state, &mut c, &registry)
            .await
            .unwrap();
        assert!(
            matches!(out.egress_profile, EgressProfile::None),
            "default egress profile must be None, got: {:?}",
            out.egress_profile
        );
    }

    #[tokio::test]
    async fn verify_trust_rejects_unregistered_digest() {
        let (state, _) = test_app_state();
        let mut c = ctx("test_action");
        let manifest = latchgate_registry::ActionSpec::from_yaml(TEST_ACTION_YAML).unwrap();
        let result = step_verify_trust(&state, &mut c, &manifest).await;
        assert!(result.is_err(), "unregistered digest must be denied");
    }

    #[tokio::test]
    async fn verify_trust_accepts_registered_builtin() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let mut c = ctx("test_action");
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();
        let (out, verdict) = step_verify_trust(&state, &mut c, manifest).await.unwrap();
        assert_eq!(out.trust_verdict_str, "digest_ok");
        assert!(matches!(*verdict, TrustVerdict::DigestOk));
    }
}
