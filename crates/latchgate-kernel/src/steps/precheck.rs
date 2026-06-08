//! Steps 5–5b: domain and path pre-checks.

use latchgate_core::EgressProfile;
use latchgate_registry::ActionSpec;
use tracing::info;

use super::types::{DomainPrecheckOutput, PathPrecheckOutput};
use crate::learned_allowlist;
use crate::request::RequestCtx;
use crate::state::AppState;

/// Check the target domain against the manifest allowlist ∪ learned allowlist.
///
/// SECURITY: this is an optimization, NOT the authoritative domain
/// check. The host I/O layer's `validate_sink()` at dispatch time is
/// the binding enforcement — a bug here cannot grant unauthorized
/// egress, only waste an OPA round-trip. Fail-safe by design: if the
/// domain cannot be determined, returns an empty unresolved set and
/// defers to OPA (which can trigger pending_approval or deny).
pub(crate) async fn step_domain_precheck(
    state: &AppState,
    ctx: &RequestCtx,
    manifest: &ActionSpec,
    request_body: &serde_json::Value,
    egress_profile: &EgressProfile,
) -> DomainPrecheckOutput {
    #[allow(unreachable_patterns)]
    let unresolved_domains = match egress_profile {
        EgressProfile::ProxyAllowlist { allowed_domains } => {
            match learned_allowlist::extract_target_domain(manifest.template.as_ref(), request_body)
            {
                Some(target_domain) => {
                    // Check manifest allowlist first — no allocation needed
                    // for the common case where the domain is already declared.
                    if learned_allowlist::domain_in_allowlist(&target_domain, allowed_domains) {
                        vec![]
                    } else {
                        // Manifest miss — check learned domains from the
                        // in-memory cache before escalating to OPA.
                        let learned =
                            learned_allowlist::get_learned_domains(&state.ledger, &ctx.action_id)
                                .await;
                        if !learned.is_empty()
                            && learned_allowlist::domain_in_allowlist(&target_domain, &learned)
                        {
                            vec![]
                        } else {
                            info!(
                                trace_id = %ctx.trace_id,
                                action_id = %ctx.action_id,
                                domain = %target_domain,
                                "target domain not in effective allowlist — forwarding to policy"
                            );
                            vec![target_domain]
                        }
                    }
                }
                None => vec![],
            }
        }
        EgressProfile::None => vec![],
        // SECURITY: unknown egress profiles have no allowlist to check against.
        _ => vec![],
    };

    DomainPrecheckOutput { unresolved_domains }
}

/// Check the requested filesystem path against the manifest's allowed/denied
/// patterns. Mirrors [`step_domain_precheck`] for the fs provider.
///
/// SECURITY: this is a pre-policy optimization. The authoritative path
/// validation happens in the host import (Layer 1) at I/O time. This step
/// provides early feedback and populates the OPA input for policy decisions.
pub(crate) async fn step_path_precheck(
    state: &AppState,
    action_id: &str,
    manifest: &ActionSpec,
    request_body: &serde_json::Value,
) -> PathPrecheckOutput {
    let fs_config = match &manifest.fs {
        Some(c) => c,
        None => {
            return PathPrecheckOutput {
                fs_path: None,
                unresolved_paths: vec![],
                compiled_allowed: None,
                compiled_denied: None,
            }
        }
    };

    // Extract path from request body.
    let path_str = match request_body.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => {
            return PathPrecheckOutput {
                fs_path: None,
                unresolved_paths: vec![],
                compiled_allowed: None,
                compiled_denied: None,
            }
        }
    };

    let fs_path = Some(path_str.to_string());

    // Manifest patterns are pre-compiled at registry load (zero per-request
    // cost). Only learned patterns — which can change between requests —
    // need per-request compilation.
    let learned = learned_allowlist::get_learned_paths(&state.ledger, action_id).await;
    let learned_compiled = if learned.is_empty() {
        Vec::new()
    } else {
        latchgate_core::fs_path::compile_patterns(learned.iter().map(String::as_str))
            .unwrap_or_default()
    };

    // Evaluate: deny overrides allow. Check manifest allowed first
    // (pre-compiled), then learned allowed (dynamic).
    let path_ref = std::path::Path::new(path_str);
    let path_lossy = path_ref.to_string_lossy();

    let denied = &fs_config.compiled_denied;
    let decision = if denied.iter().any(|g| g.matches(&path_lossy)) {
        latchgate_core::fs_path::PathDecision::Denied
    } else if fs_config
        .compiled_allowed
        .iter()
        .any(|g| g.matches(&path_lossy))
        || learned_compiled.iter().any(|g| g.matches(&path_lossy))
    {
        latchgate_core::fs_path::PathDecision::Allowed
    } else {
        latchgate_core::fs_path::PathDecision::NotMatched
    };

    let unresolved_paths = match decision {
        latchgate_core::fs_path::PathDecision::Allowed => vec![],
        latchgate_core::fs_path::PathDecision::Denied => vec![],
        latchgate_core::fs_path::PathDecision::NotMatched => vec![path_str.to_string()],
    };

    // Merge manifest + learned compiled patterns for downstream reuse by
    // build_fs_host_config, which passes them straight into FsHostConfig
    // without recompilation.
    let mut all_allowed = fs_config.compiled_allowed.clone();
    all_allowed.extend(learned_compiled);

    PathPrecheckOutput {
        fs_path,
        unresolved_paths,
        compiled_allowed: Some(all_allowed),
        compiled_denied: Some(fs_config.compiled_denied.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use latchgate_core::EgressProfile;

    use super::*;
    use crate::request::RequestCtx;
    use crate::test_support::{
        registry_with_test_action, test_app_state, test_app_state_with_registry, TEST_ACTION_YAML,
    };

    fn ctx(action_id: &str) -> RequestCtx {
        RequestCtx::new(Arc::from("trace-test-001"), Arc::from(action_id), true)
    }

    #[tokio::test]
    async fn domain_precheck_no_egress_returns_empty() {
        let (state, _) = test_app_state();
        let c = ctx("test_action");
        let manifest = latchgate_registry::ActionSpec::from_yaml(TEST_ACTION_YAML).unwrap();

        let out = step_domain_precheck(
            &state,
            &c,
            &manifest,
            &serde_json::json!({"url": "https://unknown.example.com"}),
            &EgressProfile::None,
        )
        .await;
        assert!(
            out.unresolved_domains.is_empty(),
            "EgressProfile::None must produce no unresolved domains"
        );
    }

    #[tokio::test]
    async fn domain_precheck_proxy_allowlist_unknown_domain_is_unresolved() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let c = ctx("test_action");
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();

        let out = step_domain_precheck(
            &state,
            &c,
            manifest,
            &serde_json::json!({"path": "api/data"}),
            &EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["api.other.com".into()],
            },
        )
        .await;
        assert!(
            !out.unresolved_domains.is_empty(),
            "domain not in allowlist must appear in unresolved"
        );
        assert_eq!(out.unresolved_domains[0], "example.com");
    }

    #[tokio::test]
    async fn domain_precheck_proxy_allowlist_known_domain_is_resolved() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let c = ctx("test_action");
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();

        let out = step_domain_precheck(
            &state,
            &c,
            manifest,
            &serde_json::json!({"path": "api/data"}),
            &EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["example.com".into()],
            },
        )
        .await;
        assert!(
            out.unresolved_domains.is_empty(),
            "domain in allowlist must be resolved (empty unresolved), got: {:?}",
            out.unresolved_domains
        );
    }

    #[tokio::test]
    async fn path_precheck_no_fs_config_returns_empty() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();
        assert!(manifest.fs.is_none());

        let out = step_path_precheck(
            &state,
            "test_action",
            manifest,
            &serde_json::json!({"path": "/some/file"}),
        )
        .await;
        assert!(out.fs_path.is_none());
        assert!(out.unresolved_paths.is_empty());
    }
}
