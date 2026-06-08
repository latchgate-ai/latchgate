//! Runtime allowlist merging for learned domains and filesystem paths.
//!
//! Operators can approve egress domains and filesystem path globs at
//! runtime (via CLI, approval flow, or domain-learning). This module
//! merges those operator-approved entries into the effective allowlist
//! that the enforcement pipeline evaluates at dispatch time.
//!
//! # Security properties
//!
//! - Learned entries are per-action — a domain approved for `slack_post`
//!   is never added to `web_read`'s effective allowlist.
//! - Merging is additive only: manifest entries cannot be removed at
//!   runtime (they are the immutable baseline).
//! - Errors are non-fatal: if the ledger is temporarily unreadable,
//!   the action runs with manifest-only entries (fail-closed to
//!   baseline, not fail-open to all).

use std::sync::Arc;

use latchgate_ledger::LedgerStore;

/// Retrieve operator-learned domains for an action from the in-memory cache.
///
/// Returns an `Arc<Vec<String>>` — callers that only test membership can
/// borrow through the `Arc` without allocating. On error, returns the
/// shared empty vec (fail-closed to manifest-only baseline).
pub async fn get_learned_domains(ledger: &Arc<LedgerStore>, action_id: &str) -> Arc<Vec<String>> {
    match ledger.get_learned_domains_cached(action_id) {
        Ok(domains) => domains,
        Err(latchgate_ledger::LedgerError::LockPoisoned) => {
            let ledger = Arc::clone(ledger);
            let aid = action_id.to_string();
            match tokio::task::spawn_blocking(move || ledger.get_learned_domains_for_action(&aid))
                .await
            {
                Ok(Ok(domains)) => Arc::new(domains),
                Ok(Err(e)) => {
                    tracing::warn!(
                        action_id = %action_id,
                        error = %e,
                        "failed to read learned domains — using manifest-only allowlist"
                    );
                    Arc::new(Vec::new())
                }
                Err(e) => {
                    tracing::warn!(
                        action_id = %action_id,
                        error = %e,
                        "learned domains spawn_blocking panicked — using manifest-only allowlist"
                    );
                    Arc::new(Vec::new())
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                action_id = %action_id,
                error = %e,
                "failed to read learned domains — using manifest-only allowlist"
            );
            Arc::new(Vec::new())
        }
    }
}

/// Merge learned domains into the concrete sink list for an action.
///
/// Queries the ledger for operator-approved domains for `action_id` and
/// appends any that are not already in `sinks`. Returns the number of
/// learned domains added.
///
/// SECURITY: learned domains are per-action — a domain approved for
/// `slack_post` is never added to `web_read`'s effective allowlist.
/// The merge is additive only: manifest domains cannot be removed at
/// runtime (they are the immutable baseline).
///
/// Errors are logged but do not fail the pipeline — if the ledger is
/// temporarily unreadable, the action runs with manifest-only domains
/// (fail-closed to baseline, not fail-open to all).
pub async fn merge_learned_domains(
    ledger: &Arc<LedgerStore>,
    action_id: &str,
    sinks: &mut Vec<String>,
) -> usize {
    let learned = get_learned_domains(ledger, action_id).await;

    if learned.is_empty() {
        return 0;
    }

    // Deduplicate: only add domains not already in the manifest allowlist.
    // Case-insensitive comparison — domain matching in validate_sink is
    // case-insensitive, so the dedup must be too.
    let existing: std::collections::HashSet<String> =
        sinks.iter().map(|s| s.to_lowercase()).collect();

    let mut added = 0usize;
    for domain in learned.iter() {
        if !existing.contains(&domain.to_lowercase()) {
            sinks.push(domain.clone());
            added += 1;
        }
    }

    if added > 0 {
        tracing::info!(
            action_id = %action_id,
            learned_domains_added = added,
            "merged learned domains into effective allowlist"
        );
    }

    added
}

/// Extract the target domain from a request, if determinable at pipeline time.
///
/// For template actions: resolves the URL template against the request body
/// and parses the host. For non-template actions: checks for `url` or `target`
/// fields in the request body.
///
/// Returns `None` if the target domain cannot be determined — this is safe
/// because runtime enforcement (host I/O `validate_sink`) will still catch
/// unknown domains at dispatch time. The pre-check is an optimization for
/// early rejection, not a replacement for runtime enforcement.
pub fn extract_target_domain(
    template: Option<&latchgate_registry::TemplateConfig>,
    request_body: &serde_json::Value,
) -> Option<String> {
    let url_str = if let Some(tmpl) = template {
        // Template action: resolve the URL template.
        match crate::template::resolve_template(tmpl, request_body) {
            Ok(resolved) => resolved["url"].as_str().map(|s| s.to_string()),
            Err(_) => None, // Template error — schema validation should have caught this.
        }
    } else {
        // Non-template action: look for common URL fields.
        request_body["url"]
            .as_str()
            .or_else(|| request_body["target"].as_str())
            .map(|s| s.to_string())
    };

    let url_str = url_str?;
    latchgate_core::parse_host_from_url(&url_str)
}

/// Check if a domain is in the effective allowlist (manifest + learned).
///
/// Re-exported from [`latchgate_core::domain_in_allowlist`] for ergonomic
/// use within the kernel pipeline.
pub fn domain_in_allowlist(domain: &str, allowlist: &[impl AsRef<str>]) -> bool {
    latchgate_core::domain_in_allowlist(domain, allowlist)
}

/// Resolve the effective concrete sink list for an action.
///
/// Combines three steps that both the auto-allow and human-approval
/// execution paths must perform identically:
///
/// 1. Extract concrete domains from the policy-approved egress profile.
/// 2. Merge operator-learned domains from the ledger.
/// 3. Apply the operator's runtime egress narrowing constraint.
///
/// Returns the final `Vec<String>` of allowed sinks ready for injection
/// into the [`RunTask`](latchgate_providers::RunTask).
pub async fn resolve_effective_sinks(
    ledger: &Arc<LedgerStore>,
    config: &latchgate_config::Config,
    action_id: &str,
    trace_id: &str,
    approved_egress: &latchgate_core::EgressProfile,
) -> Vec<Arc<str>> {
    // Convert to owned Strings for the mutable merge/narrow phase.
    // `merge_learned_domains` and `narrow_egress_domains` both operate on
    // `Vec<String>` because learned domains (from SQLite) and runtime
    // allowlists (from TOML config) are naturally String-typed. The
    // conversion cost is paid once per request; subsequent clones in the
    // pipeline (plans, grants, audit events) benefit from Arc<str>.
    let mut sinks: Vec<String> = approved_egress
        .concrete_allowed_domains()
        .iter()
        .map(|s| s.to_string())
        .collect();
    merge_learned_domains(ledger, action_id, &mut sinks).await;

    let narrowed = config.narrow_egress_domains(&mut sinks);
    if narrowed > 0 {
        tracing::info!(
            trace_id = %trace_id,
            action_id = %action_id,
            removed = narrowed,
            "egress_runtime_allowlist narrowed effective domain set"
        );
    }
    sinks.into_iter().map(Arc::from).collect()
}

/// Merge operator-learned path globs into the effective `allowed_paths`.
///
/// Mirrors [`merge_learned_domains`] for the filesystem subsystem: reads
/// globs from the ledger cache and appends any not already present in the
/// manifest's static allowlist.
///
/// Errors are logged but do not fail the pipeline — if the ledger is
/// temporarily unreadable, the action runs with manifest-only paths
/// (fail-closed to baseline, not fail-open to all).
pub async fn get_learned_paths(ledger: &Arc<LedgerStore>, action_id: &str) -> Arc<Vec<String>> {
    let learned = match ledger.get_learned_paths_cached(action_id) {
        Ok(p) => p,
        Err(latchgate_ledger::LedgerError::LockPoisoned) => {
            let ledger = Arc::clone(ledger);
            let aid = action_id.to_string();
            match tokio::task::spawn_blocking(move || ledger.get_learned_paths_for_action(&aid))
                .await
            {
                Ok(Ok(p)) => Arc::new(p),
                Ok(Err(e)) => {
                    tracing::warn!(
                        action_id = %action_id,
                        error = %e,
                        "failed to read learned paths — using manifest-only allowlist"
                    );
                    return Arc::new(Vec::new());
                }
                Err(e) => {
                    tracing::warn!(
                        action_id = %action_id,
                        error = %e,
                        "learned paths spawn_blocking panicked — using manifest-only allowlist"
                    );
                    return Arc::new(Vec::new());
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                action_id = %action_id,
                error = %e,
                "failed to read learned paths — using manifest-only allowlist"
            );
            return Arc::new(Vec::new());
        }
    };

    if !learned.is_empty() {
        tracing::info!(
            action_id = %action_id,
            learned_count = learned.len(),
            "loaded learned paths for action"
        );
    }

    learned
}

/// Construct the [`FsHostConfig`](latchgate_providers::FsHostConfig) for an fs
/// action, binding the manifest's `fs` block to the operator-configured root
/// and the action's effective (manifest ∪ learned) path globs.
///
/// This is the single source of truth shared by both execution paths:
///
/// - The **auto-allow** path passes its `precompiled` globs from
///   [`step_path_precheck`](crate::steps::step_path_precheck), avoiding a
///   redundant ledger query and glob compilation on the hot path.
/// - The **approval** path passes `precompiled = None`, forcing a fresh
///   compile that merges currently-learned paths at execution time.
///
/// # Security
///
/// - Returns `None` (provider permits nothing) whenever the action declares no
///   `fs` block or the gate has no configured filesystem root — fail-closed.
/// - Learned paths only ever **extend** `allowed_paths`; `denied_paths` comes
///   solely from the manifest and is never widened by learning.
/// - A malformed glob in the manifest fails closed to an empty pattern set
///   rather than a permissive one.
///
/// Both paths converge here so they cannot diverge on filesystem scope.
pub async fn build_fs_host_config(
    state: &crate::state::AppState,
    action_id: &str,
    fs_config: &latchgate_registry::manifest::FsConfig,
    precompiled: Option<(
        Vec<latchgate_core::fs_path::GlobPattern>,
        Vec<latchgate_core::fs_path::GlobPattern>,
    )>,
    session_fs_root: Option<&std::path::Path>,
) -> Option<Arc<latchgate_providers::FsHostConfig>> {
    let (root_fd, root_canonical) = if let Some(session_root) = session_fs_root {
        // Per-session root: open fd at execution time.
        //
        // SECURITY: must be in spawn_blocking — canonicalize() and
        // libc::open() are blocking syscalls that must not run on
        // the tokio runtime.
        let session_root_owned = session_root.to_path_buf();
        let open_result = tokio::task::spawn_blocking(move || {
            latchgate_providers::open_root_fd(&session_root_owned)
        })
        .await;

        match open_result {
            Ok(Ok((fd, actual_canonical))) => {
                // TOCTOU defense: verify the canonical path has not changed
                // since lease validation. If the directory was replaced
                // (deleted + recreated, or swapped via rename/symlink),
                // the canonical path will differ. Reject.
                if actual_canonical != session_root {
                    tracing::error!(
                        action_id = %action_id,
                        stored = %session_root.display(),
                        actual = %actual_canonical.display(),
                        "SECURITY: session fs_root canonical mismatch — \
                         directory may have been swapped since lease time"
                    );
                    return None; // fail-closed
                }
                (Arc::new(fd), actual_canonical)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    action_id = %action_id,
                    session_root = %session_root.display(),
                    error = %e,
                    "session fs_root no longer accessible"
                );
                return None; // fail-closed
            }
            Err(e) => {
                tracing::error!(
                    action_id = %action_id,
                    error = %e,
                    "open_root_fd spawn_blocking panicked"
                );
                return None; // fail-closed
            }
        }
    } else {
        // Fallback: global fs_root from startup (existing behavior).
        match (&state.runtime.fs_root_fd, &state.runtime.fs_root_canonical) {
            (Some(fd), Some(canonical)) => (Arc::clone(fd), canonical.clone()),
            _ => {
                tracing::warn!(
                    action_id = %action_id,
                    "fs action requested but fs_root_path not configured"
                );
                return None;
            }
        }
    };

    let (allowed, denied) = match precompiled {
        Some((allowed, denied)) => (allowed, denied),
        None => {
            // Manifest patterns are pre-compiled at load time. Only learned
            // patterns need per-request compilation.
            let learned = get_learned_paths(&state.ledger, action_id).await;
            let mut allowed = fs_config.compiled_allowed.clone();
            if !learned.is_empty() {
                let learned_compiled =
                    latchgate_core::fs_path::compile_patterns(learned.iter().map(String::as_str))
                        .unwrap_or_default();
                allowed.extend(learned_compiled);
            }
            let denied = fs_config.compiled_denied.clone();
            (allowed, denied)
        }
    };

    Some(Arc::new(latchgate_providers::FsHostConfig {
        root_fd,
        root_canonical,
        allowed_operations: fs_config.allowed_operations.clone(),
        allowed_paths: allowed,
        denied_paths: denied,
        max_file_bytes: fs_config.max_file_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use latchgate_ledger::EntrySource;

    fn test_ledger() -> Arc<LedgerStore> {
        Arc::new(LedgerStore::open_in_memory(None).unwrap())
    }

    #[tokio::test]
    async fn merge_adds_learned_domains() {
        let ledger = test_ledger();
        ledger
            .add_learned_domain(
                "web_read",
                "newsite.com",
                "alice",
                EntrySource::Cli,
                None,
                false,
            )
            .unwrap();

        let mut sinks = vec!["example.com".to_string()];
        let added = merge_learned_domains(&ledger, "web_read", &mut sinks).await;

        assert_eq!(added, 1);
        assert_eq!(sinks, vec!["example.com", "newsite.com"]);
    }

    #[tokio::test]
    async fn merge_deduplicates_case_insensitive() {
        let ledger = test_ledger();
        ledger
            .add_learned_domain(
                "web_read",
                "Example.COM",
                "alice",
                EntrySource::Cli,
                None,
                false,
            )
            .unwrap();

        let mut sinks = vec!["example.com".to_string()];
        let added = merge_learned_domains(&ledger, "web_read", &mut sinks).await;

        assert_eq!(added, 0, "case-insensitive duplicate must not be added");
        assert_eq!(sinks.len(), 1);
    }

    #[tokio::test]
    async fn merge_respects_action_isolation() {
        let ledger = test_ledger();
        ledger
            .add_learned_domain(
                "slack_post",
                "hooks.slack.com",
                "alice",
                EntrySource::Cli,
                None,
                false,
            )
            .unwrap();

        let mut sinks = vec![];
        let added = merge_learned_domains(&ledger, "web_read", &mut sinks).await;

        assert_eq!(added, 0, "domain from different action must not leak");
        assert!(sinks.is_empty());
    }

    #[tokio::test]
    async fn merge_no_learned_domains_is_noop() {
        let ledger = test_ledger();
        let mut sinks = vec!["api.github.com".to_string()];
        let added = merge_learned_domains(&ledger, "web_read", &mut sinks).await;

        assert_eq!(added, 0);
        assert_eq!(sinks, vec!["api.github.com"]);
    }

    #[tokio::test]
    async fn merge_multiple_learned_domains() {
        let ledger = test_ledger();
        ledger
            .add_learned_domain("web_read", "a.com", "alice", EntrySource::Cli, None, false)
            .unwrap();
        ledger
            .add_learned_domain(
                "web_read",
                "b.com",
                "alice",
                EntrySource::Approval,
                Some("appr-1"),
                false,
            )
            .unwrap();

        let mut sinks = vec!["existing.com".to_string()];
        let added = merge_learned_domains(&ledger, "web_read", &mut sinks).await;

        assert_eq!(added, 2);
        assert_eq!(sinks.len(), 3);
        assert!(sinks.contains(&"a.com".to_string()));
        assert!(sinks.contains(&"b.com".to_string()));
    }

    // -- extract_target_domain --

    #[test]
    fn extract_domain_from_url_field() {
        let body = serde_json::json!({"url": "https://newsite.com/article"});
        assert_eq!(
            extract_target_domain(None, &body),
            Some("newsite.com".into())
        );
    }

    #[test]
    fn extract_domain_from_target_field() {
        let body = serde_json::json!({"target": "https://hooks.slack.com/webhook"});
        assert_eq!(
            extract_target_domain(None, &body),
            Some("hooks.slack.com".into())
        );
    }

    #[test]
    fn extract_domain_from_template() {
        use latchgate_registry::TemplateConfig;
        let tmpl = TemplateConfig {
            method: "GET".into(),
            url_template: "{{url}}".into(),
            headers: Default::default(),
            body_template: None,
        };
        let body = serde_json::json!({"url": "https://example.com/page"});
        assert_eq!(
            extract_target_domain(Some(&tmpl), &body),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_domain_no_url_returns_none() {
        let body = serde_json::json!({"query": "SELECT 1"});
        assert_eq!(extract_target_domain(None, &body), None);
    }

    // -- extract_target_domain: edge cases --

    #[test]
    fn extract_domain_url_with_port_strips_port() {
        let body = serde_json::json!({"url": "https://api.example.com:8443/v1/data"});
        assert_eq!(
            extract_target_domain(None, &body),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn extract_domain_url_with_query_and_fragment() {
        let body = serde_json::json!({"url": "https://site.com/path?q=1&x=2#section"});
        assert_eq!(extract_target_domain(None, &body), Some("site.com".into()));
    }

    #[test]
    fn extract_domain_url_with_userinfo() {
        // SECURITY: userinfo in URLs must not confuse host extraction.
        // "https://evil.com@legit.com/" — host is legit.com, not evil.com.
        let body = serde_json::json!({"url": "https://evil.com@legit.com/path"});
        // url::Url parses host correctly as legit.com (evil.com is userinfo).
        assert_eq!(extract_target_domain(None, &body), Some("legit.com".into()));
    }

    #[test]
    fn extract_domain_non_string_url_returns_none() {
        let body = serde_json::json!({"url": 42});
        assert_eq!(extract_target_domain(None, &body), None);
    }

    #[test]
    fn extract_domain_null_url_returns_none() {
        let body = serde_json::json!({"url": null});
        assert_eq!(extract_target_domain(None, &body), None);
    }

    #[test]
    fn extract_domain_empty_url_returns_none() {
        let body = serde_json::json!({"url": ""});
        assert_eq!(extract_target_domain(None, &body), None);
    }

    #[test]
    fn extract_domain_template_with_fixed_prefix() {
        use latchgate_registry::TemplateConfig;
        let tmpl = TemplateConfig {
            method: "POST".into(),
            url_template: "https://api.github.com/repos/{{owner}}/{{repo}}/issues".into(),
            headers: Default::default(),
            body_template: None,
        };
        let body = serde_json::json!({"owner": "torvalds", "repo": "linux"});
        assert_eq!(
            extract_target_domain(Some(&tmpl), &body),
            Some("api.github.com".into())
        );
    }

    #[test]
    fn extract_domain_template_missing_var_returns_none() {
        use latchgate_registry::TemplateConfig;
        let tmpl = TemplateConfig {
            method: "GET".into(),
            url_template: "{{url}}".into(),
            headers: Default::default(),
            body_template: None,
        };
        // Missing 'url' field — template resolution fails gracefully.
        let body = serde_json::json!({"other": "value"});
        assert_eq!(extract_target_domain(Some(&tmpl), &body), None);
    }

    #[test]
    fn extract_domain_prefers_template_over_body_url() {
        // When a template is provided, the template URL takes precedence
        // over a raw "url" field in the body.
        use latchgate_registry::TemplateConfig;
        let tmpl = TemplateConfig {
            method: "GET".into(),
            url_template: "https://correct.com/{{path}}".into(),
            headers: Default::default(),
            body_template: None,
        };
        let body = serde_json::json!({"url": "https://wrong.com/", "path": "data"});
        assert_eq!(
            extract_target_domain(Some(&tmpl), &body),
            Some("correct.com".into())
        );
    }

    // -- merge_learned_domains: integrity --

    #[tokio::test]
    async fn merge_preserves_manifest_domains() {
        let ledger = test_ledger();
        ledger
            .add_learned_domain(
                "web_read",
                "learned.com",
                "alice",
                EntrySource::Cli,
                None,
                false,
            )
            .unwrap();

        let mut sinks = vec!["manifest.com".to_string()];
        merge_learned_domains(&ledger, "web_read", &mut sinks).await;

        assert!(
            sinks.contains(&"manifest.com".to_string()),
            "manifest domain must survive merge"
        );
        assert!(
            sinks.contains(&"learned.com".to_string()),
            "learned domain must be added"
        );
    }

    #[tokio::test]
    async fn merge_repeated_is_deterministic() {
        let ledger = test_ledger();
        for i in 0..10 {
            ledger
                .add_learned_domain(
                    "web_read",
                    &format!("site-{i}.com"),
                    "alice",
                    EntrySource::Cli,
                    None,
                    false,
                )
                .unwrap();
        }

        // Two independent merges must produce identical results.
        let mut sinks_a = vec!["base.com".to_string()];
        let mut sinks_b = vec!["base.com".to_string()];

        merge_learned_domains(&ledger, "web_read", &mut sinks_a).await;
        merge_learned_domains(&ledger, "web_read", &mut sinks_b).await;

        sinks_a.sort();
        sinks_b.sort();
        assert_eq!(
            sinks_a, sinks_b,
            "repeated merges must produce identical results"
        );
        assert_eq!(sinks_a.len(), 11); // 1 base + 10 learned
    }

    /// The hot-path cache returns `Arc<Vec<String>>` — verify the precheck
    /// code path works without cloning the inner vec.
    #[tokio::test]
    async fn get_learned_domains_returns_arc() {
        let ledger = test_ledger();
        ledger
            .add_learned_domain("web_read", "a.com", "alice", EntrySource::Cli, None, false)
            .unwrap();

        let arc1 = get_learned_domains(&ledger, "web_read").await;
        let arc2 = get_learned_domains(&ledger, "web_read").await;

        // Both should resolve to the same cached Arc (same pointer).
        assert!(Arc::ptr_eq(&arc1, &arc2), "cache must return the same Arc");
        assert_eq!(&*arc1, &["a.com"]);

        // Membership check works via Deref — no clone needed.
        assert!(domain_in_allowlist("a.com", &arc1));
        assert!(!domain_in_allowlist("b.com", &arc1));
    }
}
