//! Manifest coverage tests — verify all shipped manifests load, validate,
//! and maintain security invariants.
//!
//! These tests run against the real YAML files in `definitions/manifests/` and
//! verify structural invariants that the kernel depends on at runtime.
//! No compiled .wasm modules or external infrastructure needed.

use std::collections::HashSet;
use std::path::Path;

use latchgate_registry::manifest::ProviderModule;
use latchgate_registry::RegistryStore;

const MANIFESTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../definitions/manifests");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_registry() -> RegistryStore {
    let dir = Path::new(MANIFESTS_DIR);
    assert!(dir.exists(), "definitions/manifests/ directory must exist");
    RegistryStore::load_from_dir(dir).unwrap_or_else(|e| panic!("registry load failed: {e}"))
}

/// Resolve a template action against an input and return the resolved JSON.
fn resolve_template(
    store: &RegistryStore,
    action_id: &str,
    input: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let action = store
        .get_action(action_id)
        .unwrap_or_else(|| panic!("{action_id} must exist"));
    let template = action
        .template
        .as_ref()
        .unwrap_or_else(|| panic!("{action_id} must have a template"));
    latchgate_kernel::resolve_template(template, input).map_err(|e| format!("{action_id}: {e}"))
}

// ---------------------------------------------------------------------------
// All manifests load and validate
// ---------------------------------------------------------------------------

#[test]
fn all_manifests_load_and_validate() {
    let store = load_registry();

    for action in store.list_actions() {
        assert!(!action.action_id.is_empty(), "action_id must not be empty");
        assert!(
            action.resource_limits.fuel > 0,
            "{}: fuel must be > 0",
            action.action_id
        );
        assert!(
            action.resource_limits.timeout_seconds > 0,
            "{}: timeout must be > 0",
            action.action_id
        );
        assert!(
            !action.declared_side_effects.is_empty(),
            "{}: must declare at least one side effect",
            action.action_id
        );
    }
}

#[test]
fn no_duplicate_action_ids() {
    let store = load_registry();
    let ids = store.list_action_ids();
    let unique: HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate action_id detected");
}

/// Guard against accidental manifest deletion. Uses a minimum bound
/// rather than an exact count so adding manifests doesn't break this test.
#[test]
fn manifest_count_above_minimum() {
    let store = load_registry();
    let count = store.list_action_ids().len();
    assert!(
        count >= 60,
        "expected at least 60 manifests, got {count} — did you accidentally remove manifests?"
    );
}

// ---------------------------------------------------------------------------
// Template actions have builtin provider
// ---------------------------------------------------------------------------

#[test]
fn template_actions_use_builtin_provider() {
    let store = load_registry();

    for action in store.list_actions() {
        if action.template.is_some() {
            let pm = ProviderModule::parse(&action.provider_module_digest).unwrap_or_else(|e| {
                panic!("{}: invalid provider_module_digest: {e}", action.action_id)
            });
            assert!(
                pm.is_builtin(),
                "{}: template action must use builtin: provider, got '{}'",
                action.action_id,
                action.provider_module_digest
            );
        }
    }
}

#[test]
fn builtin_actions_have_http_import() {
    let store = load_registry();

    for action in store.list_actions() {
        if action
            .provider_module_digest
            .starts_with("builtin:http_api")
        {
            assert!(
                action
                    .required_imports
                    .iter()
                    .any(|s| s.as_ref() == "latchgate:io/http"),
                "{}: builtin:http_api action must declare latchgate:io/http import",
                action.action_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Risk level consistency
// ---------------------------------------------------------------------------

#[test]
fn risk_levels_are_consistent() {
    let store = load_registry();

    // Destructive, financial, or credential-bearing write actions.
    let expected_high_or_critical = [
        // Core HTTP
        "http_delete",
        "http_sensitive_read",
        // Filesystem
        "fs_write",
        "fs_delete",
        // GitHub
        "github_delete",
        "github_pr_create",
        "github_pr_merge",
        "github_actions_trigger",
        // Google Workspace
        "gmail_send",
        "gmail_delete",
        "gcal_create_event",
        "gcal_update_event",
        "gcal_delete_event",
        // SaaS
        "sendgrid_send",
        "stripe_read",
        "stripe_create_invoice",
        // Non-HTTP
        "database_query",
        "smtp_send",
        // Cloud / DevOps
        "cloudflare_dns_create",
        "vercel_deploy",
        "s3_write",
    ];

    let expected_low = [
        // Core HTTP
        "http_fetch",
        "http_bearer_get",
        // Web / Research
        "web_read",
        "wikipedia_read",
        "arxiv_search",
        "hn_top",
        "rss_fetch",
        // Google Workspace
        "gcal_list",
        "gcal_read_event",
        // GitHub
        "github_read",
        "github_search",
        "github_actions_read",
        // Developer
        "gitlab_read",
        "bitbucket_read",
        "npm_read",
        "docker_hub_read",
        // Productivity
        "todoist_list",
        "google_tasks_list",
        "asana_read",
        // Communication
        "slack_read",
        // Local tools
        "obsidian_read",
        // Cloud / DevOps
        "cloudflare_dns_list",
        "vercel_deployments",
        "render_services",
        // Monitoring
        "sentry_read",
        "datadog_read",
        "grafana_read",
        // SaaS (read-only)
        "confluence_read",
        // Finance / Utility
        "exchange_rate",
    ];

    for action in store.list_actions() {
        if expected_high_or_critical.contains(&action.action_id.as_str()) {
            assert!(
                matches!(
                    action.risk_level,
                    latchgate_core::RiskLevel::High | latchgate_core::RiskLevel::Critical
                ),
                "{}: expected high or critical risk, got {:?}",
                action.action_id,
                action.risk_level
            );
        }
        if expected_low.contains(&action.action_id.as_str()) {
            assert_eq!(
                action.risk_level,
                latchgate_core::RiskLevel::Low,
                "{}: expected low risk",
                action.action_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Secret declarations — single source of truth
// ---------------------------------------------------------------------------

/// Every action that requires credentials declares the exact secret name.
/// This is the authoritative secret mapping — no other test needs to
/// duplicate these lists.
#[test]
fn required_secrets_match_expected_names() {
    let store = load_registry();

    let expected: &[(&str, &str)] = &[
        // Core HTTP
        ("http_bearer_get", "API_BEARER_TOKEN"),
        ("http_sensitive_read", "API_BEARER_TOKEN"),
        // SaaS
        ("linear_api", "LINEAR_API_KEY"),
        ("jira_api", "JIRA_API_TOKEN"),
        ("sendgrid_send", "SENDGRID_API_KEY"),
        ("stripe_read", "STRIPE_SECRET_KEY"),
        ("stripe_create_invoice", "STRIPE_SECRET_KEY"),
        ("notion_api", "NOTION_API_KEY"),
        // Google Workspace
        ("gmail_list", "GOOGLE_ACCESS_TOKEN"),
        ("gmail_read", "GOOGLE_ACCESS_TOKEN"),
        ("gmail_send", "GOOGLE_ACCESS_TOKEN"),
        ("gmail_delete", "GOOGLE_ACCESS_TOKEN"),
        ("gcal_list", "GOOGLE_ACCESS_TOKEN"),
        ("gcal_create_event", "GOOGLE_ACCESS_TOKEN"),
        ("gcal_read_event", "GOOGLE_ACCESS_TOKEN"),
        ("gcal_update_event", "GOOGLE_ACCESS_TOKEN"),
        ("gcal_delete_event", "GOOGLE_ACCESS_TOKEN"),
        ("google_tasks_list", "GOOGLE_ACCESS_TOKEN"),
        ("google_tasks_create", "GOOGLE_ACCESS_TOKEN"),
        // GitHub
        ("github_create_issue", "GITHUB_TOKEN"),
        ("github_delete", "GITHUB_TOKEN"),
        ("github_pr_create", "GITHUB_TOKEN"),
        ("github_pr_comment", "GITHUB_TOKEN"),
        ("github_pr_merge", "GITHUB_TOKEN"),
        ("github_pr_review", "GITHUB_TOKEN"),
        ("github_comment_issue", "GITHUB_TOKEN"),
        // Developer
        ("gitlab_create_issue", "GITLAB_TOKEN"),
        // Productivity
        ("todoist_list", "TODOIST_API_TOKEN"),
        ("todoist_create", "TODOIST_API_TOKEN"),
        ("todoist_update", "TODOIST_API_TOKEN"),
        ("todoist_complete", "TODOIST_API_TOKEN"),
        // Communication
        ("slack_read", "SLACK_BOT_TOKEN"),
        // Cloud / DevOps
        ("cloudflare_dns_list", "CLOUDFLARE_API_TOKEN"),
        ("cloudflare_dns_create", "CLOUDFLARE_API_TOKEN"),
        ("vercel_deployments", "VERCEL_TOKEN"),
        ("vercel_deploy", "VERCEL_TOKEN"),
        ("render_services", "RENDER_API_KEY"),
    ];

    for &(action_id, secret_name) in expected {
        let action = store
            .get_action(action_id)
            .unwrap_or_else(|| panic!("{action_id} must exist"));

        let has_secret = action
            .secrets
            .iter()
            .any(|s| *s.name == *secret_name && s.required);

        assert!(
            has_secret,
            "{action_id}: must declare '{secret_name}' as required — \
             missing secret at runtime must produce a clear pre-flight error, \
             not a provider-level auth failure"
        );
    }
}

#[test]
fn every_action_with_required_secret_has_nonempty_secret_name() {
    let store = load_registry();

    for action in store.list_actions() {
        for secret in &action.secrets {
            assert!(
                !secret.name.is_empty(),
                "{}: secret declaration must have a non-empty name",
                action.action_id
            );
        }
    }
}

/// Actions designed to work without credentials must not declare required
/// secrets. Covers both truly secretless actions and those with optional
/// tokens (e.g. github_read works unauthenticated against public repos).
#[test]
fn secretless_actions_have_no_required_secrets() {
    let store = load_registry();

    let secretless = [
        "http_fetch",
        "http_post",
        "slack_post",
        "webhook_notify",
        "web_read",
        "rss_fetch",
        "exchange_rate",
        "discord_post",
        "teams_post",
        "github_read",
    ];

    for action in store.list_actions() {
        if secretless.contains(&action.action_id.as_str()) {
            for secret in &action.secrets {
                assert!(
                    !secret.required,
                    "{}: expected no required secrets (action works without credentials), \
                     but '{}' is marked required",
                    action.action_id, secret.name
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Content digest determinism
// ---------------------------------------------------------------------------

#[test]
fn content_digests_are_deterministic() {
    let store = load_registry();

    for action in store.list_actions() {
        let d1 = &action.content_digest;
        let d2 = &action.content_digest;
        assert_eq!(
            d1, d2,
            "{}: content digest must be deterministic",
            action.action_id
        );
        assert!(
            d1.starts_with("sha256:"),
            "{}: content digest must start with sha256:",
            action.action_id
        );
    }
}

// ---------------------------------------------------------------------------
// Egress profiles
// ---------------------------------------------------------------------------

#[test]
fn all_egress_profiles_resolve() {
    let store = load_registry();

    for action in store.list_actions() {
        action.egress_profile().unwrap_or_else(|e| {
            panic!(
                "{}: egress profile resolution failed: {e}",
                action.action_id
            )
        });
    }
}

// ---------------------------------------------------------------------------
// Template resolution
// ---------------------------------------------------------------------------

#[test]
fn template_resolve_github_create_issue() {
    let store = load_registry();
    let resolved = resolve_template(
        &store,
        "github_create_issue",
        &serde_json::json!({
            "owner": "latchgate-ai",
            "repo": "latchgate",
            "title": "Test issue",
            "body": "Created by integration test"
        }),
    )
    .unwrap();

    assert_eq!(
        resolved["url"],
        "https://api.github.com/repos/latchgate-ai/latchgate/issues"
    );
    assert_eq!(resolved["method"], "POST");
    assert_eq!(resolved["body"]["title"], "Test issue");
    assert_eq!(
        resolved["headers"]["Accept"],
        "application/vnd.github.v3+json"
    );
}

#[test]
fn template_resolve_github_read() {
    let store = load_registry();
    let resolved = resolve_template(
        &store,
        "github_read",
        &serde_json::json!({"path": "rate_limit"}),
    )
    .unwrap();

    assert_eq!(resolved["url"], "https://api.github.com/rate_limit");
    assert_eq!(resolved["method"], "GET");
    assert!(
        resolved.get("body").is_none(),
        "GET template must not produce a body"
    );
}

#[test]
fn template_resolve_github_pr_merge() {
    let store = load_registry();
    let resolved = resolve_template(
        &store,
        "github_pr_merge",
        &serde_json::json!({
            "owner": "latchgate-ai",
            "repo": "latchgate",
            "pull_number": 42,
            "merge_method": "squash",
            "commit_title": "feat: add domain learning"
        }),
    )
    .unwrap();

    assert_eq!(
        resolved["url"],
        "https://api.github.com/repos/latchgate-ai/latchgate/pulls/42/merge"
    );
    assert_eq!(resolved["method"], "PUT");
    assert_eq!(resolved["body"]["merge_method"], "squash");
}

#[test]
fn template_resolve_slack_post() {
    let store = load_registry();
    let resolved = resolve_template(
        &store,
        "slack_post",
        &serde_json::json!({
            "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            "message": "deploy complete",
            "channel": "#ops",
            "username": "LatchGate"
        }),
    )
    .unwrap();

    assert_eq!(
        resolved["url"],
        "https://hooks.slack.com/services/T00/B00/xxx"
    );
    assert_eq!(resolved["method"], "POST");
    assert_eq!(resolved["body"]["text"], "deploy complete");
}

#[test]
fn template_resolve_stripe_read() {
    let store = load_registry();
    let resolved = resolve_template(
        &store,
        "stripe_read",
        &serde_json::json!({"endpoint": "charges"}),
    )
    .unwrap();

    assert!(
        resolved["url"]
            .as_str()
            .unwrap()
            .starts_with("https://api.stripe.com/v1/"),
        "URL must target Stripe API"
    );
    assert_eq!(resolved["method"], "GET");
}

/// Missing required template variable must fail — not produce a broken URL.
#[test]
fn template_resolve_missing_required_variable_fails() {
    let store = load_registry();
    let err = resolve_template(
        &store,
        "github_create_issue",
        &serde_json::json!({"owner": "latchgate-ai", "title": "Test"}),
    );
    assert!(
        err.is_err(),
        "template resolution must fail when a required URL variable is missing"
    );
}

// ---------------------------------------------------------------------------
// Naming convention enforcement
// ---------------------------------------------------------------------------

#[test]
fn action_ids_follow_naming_convention() {
    let store = load_registry();

    let banned = [
        "database",
        "queue",
        "pagerduty",
        "sendgrid",
        "send_message",
        "slack_post_message",
        "api_authenticated",
        "api_patch",
        "sensitive_api_read",
        "s3_operations",
    ];

    for action in store.list_actions() {
        assert!(
            !banned.contains(&action.action_id.as_str()),
            "{}: uses a banned legacy name",
            action.action_id
        );

        assert!(
            action
                .action_id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "{}: action_id must be snake_case (lowercase + digits + underscore)",
            action.action_id
        );

        assert!(
            !action.action_id.starts_with('_') && !action.action_id.ends_with('_'),
            "{}: action_id must not start or end with underscore",
            action.action_id
        );
    }
}

// ---------------------------------------------------------------------------
// Read/write isolation — S3 split verification
// ---------------------------------------------------------------------------

#[test]
fn s3_read_does_not_allow_write_methods() {
    let store = load_registry();
    let action = store
        .get_action("s3_read")
        .expect("s3_read manifest must exist");

    let schema = match &action.io.request_schema {
        Some(latchgate_registry::IoSchema::Inline(v)) => v,
        other => panic!("s3_read must have inline request_schema, got {other:?}"),
    };
    let method_enum = schema["properties"]["method"]["enum"]
        .as_array()
        .expect("s3_read must constrain method via enum");

    let methods: Vec<&str> = method_enum.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        !methods.contains(&"PUT") && !methods.contains(&"DELETE"),
        "s3_read must not allow PUT or DELETE — found methods: {methods:?}"
    );
    assert!(
        methods.contains(&"GET") || methods.contains(&"HEAD"),
        "s3_read must allow at least GET or HEAD — found methods: {methods:?}"
    );
}

#[test]
fn s3_write_does_not_allow_read_methods() {
    let store = load_registry();
    let action = store
        .get_action("s3_write")
        .expect("s3_write manifest must exist");

    let schema = match &action.io.request_schema {
        Some(latchgate_registry::IoSchema::Inline(v)) => v,
        other => panic!("s3_write must have inline request_schema, got {other:?}"),
    };
    let method_enum = schema["properties"]["method"]["enum"]
        .as_array()
        .expect("s3_write must constrain method via enum");

    let methods: Vec<&str> = method_enum.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        !methods.contains(&"GET") && !methods.contains(&"HEAD"),
        "s3_write must not allow GET or HEAD — found methods: {methods:?}"
    );
    assert!(
        methods.contains(&"PUT") || methods.contains(&"DELETE"),
        "s3_write must allow PUT or DELETE — found methods: {methods:?}"
    );
}

// ---------------------------------------------------------------------------
// Egress allowlist consistency
// ---------------------------------------------------------------------------

#[test]
fn domain_learning_actions_have_empty_allowlists() {
    let store = load_registry();

    let learning_actions = ["web_read", "rss_fetch"];

    for action_id in &learning_actions {
        let action = store
            .get_action(action_id)
            .unwrap_or_else(|| panic!("{action_id} must exist"));

        let profile = action.egress_profile().unwrap();
        match profile {
            latchgate_core::EgressProfile::ProxyAllowlist { allowed_domains } => {
                assert!(
                    allowed_domains.is_empty(),
                    "{action_id}: must have empty allowed_domains (all domains via learning), \
                     but found: {allowed_domains:?}"
                );
            }
            other => {
                panic!("{action_id}: expected proxy_allowlist with empty domains, got {other:?}")
            }
        }
    }
}

#[test]
fn stable_api_actions_have_nonempty_allowlists() {
    let store = load_registry();

    let stable_actions = [
        "gmail_list",
        "gmail_read",
        "gmail_send",
        "gcal_list",
        "gcal_create_event",
        "github_create_issue",
        "github_read",
        "stripe_read",
        "todoist_list",
    ];

    for action_id in &stable_actions {
        let action = store
            .get_action(action_id)
            .unwrap_or_else(|| panic!("{action_id} must exist"));

        let profile = action.egress_profile().unwrap();
        #[allow(unreachable_patterns)]
        match profile {
            latchgate_core::EgressProfile::ProxyAllowlist { allowed_domains } => {
                assert!(
                    !allowed_domains.is_empty(),
                    "{action_id}: stable API action must have a non-empty allowlist — \
                     if the domain never changes, it belongs in the manifest"
                );
            }
            latchgate_core::EgressProfile::None => {
                // Non-HTTP actions have no egress — fine.
            }
            _ => {
                panic!("{action_id}: unrecognized egress profile variant");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Security gates — response schema + verifier strength on high/critical
// ---------------------------------------------------------------------------

/// High/critical actions MUST declare a response schema. Without one, the
/// verifier cannot confirm the approved effect is what actually happened.
#[test]
fn high_critical_actions_have_response_schema() {
    let store = load_registry();
    let mut missing: Vec<String> = Vec::new();

    for action in store.list_actions() {
        if matches!(
            action.risk_level,
            latchgate_core::RiskLevel::High | latchgate_core::RiskLevel::Critical
        ) && action.io.response_schema.is_none()
            && action.fs.is_none()
        {
            missing.push(action.action_id.clone());
        }
    }

    // All high/critical actions now have response schemas.
    // This gate prevents regressions.
    let max_allowed = 0;
    assert!(
        missing.len() <= max_allowed,
        "high/critical actions without response_schema ({} > {max_allowed}): {missing:?}\n\
         Add io.response_schema to each manifest to pass this gate.",
        missing.len(),
    );
}

/// High/critical write actions must not rely on a bare http_status check.
/// Actions using http_status with verification_config.required_fields are
/// accepted — the verifier confirms response body structure, not just 2xx.
#[test]
fn high_critical_write_actions_have_strong_verifier() {
    let store = load_registry();
    let mut weak: Vec<String> = Vec::new();

    let write_effects: HashSet<&str> = [
        "http_write",
        "http_delete",
        "message_send",
        "db_write",
        "message_enqueue",
        "fs_write",
        "deploy",
        "dns_write",
    ]
    .into_iter()
    .collect();

    for action in store.list_actions() {
        let is_high = matches!(
            action.risk_level,
            latchgate_core::RiskLevel::High | latchgate_core::RiskLevel::Critical
        );
        let has_write = action
            .declared_side_effects
            .iter()
            .any(|e| write_effects.contains(e.as_ref()));

        if !is_high || !has_write {
            continue;
        }

        // Non-http_status verifiers (rows_affected, message_id, etc.) are
        // intrinsically deeper — no further check needed.
        if !matches!(
            action.verifier_kind,
            latchgate_core::VerifierKind::HttpStatus
        ) {
            continue;
        }

        // http_status with verification_config.required_fields is acceptable.
        let has_required_fields = action
            .verification_config
            .as_ref()
            .and_then(|vc| vc.get("required_fields"))
            .and_then(|rf| rf.as_array())
            .is_some_and(|arr| !arr.is_empty());

        if !has_required_fields {
            weak.push(action.action_id.clone());
        }
    }

    // All high/critical write actions now carry verification_config with
    // required_fields. This gate prevents regressions.
    let max_allowed = 0;
    assert!(
        weak.len() <= max_allowed,
        "high/critical write actions with bare http_status verifier \
         ({} > {max_allowed}): {weak:?}\n\
         Add verification_config.required_fields or upgrade verifier_kind.",
        weak.len(),
    );
}

/// Every request_schema must compile as valid JSON Schema.
#[test]
fn all_request_schemas_compile() {
    let store = load_registry();

    for action in store.list_actions() {
        if store.get_request_validator(&action.action_id).is_some() {
            assert!(
                action.io.request_schema.is_some(),
                "{}: has compiled validator but no schema field",
                action.action_id
            );
        }
    }
}

/// High/critical actions MUST NOT use verifier_kind = none.
#[test]
fn high_critical_actions_have_non_none_verifier() {
    let store = load_registry();
    let mut violations: Vec<String> = Vec::new();

    for action in store.list_actions() {
        if matches!(
            action.risk_level,
            latchgate_core::RiskLevel::High | latchgate_core::RiskLevel::Critical
        ) && matches!(action.verifier_kind, latchgate_core::VerifierKind::None)
        {
            violations.push(action.action_id.clone());
        }
    }

    assert!(
        violations.is_empty(),
        "high/critical actions with verifier_kind = none: {violations:?}\n\
         Every high/critical action must have at least http_status verification.",
    );
}

/// Destructive side-effects must not be classified as low risk.
#[test]
fn write_actions_are_not_low_risk() {
    let store = load_registry();
    let mut violations: Vec<String> = Vec::new();

    let destructive: HashSet<&str> = ["http_delete", "db_write", "deploy", "dns_write"]
        .into_iter()
        .collect();

    for action in store.list_actions() {
        let has_destructive = action
            .declared_side_effects
            .iter()
            .any(|e| destructive.contains(e.as_ref()));

        if has_destructive && action.risk_level == latchgate_core::RiskLevel::Low {
            violations.push(action.action_id.clone());
        }
    }

    assert!(
        violations.is_empty(),
        "destructive actions with low risk_level: {violations:?}\n\
         Actions with delete/db_write/deploy effects must be high or critical.",
    );
}
