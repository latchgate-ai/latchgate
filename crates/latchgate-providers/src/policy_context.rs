//! Generic policy-context dispatcher.
//!
//! The kernel calls [`build_policy_context`] without knowing which provider is
//! involved. This module inspects `database_config` to determine the provider
//! kind and delegates to the appropriate context builder.
//!
//! SECURITY: returning `None` is always safe — OPA receives no enrichment and
//! must decide on base facts alone (fail-closed).

use crate::database;

/// Build provider-specific policy context from manifest config and request body.
///
/// Returns opaque JSON for the policy engine. The kernel calls this generically;
/// provider-specific logic lives entirely in `latchgate-providers`.
///
/// # Arguments
///
/// * `provider_module_digest` — the `provider_module_digest` field from the action manifest
///   (e.g. `"sha256:abcd..."` or `"builtin:http_api"`). Reserved for future
///   dispatch; currently unused because provider kind is inferred from config
///   shape.
/// * `database_config` — optional provider-specific configuration from the
///   manifest. Its schema determines which provider context builder runs.
/// * `request_body` — the caller-supplied request body for the action.
pub fn build_policy_context(
    _provider_module_digest: &str,
    database_config: Option<&serde_json::Value>,
    request_body: &serde_json::Value,
) -> Option<serde_json::Value> {
    // Try each known provider context builder in turn.
    // The first successful parse wins. If none match, return None (no enrichment).
    //
    // SAFETY (logical): ordering does not matter because provider config schemas
    // are non-overlapping — a valid DatabaseConfig cannot deserialize as another
    // provider's config. If schemas ever overlap, add an explicit discriminator
    // field.

    if let Some(ctx) = database::build_database_policy_context(database_config, request_body) {
        return Some(ctx);
    }

    // Future providers: add context builders here.
    // e.g. queue::build_queue_policy_context(queue_config, request_body)

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::types::{DatabaseConfig, DatabaseMode, DatabaseRules, DatabaseStatement};

    fn db_config_value() -> serde_json::Value {
        serde_json::to_value(DatabaseConfig {
            mode: DatabaseMode::Hybrid,
            statements: vec![DatabaseStatement {
                id: "get_user".into(),
                sql: "SELECT * FROM users WHERE id = $1".into(),
            }],
            rules: DatabaseRules::mvp_defaults(),
        })
        .unwrap()
    }

    #[test]
    fn dispatches_to_database_context_for_valid_db_config() {
        let config = db_config_value();
        let body = serde_json::json!({"statement_id": "get_user", "params": ["u-1"]});

        let ctx = build_policy_context("sha256:aabbcc", Some(&config), &body);
        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert_eq!(ctx["operation_class"], "select");
        assert_eq!(ctx["statement_mode"], "predeclared");
    }

    #[test]
    fn returns_none_when_no_database_config() {
        let body = serde_json::json!({"statement_id": "x"});
        assert!(build_policy_context("sha256:aabb", None, &body).is_none());
    }

    #[test]
    fn returns_none_for_unrecognized_database_config() {
        // Config that doesn't match any known provider schema.
        let config = serde_json::json!({"some_unknown_field": true});
        let body = serde_json::json!({"data": 42});
        assert!(build_policy_context("builtin:http_api", Some(&config), &body).is_none());
    }

    #[test]
    fn provider_module_does_not_affect_dispatch() {
        // Same db config, different provider_module_digest strings — all dispatch to database.
        let config = db_config_value();
        let body = serde_json::json!({"statement_id": "get_user", "params": ["u-1"]});

        let r1 = build_policy_context("sha256:000000", Some(&config), &body);
        let r2 = build_policy_context("builtin:http_api", Some(&config), &body);
        assert_eq!(r1, r2);
    }
}
