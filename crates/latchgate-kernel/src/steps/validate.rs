//! Step 4: request body parsing, schema validation, and canonical hashing.

use std::sync::Arc;

use latchgate_core::crypto::canonical;
use latchgate_ledger::Decision;
use latchgate_registry::{schema, ActionSpec, SchemaError, ValidationLimits};

use super::deny_and_audit;
use super::types::ValidateAndHashOutput;
use crate::pipeline::PipelineError;
use crate::request::RequestCtx;
use crate::state::AppState;

/// Pre-allocated empty JSON object for no-arg action requests.
///
/// Stored as `Arc<Value>` so no-arg requests can produce the pipeline's
/// `Arc<serde_json::Value>` via `Arc::clone` — zero per-request allocation.
static EMPTY_JSON_OBJECT: std::sync::LazyLock<Arc<serde_json::Value>> =
    std::sync::LazyLock::new(|| Arc::new(serde_json::Value::Object(serde_json::Map::new())));

/// Parse the body as JSON, validate against the action's request schema,
/// compute the canonical hash, and enrich `ctx.audit` with both.
///
/// SECURITY:
/// - Empty body => `{}` for actions with no declared arguments (valid).
/// - Schema mismatch is a deny, not a 4xx parser error: the caller sent
///   a request the policy layer cannot safely reason about.
/// - Canonical hashing uses JCS (RFC 8785). The hash becomes part of the
///   approval plan, execution grant, and receipt — it is the binding
///   invariant that ties request => approval => execution.
pub(crate) async fn step_validate_and_hash(
    state: &AppState,
    ctx: &mut RequestCtx,
    manifest: &ActionSpec,
    body: &[u8],
) -> Result<ValidateAndHashOutput, PipelineError> {
    let request_limits = ValidationLimits {
        max_bytes: manifest.io.max_request_bytes,
        max_depth: 10,
        max_items: 100,
    };

    // SECURITY: empty body is valid for actions that take no arguments.
    let request_body: Arc<serde_json::Value> = if body.is_empty() {
        Arc::clone(&EMPTY_JSON_OBJECT)
    } else {
        match serde_json::from_slice(body) {
            Ok(v) => Arc::new(v),
            Err(e) => {
                let reason = format!("invalid JSON body: {e}");
                return Err(deny_and_audit(
                    state,
                    ctx,
                    Decision::Deny,
                    "deny",
                    None,
                    reason,
                    PipelineError::Schema(SchemaError::ValidationFailed {
                        reason: format!("request body is not valid JSON: {e}"),
                    }),
                )
                .await);
            }
        }
    };

    let registry = state.registry.load();
    let request_validator = registry.get_request_validator(&ctx.action_id);

    let schema_result = match request_validator {
        Some(validator) => schema::validate_request(validator, &request_body, &request_limits),
        None => schema::validate_request_limits_only(&request_body, &request_limits),
    };
    if let Err(e) = schema_result {
        let reason = format!("request schema: {e}");
        return Err(deny_and_audit(
            state,
            ctx,
            Decision::Deny,
            "deny",
            None,
            reason,
            PipelineError::Schema(e),
        )
        .await);
    }

    // SECURITY: scope canonical limits to the action's declared request
    // size — not the canonicalizer default (64 KiB). Failures route through
    // deny_and_audit so the denial is recorded in metrics and the audit
    // ledger, consistent with schema validation failures above.
    let canonical_limits = canonical::Limits {
        max_bytes: manifest.io.max_request_bytes,
        max_depth: 32,
    };
    let request_hash: Arc<str> = match canonical::canonical_hash(&request_body, &canonical_limits) {
        Ok(hash) => hash.into(),
        Err(e) => {
            let reason = format!("request canonicalization: {e}");
            return Err(deny_and_audit(
                state,
                ctx,
                Decision::Deny,
                "deny",
                None,
                reason,
                PipelineError::CanonicalHash(e.to_string()),
            )
            .await);
        }
    };

    let schema_id: Option<String> = request_validator.map(|_| format!("{}:request", ctx.action_id));

    ctx.audit.set_request(
        Arc::clone(&request_hash),
        schema_id.as_deref().map(Arc::from),
    );

    Ok(ValidateAndHashOutput {
        request_body,
        request_hash,
        schema_id,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::request::RequestCtx;
    use crate::test_support::{registry_with_test_action, test_app_state_with_registry};

    fn ctx(action_id: &str) -> RequestCtx {
        RequestCtx::new(Arc::from("trace-test-001"), Arc::from(action_id), true)
    }

    #[tokio::test]
    async fn validate_empty_body_produces_empty_json_object() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let mut c = ctx("test_action");
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();

        let out = step_validate_and_hash(&state, &mut c, manifest, b"")
            .await
            .unwrap();
        assert_eq!(*out.request_body, serde_json::json!({}));
        assert!(
            out.request_hash.starts_with("sha256:"),
            "hash must have sha256: prefix, got: {}",
            out.request_hash
        );
    }

    #[tokio::test]
    async fn validate_invalid_json_is_denied() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let mut c = ctx("test_action");
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();

        let err = step_validate_and_hash(&state, &mut c, manifest, b"not json{")
            .await
            .unwrap_err();
        assert!(
            matches!(err, PipelineError::Schema(_)),
            "invalid JSON body must return Schema error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn validate_valid_json_produces_deterministic_hash() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();

        let body = br#"{"path": "hello"}"#;

        let mut c1 = ctx("test_action");
        let out1 = step_validate_and_hash(&state, &mut c1, manifest, body)
            .await
            .unwrap();

        let mut c2 = ctx("test_action");
        let out2 = step_validate_and_hash(&state, &mut c2, manifest, body)
            .await
            .unwrap();

        assert_eq!(
            out1.request_hash, out2.request_hash,
            "canonical hash must be deterministic across calls"
        );
    }

    #[tokio::test]
    async fn validate_reorders_keys_in_canonical_hash() {
        let registry = registry_with_test_action();
        let (state, _) = test_app_state_with_registry(registry);
        let registry = state.registry.load();
        let manifest = registry.get_action("test_action").unwrap();

        let body_a = br#"{"path": "x", "extra": 1}"#;
        let body_b = br#"{"extra": 1, "path": "x"}"#;

        let mut c1 = ctx("test_action");
        let out1 = step_validate_and_hash(&state, &mut c1, manifest, body_a)
            .await
            .unwrap();

        let mut c2 = ctx("test_action");
        let out2 = step_validate_and_hash(&state, &mut c2, manifest, body_b)
            .await
            .unwrap();

        assert_eq!(
            out1.request_hash, out2.request_hash,
            "JCS canonical hash must be key-order independent"
        );
    }

    // -- Action-scoped canonical limits (regression) -----------------------

    /// Manifest with generous I/O limits for large-body tests.
    const LARGE_IO_ACTION_YAML: &str = r#"
action_id: "large_io_action"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
required_imports:
  - "latchgate:io/http"
  - "latchgate:io/log"
template:
  method: POST
  url_template: "https://example.com/api"
io:
  max_request_bytes: 524288
  max_response_bytes: 2097152
risk_level: low
"#;

    fn registry_with_large_io_action() -> latchgate_registry::RegistryStore {
        latchgate_registry::RegistryBuilder::new()
            .add_embedded([("large_io_action.yaml", LARGE_IO_ACTION_YAML)].into_iter())
            .expect("large_io_action manifest should parse")
            .build()
    }

    /// A 100 KiB request body must succeed for an action with a 512 KiB limit.
    ///
    /// Regression: canonical hashing previously used Limits::default() (64 KiB)
    /// regardless of the action config, causing valid large requests to fail
    /// with a CanonicalHash error or produce degraded audit evidence.
    #[tokio::test]
    async fn validate_body_over_64k_succeeds_when_action_permits() {
        let registry = registry_with_large_io_action();
        let (state, _) = test_app_state_with_registry(registry);
        let mut c = ctx("large_io_action");
        let registry = state.registry.load();
        let manifest = registry.get_action("large_io_action").unwrap();

        // 100 KiB payload — exceeds canonical::Limits::default() (64 KiB)
        // but well within the action's max_request_bytes (512 KiB).
        let padding = "x".repeat(100 * 1024);
        let body = serde_json::to_vec(&serde_json::json!({"data": padding})).unwrap();

        let out = step_validate_and_hash(&state, &mut c, manifest, &body)
            .await
            .expect("100 KiB body must succeed for action with 512 KiB request limit");

        assert!(
            out.request_hash.starts_with("sha256:"),
            "canonical hash must be real, got: {}",
            out.request_hash
        );
    }

    /// The hash for a large body must be deterministic and key-order independent.
    #[tokio::test]
    async fn validate_large_body_hash_is_deterministic_and_canonical() {
        let registry = registry_with_large_io_action();
        let (state, _) = test_app_state_with_registry(registry);
        let registry = state.registry.load();
        let manifest = registry.get_action("large_io_action").unwrap();

        let padding = "z".repeat(80 * 1024);
        let body_a = serde_json::to_vec(&serde_json::json!({"data": padding, "seq": 1})).unwrap();
        let body_b = serde_json::to_vec(&serde_json::json!({"seq": 1, "data": padding})).unwrap();

        let mut c1 = ctx("large_io_action");
        let out1 = step_validate_and_hash(&state, &mut c1, manifest, &body_a)
            .await
            .unwrap();

        let mut c2 = ctx("large_io_action");
        let out2 = step_validate_and_hash(&state, &mut c2, manifest, &body_b)
            .await
            .unwrap();

        assert_eq!(
            out1.request_hash, out2.request_hash,
            "JCS canonical hash must be key-order independent for large bodies"
        );
    }
}
