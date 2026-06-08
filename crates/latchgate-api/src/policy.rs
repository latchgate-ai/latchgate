//! Policy management endpoints for the admin router.
//!
//! Exposes the OPA ACL over HTTP so the TUI and external tooling can
//! grant/revoke actions without direct `data.json` edits. Mutations
//! validate action IDs against the loaded registry, auto-derive
//! `allowed_sinks` from `declared_side_effects`, write `data.json`
//! atomically (tmp+fsync+rename), and hot-reload the embedded OPA
//! evaluator.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tracing::warn;

use latchgate_kernel::AppState;
use latchgate_ledger::EventType;

use crate::admin::require_operator_auth;
use crate::json_response::JsonResponse as ApiError;

const MAX_PRINCIPAL_LEN: usize = 253;
const MAX_ACTION_ID_LEN: usize = 253;
const MAX_ACTIONS_PER_REQUEST: usize = 100;

#[derive(Debug, Deserialize)]
pub struct GrantRevokeBody {
    /// Principal name (e.g. "agent-ops"). Use "*" for wildcard.
    pub principal: String,
    /// Action IDs to grant or revoke.
    pub actions: Vec<String>,
}

fn validate_principal(p: &str) -> Result<(), ApiError> {
    if p.is_empty() || p.len() > MAX_PRINCIPAL_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_principal")
            .field("detail", "principal must be 1-253 characters"));
    }
    Ok(())
}

fn validate_action_id(aid: &str) -> Result<(), ApiError> {
    if aid.is_empty() || aid.len() > MAX_ACTION_ID_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_action_id")
            .field("detail", "action_id must be 1-253 characters"));
    }
    if !aid
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_action_id")
            .field("detail", "action_id must contain only [a-zA-Z0-9_-]"));
    }
    Ok(())
}

pub(crate) fn resolve_data_json_path(config: &latchgate_config::Config) -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(".latchgate/policies/data.json"),
        PathBuf::from("policies/data.json"),
        PathBuf::from("policies/opa/data.json"),
    ];
    for p in &candidates {
        if p.is_file() {
            return Some(p.clone());
        }
    }
    // Config-relative: sibling of manifests_dir.
    Path::new(&config.manifests_dir)
        .parent()
        .map(|p| p.join("data.json"))
        .filter(|p| p.is_file())
}

fn read_data_json(path: &Path) -> Result<Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
}

fn write_data_json_atomic(path: &Path, doc: &Value) -> Result<String, String> {
    let content =
        serde_json::to_string_pretty(doc).map_err(|e| format!("cannot serialize: {e}"))?;

    latchgate_core::atomic_write_str(path, &content)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;

    Ok(content)
}

fn ensure_acl_object(doc: &mut Value) -> Result<&mut Map<String, Value>, String> {
    latchgate_core::ensure_acl_object(doc).map_err(|e| e.to_string())
}

fn increment_version(doc: &mut Value) -> Result<(), String> {
    latchgate_core::increment_version(doc).map_err(|e| e.to_string())
}

/// Derive the union of all sinks for a set of actions from the registry.
fn derive_sinks(
    actions: &BTreeSet<String>,
    registry: &latchgate_registry::RegistryStore,
) -> BTreeSet<Arc<str>> {
    let mut sinks = BTreeSet::new();
    for aid in actions {
        if let Some(spec) = registry.get_action(aid) {
            for sink in &spec.declared_side_effects {
                sinks.insert(sink.clone());
            }
        }
    }
    sinks
}

/// Show the full ACL (all principals).
pub async fn show_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_operator_auth(&state, &headers, "GET", "/v1/admin/policy").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let config = Arc::clone(&state.config);
    let doc = tokio::task::spawn_blocking(move || {
        let path =
            resolve_data_json_path(&config).ok_or_else(|| "data.json not found".to_string())?;
        read_data_json(&path)
    })
    .await
    .map_err(|e| {
        warn!(error = %e, "show_policy task panicked");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?
    .map_err(|e| {
        warn!(error = %e, "show_policy read error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy_read_error").field("detail", &e)
    })?;

    let policy_version = doc["policy_version"].as_str().unwrap_or("").to_string();
    let acl = doc.get("acl").cloned().unwrap_or(json!({}));

    Ok(Json(json!({
        "policy_version": policy_version,
        "acl": acl,
    })))
}

/// Show one principal's ACL.
pub async fn show_principal(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(principal): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    require_operator_auth(
        &state,
        &headers,
        "GET",
        &format!("/v1/admin/policy/{principal}"),
    )
    .await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_principal(&principal)?;

    let config = Arc::clone(&state.config);
    let p = principal.clone();
    let doc = tokio::task::spawn_blocking(move || {
        let path =
            resolve_data_json_path(&config).ok_or_else(|| "data.json not found".to_string())?;
        read_data_json(&path)
    })
    .await
    .map_err(|e| {
        warn!(error = %e, "show_principal task panicked");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?
    .map_err(|e| {
        warn!(error = %e, "show_principal read error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy_read_error").field("detail", &e)
    })?;

    let entry = doc
        .get("acl")
        .and_then(|acl| acl.get(&p))
        .cloned()
        .unwrap_or(json!(null));

    if entry.is_null() {
        return Err(
            ApiError::new(StatusCode::NOT_FOUND, "principal_not_found").field("principal", &p)
        );
    }

    Ok(Json(json!({
        "principal": p,
        "acl": entry,
    })))
}

/// Grant actions to a principal.
///
/// Validates action IDs against the loaded registry. Auto-derives
/// `allowed_sinks` from `declared_side_effects`. Atomic write, then
/// hot-reload the embedded OPA evaluator.
pub async fn grant_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GrantRevokeBody>,
) -> Result<Json<Value>, ApiError> {
    let operator_ctx =
        require_operator_auth(&state, &headers, "POST", "/v1/admin/policy/grant").await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_principal(&body.principal)?;

    if body.actions.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "empty_actions")
            .field("detail", "at least one action required"));
    }
    if body.actions.len() > MAX_ACTIONS_PER_REQUEST {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, "too_many_actions").field(
                "detail",
                &format!("max {MAX_ACTIONS_PER_REQUEST} actions per request"),
            ),
        );
    }

    // Validate all action IDs against the registry.
    for aid in &body.actions {
        validate_action_id(aid)?;
        if state.registry.load().get_action(aid).is_none() {
            return Err(
                ApiError::new(StatusCode::BAD_REQUEST, "unknown_action").field("action_id", aid)
            );
        }
    }

    let operator_id = operator_ctx.operator_id.clone();
    let principal = body.principal.clone();
    let action_ids: Vec<String> = body.actions.clone();
    let config = Arc::clone(&state.config);
    let registry = state.registry.load_full();

    // Mutate data.json in a blocking task.
    let result = tokio::task::spawn_blocking(move || {
        let data_path =
            resolve_data_json_path(&config).ok_or_else(|| "data.json not found".to_string())?;

        let mut doc = read_data_json(&data_path)?;
        let acl = ensure_acl_object(&mut doc)?;

        let entry = acl
            .entry(principal.clone())
            .or_insert_with(|| json!({ "allowed_actions": [], "allowed_sinks": [] }));

        let entry_obj = entry
            .as_object_mut()
            .ok_or_else(|| "ACL entry is not an object".to_string())?;

        let mut current_actions: BTreeSet<String> = entry_obj
            .get("allowed_actions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for aid in &action_ids {
            current_actions.insert(aid.clone());
        }

        let sinks = derive_sinks(&current_actions, &registry);

        entry_obj.insert(
            "allowed_actions".into(),
            json!(current_actions.iter().collect::<Vec<_>>()),
        );
        entry_obj.insert(
            "allowed_sinks".into(),
            json!(sinks.iter().collect::<Vec<_>>()),
        );

        increment_version(&mut doc)?;

        let new_content = write_data_json_atomic(&data_path, &doc)?;

        Ok::<(String, Value, usize, Vec<Arc<str>>), String>((
            new_content,
            doc,
            current_actions.len(),
            sinks.into_iter().collect(),
        ))
    })
    .await
    .map_err(|e| {
        warn!(error = %e, "grant task panicked");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?
    .map_err(|e| {
        warn!(error = %e, "grant mutation error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy_write_error").field("detail", &e)
    })?;

    let (new_content, _doc, total_actions, sinks) = result;

    // Hot-reload the embedded OPA evaluator.
    state.reload_policy_data(
        latchgate_embed::embedded_policies::POLICY_REGO,
        Some(&new_content),
    );

    // Audit.
    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::PolicyGrant,
        &operator_id,
        Some(format!(
            "principal={} actions={} total={}",
            body.principal,
            body.actions.join(","),
            total_actions,
        )),
    )
    .await;

    Ok(Json(json!({
        "principal": body.principal,
        "granted": body.actions,
        "total_actions": total_actions,
        "allowed_sinks": sinks,
    })))
}

/// Revoke actions from a principal.
///
/// Removes the specified actions and recomputes `allowed_sinks`.
/// If no actions remain, removes the principal entry entirely.
pub async fn revoke_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GrantRevokeBody>,
) -> Result<Json<Value>, ApiError> {
    let operator_ctx =
        require_operator_auth(&state, &headers, "POST", "/v1/admin/policy/revoke").await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_principal(&body.principal)?;

    if body.actions.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "empty_actions")
            .field("detail", "at least one action required"));
    }
    if body.actions.len() > MAX_ACTIONS_PER_REQUEST {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, "too_many_actions").field(
                "detail",
                &format!("max {MAX_ACTIONS_PER_REQUEST} actions per request"),
            ),
        );
    }

    for aid in &body.actions {
        validate_action_id(aid)?;
    }

    let operator_id = operator_ctx.operator_id.clone();
    let principal = body.principal.clone();
    let action_ids: Vec<String> = body.actions.clone();
    let config = Arc::clone(&state.config);
    let registry = state.registry.load_full();

    let result = tokio::task::spawn_blocking(move || {
        let data_path =
            resolve_data_json_path(&config).ok_or_else(|| "data.json not found".to_string())?;

        let mut doc = read_data_json(&data_path)?;
        let acl = ensure_acl_object(&mut doc)?;

        let entry = match acl.get_mut(&principal) {
            Some(e) => e,
            None => {
                return Ok::<(String, usize, Vec<Arc<str>>, bool), String>((
                    std::fs::read_to_string(&data_path).unwrap_or_default(),
                    0,
                    Vec::new(),
                    false,
                ));
            }
        };

        let entry_obj = entry
            .as_object_mut()
            .ok_or_else(|| "ACL entry is not an object".to_string())?;

        let mut current_actions: BTreeSet<String> = entry_obj
            .get("allowed_actions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for aid in &action_ids {
            current_actions.remove(aid);
        }

        if current_actions.is_empty() {
            acl.remove(&principal);
        } else {
            let sinks = derive_sinks(&current_actions, &registry);
            let entry = acl
                .get_mut(&principal)
                .and_then(|v| v.as_object_mut())
                .ok_or_else(|| "ACL entry disappeared during revoke".to_string())?;
            entry.insert(
                "allowed_actions".into(),
                json!(current_actions.iter().collect::<Vec<_>>()),
            );
            entry.insert(
                "allowed_sinks".into(),
                json!(sinks.iter().collect::<Vec<_>>()),
            );
        }

        increment_version(&mut doc)?;

        let remaining = current_actions.len();
        let sinks: Vec<Arc<str>> = if remaining > 0 {
            derive_sinks(&current_actions, &registry)
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };

        let new_content = write_data_json_atomic(&data_path, &doc)?;

        Ok((new_content, remaining, sinks, true))
    })
    .await
    .map_err(|e| {
        warn!(error = %e, "revoke task panicked");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?
    .map_err(|e| {
        warn!(error = %e, "revoke mutation error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy_write_error").field("detail", &e)
    })?;

    let (new_content, remaining, sinks, modified) = result;

    // Hot-reload.
    if modified {
        state.reload_policy_data(
            latchgate_embed::embedded_policies::POLICY_REGO,
            Some(&new_content),
        );
    }

    // Audit.
    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::PolicyRevoke,
        &operator_id,
        Some(format!(
            "principal={} actions={} remaining={}",
            body.principal,
            body.actions.join(","),
            remaining,
        )),
    )
    .await;

    Ok(Json(json!({
        "principal": body.principal,
        "revoked": body.actions,
        "remaining_actions": remaining,
        "allowed_sinks": sinks,
        "principal_removed": remaining == 0 && modified,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn validate_principal_accepts_normal() {
        assert!(validate_principal("agent-ops").is_ok());
    }

    #[test]
    fn validate_principal_accepts_wildcard() {
        assert!(validate_principal("*").is_ok());
    }

    #[test]
    fn validate_principal_accepts_single_char() {
        assert!(validate_principal("a").is_ok());
    }

    #[test]
    fn validate_principal_accepts_max_length() {
        let p = "a".repeat(MAX_PRINCIPAL_LEN);
        assert!(validate_principal(&p).is_ok());
    }

    #[test]
    fn validate_principal_rejects_empty() {
        let err = validate_principal("").unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_principal_rejects_over_max_length() {
        let p = "a".repeat(MAX_PRINCIPAL_LEN + 1);
        let err = validate_principal(&p).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_action_id_accepts_alphanumeric_with_underscores() {
        assert!(validate_action_id("http_fetch").is_ok());
        assert!(validate_action_id("github-pr-create").is_ok());
        assert!(validate_action_id("s3_read").is_ok());
        assert!(validate_action_id("Action123").is_ok());
    }

    #[test]
    fn validate_action_id_accepts_max_length() {
        let aid = "a".repeat(MAX_ACTION_ID_LEN);
        assert!(validate_action_id(&aid).is_ok());
    }

    #[test]
    fn validate_action_id_rejects_empty() {
        let err = validate_action_id("").unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_action_id_rejects_over_max_length() {
        let aid = "a".repeat(MAX_ACTION_ID_LEN + 1);
        let err = validate_action_id(&aid).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_action_id_rejects_dots() {
        let err = validate_action_id("http.fetch").unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_action_id_rejects_slashes() {
        assert!(validate_action_id("path/traversal").is_err());
        assert!(validate_action_id("path\\traversal").is_err());
    }

    #[test]
    fn validate_action_id_rejects_spaces() {
        assert!(validate_action_id("http fetch").is_err());
    }

    #[test]
    fn validate_action_id_rejects_special_chars() {
        assert!(validate_action_id("action;drop").is_err());
        assert!(validate_action_id("action@host").is_err());
        assert!(validate_action_id("action$var").is_err());
    }

    #[test]
    fn read_write_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");

        let doc = json!({
            "policy_version": "v1",
            "acl": {
                "agent-1": {
                    "allowed_actions": ["http_fetch"],
                    "allowed_sinks": ["api.example.com"]
                }
            }
        });

        write_data_json_atomic(&path, &doc).unwrap();
        let loaded = read_data_json(&path).unwrap();

        assert_eq!(loaded["policy_version"], "v1");
        assert_eq!(loaded["acl"]["agent-1"]["allowed_actions"][0], "http_fetch");
    }

    #[test]
    fn read_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        assert!(read_data_json(&path).is_err());
    }

    #[test]
    fn read_invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not { valid json").unwrap();
        assert!(read_data_json(&path).is_err());
    }

    #[test]
    fn write_creates_parent_dirs_via_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/dir/data.json");
        // atomic_write_str should handle existing parent or fail gracefully.
        // The parent must exist for atomic_write_str — test that it works
        // when parent exists.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let doc = json!({"test": true});
        assert!(write_data_json_atomic(&path, &doc).is_ok());
    }

    #[test]
    fn write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");

        write_data_json_atomic(&path, &json!({"v": 1})).unwrap();
        write_data_json_atomic(&path, &json!({"v": 2})).unwrap();

        let loaded = read_data_json(&path).unwrap();
        assert_eq!(loaded["v"], 2);
    }

    #[test]
    fn write_produces_pretty_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");

        write_data_json_atomic(&path, &json!({"a": 1})).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains('\n'),
            "output must be pretty-printed (multi-line)"
        );
    }

    #[test]
    fn derive_sinks_from_manifest_dir() {
        let dir = tempfile::tempdir().unwrap();

        // Write a minimal manifest.
        let manifest = r#"
action_id: "test_action"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
required_imports:
  - "latchgate:io/http"
template:
  method: GET
  url_template: "{{url}}"
io:
  request_schema:
    type: object
    required: [url]
    additionalProperties: false
    properties:
      url:
        type: string
egress:
  profile: "proxy_allowlist"
  allowed_domains:
    - "api.example.com"
risk_level: "low"
verifier_kind: http_status
declared_side_effects:
  - "api.example.com"
  - "cdn.example.com"
"#;
        std::fs::write(dir.path().join("test_action.yaml"), manifest).unwrap();

        let registry = latchgate_registry::RegistryStore::load_from_dir(dir.path()).unwrap();

        let mut actions = BTreeSet::new();
        actions.insert("test_action".into());

        let sinks = derive_sinks(&actions, &registry);
        assert!(sinks.contains("api.example.com"));
        assert!(sinks.contains("cdn.example.com"));
        assert_eq!(sinks.len(), 2);
    }

    #[test]
    fn derive_sinks_empty_actions_returns_empty() {
        let registry = latchgate_registry::RegistryStore::empty();
        let actions = BTreeSet::new();
        let sinks = derive_sinks(&actions, &registry);
        assert!(sinks.is_empty());
    }

    #[test]
    fn derive_sinks_unknown_action_skipped() {
        let registry = latchgate_registry::RegistryStore::empty();
        let mut actions = BTreeSet::new();
        actions.insert("nonexistent_action".into());
        let sinks = derive_sinks(&actions, &registry);
        assert!(sinks.is_empty());
    }

    #[test]
    fn derive_sinks_union_of_multiple_actions() {
        let dir = tempfile::tempdir().unwrap();

        let m1 = r#"
action_id: "action_a"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
required_imports: ["latchgate:io/http"]
template:
  method: GET
  url_template: "{{url}}"
io:
  request_schema:
    type: object
    required: [url]
    additionalProperties: false
    properties:
      url:
        type: string
egress:
  profile: "proxy_allowlist"
  allowed_domains: ["a.com"]
risk_level: "low"
verifier_kind: http_status
declared_side_effects: ["a.com"]
"#;
        let m2 = r#"
action_id: "action_b"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
required_imports: ["latchgate:io/http"]
template:
  method: POST
  url_template: "{{url}}"
io:
  request_schema:
    type: object
    required: [url]
    additionalProperties: false
    properties:
      url:
        type: string
egress:
  profile: "proxy_allowlist"
  allowed_domains: ["b.com"]
risk_level: "low"
verifier_kind: http_status
declared_side_effects: ["b.com", "shared.com"]
"#;
        std::fs::write(dir.path().join("action_a.yaml"), m1).unwrap();
        std::fs::write(dir.path().join("action_b.yaml"), m2).unwrap();

        let registry = latchgate_registry::RegistryStore::load_from_dir(dir.path()).unwrap();

        let mut actions = BTreeSet::new();
        actions.insert("action_a".into());
        actions.insert("action_b".into());

        let sinks = derive_sinks(&actions, &registry);
        assert_eq!(sinks.len(), 3);
        assert!(sinks.contains("a.com"));
        assert!(sinks.contains("b.com"));
        assert!(sinks.contains("shared.com"));
    }

    #[test]
    fn resolve_data_json_path_returns_none_when_no_candidates_exist() {
        // Default config with non-existent manifests_dir.
        let config = latchgate_config::Config {
            manifests_dir: "/tmp/nonexistent-latchgate-test-dir/manifests".into(),
            ..Default::default()
        };
        // None of the candidate paths exist.
        let result = resolve_data_json_path(&config);
        assert!(result.is_none());
    }
}
