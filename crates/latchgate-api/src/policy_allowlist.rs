//! Allowlist management endpoints for the admin router.
//!
//! Manages the `data.latchgate.allowlist` OPA data section — a map of
//! `{action_id: {agent_id: true}}` entries that bypass the approval hold
//! for matched (action, principal) pairs.
//!
//! The allowlist only bypasses approval (step 5b). All deny rules
//! (trust, ACL, scope, budget, sink) still apply unconditionally.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{info, warn};

use latchgate_kernel::AppState;
use latchgate_ledger::EventType;

use crate::admin::require_operator_auth;
use crate::json_response::JsonResponse as ApiError;

#[derive(Debug, Deserialize)]
pub(crate) struct AllowlistBody {
    pub action_id: String,
    pub agent_id: String,
}

const MAX_ID_LEN: usize = 128;

fn validate_id(id: &str, label: &str) -> Result<(), ApiError> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_input").field(
                "detail",
                &format!("{label} must be 1-{MAX_ID_LEN} characters"),
            ),
        );
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b':')
    {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_input").field(
                "detail",
                &format!("{label} must contain only [a-zA-Z0-9_-:]"),
            ),
        );
    }
    Ok(())
}

fn resolve_data_json_path(config: &latchgate_config::Config) -> Option<PathBuf> {
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

/// Ensure `doc["latchgate"]["allowlist"]` exists as an object. Creates
/// intermediate keys if missing. Returns a mutable reference to the
/// allowlist map.
fn ensure_allowlist_object(doc: &mut Value) -> Result<&mut serde_json::Map<String, Value>, String> {
    if !doc.get("latchgate").is_some_and(|v| v.is_object()) {
        doc["latchgate"] = json!({});
    }
    let lg = doc["latchgate"]
        .as_object_mut()
        .ok_or("latchgate must be an object")?;

    if !lg.get("allowlist").is_some_and(|v| v.is_object()) {
        lg.insert("allowlist".into(), json!({}));
    }
    lg.get_mut("allowlist")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "latchgate.allowlist must be an object".into())
}

/// Add an allowlist entry: (action_id, agent_id) pair bypasses approval.
///
/// The action_id must exist in the registry. This prevents typos from
/// creating silent policy holes — an allowlist entry for a nonexistent
/// action is rejected immediately.
pub(crate) async fn add_allowlist_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AllowlistBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let operator_ctx =
        require_operator_auth(&state, &headers, "POST", "/v1/admin/policy/allowlist").await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_id(&body.action_id, "action_id")?;
    validate_id(&body.agent_id, "agent_id")?;

    // Validate action exists in registry.
    if state.registry.load().get_action(&body.action_id).is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "action_not_found")
            .field("action_id", &body.action_id));
    }

    let config = Arc::clone(&state.config);
    let action_id = body.action_id.clone();
    let agent_id = body.agent_id.clone();
    let operator_id = operator_ctx.operator_id.clone();

    let result = tokio::task::spawn_blocking({
        let action_id = action_id.clone();
        let agent_id = agent_id.clone();
        move || {
            let path =
                resolve_data_json_path(&config).ok_or_else(|| "data.json not found".to_string())?;
            let mut doc = read_data_json(&path)?;

            let allowlist = ensure_allowlist_object(&mut doc)?;

            // Insert: allowlist[action_id][agent_id] = true
            if !allowlist.get(&action_id).is_some_and(|v| v.is_object()) {
                allowlist.insert(action_id.clone(), json!({}));
            }
            let action_map = allowlist
                .get_mut(&action_id)
                .and_then(|v| v.as_object_mut())
                .ok_or("allowlist entry must be an object")?;
            action_map.insert(agent_id.clone(), json!(true));

            let new_content = write_data_json_atomic(&path, &doc)?;
            Ok::<_, String>(new_content)
        }
    })
    .await
    .map_err(|e| {
        warn!(error = %e, "add_allowlist task panicked");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?;

    let new_content = match result {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "add_allowlist write error");
            return Err(
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy_write_error")
                    .field("detail", &e),
            );
        }
    };

    // Hot-reload the embedded OPA evaluator with updated data.
    state.reload_policy_data(
        latchgate_embed::embedded_policies::POLICY_REGO,
        Some(&new_content),
    );

    info!(
        action_id = %action_id,
        agent_id = %agent_id,
        operator_id = %operator_id,
        "allowlist entry added"
    );

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::PolicyAllowlistAdded,
        &operator_id,
        Some(format!("action_id={action_id} agent_id={agent_id}")),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "action_id": action_id,
            "agent_id": agent_id,
        })),
    ))
}

/// Remove an allowlist entry.
pub(crate) async fn remove_allowlist_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AllowlistBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let operator_ctx =
        require_operator_auth(&state, &headers, "DELETE", "/v1/admin/policy/allowlist").await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_id(&body.action_id, "action_id")?;
    validate_id(&body.agent_id, "agent_id")?;

    let config = Arc::clone(&state.config);
    let action_id = body.action_id.clone();
    let agent_id = body.agent_id.clone();
    let operator_id = operator_ctx.operator_id.clone();

    let result = tokio::task::spawn_blocking({
        let action_id = action_id.clone();
        let agent_id = agent_id.clone();
        move || {
            let path =
                resolve_data_json_path(&config).ok_or_else(|| "data.json not found".to_string())?;
            let mut doc = read_data_json(&path)?;

            let allowlist = ensure_allowlist_object(&mut doc)?;

            // Remove: allowlist[action_id][agent_id]
            let removed = allowlist
                .get_mut(&action_id)
                .and_then(|v| v.as_object_mut())
                .map(|m| m.remove(&agent_id).is_some())
                .unwrap_or(false);

            if !removed {
                return Err("allowlist_entry_not_found".to_string());
            }

            // Clean up empty action map.
            if allowlist
                .get(&action_id)
                .and_then(|v| v.as_object())
                .is_some_and(|m| m.is_empty())
            {
                allowlist.remove(&action_id);
            }

            let new_content = write_data_json_atomic(&path, &doc)?;
            Ok(new_content)
        }
    })
    .await
    .map_err(|e| {
        warn!(error = %e, "remove_allowlist task panicked");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?;

    let new_content = match result {
        Ok(c) => c,
        Err(ref e) if e == "allowlist_entry_not_found" => {
            return Err(
                ApiError::new(StatusCode::NOT_FOUND, "allowlist_entry_not_found").field(
                    "detail",
                    &format!(
                        "no allowlist entry for action_id={} agent_id={}",
                        body.action_id, body.agent_id
                    ),
                ),
            );
        }
        Err(e) => {
            warn!(error = %e, "remove_allowlist write error");
            return Err(
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy_write_error")
                    .field("detail", &e),
            );
        }
    };

    state.reload_policy_data(
        latchgate_embed::embedded_policies::POLICY_REGO,
        Some(&new_content),
    );

    info!(
        action_id = %action_id,
        agent_id = %agent_id,
        operator_id = %operator_id,
        "allowlist entry removed"
    );

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::PolicyAllowlistRemoved,
        &operator_id,
        Some(format!("action_id={action_id} agent_id={agent_id}")),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "action_id": action_id,
            "agent_id": agent_id,
        })),
    ))
}
