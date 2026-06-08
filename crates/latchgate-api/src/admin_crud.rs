//! Generic admin CRUD handlers for learned resources (domains, paths).
//!
//! Extracts the shared skeleton — auth, rate limiting, action_id validation,
//! ledger error mapping, and audit writing — into generic async functions
//! parameterized by [`AdminCrudOps`]. Per-resource modules (domains, paths)
//! implement the trait and expose thin public handlers that delegate here.

use std::future::Future;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::warn;

use latchgate_kernel::AppState;
use latchgate_ledger::EventType;

use crate::admin::{require_operator_auth, validate_action_id};
use crate::json_response::JsonResponse as ApiError;

/// Response for the clear (DELETE all) operation. Field names are static,
/// so this can be a typed struct unlike add/remove/list which have
/// resource-specific dynamic keys via `AdminCrudOps::value_key()`.
#[derive(Serialize)]
struct ClearResponse {
    action_id: String,
    deleted_count: usize,
}

/// Query parameter for list endpoints: optional action_id filter.
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    pub action: Option<String>,
}

/// Request body for add/remove endpoints.
///
/// The `value` field accepts resource-specific aliases (`domain`,
/// `path_glob`) so the API contract uses natural field names while the
/// generic handler works with a single `value` field.
#[derive(Debug, Deserialize)]
pub(crate) struct MutateBody {
    pub action_id: String,
    #[serde(alias = "domain", alias = "path_glob")]
    pub value: String,
}

/// Query parameter for clear endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct ClearQuery {
    pub action: String,
}

/// Resource-specific operations for admin CRUD endpoints.
///
/// Each learned resource (domains, paths) implements this trait to plug
/// its validation, kernel delegation, and audit metadata into the shared
/// handler skeleton.
pub(crate) trait AdminCrudOps: Send + Sync + 'static {
    /// Validate the resource-specific value (domain hostname, path glob, …).
    fn validate(value: &str) -> Result<(), ApiError>;

    /// List entries as JSON objects, optionally filtered by action_id.
    fn list(
        state: &AppState,
        action_id: Option<&str>,
    ) -> impl Future<Output = Result<Vec<serde_json::Value>, String>> + Send;

    /// Add an entry. Returns `true` if newly inserted.
    fn add(
        state: &AppState,
        action_id: &str,
        value: &str,
        operator_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    /// Remove an entry. Returns `true` if actually deleted.
    fn remove(
        state: &AppState,
        action_id: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    /// Clear all entries for an action. Returns count deleted.
    fn clear(
        state: &AppState,
        action_id: &str,
    ) -> impl Future<Output = Result<usize, String>> + Send;

    /// Human-readable resource name for log messages (e.g. `"domain"`).
    fn resource_name() -> &'static str;

    /// JSON key for the resource value in responses (e.g. `"domain"`, `"path_glob"`).
    fn value_key() -> &'static str;

    /// JSON key for the list wrapper (e.g. `"domains"`, `"paths"`).
    fn list_key() -> &'static str;

    /// Audit event types for add, remove, and clear operations.
    fn add_event() -> EventType;
    fn remove_event() -> EventType;
    fn clear_event() -> EventType;

    /// Admin API base path (e.g. `"/v1/admin/domains"`).
    fn base_path() -> &'static str;
}

/// GET handler: list entries with optional action_id filter.
pub(crate) async fn handle_list<R: AdminCrudOps>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_operator_auth(&state, &headers, "GET", R::base_path()).await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    if let Some(ref aid) = query.action {
        validate_action_id(aid)?;
    }

    let entries = R::list(&state, query.action.as_deref())
        .await
        .map_err(|e| {
            warn!(error = %e, resource = R::resource_name(), "list failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ledger_error")
        })?;

    let mut map = serde_json::Map::with_capacity(1);
    map.insert(
        R::list_key().into(),
        serde_json::to_value(&entries).map_err(|e| {
            warn!(error = %e, resource = R::resource_name(), "serialization failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error")
        })?,
    );
    Ok(Json(serde_json::Value::Object(map)))
}

/// POST handler: add an entry.
pub(crate) async fn handle_add<R: AdminCrudOps>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MutateBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let operator_ctx = require_operator_auth(&state, &headers, "POST", R::base_path()).await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_action_id(&body.action_id)?;
    R::validate(&body.value)?;

    let operator_id = operator_ctx.operator_id.clone();
    let action_id = body.action_id.clone();
    let value = body.value.clone();

    let inserted = R::add(&state, &action_id, &value, &operator_id)
        .await
        .map_err(|e| {
            warn!(error = %e, resource = R::resource_name(), "add failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ledger_error")
        })?;

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        R::add_event(),
        &operator_id,
        Some(format!(
            "action={action_id} {key}={value} inserted={inserted}",
            key = R::value_key(),
        )),
    )
    .await;

    let mut map = serde_json::Map::with_capacity(3);
    map.insert(
        "action_id".into(),
        serde_json::Value::String(body.action_id),
    );
    map.insert(R::value_key().into(), serde_json::Value::String(body.value));
    map.insert("inserted".into(), serde_json::Value::Bool(inserted));
    Ok(Json(serde_json::Value::Object(map)))
}

/// DELETE handler: remove a single entry.
pub(crate) async fn handle_remove<R: AdminCrudOps>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MutateBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let operator_ctx = require_operator_auth(&state, &headers, "DELETE", R::base_path()).await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_action_id(&body.action_id)?;
    R::validate(&body.value)?;

    let operator_id = operator_ctx.operator_id.clone();
    let action_id = body.action_id.clone();
    let value = body.value.clone();

    let deleted = R::remove(&state, &action_id, &value).await.map_err(|e| {
        warn!(error = %e, resource = R::resource_name(), "remove failed");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ledger_error")
    })?;

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        R::remove_event(),
        &operator_id,
        Some(format!(
            "action={action_id} {key}={value} deleted={deleted}",
            key = R::value_key(),
        )),
    )
    .await;

    let mut map = serde_json::Map::with_capacity(3);
    map.insert(
        "action_id".into(),
        serde_json::Value::String(body.action_id),
    );
    map.insert(R::value_key().into(), serde_json::Value::String(body.value));
    map.insert("deleted".into(), serde_json::Value::Bool(deleted));
    Ok(Json(serde_json::Value::Object(map)))
}

/// DELETE handler: clear all entries for an action.
pub(crate) async fn handle_clear<R: AdminCrudOps>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClearQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let clear_path = format!("{}/clear", R::base_path());
    let operator_ctx = require_operator_auth(&state, &headers, "DELETE", &clear_path).await?;

    if !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    validate_action_id(&query.action)?;

    let operator_id = operator_ctx.operator_id.clone();
    let action_id = query.action.clone();

    let deleted_count = R::clear(&state, &action_id).await.map_err(|e| {
        warn!(error = %e, resource = R::resource_name(), "clear failed");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ledger_error")
    })?;

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        R::clear_event(),
        &operator_id,
        Some(format!("action={action_id} deleted_count={deleted_count}")),
    )
    .await;

    let resp = ClearResponse {
        action_id: query.action,
        deleted_count,
    };
    serde_json::to_value(resp).map(Json).map_err(|e| {
        warn!(error = %e, resource = R::resource_name(), "serialization failed");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error")
    })
}
