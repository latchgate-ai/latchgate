//! Admin endpoints for operational control.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::json;
use tracing::{info, warn};

use latchgate_kernel::ops::operator_auth::OperatorAuthHeaders;
use latchgate_kernel::AppState;
use latchgate_ledger::EventType;

use crate::json_response::JsonResponse as ApiError;

/// Maximum length for an action_id string.
pub(crate) const MAX_ACTION_ID_LEN: usize = 253;

/// Validate an action_id: non-empty, within length limit, ASCII
/// alphanumeric plus underscore/hyphen only.
pub(crate) fn validate_action_id(action_id: &str) -> Result<(), ApiError> {
    if action_id.is_empty() || action_id.len() > MAX_ACTION_ID_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_action_id")
            .field("detail", "action_id must be 1-253 characters"));
    }
    if !action_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_action_id")
            .field("detail", "action_id must contain only [a-zA-Z0-9_-]"));
    }
    Ok(())
}

/// Verify operator authentication using DPoP proof-of-possession.
///
/// SECURITY (04.2): all operator credentials require `dpop_jkt` — enforced
/// at startup by `Config::validate_operator_auth()`. Returns operator context
/// on success.
pub(crate) async fn require_operator_auth(
    state: &AppState,
    headers: &HeaderMap,
    request_method: &str,
    request_path: &str,
) -> Result<latchgate_auth::OperatorAuthContext, ApiError> {
    let auth_headers = OperatorAuthHeaders {
        authorization: headers.get("authorization").and_then(|v| v.to_str().ok()),
        dpop: headers.get("dpop").and_then(|v| v.to_str().ok()),
    };

    latchgate_kernel::ops::operator_auth::verify(state, &auth_headers, request_method, request_path)
        .await
        .map_err(|e| match e {
            latchgate_kernel::PipelineError::Internal(_) => {
                warn!("admin endpoint called but no operator key is configured — denying");
                ApiError::new(StatusCode::UNAUTHORIZED, "operator_auth_not_configured")
            }
            _ => ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"),
        })
}

/// Advance the revocation epoch (kill-switch).
///
/// After this call, every `ExecutionGrant` issued before the bump will fail
/// `is_valid()` checks. New grants carry the new epoch and remain valid.
/// Requires operator authentication (DPoP). Operator identity is logged for
/// forensics.
pub async fn revoke_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let operator_ctx =
        require_operator_auth(&state, &headers, "POST", "/v1/admin/revoke-all").await?;

    if !state.config.dev_mode() && !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let operator_id = operator_ctx.operator_id.clone();

    let old_epoch = state.lifecycle.revocation_epoch.load(Ordering::Acquire);
    let new_epoch = state.advance_revocation_epoch();

    warn!(
        operator_id = %operator_id,
        old_epoch,
        new_epoch,
        "KILL-SWITCH: revocation epoch advanced — all outstanding grants invalidated"
    );

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::AdminRevokeAll,
        &operator_id,
        Some(format!("epoch {old_epoch} => {new_epoch}")),
    )
    .await;

    state.emit(latchgate_core::DomainEvent::Revocation {
        old_epoch,
        new_epoch,
        operator_id: Arc::clone(&operator_id),
    });

    Ok((
        StatusCode::OK,
        Json(json!({
            "previous_epoch": old_epoch,
            "current_epoch": new_epoch,
        })),
    ))
}

/// Operational status snapshot for orchestrators and dashboards.
///
/// Returns version, uptime, registered actions count, pending approvals count,
/// revocation epoch, dependency health (Redis, OPA), and webhook dispatcher
/// status. Designed for frequent polling (Platform watcher loop, monitoring).
///
/// NOT audited — unlike `epoch` and `receipt-keys`, this is a read-only
/// diagnostic called every 30 seconds by orchestrators. Auditing it would
/// flood the evidence ledger with noise that obscures security-relevant events.
///
/// Requires operator authentication.
pub async fn get_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_operator_auth(&state, &headers, "GET", "/v1/admin/status").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let uptime = state.lifecycle.started_at.elapsed();
    let actions_registered = state.registry.load().len();
    let revocation_epoch = state.current_revocation_epoch();
    let redis_healthy = state.auth.replay_cache.ping().await;
    let opa_healthy = state.enforcement.policy.is_healthy().await;

    let pending_approvals = latchgate_kernel::ops::approvals::list_approvals(
        &state,
        Some(latchgate_kernel::ops::approvals::ApprovalState::Pending),
        1000,
    )
    .await
    .map(|v| v.len())
    .unwrap_or(0);

    let webhooks_active = state.lifecycle.event_sink.is_some();

    let webhooks_pending: usize = 0;

    let all_healthy = redis_healthy && opa_healthy;
    let is_draining = state.draining();
    let in_flight = state.runtime.wasm_runtime.in_flight_count();

    Ok(Json(json!({
        "status": if is_draining { "draining" } else if all_healthy { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime.as_secs(),
        "actions_registered": actions_registered,
        "pending_approvals": pending_approvals,
        "revocation_epoch": revocation_epoch,
        "draining": is_draining,
        "in_flight_executions": in_flight,
        "dependencies": {
            "redis": redis_healthy,
            "opa": opa_healthy,
        },
        "webhooks": {
            "active": webhooks_active,
            "pending_deliveries": webhooks_pending,
        },
    })))
}

/// Hot-reload manifests and policy data without restarting the gate.
///
/// Atomically rebuilds the registry from the configured `manifests_dir` and
/// re-loads `data.json` + Rego source. On failure the previous state remains
/// active — no partial reload.
///
/// Requires operator authentication (DPoP). Audited as a first-class admin
/// event since the reload changes the enforcement surface.
pub async fn reload(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let operator_ctx = require_operator_auth(&state, &headers, "POST", "/v1/admin/reload").await?;

    if !state.config.dev_mode() && !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    // 1. Reload registry (manifests).
    let action_count = state
        .reload_registry(std::path::Path::new(&state.config.manifests_dir))
        .map_err(|e| {
            warn!(error = %e, "registry reload failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "reload_failed").field("detail", &e)
        })?;

    // 2. Reload policy data (embedded rego + data.json from disk).
    //    The Rego source is compiled into the binary and never changes at
    //    runtime. data.json is resolved from conventional paths.
    let rego_source = latchgate_embed::embedded_policies::POLICY_REGO;
    let data_json = crate::policy::resolve_data_json_path(&state.config)
        .and_then(|p| std::fs::read_to_string(p).ok());
    state.reload_policy_data(rego_source, data_json.as_deref());

    let policy_version = data_json
        .as_deref()
        .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
        .and_then(|v| v["policy_version"].as_str().map(str::to_string))
        .unwrap_or_default();

    info!(
        operator_id = %operator_ctx.operator_id,
        action_count,
        policy_version = %policy_version,
        "hot-reload completed"
    );

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::AdminReload,
        &operator_ctx.operator_id,
        Some(format!("actions={action_count} policy={policy_version}")),
    )
    .await;

    Ok(Json(json!({
        "ok": true,
        "actions": action_count,
        "policy_version": policy_version,
        "reloaded_at": chrono::Utc::now().to_rfc3339(),
    })))
}

/// Initiate graceful drain. Stops accepting new action calls and lease
/// requests, then waits for in-flight WASM executions to complete.
///
/// The drain is irreversible within the process lifetime. Platform calls
/// this before SIGTERM to ensure no in-flight side effects are interrupted.
///
/// Returns immediately with 200 and the drain status. The response includes
/// `in_flight_executions` so the caller can poll `/v1/admin/status` to wait
/// for zero in-flight before sending SIGTERM.
///
/// Idempotent: calling drain on an already-draining gate returns 200 with
/// `already_draining: true`.
///
/// Requires operator authentication.
pub async fn post_drain(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let operator_ctx = require_operator_auth(&state, &headers, "POST", "/v1/admin/drain").await?;

    if !state.config.dev_mode() && !state.lifecycle.operator_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let operator_id = operator_ctx.operator_id.clone();

    let was_first = state.start_drain();
    let in_flight = state.runtime.wasm_runtime.in_flight_count();

    if was_first {
        warn!(
            operator_id = %operator_id,
            in_flight,
            "DRAIN: gate entering drain mode — new requests will be rejected"
        );
    } else {
        info!(
            operator_id = %operator_id,
            in_flight,
            "drain called (already draining)"
        );
    }

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::AdminDrain,
        &operator_id,
        Some(format!(
            "drain initiated, in_flight={in_flight}, was_first={was_first}"
        )),
    )
    .await;

    Ok(Json(json!({
        "draining": true,
        "already_draining": !was_first,
        "in_flight_executions": in_flight,
    })))
}

/// Return the current revocation epoch. Read-only diagnostic.
/// Requires operator auth.
pub async fn get_epoch(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let operator_ctx = require_operator_auth(&state, &headers, "GET", "/v1/admin/epoch").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let operator_id = operator_ctx.operator_id.clone();
    let epoch = state.current_revocation_epoch();

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::AdminEpochRead,
        &operator_id,
        None,
    )
    .await;

    Ok(Json(json!({ "current_epoch": epoch })))
}

/// Return the current receipt signing public key.
///
/// Allows external verifiers to validate receipt signatures after restart or
/// key rotation without access to the signing key. Requires operator auth.
pub async fn get_receipt_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let operator_ctx = require_operator_auth(&state, &headers, "GET", "/v1/receipt-keys").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let operator_id = operator_ctx.operator_id.clone();

    latchgate_kernel::ops::audit::write_admin_event(
        &state,
        EventType::AdminReceiptKeysRead,
        &operator_id,
        None,
    )
    .await;

    let keys = latchgate_kernel::ops::receipts::receipt_verifying_keys(&state);

    Ok(Json(json!({ "keys": keys })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, operator_headers, test_router};

    #[tokio::test]
    async fn revoke_all_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/revoke-all")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_epoch_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/epoch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn receipt_keys_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipt-keys")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_all_advances_epoch() {
        let app = test_router();

        let (authz, dpop) = operator_headers("GET", "/v1/admin/epoch");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/epoch")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["current_epoch"], 0);

        let (authz, dpop) = operator_headers("POST", "/v1/admin/revoke-all");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/revoke-all")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["previous_epoch"], 0);
        assert_eq!(json["current_epoch"], 1);

        let (authz, dpop) = operator_headers("GET", "/v1/admin/epoch");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/epoch")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["current_epoch"], 1);
    }

    #[tokio::test]
    async fn revoke_all_is_monotonic() {
        let app = test_router();
        for expected in 1..=5u64 {
            let (authz, dpop) = operator_headers("POST", "/v1/admin/revoke-all");
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/admin/revoke-all")
                        .header("authorization", &authz)
                        .header("dpop", &dpop)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let json = body_json(resp).await;
            assert_eq!(json["current_epoch"], expected);
        }
    }

    #[tokio::test]
    async fn wrong_key_returns_401() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/revoke-all")
                    .header("authorization", "DPoP wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn receipt_keys_returns_key_info() {
        let app = test_router();
        let (authz, dpop) = operator_headers("GET", "/v1/receipt-keys");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipt-keys")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let keys = json["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert!(keys[0]["kid"].as_str().unwrap().len() == 16);
        assert!(keys[0]["x_hex"].as_str().unwrap().len() == 64);
    }

    // -- GET /v1/admin/status --

    #[tokio::test]
    async fn status_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn status_returns_required_fields() {
        let app = test_router();
        let (authz, dpop) = operator_headers("GET", "/v1/admin/status");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/status")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;

        // All required fields must be present.
        assert!(json["status"].is_string());
        assert!(json["version"].is_string());
        assert!(json["uptime_seconds"].is_number());
        assert!(json["actions_registered"].is_number());
        assert!(json["pending_approvals"].is_number());
        assert!(json["revocation_epoch"].is_number());
        assert!(json["draining"].is_boolean());
        assert!(json["in_flight_executions"].is_number());
        assert!(json["dependencies"]["redis"].is_boolean());
        assert!(json["dependencies"]["opa"].is_boolean());
        assert!(json["webhooks"]["active"].is_boolean());
        assert!(json["webhooks"]["pending_deliveries"].is_number());
    }

    // -- POST /v1/admin/drain --

    #[tokio::test]
    async fn drain_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/drain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn drain_returns_200_and_status() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/drain");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/drain")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["draining"], true);
        assert_eq!(json["already_draining"], false);
    }

    #[tokio::test]
    async fn drain_is_idempotent() {
        let app = test_router();

        let (authz, dpop) = operator_headers("POST", "/v1/admin/drain");
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/drain")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let (authz, dpop) = operator_headers("POST", "/v1/admin/drain");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/drain")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["already_draining"], true);
    }

    #[tokio::test]
    async fn drain_reflected_in_status() {
        let app = test_router();

        // Status before drain.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/status");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/status")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["draining"], false);
        // Status may be "ok" or "degraded" depending on Redis/OPA availability.
        // The invariant: it must NOT be "draining" before we drain.
        assert_ne!(
            json["status"], "draining",
            "status must not be 'draining' before drain is triggered"
        );

        // Drain.
        let (authz, dpop) = operator_headers("POST", "/v1/admin/drain");
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/drain")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Status after drain.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/status");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/status")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["draining"], true);
        assert_eq!(json["status"], "draining");
    }
}
