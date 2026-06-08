#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! HTTP API layer for LatchGate.
//!
//! Thin routing layer that delegates all enforcement logic to the kernel.
//! Provides the axum router with routes for action execution, leases,
//! approvals, audit queries, health checks, and Prometheus metrics.

pub(crate) mod actions;
pub(crate) mod admin;
pub(crate) mod admin_crud;
pub(crate) mod approvals;
pub(crate) mod audit;
pub(crate) mod domains;
pub(crate) mod expiry;
pub(crate) mod health;
pub(crate) mod json_response;
pub(crate) mod leases;
pub(crate) mod listen;
pub(crate) mod metrics;
pub(crate) mod outbox;
pub(crate) mod paths;
pub(crate) mod policy;
pub(crate) mod policy_allowlist;
pub(crate) mod receipts;
pub mod server;

#[cfg(test)]
pub(crate) mod test_support;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use latchgate_kernel::AppState;

/// Health routes shared by both client and admin sockets.
fn health_routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
}

/// Agent-only routes: lease issuance, action discovery, execution.
fn client_only_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/leases", post(leases::issue_lease))
        .route("/.well-known/jwks.json", get(leases::jwks))
        .route("/v1/actions", get(actions::list_actions))
        .route("/v1/actions/{action_id}", get(actions::get_action))
        .route(
            "/v1/actions/{action_id}/schema/request",
            get(actions::get_action_request_schema),
        )
        .route(
            "/v1/actions/{action_id}/execute",
            post(actions::action_call),
        )
        .route(
            "/v1/approvals/{approval_id}/poll",
            get(approvals::poll_approval_status),
        )
}

/// Operator-only routes: approvals, audit, metrics, admin controls.
fn admin_only_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/approvals", get(approvals::list_approvals))
        .route("/v1/approvals/{approval_id}", get(approvals::get_approval))
        .route(
            "/v1/approvals/{approval_id}/approve",
            post(approvals::approve_call),
        )
        .route(
            "/v1/approvals/{approval_id}/deny",
            post(approvals::deny_call),
        )
        .route("/v1/audit/events", get(audit::query_audit_events))
        .route("/v1/audit/verify", get(audit::verify_chain))
        .route("/metrics", get(metrics::prometheus_metrics))
        .route("/v1/admin/revoke-all", post(admin::revoke_all))
        .route("/v1/admin/epoch", get(admin::get_epoch))
        .route("/v1/admin/status", get(admin::get_status))
        .route("/v1/admin/drain", post(admin::post_drain))
        .route("/v1/admin/reload", post(admin::reload))
        .route("/v1/receipt-keys", get(admin::get_receipt_keys))
        .route("/v1/admin/domains", get(domains::list_domains))
        .route("/v1/admin/domains", post(domains::add_domain))
        .route("/v1/admin/domains", delete(domains::remove_domain))
        .route("/v1/admin/domains/clear", delete(domains::clear_domains))
        .route("/v1/admin/paths", get(paths::list_paths))
        .route("/v1/admin/paths", post(paths::add_path))
        .route("/v1/admin/paths", delete(paths::remove_path))
        .route("/v1/admin/paths/clear", delete(paths::clear_paths))
        .route("/v1/admin/policy", get(policy::show_policy))
        .route("/v1/admin/policy/{principal}", get(policy::show_principal))
        .route("/v1/admin/policy/grant", post(policy::grant_actions))
        .route("/v1/admin/policy/revoke", post(policy::revoke_actions))
        .route(
            "/v1/admin/policy/allowlist",
            post(policy_allowlist::add_allowlist_entry),
        )
        .route(
            "/v1/admin/policy/allowlist",
            delete(policy_allowlist::remove_allowlist_entry),
        )
}

/// Body limit + tracing layers applied to every public router.
fn apply_layers(router: Router, body_limit: usize) -> Router {
    router
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TraceLayer::new_for_http())
}

/// Agent-facing router: lease issuance, action execution, and receipt retrieval.
///
/// Served on `listen_uds_path`. Agent processes must have access to this
/// socket and no access to the admin socket.
///
/// SECURITY: `DefaultBodyLimit` rejects oversized HTTP bodies at the transport
/// layer, before buffering into memory. This prevents memory exhaustion from
/// concurrent large payloads — the per-action `max_request_bytes` check in the
/// pipeline fires too late (after full body buffering) to protect against this.
pub fn client_router(state: AppState) -> Router {
    let body_limit = latchgate_core::security_constants::MAX_REQUEST_BODY_BYTES;
    let routes = health_routes()
        .merge(client_only_routes())
        .route(
            "/v1/receipts/{receipt_id}",
            get(receipts::get_receipt_client),
        )
        .with_state(state);
    apply_layers(routes, body_limit)
}

/// Operator-facing router: approvals, audit, receipts, metrics, admin controls,
/// plus read-only client endpoints (action list, schemas) for operator tooling.
///
/// Served on `listen_admin_uds_path`. Only operator processes (humans,
/// monitoring, CI) should have filesystem access to this socket.
///
/// All admin-specific routes require operator authentication via DPoP
/// proof-of-possession. The client-only routes (action list, lease JWKS) are
/// included so that operator tools (TUI, CLI) can discover actions without
/// needing a second connection to the client socket.
pub fn admin_router(state: AppState) -> Router {
    let body_limit = latchgate_core::security_constants::MAX_REQUEST_BODY_BYTES;
    let routes = health_routes()
        .merge(client_only_routes())
        .merge(admin_only_routes())
        .route("/v1/receipts/{receipt_id}", get(receipts::get_receipt))
        .with_state(state);
    apply_layers(routes, body_limit)
}

/// Combined router used in tests.
///
/// Merges all client and admin routes onto a single router so unit and
/// integration tests can exercise the full API surface without standing up
/// two separate listeners. The receipt endpoint uses the admin (operator-auth)
/// handler since existing tests authenticate with operator keys.
pub fn router(state: AppState) -> Router {
    let body_limit = latchgate_core::security_constants::MAX_REQUEST_BODY_BYTES;
    let routes = health_routes()
        .merge(client_only_routes())
        .merge(admin_only_routes())
        .route("/v1/receipts/{receipt_id}", get(receipts::get_receipt))
        .with_state(state);
    apply_layers(routes, body_limit)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use latchgate_config::Config;

    use crate::test_support::build_app_state;

    fn router_with_default_limit() -> axum::Router {
        let state = build_app_state(Config::default());
        crate::router(state)
    }

    #[tokio::test]
    async fn request_within_body_limit_is_accepted() {
        let app = router_with_default_limit();
        let body = vec![b'x'; 512];
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/leases")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Passes body limit layer — will fail auth (no DPoP) but must not be 413.
        assert_ne!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn request_exceeding_body_limit_is_rejected() {
        use latchgate_core::security_constants::MAX_REQUEST_BODY_BYTES;
        let app = router_with_default_limit();
        let body = vec![b'x'; MAX_REQUEST_BODY_BYTES + 1];
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/leases")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn body_limit_applies_to_execute_endpoint() {
        use latchgate_core::security_constants::MAX_REQUEST_BODY_BYTES;
        let app = router_with_default_limit();
        let body = vec![b'x'; MAX_REQUEST_BODY_BYTES + 1];
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/smtp_send/execute")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn default_config_body_limit_is_1mb() {
        let _config = Config::default();
        assert_eq!(
            latchgate_core::security_constants::MAX_REQUEST_BODY_BYTES,
            1_048_576
        );
    }
}
