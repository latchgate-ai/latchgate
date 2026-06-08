use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use latchgate_kernel::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

/// GET /healthz — liveness probe.
///
/// Returns 200 with `{"status":"ok"}` when the server is running.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

#[derive(Serialize)]
pub struct ReadyzResponse {
    pub status: &'static str,
    pub redis: bool,
    pub opa: bool,
    pub ledger: bool,
    pub approval_store: bool,
    pub egress_proxy: Option<bool>,
    pub actions_registered: usize,
}

/// GET /readyz — readiness probe.
///
/// Checks that all dependencies are reachable and the Gate can handle traffic:
/// - Redis is reachable (replay cache, budgets)
/// - OPA is reachable (policy evaluation)
/// - Ledger is accessible (audit trail)
/// - Approval store is reachable (approval lifecycle)
/// - Egress proxy is reachable (if configured)
/// - At least one action is registered
///
/// Returns 200 when ready, 503 when not ready.
/// Status values: `ready`, `degraded`, `not_ready`.
///
/// `degraded` means core pipeline works (redis, opa, ledger, approvals,
/// actions) but optional infrastructure (egress proxy) is unavailable.
/// Orchestrators should keep routing traffic but alert operators.
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let redis = state.auth.replay_cache.ping().await;
    let opa = state.enforcement.policy.is_healthy().await;
    let actions_registered = state.registry.load().len();
    let approval_store = state.enforcement.approval_store.ping().await;

    // Ledger: verify connection is alive by reading event count.
    // This is a read-only SELECT — no mutation.
    let ledger = tokio::task::spawn_blocking({
        let ledger = state.ledger.clone();
        move || ledger.event_count().is_ok()
    })
    .await
    .unwrap_or(false);

    // Egress proxy: check TCP connectivity if configured.
    let egress_proxy = match &state.config.egress.egress_proxy_url {
        Some(url) => Some(check_egress_proxy(url).await),
        None => None,
    };

    let core_ready = redis && opa && ledger && approval_store && actions_registered > 0;
    let all_ready = core_ready && egress_proxy.unwrap_or(true);

    let status_str = if all_ready {
        "ready"
    } else if core_ready {
        "degraded"
    } else {
        "not_ready"
    };

    let resp = ReadyzResponse {
        status: status_str,
        redis,
        opa,
        ledger,
        approval_store,
        egress_proxy,
        actions_registered,
    };

    let code = if core_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (code, Json(resp))
}

/// TCP connect probe to the egress proxy with a short timeout.
async fn check_egress_proxy(url: &str) -> bool {
    let addr_str = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:3128");

    let addr: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => match format!("{addr_str}:3128").parse() {
            Ok(a) => a,
            Err(_) => return false,
        },
    };

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, test_router};

    #[tokio::test]
    async fn healthz_returns_200_ok() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn unknown_route_returns_404_with_empty_body() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // SECURITY: 404 body must not leak route listings, stack traces,
        // or internal module names.
        let body = axum::body::to_bytes(response.into_body(), 256)
            .await
            .unwrap();
        assert!(body.is_empty(), "404 body must be empty; got: {body:?}");
    }
}
