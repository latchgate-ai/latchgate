//! Prometheus metrics endpoint (admin socket, operator auth).

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};

use latchgate_kernel::AppState;

use crate::admin::require_operator_auth;
use crate::json_response::JsonResponse as ApiError;

/// Requires operator authentication to prevent information disclosure
/// (counter names, action IDs, error rates) to unauthenticated callers.
pub async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, [(header::HeaderName, HeaderValue); 1], String), ApiError> {
    require_operator_auth(&state, &headers, "GET", "/metrics").await?;

    let body = state.metrics.encode().map_err(|e| {
        tracing::error!(error = %e, "metrics encoding failed");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    })?;

    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            // prometheus-client encodes OpenMetrics format. Prometheus scrapers
            // accept both this and the legacy text/plain content type.
            HeaderValue::from_static("application/openmetrics-text; version=1.0.0; charset=utf-8"),
        )],
        body,
    ))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_bytes, operator_headers, test_state};

    fn test_router() -> axum::Router {
        crate::router(test_state())
    }

    #[tokio::test]
    async fn metrics_endpoint_requires_auth() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_endpoint_rejects_invalid_token() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", "DPoP wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_200() {
        let app = test_router();
        let (authz, dpop) = operator_headers("GET", "/metrics");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type
            .to_str()
            .unwrap()
            .starts_with("application/openmetrics-text"),);
    }

    #[tokio::test]
    async fn metrics_endpoint_contains_counters() {
        let state = test_state();
        state.metrics.record_call("http_fetch", "allow");
        state.metrics.record_call("http_fetch", "allow");

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/metrics");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = String::from_utf8(body_bytes(response).await).unwrap();
        assert!(body.contains("latchgate_calls_total"));
        assert!(body.contains("http_fetch"));
        // Counter was incremented twice.
        assert!(body.contains("2"));
    }
}
