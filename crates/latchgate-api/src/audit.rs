//! Audit query endpoint.
//!
//! `GET /v1/audit/events` returns filtered audit events as JSON.
//! Query parameters map directly to [`EventFilter`] fields.
//!
//! # Security
//!
//! This endpoint is served exclusively on the admin socket. Every request
//! requires operator authentication (DPoP proof-of-possession) regardless of
//! transport — application-level auth provides accountability within the
//! operator group.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use tracing::instrument;

use latchgate_kernel::AppState;
use latchgate_ledger::EventFilter;

use crate::admin::require_operator_auth;
use crate::json_response::JsonResponse as ApiError;

#[instrument(
    name = "api.query_audit_events",
    skip(state, headers, params),
    fields(
        filter.trace_id = params.trace_id.as_deref().unwrap_or("-"),
        filter.action_id = params.action_id.as_deref().unwrap_or("-"),
    ),
)]
pub async fn query_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<EventFilter>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_operator_auth(&state, &headers, "GET", "/v1/audit/events").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let events = latchgate_kernel::ops::audit::query_events(&state, params)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit query failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        })?;

    Ok(Json(serde_json::json!({ "events": events })))
}

/// GET /v1/audit/verify — verify ledger hash-chain integrity.
///
/// Walks every event in insertion order and checks that each `prev_hash`
/// matches the SHA-256 of the preceding event's JSON. Returns the
/// verification report.
///
/// This is an expensive operation for large ledgers — callers should not
/// poll it on a tight interval.
#[instrument(name = "api.verify_chain", skip(state, headers))]
pub async fn verify_chain(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_operator_auth(&state, &headers, "GET", "/v1/audit/verify").await?;

    if !state.lifecycle.operator_read_rate_limiter.check() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
        ));
    }

    let result = latchgate_kernel::ops::audit::verify_chain(&state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "chain verification failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        })?;

    Ok(Json(serde_json::json!({
        "intact": result.is_intact(),
        "total_events": result.total_events,
        "verified_links": result.verified_links,
        "broken_at": result.broken_at,
    })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, operator_headers, test_state};
    use latchgate_ledger::Decision;
    use latchgate_ledger::{AuditEventBuilder, EventType};

    fn test_router() -> axum::Router {
        crate::router(test_state())
    }

    #[tokio::test]
    async fn audit_endpoint_returns_200_with_valid_auth() {
        let app = test_router();
        let (authz, dpop) = operator_headers("GET", "/v1/audit/events");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/events")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(json["events"].is_array());
    }

    #[tokio::test]
    async fn audit_endpoint_requires_auth() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_endpoint_rejects_wrong_key() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/events")
                    .header("authorization", "DPoP wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_endpoint_returns_written_events() {
        let state = test_state();
        let mut event = AuditEventBuilder::new("t-api-1", EventType::ActionCall)
            .principal("agent:test", "sess", "jti")
            .action("http_fetch", None, "sha256:d", "digest_ok")
            .policy(Decision::Allow, None, None)
            .build();

        state.ledger.write_event(&mut event).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/audit/events");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/events?action_id=http_fetch")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["trace_id"], "t-api-1");
    }

    #[tokio::test]
    async fn audit_endpoint_filters_by_decision() {
        let state = test_state();

        let mut allow_event = AuditEventBuilder::new("t-api-allow", EventType::ActionCall)
            .policy(Decision::Allow, None, None)
            .build();
        let mut deny_event = AuditEventBuilder::new("t-api-deny", EventType::ActionCall)
            .policy(Decision::Deny, None, Some("budget".into()))
            .build();

        state.ledger.write_event(&mut allow_event).unwrap();
        state.ledger.write_event(&mut deny_event).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/audit/events");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/events?decision=deny")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let json = body_json(response).await;
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["trace_id"], "t-api-deny");
    }

    #[tokio::test]
    async fn verify_endpoint_returns_intact_on_empty_ledger() {
        let app = test_router();
        let (authz, dpop) = operator_headers("GET", "/v1/audit/verify");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/verify")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["intact"], true);
        assert_eq!(json["total_events"], 0);
        assert_eq!(json["verified_links"], 0);
        assert!(json["broken_at"].is_null());
    }

    #[tokio::test]
    async fn verify_endpoint_returns_intact_with_events() {
        let state = test_state();

        let mut e1 = AuditEventBuilder::new("t-v-1", EventType::ActionCall)
            .policy(Decision::Allow, None, None)
            .build();
        let mut e2 = AuditEventBuilder::new("t-v-2", EventType::ActionCall)
            .policy(Decision::Deny, None, None)
            .build();
        state.ledger.write_event(&mut e1).unwrap();
        state.ledger.write_event(&mut e2).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/audit/verify");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/verify")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["intact"], true);
        assert_eq!(json["total_events"], 2);
        assert_eq!(json["verified_links"], 2);
    }

    #[tokio::test]
    async fn verify_endpoint_requires_auth() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
