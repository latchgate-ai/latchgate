//! Approval API + operator contract tests.
//!
//! Validates the HTTP contract for approval endpoints: list, show,
//! approve, deny, error shapes, and operator authentication requirements.
//!
//! Requirements: Redis on 127.0.0.1:6379 and OPA on 127.0.0.1:8181.

use axum::http::StatusCode;

use crate::harness::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn create_pending(app: &axum::Router, agent: &Agent, lease_jwt: &str) -> String {
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, lease_jwt);
    let (status, json) = post_with_auth(
        app,
        "/v1/actions/http_delete/execute",
        lease_jwt,
        &proof,
        &serde_json::json!({
            "url": "https://api.example.com/v1/resources/contract-test"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "expected 202: {json}");
    json["approval_id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// GET /v1/approvals/{id} — show
// ---------------------------------------------------------------------------

#[tokio::test]
async fn show_pending_approval_returns_review_surface() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (status, json) = get_json_operator(&app, &format!("/v1/approvals/{approval_id}")).await;
    assert_eq!(status, StatusCode::OK);

    // Operator review surface: must include action_id, state, request_hash.
    assert_eq!(json["action_id"].as_str(), Some("http_delete"));
    assert!(json["status"].is_string(), "state must be present: {json}");
    assert!(
        json["request_hash"].is_string(),
        "request_hash must be present for operator review: {json}"
    );
    // Request body must NOT be exposed — only the hash.
    assert!(
        json.get("request_body").is_none(),
        "request_body must not be exposed via GET: {json}"
    );
}

#[tokio::test]
async fn show_nonexistent_approval_returns_404() {
    let (app, _) = test_router();
    let (status, _) =
        get_json_operator(&app, "/v1/approvals/00000000-0000-0000-0000-000000000000").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST approve — success and error shapes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_pending_reaches_execution() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (status, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;

    // 502 expected: no WASM module loaded. But the approval pipeline
    // itself succeeded (claim, plan verification, grant construction).
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "approve must reach execution (502 without WASM)"
    );
}

#[tokio::test]
async fn approve_nonexistent_returns_404() {
    let (app, _) = test_router();
    let (status, _) = post_json_operator(
        &app,
        "/v1/approvals/00000000-0000-0000-0000-000000000000/approve",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST deny — success and error shapes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deny_pending_returns_200_with_deny_decision() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (status, json) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({"reason": "contract test denial"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deny must succeed: {json}");
    assert_eq!(
        json["decision"].as_str(),
        Some("deny"),
        "decision must be 'deny': {json}"
    );
}

#[tokio::test]
async fn deny_nonexistent_returns_404() {
    let (app, _) = test_router();
    let (status, _) = post_json_operator(
        &app,
        "/v1/approvals/00000000-0000-0000-0000-000000000000/deny",
        &serde_json::json!({"reason": "test"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Terminal state: already completed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_already_denied_returns_terminal_status() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Deny first.
    let (s1, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({"reason": "first"}),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Approve after deny — must return terminal status.
    let (s2, j2) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "terminal retry must return 200: {j2}");
    assert!(
        j2["decision"]
            .as_str()
            .map(|d| d.starts_with("already_"))
            .unwrap_or(false),
        "terminal retry must indicate already_*: {j2}"
    );
}

#[tokio::test]
async fn deny_already_approved_returns_terminal_status() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Approve first (will fail at WASM dispatch => terminal 'failed').
    let (s1, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert!(
        s1 == StatusCode::BAD_GATEWAY || s1 == StatusCode::OK,
        "first approve must reach execution: {s1}"
    );

    // Deny after approve — must return terminal status.
    let (s2, j2) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({"reason": "too late"}),
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "terminal retry must return 200: {j2}");
    assert!(
        j2["decision"]
            .as_str()
            .map(|d| d.starts_with("already_"))
            .unwrap_or(false),
        "terminal retry must indicate already_*: {j2}"
    );
}

// ---------------------------------------------------------------------------
// Operator authentication required
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_without_operator_auth_rejected() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Post without operator auth header.
    let (status, _) = post_json(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "approve without operator auth must be rejected: {status}"
    );
}

#[tokio::test]
async fn deny_without_operator_auth_rejected() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (status, _) = post_json(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({"reason": "no auth"}),
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "deny without operator auth must be rejected: {status}"
    );
}

#[tokio::test]
async fn show_without_operator_auth_rejected() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (status, _) = get_json(&app, &format!("/v1/approvals/{approval_id}")).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "show without operator auth must be rejected: {status}"
    );
}

// ---------------------------------------------------------------------------
// Error shapes: approve vs deny 404 are identical
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_and_deny_404_have_identical_shape() {
    let (app, _) = test_router();
    let fake_id = "00000000-0000-0000-0000-ffffffffffff";

    let (s1, j1) = post_json_operator(
        &app,
        &format!("/v1/approvals/{fake_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    let (s2, j2) = post_json_operator(
        &app,
        &format!("/v1/approvals/{fake_id}/deny"),
        &serde_json::json!({"reason": "test"}),
    )
    .await;

    assert_eq!(s1, StatusCode::NOT_FOUND);
    assert_eq!(s2, StatusCode::NOT_FOUND);

    // Same response shape — prevents approval ID enumeration.
    assert_eq!(
        j1.as_object().unwrap().keys().collect::<Vec<_>>(),
        j2.as_object().unwrap().keys().collect::<Vec<_>>(),
        "approve/deny 404 shapes must be identical"
    );
}

// ---------------------------------------------------------------------------
// Denied approval shows forensic fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_approval_shows_completed_at_and_reason() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (s1, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({"reason": "forensic test"}),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, j2) = get_json_operator(&app, &format!("/v1/approvals/{approval_id}")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(j2["status"].as_str(), Some("denied"));
    assert!(
        j2["completed_at"].is_string(),
        "completed_at must be present: {j2}"
    );
    assert_eq!(
        j2["deny_reason"].as_str(),
        Some("forensic test"),
        "deny_reason must be persisted: {j2}"
    );
}

// ---------------------------------------------------------------------------
// Malformed approve/deny requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_with_malformed_approval_id_returns_404() {
    let (app, _) = test_router();
    // Not a UUID — should get 404, not 500.
    let (status, _) = post_json_operator(
        &app,
        "/v1/approvals/not-a-valid-uuid/approve",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "malformed approval ID must return 404"
    );
}
