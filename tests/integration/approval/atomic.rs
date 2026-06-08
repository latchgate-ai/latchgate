//! E2E tests: atomic one-shot approval lifecycle.
//!
//! These tests verify that the approval lifecycle is truly atomic and
//! one-shot through the full HTTP stack — not just at the store level.
//!
//! # What is tested
//!
//! - Same approval cannot be executed twice (retry returns terminal status)
//! - Same approval cannot be denied twice (retry returns terminal status)
//! - Approve then deny (or vice versa) produces single terminal outcome
//! - Failed execution produces terminal `failed` state (not re-executable)
//! - Approval status reflects terminal state accurately via GET
//! - Concurrent requests: exactly one reaches execution
//!
//! # Retry semantics (idempotent retry)
//!
//! After an approval reaches a terminal state (approved/denied/failed),
//! subsequent approve or deny requests return **200 with the terminal
//! status** — not 404. This is idempotent retry behavior: the operator
//! can safely retry and get the same result without triggering re-execution.
//!
//! During active claim (another worker processing), requests return 409
//! (conflict / in-progress).
//!
//! # Requirements
//!
//! Redis on 127.0.0.1:6379 and OPA on 127.0.0.1:8181.

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
            "url": "https://api.example.com/v1/resources/atomic-test"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "expected 202: {json}");
    json["approval_id"].as_str().unwrap().to_string()
}

/// True if this status indicates the request reached WASM execution
/// (502 = dispatch failed, 200 = success).
fn is_execution_status(s: StatusCode) -> bool {
    s == StatusCode::BAD_GATEWAY || s == StatusCode::OK
}

/// True if this status indicates an idempotent terminal retry (idempotent retry):
/// the approval was already completed and the response carries the
/// terminal status without re-execution.
fn is_terminal_retry(s: StatusCode, json: &serde_json::Value) -> bool {
    s == StatusCode::OK
        && json
            .get("decision")
            .and_then(|d| d.as_str())
            .map(|d| d.starts_with("already_"))
            .unwrap_or(false)
}

/// True if this status indicates the claim was lost to another worker
/// (concurrent in-progress).
fn is_claim_conflict(s: StatusCode) -> bool {
    s == StatusCode::CONFLICT
}

// ===========================================================================
// Double approve: retry returns terminal status, no re-execution
// ===========================================================================

/// SECURITY: approving the same approval_id twice via HTTP must not
/// execute the action twice. The first approve wins and executes; the
/// second gets the terminal status back (idempotent retry).
#[tokio::test]
async fn same_approval_cannot_be_approved_twice_via_http() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // First approve — will fail at WASM dispatch (no module loaded)
    // but the claim succeeds and transitions to terminal `failed`.
    let (s1, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert!(
        is_execution_status(s1),
        "first approve must reach execution: got {s1}"
    );

    // Second approve must NOT re-execute. It returns 200 with the
    // terminal status (idempotent retry).
    let (s2, j2) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert!(
        is_terminal_retry(s2, &j2),
        "second approve must return terminal status (idempotent retry), not re-execute: \
         status={s2}, body={j2}"
    );
}

// ===========================================================================
// Double deny: retry returns terminal status
// ===========================================================================

/// SECURITY: denying the same approval_id twice via HTTP must return
/// the terminal status on retry, not re-process.
#[tokio::test]
async fn same_approval_cannot_be_denied_twice_via_http() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (s1, j1) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "first deny must succeed: {j1}");
    assert_eq!(
        j1["decision"], "deny",
        "first deny must produce deny decision"
    );

    let (s2, j2) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({}),
    )
    .await;
    assert!(
        is_terminal_retry(s2, &j2),
        "second deny must return terminal status (idempotent retry): status={s2}, body={j2}"
    );
    assert_eq!(
        j2["decision"].as_str(),
        Some("already_denied"),
        "retry on denied must indicate already_denied: {j2}"
    );
}

// ===========================================================================
// Approve then deny race
// ===========================================================================

/// SECURITY: approve followed immediately by deny (or vice versa) must
/// produce exactly one execution. The loser gets either a terminal
/// retry (200 with already_*) or a claim conflict (409).
#[tokio::test]
async fn approve_then_deny_produces_single_terminal_outcome() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Approve first.
    let (_s1, _j1) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;

    // Deny after.
    let (s2, j2) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({}),
    )
    .await;

    // The first request (approve) reaches execution. The second (deny)
    // must be a terminal retry or claim conflict — never a real deny action.
    assert!(
        is_terminal_retry(s2, &j2) || is_claim_conflict(s2),
        "second request must be terminal retry or conflict: deny_status={s2}, body={j2}"
    );
}

// ===========================================================================
// Failed execution produces terminal state
// ===========================================================================

/// SECURITY: when execution fails (e.g. WASM provider not loaded),
/// the approval transitions to terminal `failed` state and cannot be
/// re-executed. Retry returns the terminal status.
#[tokio::test]
async fn failed_execution_produces_terminal_failed_state() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Approve — will fail at WASM dispatch (no module loaded) => 502.
    let (s1, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        s1,
        StatusCode::BAD_GATEWAY,
        "approve without WASM module must fail at dispatch"
    );

    // Check status via GET — must show terminal `failed` state.
    let (s2, j2) = get_json_operator(&app, &format!("/v1/approvals/{approval_id}")).await;
    assert_eq!(s2, StatusCode::OK, "status query must succeed: {j2}");
    assert_eq!(
        j2["status"].as_str(),
        Some("failed"),
        "approval must be in terminal 'failed' state: {j2}"
    );

    // Re-approve must return terminal status, NOT re-execute.
    let (s3, j3) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert!(
        is_terminal_retry(s3, &j3),
        "re-approve after failed execution must return terminal status (idempotent retry): \
         status={s3}, body={j3}"
    );
    assert_eq!(
        j3["decision"].as_str(),
        Some("already_failed"),
        "terminal retry must indicate already_failed: {j3}"
    );
}

// ===========================================================================
// Status endpoint reflects terminal state with forensics
// ===========================================================================

/// Denied execution shows `denied` state and forensic fields via GET.
#[tokio::test]
async fn status_reflects_deny_terminal_state() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let (s1, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({"reason": "test denial"}),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, j2) = get_json_operator(&app, &format!("/v1/approvals/{approval_id}")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        j2["status"].as_str(),
        Some("denied"),
        "status must show denied: {j2}"
    );
    assert!(
        j2["completed_at"].is_string(),
        "completed_at must be present for terminal state: {j2}"
    );
    assert_eq!(
        j2["deny_reason"].as_str(),
        Some("test denial"),
        "deny_reason must be persisted in terminal record: {j2}"
    );
}

// ===========================================================================
// True concurrent approve — multiple tokio tasks hitting the same approval
// ===========================================================================

/// SECURITY: spawn N concurrent HTTP approve requests against the same
/// approval_id. Exactly one must reach execution (502 — no WASM loaded);
/// all others must get either a claim conflict (409) or terminal retry (200).
///
/// The key invariant: exactly ONE request dispatches the WASM provider.
#[tokio::test]
async fn concurrent_approve_requests_only_one_reaches_execution() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Spawn 8 concurrent approve requests.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let app = app.clone();
        let path = format!("/v1/approvals/{approval_id}/approve");
        handles.push(tokio::spawn(async move {
            post_json_operator(&app, &path, &serde_json::json!({})).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let reached_execution = results
        .iter()
        .filter(|(s, j)| is_execution_status(*s) && !is_terminal_retry(*s, j))
        .count();

    assert_eq!(
        reached_execution,
        1,
        "exactly one concurrent approve must reach execution — got {reached_execution} \
         (statuses: {:?})",
        results.iter().map(|(s, _)| s.as_u16()).collect::<Vec<_>>()
    );

    // All others must be claim conflict (409) or terminal retry (200).
    let non_execution = results
        .iter()
        .filter(|(s, j)| is_claim_conflict(*s) || is_terminal_retry(*s, j))
        .count();
    assert_eq!(
        non_execution,
        7,
        "all other concurrent approves must be conflict or terminal retry — got {non_execution} \
         (statuses: {:?})",
        results.iter().map(|(s, _)| s.as_u16()).collect::<Vec<_>>()
    );
}

/// SECURITY: spawn N concurrent HTTP requests — mix of approve and deny —
/// against the same approval_id. Exactly one must win; the rest get
/// conflict (409) or terminal retry (200).
#[tokio::test]
async fn concurrent_mixed_approve_deny_only_one_wins() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let mut handles = Vec::new();
    for i in 0..8 {
        let app = app.clone();
        let id = approval_id.clone();
        let is_approve = i % 2 == 0;
        handles.push(tokio::spawn(async move {
            if is_approve {
                let path = format!("/v1/approvals/{id}/approve");
                post_json_operator(&app, &path, &serde_json::json!({})).await
            } else {
                let path = format!("/v1/approvals/{id}/deny");
                post_json_operator(&app, &path, &serde_json::json!({})).await
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Non-winners: claim conflict (409) or terminal retry (200 with already_*).
    let non_winners = results
        .iter()
        .filter(|(s, j)| is_claim_conflict(*s) || is_terminal_retry(*s, j))
        .count();

    assert!(
        non_winners >= 7,
        "at most one concurrent request should win — got {non_winners} non-winners \
         (statuses: {:?})",
        results.iter().map(|(s, _)| s.as_u16()).collect::<Vec<_>>()
    );
}
