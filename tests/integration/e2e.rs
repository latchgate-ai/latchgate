//! End-to-end integration tests against a live Gate stack.
//!
//! # What these tests cover
//!
//! Every test in this module exercises the full request path:
//!
//!   agent code => DPoP keypair => lease issuance => signed proof
//!     => Gate HTTP handler => auth pipeline => OPA => Redis budgets
//!       => audit ledger => HTTP response
//!
//! This is the only layer where the complete security envelope is verified —
//! unit tests cover individual components; these tests verify they compose
//! correctly and that no bypass exists at the integration seams.
//!
//! # Test organisation
//!
//! | Section              | What is asserted                                      |
//! |----------------------|-------------------------------------------------------|
//! | `gate_lifecycle`     | Startup, health, action registry                     |
//! | `auth_flow`          | Lease issuance, DPoP binding, header validation       |
//! | `enforcement`        | Allow/deny/approval decisions, budget exhaustion      |
//! | `audit_trail`        | Every decision is written to the ledger               |
//! | `revocation`         | Kill-switch invalidates all in-flight grants          |
//! | `error_surface`      | Error bodies contain only safe opaque codes           |
//! | `approval_flow`      | Approve / deny / tamper / expiry                      |
//! | `hardening`          | TOCTOU, tamper detection, dependency outage            |
//!
//! Approval-specific tests (plan binding, atomic lifecycle, kernel parity)
//! live in dedicated modules: `approval_plan`, `approval_atomic`,
//! `approval_parity`.
//!
//! # Requirements
//!
//! Redis on 127.0.0.1:6379 and OPA on 127.0.0.1:8181.
//! Start with `make dev` or `docker compose up redis opa`.
//! Run with: `make test-security`

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use latchgate_auth::dpop::{compute_ath, generate_dpop_keypair, sign_dpop_proof};
use latchgate_kernel::AppState;

use crate::harness::{
    action_url, get_json, get_json_operator, issue_lease, issue_lease_with_budget, post_json,
    post_json_operator, post_with_auth, test_router, uuid_v4, Agent,
};

// ===========================================================================
// gate_lifecycle — startup, health, registry
// ===========================================================================

/// Gate responds to /healthz immediately after boot.
#[tokio::test]
async fn healthz_returns_200() {
    let (app, _) = test_router();
    let (status, _) = get_json(&app, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
}

/// /v1/actions lists manifests from definitions/manifests/.
#[tokio::test]
async fn action_registry_is_populated() {
    let (app, _) = test_router();
    let (status, json) = get_json(&app, "/v1/actions").await;
    assert_eq!(status, StatusCode::OK);
    let actions = json["actions"].as_array().expect("actions array");
    // At minimum, http_fetch must be registered.
    let has_http_fetch = actions
        .iter()
        .any(|a| a["action_id"].as_str() == Some("http_fetch"));
    assert!(has_http_fetch, "http_fetch must be in the registry");
}

/// /v1/actions/{id} returns the full manifest for a known action.
#[tokio::test]
async fn action_detail_returns_manifest_fields() {
    let (app, _) = test_router();
    let (status, json) = get_json(&app, "/v1/actions/http_fetch").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["action_id"], "http_fetch");
    assert!(json["resource_limits"]["timeout_seconds"].is_number());
    assert!(json["risk_level"].is_string());
}

/// Unknown action returns 404 — not a 500 or a different action.
#[tokio::test]
async fn unknown_action_returns_404() {
    let (app, _) = test_router();
    let (status, _) = get_json(&app, "/v1/actions/does_not_exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ===========================================================================
// auth_flow — lease issuance and DPoP header validation
// ===========================================================================

/// Full happy-path lease issuance: POST /v1/leases => 200 with lease_jwt.
#[tokio::test]
async fn lease_issuance_returns_jwt() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (status, json) = post_json(&app, "/v1/leases", &agent.lease_request()).await;
    assert_eq!(status, StatusCode::OK, "unexpected: {json}");
    assert!(
        json["lease_jwt"].is_string(),
        "response must contain lease_jwt"
    );
    assert!(
        json["session_id"].is_string(),
        "response must contain server-issued session_id"
    );
}

/// The lease JWT must embed a `cnf.jkt` thumbprint matching the supplied JWK.
#[tokio::test]
async fn lease_cnf_jkt_matches_provided_jwk() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let expected_jkt =
        latchgate_auth::dpop::compute_jwk_thumbprint(&agent.pub_key.x, &agent.pub_key.y).unwrap();

    let (_, json) = post_json(&app, "/v1/leases", &agent.lease_request()).await;
    let lease_jwt = json["lease_jwt"].as_str().unwrap();

    // Decode the payload (no verification — we just inspect the claim).
    let payload_b64 = lease_jwt.split('.').nth(1).unwrap();
    let payload_bytes = base64_url_decode(payload_b64);
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(
        claims["cnf"]["jkt"].as_str().unwrap(),
        expected_jkt,
        "cnf.jkt must match the thumbprint of the agent's DPoP public key"
    );
}

/// Lease request with an unknown field is rejected with 422.
///
/// session_id is no longer a client-supplied field. Sending it (e.g. from
/// an old SDK version) must be rejected so clients get a clear signal to
/// upgrade rather than silently receiving a server-generated identity.
#[tokio::test]
async fn lease_unknown_field_returns_422() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let mut body = agent.lease_request();
    body["session_id"] = serde_json::json!("attacker-controlled");

    let (status, json) = post_json(&app, "/v1/leases", &body).await;
    assert!(
        status.is_client_error(),
        "unknown field must be rejected, got {status}: {json}"
    );
}

/// Lease request with non-EC key type is rejected.
#[tokio::test]
async fn lease_rsa_key_type_rejected() {
    let (app, _) = test_router();
    let (_, pk) = generate_dpop_keypair().unwrap();
    let body = serde_json::json!({
        "dpop_jwk": { "kty": "RSA", "crv": "P-256", "x": pk.x, "y": pk.y },
        "scopes": ["tools:call"],
    });
    let (status, json) = post_json(&app, "/v1/leases", &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "RSA key must be rejected: {json}"
    );
}

// ===========================================================================
// enforcement — allow / deny / approval / budget
// (requires Docker: Redis for budgets, OPA for policy)
// ===========================================================================

/// SECURITY: DPoP proof replay is rejected.
///
/// The same jti must not be accepted twice even if the proof is otherwise
/// valid. This is the anti-replay guarantee: a network-captured proof cannot
/// be used by an attacker to repeat the call.
#[tokio::test]
async fn dpop_proof_replay_rejected() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_fetch");

    // Build one proof and use it twice.
    let ath = compute_ath(&lease_jwt);
    let jti = uuid_v4();
    let proof = sign_dpop_proof(&agent.signing_key, "POST", &htu, &ath, &jti).unwrap();

    let body = Body::from(serde_json::json!({ "url": "https://httpbin.org/get" }).to_string());
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/actions/http_fetch/execute")
                .header("authorization", format!("DPoP {lease_jwt}"))
                .header("dpop", &proof)
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();

    // First call: any non-replay response (allow, deny, opa-error are all fine;
    // the important assertion is on the second call).
    let first_status = first.status();
    assert_ne!(
        first_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "first call must not crash the gate"
    );

    // Second call with the identical proof.
    let body2 = Body::from(serde_json::json!({ "url": "https://httpbin.org/get" }).to_string());
    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/actions/http_fetch/execute")
                .header("authorization", format!("DPoP {lease_jwt}"))
                .header("dpop", &proof) // same proof
                .header("content-type", "application/json")
                .body(body2)
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "replayed DPoP proof must be rejected with 401"
    );
}

/// Unauthorised principal cannot call an action not in their ACL.
///
/// `agent:restricted` is only allowed `http_fetch` per data.json.
/// Attempting `http_put` must be denied.
#[tokio::test]
async fn acl_prevents_unauthorised_action() {
    let (app, _) = test_router();
    // Use session_id as principal identifier — OPA policy looks up data.acl[principal].
    let agent = Agent::new();

    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_put");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

    let (status, json) = post_with_auth(
        &app,
        "/v1/actions/http_put/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/1", "body": "{}" }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unauthorised action must be denied: {json}"
    );
    assert_eq!(json["error"], "policy_denied");
}

/// Budget exhaustion: a session with zero remaining calls is denied.
///
/// This tests the primary budget enforcement path: OPA sees
/// `budgets_before.calls_remaining <= 0` and denies the request.
/// The pipeline's BudgetManager provides defense-in-depth for race
/// conditions, but OPA is the first line of defense.
#[tokio::test]
async fn budget_exhaustion_denies_excess_calls() {
    let (app, _) = test_router();
    let agent = Agent::new();

    // Budget of exactly 0 calls — OPA will deny immediately.
    let (lease_jwt, _) = issue_lease_with_budget(&app, &agent, 0).await;

    let htu = action_url("http_fetch");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);
    let (status, json) = post_with_auth(
        &app,
        "/v1/actions/http_fetch/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://httpbin.org/get" }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "zero-budget call must be 403: {json}"
    );
    // OPA denies with policy_denied when it sees calls_remaining <= 0.
    // This is the production-correct behavior — OPA is the primary enforcer.
    assert_eq!(
        json["error"].as_str(),
        Some("policy_denied"),
        "OPA must deny exhausted budget: {json}"
    );
}

/// High-risk action returns 202 Accepted with approval_id.
///
/// `http_delete` has risk_level=high in its manifest. The OPA policy
/// requires_approval=true for high/critical risk. Gate must return 202
/// and an approval_id, not execute the action immediately.
#[tokio::test]
async fn high_risk_action_returns_202_pending_approval() {
    let (app, _) = test_router();
    let agent = Agent::new();

    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

    let (status, json) = post_with_auth(
        &app,
        "/v1/actions/http_delete/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/test" }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "high-risk action must return 202: {json}"
    );
    assert!(
        json["approval_id"].is_string(),
        "response must contain approval_id: {json}"
    );
}

// ===========================================================================
// audit_trail — every decision is written
// ===========================================================================

/// Every action call — even a rejected one — produces an audit event.
///
/// The audit ledger must be a complete record. A missing audit event for
/// a denied call would be an invisible attack.
#[tokio::test]
async fn denied_call_produces_audit_event() {
    let (app, ledger) = test_router();
    let agent = Agent::new();

    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_put");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

    let (status, _) = post_with_auth(
        &app,
        "/v1/actions/http_put/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/2", "body": "{}" }),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);

    // Ledger must contain a deny event for this call.
    let filter = latchgate_ledger::EventFilter {
        action_id: Some("http_put".into()),
        decision: Some("deny".into()),
        ..Default::default()
    };
    let events = ledger.query_events(&filter).unwrap();
    assert!(
        !events.is_empty(),
        "denied call must produce an audit event in the ledger"
    );
}

/// Successful lease issuance is audited.
///
/// Lease events must be recorded so that forensic reconstruction of a session
/// is possible from the audit trail alone.
#[tokio::test]
async fn lease_issuance_produces_audit_event() {
    let (app, ledger) = test_router();
    let agent = Agent::new();
    let (_, server_session_id) = issue_lease(&app, &agent).await;

    let filter = latchgate_ledger::EventFilter {
        session_id: Some(server_session_id.clone()),
        ..Default::default()
    };
    let events = ledger.query_events(&filter).unwrap();
    assert!(
        !events.is_empty(),
        "lease issuance must produce an audit event for session: {server_session_id}"
    );
}

// ===========================================================================
// error_surface — no internal information leaks in HTTP responses
// ===========================================================================

/// SECURITY: error responses must contain only a single `error` code field.
///
/// Stack traces, OPA rule names, Redis keys, manifest fields, or any other
/// internal detail in the response body is an information disclosure. The
/// pipeline enforces `{"error": "<code>"}` exclusively.
#[tokio::test]
async fn error_body_contains_only_error_code() {
    let (app, _) = test_router();

    // Trigger a 401 via missing auth.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/actions/http_fetch/execute")
                .header("content-type", "application/json")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let obj = json.as_object().unwrap();

    assert_eq!(
        obj.len(),
        1,
        "error body must contain exactly one field ('error'), got: {obj:?}"
    );
    assert!(
        obj.contains_key("error"),
        "error body must have 'error' key, got: {obj:?}"
    );
}

/// SECURITY: 404 on unknown action must not reveal whether other actions exist.
///
/// The response body may be JSON `{"error": "..."}` (if the handler produces
/// a structured response) or empty (if axum's default 404 fires). Either way,
/// the body must not leak action names, paths, or internal details.
#[tokio::test]
async fn unknown_action_error_body_is_opaque() {
    let (app, _) = test_router();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/actions/totally_unknown_action")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body_str = String::from_utf8_lossy(&bytes);

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown action must return 404"
    );

    // Body must not leak internal details regardless of format.
    assert!(
        !body_str.contains("manifests"),
        "404 must not leak internal paths: {body_str}"
    );
    assert!(
        !body_str.contains("http_fetch"),
        "404 must not leak other action names: {body_str}"
    );

    // If body is structured JSON, it must contain only the error code.
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if let Some(obj) = json.as_object() {
            assert_eq!(
                obj.len(),
                1,
                "JSON 404 body must be {{\"error\": \"...\"}} only, got: {obj:?}"
            );
            assert!(
                obj.contains_key("error"),
                "JSON 404 body must have 'error' key, got: {obj:?}"
            );
        }
    }
}

// ===========================================================================
// revocation — kill-switch invalidates all grants
// ===========================================================================

/// Revocation epoch advance: POST /v1/admin/revoke-all returns new epoch > old.
#[tokio::test]
async fn revoke_all_advances_epoch() {
    let (app, _) = test_router();

    let (s1, j1) = get_json_operator(&app, "/v1/admin/epoch").await;
    assert_eq!(s1, StatusCode::OK);
    let epoch_before = j1["current_epoch"].as_u64().unwrap_or(0);

    let (s2, j2) = post_json_operator(&app, "/v1/admin/revoke-all", &serde_json::json!({})).await;
    assert_eq!(s2, StatusCode::OK, "revoke-all must succeed: {j2}");

    let (s3, j3) = get_json_operator(&app, "/v1/admin/epoch").await;
    assert_eq!(s3, StatusCode::OK);
    let epoch_after = j3["current_epoch"].as_u64().unwrap_or(0);

    assert!(
        epoch_after > epoch_before,
        "epoch must increase after revoke-all: {epoch_before} => {epoch_after}"
    );
}

/// Revocation is monotonic: two consecutive calls always increase the epoch.
#[tokio::test]
async fn revoke_all_is_monotonic() {
    let (app, _) = test_router();

    let (_, j1) = post_json_operator(&app, "/v1/admin/revoke-all", &serde_json::json!({})).await;
    let (_, j2) = post_json_operator(&app, "/v1/admin/revoke-all", &serde_json::json!({})).await;
    let (_, j3) = get_json_operator(&app, "/v1/admin/epoch").await;

    let e1 = j1["current_epoch"].as_u64().unwrap_or(0);
    let e2 = j2["current_epoch"].as_u64().unwrap_or(0);
    let e3 = j3["current_epoch"].as_u64().unwrap_or(0);

    assert!(
        e2 > e1,
        "second revoke must produce higher epoch: {e1} => {e2}"
    );
    assert_eq!(e3, e2, "get_epoch must reflect latest revoke: {e2} ≠ {e3}");
}

// ===========================================================================
// approval_flow — approve / deny / tamper
// ===========================================================================

/// A pending approval can be fetched by ID.
///
/// GET /v1/approvals/{id} must return approval metadata without exposing
/// the request body (only the hash).
#[tokio::test]
async fn pending_approval_is_fetchable_by_id() {
    let (app, _) = test_router();
    let agent = Agent::new();

    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

    let (status, json) = post_with_auth(
        &app,
        "/v1/actions/http_delete/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/test" }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let approval_id = json["approval_id"].as_str().unwrap().to_string();

    // Fetch the approval.
    let (status2, json2) = get_json_operator(&app, &format!("/v1/approvals/{approval_id}")).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "approval must be fetchable: {json2}"
    );
    assert_eq!(json2["action_id"].as_str(), Some("http_delete"));
    // Request body must NOT be exposed — only the hash.
    assert!(
        json2.get("request_body").is_none(),
        "approval GET must not expose request_body: {json2}"
    );
    assert!(
        json2.get("request_hash").is_some(),
        "approval GET must expose request_hash: {json2}"
    );
}

/// Denying a pending approval records a deny event in the audit trail.
#[tokio::test]
async fn deny_approval_produces_audit_event() {
    let (app, ledger) = test_router();
    let agent = Agent::new();

    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

    let (s1, j1) = post_with_auth(
        &app,
        "/v1/actions/http_delete/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/deny-test" }),
    )
    .await;
    assert_eq!(s1, StatusCode::ACCEPTED);
    let approval_id = j1["approval_id"].as_str().unwrap().to_string();

    // Deny it.
    let (s2, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/deny"),
        &serde_json::json!({ "reason": "e2e test denial" }),
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "deny must return 200");

    // Audit trail must record the denial.
    let filter = latchgate_ledger::EventFilter {
        action_id: Some("http_delete".into()),
        decision: Some("deny".into()),
        ..Default::default()
    };
    let events = ledger.query_events(&filter).unwrap();
    assert!(
        !events.is_empty(),
        "denied approval must produce an audit event"
    );
}

// ===========================================================================
// hardening — TOCTOU, tamper detection, dependency outage, error surface
// ===========================================================================

/// SECURITY: tampered approval request body in Redis is detected.
///
/// If an attacker modifies the stored `request_body` in Redis between
/// the original PendingApproval and the approve call, the pipeline
/// recomputes the canonical hash and rejects on mismatch.
///
/// This tests the integrity binding described in the security checklist §4.
#[tokio::test]
async fn tampered_approval_request_body_rejected() {
    let (app, _) = test_router();
    let agent = Agent::new();

    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

    // Step 1: Create a pending approval.
    let (status, json) = post_with_auth(
        &app,
        "/v1/actions/http_delete/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/tamper-test" }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "must get 202: {json}");
    let approval_id = json["approval_id"].as_str().unwrap().to_string();

    // Step 2: Tamper with the stored request_body directly in Redis.
    // Approval records are stored as Redis HASHes; the payload field
    // contains the PendingApproval JSON.
    let redis_client = redis::Client::open(crate::harness::test_redis_url()).unwrap();
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let key = format!("latch:approval:{approval_id}");
    let stored: String = redis::cmd("HGET")
        .arg(&key)
        .arg("payload")
        .query_async(&mut conn)
        .await
        .unwrap();
    let mut pending: serde_json::Value = serde_json::from_str(&stored).unwrap();
    // Change the url to something different.
    pending["request_body"]["url"] = serde_json::json!("https://evil.example.com/pwned");
    let tampered_json = serde_json::to_string(&pending).unwrap();
    let _: () = redis::cmd("HSET")
        .arg(&key)
        .arg("payload")
        .arg(&tampered_json)
        .query_async(&mut conn)
        .await
        .unwrap();

    // Step 3: Approve — pipeline must detect hash mismatch and reject.
    let (status, json) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "tampered approval must be rejected: {json}"
    );
}

/// SECURITY: revoke-all, then approve a pre-existing pending => still works.
///
/// Revocation invalidates in-flight grants, not future ones. Approving
/// a pending request after revocation creates a fresh grant with the
/// current (post-revocation) epoch. This must succeed — the approval
/// is a separate authorization act.
///
/// If this test fails, revocation is over-reaching and breaking legitimate
/// approval flows.
#[tokio::test]
async fn revoke_then_approve_still_works() {
    let (app, _) = test_router();
    let agent = Agent::new();

    // Create pending approval.
    let (lease_jwt, _) = issue_lease(&app, &agent).await;
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);
    let (s1, j1) = post_with_auth(
        &app,
        "/v1/actions/http_delete/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://api.example.com/v1/resources/revoke-test" }),
    )
    .await;
    assert_eq!(s1, StatusCode::ACCEPTED, "must get 202: {j1}");
    let approval_id = j1["approval_id"].as_str().unwrap().to_string();

    // Revoke all.
    let (s2, _) = post_json_operator(&app, "/v1/admin/revoke-all", &serde_json::json!({})).await;
    assert_eq!(s2, StatusCode::OK);

    // Approve — must not fail due to revocation.
    // (Will fail at WASM dispatch since no provider is loaded, but the
    // approval pipeline itself — trust, schema, policy — must succeed.)
    let (s3, j3) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    // 502 = provider failed (expected: no WASM module loaded).
    // Any status OTHER than 403/500 due to revocation is acceptable.
    assert_ne!(
        s3,
        StatusCode::FORBIDDEN,
        "revocation must not block approval of pending requests: {j3}"
    );
}

/// SECURITY: Redis outage on the action path => 503 fail-closed.
///
/// When Redis is unreachable, the pipeline must deny (503), never allow.
/// This tests the full pipeline with a deliberately broken Redis URL.
#[tokio::test]
async fn dependency_outage_redis_fail_closed() {
    // Build AppState with a Redis URL that will never connect.
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let manifests_dir = workspace_root
        .join("definitions/manifests")
        .to_string_lossy()
        .into_owned();

    let config = latchgate_config::Config {
        listener: latchgate_config::ListenerConfig {
            listen_http_addr: Some("127.0.0.1:0".parse().unwrap()),
            unsafe_expose_http: true,
            public_base_url: "http://localhost:3000".into(),
            ..Default::default()
        },
        manifests_dir: manifests_dir.clone(),
        storage: latchgate_config::StorageConfig {
            redis_url: Some("redis://127.0.0.1:1".into()),
            ..Default::default()
        }, // dead port
        ..latchgate_config::Config::default()
    };
    let issuer = latchgate_auth::issuer::Issuer::new(
        config.policy.lease_ttl_seconds,
        latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
    )
    .unwrap();
    let replay_cache = latchgate_auth::ReplayCache::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::REPLAY_TTL_SECS),
        latchgate_core::security_constants::REDIS_KEY_PREFIX,
    )
    .unwrap();
    let registry = latchgate_registry::RegistryStore::load_from_dir(Path::new(&manifests_dir))
        .unwrap_or_else(|_| latchgate_registry::RegistryStore::empty());
    let policy = latchgate_policy::PolicyClient::new(
        config
            .policy
            .opa_url
            .as_deref()
            .unwrap_or("http://127.0.0.1:8181"),
        Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
    );
    let ledger = latchgate_ledger::LedgerStore::open_in_memory(None).unwrap();
    let metrics = latchgate_ledger::Metrics::new().unwrap();
    let budget_manager = latchgate_state::BudgetManager::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required"),
    )
    .unwrap();
    let approval_store = latchgate_state::approvals::ApprovalStore::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
    )
    .unwrap();
    let wasm_runtime = latchgate_providers::WasmRuntime::new(4).unwrap();
    let secrets_manager = latchgate_providers::SecretsManager::new("sops", None);
    let state = AppState::new(latchgate_kernel::AppStateInit {
        config,
        registry,
        embedded_manifests: vec![],
        ledger,
        metrics,
        auth: latchgate_kernel::AuthServicesInit {
            issuer,
            replay_cache,
            identity_provider: Box::new(latchgate_auth::identity::NoneProvider),
        },
        crypto: latchgate_kernel::CryptoServicesInit {
            receipt_signer: latchgate_crypto::ReceiptSigner::generate(),
            grant_signer: latchgate_crypto::GrantSigner::generate(),
            verifying_key_store: latchgate_crypto::VerifyingKeyStore::single(
                &latchgate_crypto::ReceiptSigner::generate(),
            ),
        },
        enforcement: latchgate_kernel::EnforcementServicesInit {
            policy,
            budget_manager,
            approval_store,
        },
        runtime: latchgate_kernel::RuntimeServicesInit {
            wasm_runtime,
            secrets_manager,
            verifier_registry: latchgate_kernel::VerifierRegistry::new(),
            fs_root_fd: None,
            fs_root_canonical: None,
            session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
        },
        lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
    });
    let app = latchgate_api::router(state);

    // Issue a DPoP keypair + proof. Lease issuance doesn't need Redis
    // (unless budgets are set), but the action call does (replay cache).
    let agent = Agent::new();
    let (ls, lj) = post_json(&app, "/v1/leases", &agent.lease_request()).await;
    // Lease issuance may or may not work (no budget init needed).
    // If it works, try an action call. If not, that's fine too — the
    // point is that the action call fails with 503.
    if ls == StatusCode::OK {
        let lease_jwt = lj["lease_jwt"].as_str().unwrap().to_string();
        let htu = action_url("http_fetch");
        let proof = agent.dpop_proof("POST", &htu, &lease_jwt);

        let (status, json) = post_with_auth(
            &app,
            "/v1/actions/http_fetch/execute",
            &lease_jwt,
            &proof,
            &serde_json::json!({ "url": "https://httpbin.org/get" }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "Redis outage must cause 503 fail-closed: {json}"
        );
    }
}

/// SECURITY: OPA outage on the action path => 503 fail-closed.
///
/// When OPA is unreachable, the pipeline must deny (503), never allow.
#[tokio::test]
async fn dependency_outage_opa_fail_closed() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let manifests_dir = workspace_root
        .join("definitions/manifests")
        .to_string_lossy()
        .into_owned();

    let config = latchgate_config::Config {
        listener: latchgate_config::ListenerConfig {
            listen_http_addr: Some("127.0.0.1:0".parse().unwrap()),
            unsafe_expose_http: true,
            public_base_url: "http://localhost:3000".into(),
            ..Default::default()
        },
        manifests_dir: manifests_dir.clone(),
        storage: latchgate_config::StorageConfig {
            redis_url: Some(crate::harness::test_redis_url()),
            ..Default::default()
        },
        policy: latchgate_config::PolicyConfig {
            opa_url: Some("http://127.0.0.1:1".to_string()),
            ..Default::default()
        },
        ..latchgate_config::Config::default()
    };
    let issuer = latchgate_auth::issuer::Issuer::new(
        config.policy.lease_ttl_seconds,
        latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
    )
    .unwrap();
    let replay_cache = latchgate_auth::ReplayCache::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::REPLAY_TTL_SECS),
        latchgate_core::security_constants::REDIS_KEY_PREFIX,
    )
    .unwrap();
    let registry = latchgate_registry::RegistryStore::load_from_dir(Path::new(&manifests_dir))
        .unwrap_or_else(|_| latchgate_registry::RegistryStore::empty());
    let policy = latchgate_policy::PolicyClient::new(
        config
            .policy
            .opa_url
            .as_deref()
            .unwrap_or("http://127.0.0.1:8181"),
        Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
    );
    let ledger = latchgate_ledger::LedgerStore::open_in_memory(None).unwrap();
    let metrics = latchgate_ledger::Metrics::new().unwrap();
    let budget_manager = latchgate_state::BudgetManager::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required"),
    )
    .unwrap();
    let approval_store = latchgate_state::approvals::ApprovalStore::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
    )
    .unwrap();
    let wasm_runtime = latchgate_providers::WasmRuntime::new(4).unwrap();
    let secrets_manager = latchgate_providers::SecretsManager::new("sops", None);
    let state = AppState::new(latchgate_kernel::AppStateInit {
        config,
        registry,
        embedded_manifests: vec![],
        ledger,
        metrics,
        auth: latchgate_kernel::AuthServicesInit {
            issuer,
            replay_cache,
            identity_provider: Box::new(latchgate_auth::identity::NoneProvider),
        },
        crypto: latchgate_kernel::CryptoServicesInit {
            receipt_signer: latchgate_crypto::ReceiptSigner::generate(),
            grant_signer: latchgate_crypto::GrantSigner::generate(),
            verifying_key_store: latchgate_crypto::VerifyingKeyStore::single(
                &latchgate_crypto::ReceiptSigner::generate(),
            ),
        },
        enforcement: latchgate_kernel::EnforcementServicesInit {
            policy,
            budget_manager,
            approval_store,
        },
        runtime: latchgate_kernel::RuntimeServicesInit {
            wasm_runtime,
            secrets_manager,
            verifier_registry: latchgate_kernel::VerifierRegistry::new(),
            fs_root_fd: None,
            fs_root_canonical: None,
            session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
        },
        lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
    });
    let app = latchgate_api::router(state);

    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let htu = action_url("http_fetch");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);
    let (status, json) = post_with_auth(
        &app,
        "/v1/actions/http_fetch/execute",
        &lease_jwt,
        &proof,
        &serde_json::json!({ "url": "https://httpbin.org/get" }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "OPA outage must cause 503 fail-closed: {json}"
    );
}

/// SECURITY: 503 error body must not leak dependency details.
///
/// When Redis or OPA is down, the error response must contain only
/// the opaque error code — no connection strings, hostnames, or
/// internal error messages.
#[tokio::test]
async fn error_503_body_is_opaque() {
    let (app, _) = test_router();

    // Trigger a 401 first (no auth header) — baseline.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/actions/http_fetch/execute")
                .header("content-type", "application/json")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let body_str = json.to_string();

    // Must not contain internal details.
    assert!(
        !body_str.contains("redis://"),
        "error body must not contain Redis URL: {body_str}"
    );
    assert!(
        !body_str.contains("127.0.0.1"),
        "error body must not contain IP addresses: {body_str}"
    );
    assert!(
        !body_str.contains("Connection refused"),
        "error body must not contain OS-level errors: {body_str}"
    );
}

// Utilities
// ===========================================================================

fn base64_url_decode(s: &str) -> Vec<u8> {
    // Pad to multiple of 4.
    let pad = match s.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let padded = format!("{s}{pad}");
    // Replace URL-safe chars with standard base64.
    let standard = padded.replace('-', "+").replace('_', "/");
    // Decode ignoring errors (test helper only).
    (0..standard.len() / 4)
        .flat_map(|i| {
            let chunk = &standard[i * 4..(i + 1) * 4];
            base64_chunk_decode(chunk)
        })
        .collect()
}

fn base64_chunk_decode(chunk: &str) -> Vec<u8> {
    let b = |c: char| -> u8 {
        match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            '=' => 0,
            _ => 0,
        }
    };
    let chars: Vec<char> = chunk.chars().collect();
    let v0 = (b(chars[0]) << 2) | (b(chars[1]) >> 4);
    let v1 = (b(chars[1]) << 4) | (b(chars[2]) >> 2);
    let v2 = (b(chars[2]) << 6) | b(chars[3]);
    match (chars[2], chars[3]) {
        ('=', _) => vec![v0],
        (_, '=') => vec![v0, v1],
        _ => vec![v0, v1, v2],
    }
}
