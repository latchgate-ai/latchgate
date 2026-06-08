//! Resilience integration tests.
//!
//! These exercise failure modes that only manifest with real infrastructure:
//! mid-session backend death, unreachable policy engine, and embedded-mode
//! state persistence across restart.
//!
//! Run via: `cargo test --test integration resilience`
//! Prerequisites: `docker compose up redis opa` for scenarios 1–2.
//! Scenario 3 runs fully embedded (no external services).

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;

use latchgate_state::approvals::ApprovalStore;
use latchgate_state::SqliteStateDb;

use crate::harness;

// ───────────────────────────────────────────────────────────────────────────
// Scenario 1: Mid-session Redis death (Redis mode only)
// ───────────────────────────────────────────────────────────────────────────

/// Establish an agent session, succeed once, stop Redis, attempt a second
/// call. The gate must return 503 within 5 s — never hang or 200.
///
/// Restart Redis, verify the third call succeeds.
///
/// Requires: `docker compose up redis opa`
/// This test is gated behind `LATCHGATE_RESILIENCE_REDIS=1` because it
/// calls `docker compose stop redis` and must not interfere with other
/// test suites running in parallel.
#[tokio::test]
async fn mid_session_redis_death() {
    if std::env::var("LATCHGATE_RESILIENCE_REDIS").as_deref() != Ok("1") {
        eprintln!("skipping: set LATCHGATE_RESILIENCE_REDIS=1 to run");
        return;
    }

    let (app, _ledger) = harness::test_router();
    let agent = harness::Agent::new();

    // Issue lease and succeed once.
    let (lease_jwt, _sid) = harness::issue_lease(&app, &agent).await;
    let htu = harness::action_url("http_get");
    let proof1 = agent.dpop_proof("POST", &htu, &lease_jwt);
    let (status1, _) = harness::post_with_auth(
        &app,
        "/v1/actions/http_get/execute",
        &lease_jwt,
        &proof1,
        &serde_json::json!({"url": "https://httpbin.org/get"}),
    )
    .await;
    // Accept 200 or 403 (policy deny is fine — we're testing infrastructure, not policy).
    assert!(
        status1 != StatusCode::INTERNAL_SERVER_ERROR,
        "first call must not 500: got {status1}"
    );

    // Stop Redis.
    let stop = std::process::Command::new("docker")
        .args(["compose", "stop", "redis"])
        .output();
    assert!(
        stop.map(|o| o.status.success()).unwrap_or(false),
        "docker compose stop redis failed"
    );

    // Second call with Redis down: must get 503 within 5 s.
    let proof2 = agent.dpop_proof("POST", &htu, &lease_jwt);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        harness::post_with_auth(
            &app,
            "/v1/actions/http_get/execute",
            &lease_jwt,
            &proof2,
            &serde_json::json!({"url": "https://httpbin.org/get"}),
        ),
    )
    .await;
    match result {
        Ok((status, _)) => {
            assert!(
                status == StatusCode::SERVICE_UNAVAILABLE
                    || status == StatusCode::INTERNAL_SERVER_ERROR,
                "with Redis down, expected 503 or 500, got {status}"
            );
        }
        Err(_) => panic!("request hung for >5s with Redis down — must not hang"),
    }

    // Restart Redis.
    let start = std::process::Command::new("docker")
        .args(["compose", "start", "redis"])
        .output();
    assert!(
        start.map(|o| o.status.success()).unwrap_or(false),
        "docker compose start redis failed"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Third call: must recover.
    let proof3 = agent.dpop_proof("POST", &htu, &lease_jwt);
    let (status3, _) = harness::post_with_auth(
        &app,
        "/v1/actions/http_get/execute",
        &lease_jwt,
        &proof3,
        &serde_json::json!({"url": "https://httpbin.org/get"}),
    )
    .await;
    assert_ne!(
        status3,
        StatusCode::SERVICE_UNAVAILABLE,
        "third call after Redis restart must not be 503"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Scenario 2: OPA unreachable (external-OPA mode only)
// ───────────────────────────────────────────────────────────────────────────

/// Stop OPA, fire a call. Must return 503 or 403 — never 200.
/// Fail-closed is non-negotiable.
///
/// Gated behind `LATCHGATE_RESILIENCE_OPA=1`.
#[tokio::test]
async fn opa_unreachable_denies() {
    if std::env::var("LATCHGATE_RESILIENCE_OPA").as_deref() != Ok("1") {
        eprintln!("skipping: set LATCHGATE_RESILIENCE_OPA=1 to run");
        return;
    }

    // Stop OPA.
    let stop = std::process::Command::new("docker")
        .args(["compose", "stop", "opa"])
        .output();
    assert!(
        stop.map(|o| o.status.success()).unwrap_or(false),
        "docker compose stop opa failed"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (app, _ledger) = harness::test_router();
    let agent = harness::Agent::new();
    let (lease_jwt, _sid) = harness::issue_lease(&app, &agent).await;

    let htu = harness::action_url("http_get");
    let proof = agent.dpop_proof("POST", &htu, &lease_jwt);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        harness::post_with_auth(
            &app,
            "/v1/actions/http_get/execute",
            &lease_jwt,
            &proof,
            &serde_json::json!({"url": "https://httpbin.org/get"}),
        ),
    )
    .await;

    // Restart OPA before assertions so we leave infra clean.
    let _ = std::process::Command::new("docker")
        .args(["compose", "start", "opa"])
        .output();

    match result {
        Ok((status, _)) => {
            assert!(
                status == StatusCode::SERVICE_UNAVAILABLE
                    || status == StatusCode::FORBIDDEN
                    || status == StatusCode::INTERNAL_SERVER_ERROR,
                "with OPA down, expected 503/403/500 (fail-closed), got {status}"
            );
            assert_ne!(
                status,
                StatusCode::OK,
                "OPA unreachable must NEVER return 200"
            );
        }
        Err(_) => panic!("request hung for >5s with OPA down — must not hang"),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Scenario 3: Embedded-mode steady-state restart
// ───────────────────────────────────────────────────────────────────────────

/// Create 10 approvals in a SQLite-backed ApprovalStore, drop the store
/// (simulating process kill), reopen from the same file, verify all 10
/// approvals are still queryable.
///
/// No external services required. This is the primary security check for
/// the SQLite approval persistence path (workstream 2b).
#[tokio::test]
async fn embedded_mode_approvals_survive_restart() {
    use latchgate_state::approvals::{PendingApproval, StoredAuthContext};

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("state.db");

    // --- Phase 1: create approvals, then drop the store ---

    let approval_ids: Vec<String> = {
        let state_db = Arc::new(SqliteStateDb::open(&db_path).unwrap());
        let store = ApprovalStore::sqlite(
            state_db,
            Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
        );

        let mut ids = Vec::new();
        for i in 0..10 {
            let id = format!("resilience-{i:04}");
            let mut plan = latchgate_core::ApprovedExecutionPlan::test_default();
            plan.core.action_id = "http_get".into();

            let pending = PendingApproval {
                approval_id: id.clone(),
                trace_id: format!("trace-{i}").into(),
                action_id: "http_get".into(),
                auth_context: StoredAuthContext {
                    principal: "bench-principal".into(),
                    session_id: "bench-session".into(),
                    lease_jti: format!("jti-{i}").into(),
                    sender_thumbprint: "thumbprint-abc".into(),
                    owner: None,
                },
                request_hash: format!("hash-{i:04}").into(),
                request_body: std::sync::Arc::new(
                    serde_json::json!({"url": "https://example.com"}),
                ),
                policy_version: Some("test-init".into()),
                created_at: chrono::Utc::now().to_rfc3339(),
                plan,
                unresolved_domains: vec![],
                unresolved_paths: vec![],
            };
            store.create_pending(&pending).await.unwrap_or_else(|e| {
                panic!("approval {i} creation failed: {e}");
            });
            ids.push(id);
        }
        assert_eq!(ids.len(), 10);
        // Drop store — simulates process kill.
        ids
    };

    // --- Phase 2: reopen from same SQLite, verify all approvals persist ---

    {
        let state_db = Arc::new(SqliteStateDb::open(&db_path).unwrap());
        let store = ApprovalStore::sqlite(
            state_db,
            Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
        );

        for (i, id) in approval_ids.iter().enumerate() {
            let record = store.get_pending(id).await.unwrap_or_else(|e| {
                panic!("approval {i} ({id}) query failed after restart: {e}");
            });
            assert!(
                record.is_some(),
                "approval {i} ({id}) not found after restart — SQLite persistence broken"
            );
            let record = record.unwrap();
            assert_eq!(record.approval_id, *id);
            assert_eq!(&*record.action_id, "http_get");
        }
    }
}
