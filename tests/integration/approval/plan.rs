//! E2E tests: approval binds the exact execution plan.
//!
//! These tests verify that `PendingApproval` captures an immutable
//! execution plan at decision time, and that the approve endpoint
//! uses the stored plan — never the live manifest.
//!
//! # What is tested
//!
//! - Manifest change after `pending` does not alter stored plan targets
//! - Manifest change does not alter stored provider module digest
//! - Manifest change does not alter stored secrets
//! - Expired execution plan is rejected on approve
//! - Tampered plan hash in Redis is detected and rejected
//! - Plan fields survive Redis roundtrip with hash integrity intact
//!
//! # Requirements
//!
//! Redis on 127.0.0.1:6379 and OPA on 127.0.0.1:8181.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::harness::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a pending approval for `http_delete` (high-risk => OPA returns
/// PendingApproval). Returns the approval_id.
async fn create_pending(app: &axum::Router, agent: &Agent, lease_jwt: &str) -> String {
    let htu = action_url("http_delete");
    let proof = agent.dpop_proof("POST", &htu, lease_jwt);
    let (status, json) = post_with_auth(
        app,
        "/v1/actions/http_delete/execute",
        lease_jwt,
        &proof,
        &serde_json::json!({
            "url": "https://api.example.com/v1/resources/plan-test"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "expected 202: {json}");
    json["approval_id"].as_str().unwrap().to_string()
}

/// Read the raw pending approval payload from Redis.
async fn read_plan_from_redis(approval_id: &str) -> serde_json::Value {
    let client = redis::Client::open(crate::harness::test_redis_url()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let key = format!("latch:approval:{approval_id}");
    let stored: String = redis::cmd("HGET")
        .arg(&key)
        .arg("payload")
        .query_async(&mut conn)
        .await
        .unwrap();
    serde_json::from_str(&stored).unwrap()
}

/// Overwrite the pending approval payload in Redis (simulating tampering
/// or manifest drift detection).
async fn write_payload_to_redis(approval_id: &str, payload: &serde_json::Value) {
    let client = redis::Client::open(crate::harness::test_redis_url()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let key = format!("latch:approval:{approval_id}");
    let json = serde_json::to_string(payload).unwrap();
    let _: () = redis::cmd("HSET")
        .arg(&key)
        .arg("payload")
        .arg(&json)
        .query_async(&mut conn)
        .await
        .unwrap();
}

// ===========================================================================
// Plan captures immutable targets
// ===========================================================================

/// SECURITY: the stored plan captures `approved_targets` from the policy-
/// narrowed `allowed_sinks` at pending-approval time — not from the raw
/// manifest `declared_side_effects`. Even if someone could modify the
/// stored plan targets between `pending` and `approve`, the plan hash
/// verification detects the tampering.
///
/// Regression: approved_targets must come from
/// policy-narrowed allowed_sinks, not manifest declared_side_effects.
#[tokio::test]
async fn approved_execution_uses_stored_targets_not_current_manifest_targets() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Read the stored plan from Redis and verify targets are captured.
    let payload = read_plan_from_redis(&approval_id).await;
    let plan = &payload["plan"];
    assert!(
        plan["approved_targets"].is_array(),
        "plan must capture approved_targets"
    );
    let original_targets = plan["approved_targets"].clone();

    // Simulate manifest drift: widen targets in the stored payload.
    // This mimics what would happen if the approve endpoint re-read
    // targets from a modified live manifest instead of the stored plan.
    let mut tampered = payload.clone();
    tampered["plan"]["approved_targets"] = serde_json::json!(["message_send", "evil_target"]);
    // Don't update plan_hash — this makes the tampering detectable.
    write_payload_to_redis(&approval_id, &tampered).await;

    // Approve — must detect tampered plan (plan hash mismatch).
    let (status, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "tampered targets must cause plan hash verification failure"
    );

    // Verify the ORIGINAL targets were the policy-narrowed allowed_sinks
    // (from OPA ACL), not the raw manifest declared_side_effects.
    // The wildcard ACL allows ["http_read", "http_write", "http_delete"].
    assert_eq!(
        original_targets,
        serde_json::json!(["http_read", "http_write", "http_delete"]),
        "stored plan must have captured policy-narrowed allowed_sinks, not manifest targets"
    );
}

// ===========================================================================
// Plan captures immutable provider module digest
// ===========================================================================

/// SECURITY: the stored plan captures `provider_module_digest` at
/// pending-approval time. Swapping the WASM module after approval does
/// not change what the plan records.
#[tokio::test]
async fn approved_execution_uses_stored_provider_digest_not_current_manifest_digest() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let payload = read_plan_from_redis(&approval_id).await;
    let plan = &payload["plan"];

    // Verify the plan captured the original provider module digest.
    let stored_digest = plan["provider_module_digest"].as_str().unwrap();
    assert!(
        stored_digest.starts_with("sha256:") || stored_digest.starts_with("builtin:"),
        "plan must capture provider_module_digest, got: {stored_digest}"
    );

    // Read expected digest from the manifest (not hardcoded — digests change
    // after `latchgate providers rehash`).
    let expected_digest = {
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("definitions/manifests/http_delete.yaml");
        let spec = latchgate_registry::manifest::ActionSpec::from_file(&manifest_path).unwrap();
        spec.provider_module_digest
    };
    assert_eq!(
        stored_digest, &*expected_digest,
        "plan must capture http_delete's provider digest"
    );

    // Tamper: change the provider digest (simulating a module swap attack).
    let mut tampered = payload.clone();
    tampered["plan"]["provider_module_digest"] = serde_json::json!(
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    write_payload_to_redis(&approval_id, &tampered).await;

    let (status, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "tampered provider digest must cause plan hash verification failure"
    );
}

// ===========================================================================
// Plan captures immutable secrets
// ===========================================================================

/// SECURITY: the stored plan captures `approved_secrets` at pending time.
/// Adding a new secret to the manifest after approval does not expand
/// what the execution can access.
#[tokio::test]
async fn approved_execution_uses_stored_secrets_not_current_manifest_secrets() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let payload = read_plan_from_redis(&approval_id).await;
    let plan = &payload["plan"];

    // http_delete declares one optional secret (API_TOKEN).
    let approved_secrets = plan["approved_secrets"].as_array().unwrap();
    assert_eq!(
        approved_secrets,
        &vec![serde_json::json!("API_TOKEN")],
        "http_delete declares API_TOKEN as its only secret"
    );

    // Tamper: inject secrets into the plan (simulating widened access).
    let mut tampered = payload.clone();
    tampered["plan"]["approved_secrets"] =
        serde_json::json!(["STOLEN_API_KEY", "STOLEN_DB_PASSWORD"]);
    write_payload_to_redis(&approval_id, &tampered).await;

    let (status, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "injected secrets must cause plan hash verification failure"
    );
}

// ===========================================================================
// Plan expiry
// ===========================================================================

/// SECURITY: an execution plan that has expired must be rejected even
/// if the Redis key hasn't expired yet.
#[tokio::test]
async fn approved_execution_rejects_when_plan_expired() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    // Tamper: set plan expiry to the past.
    let mut payload = read_plan_from_redis(&approval_id).await;
    payload["plan"]["expires_at"] = serde_json::json!("2020-01-01T00:00:00Z");
    // Recompute plan_hash so the hash check passes — the expiry check
    // must be a separate enforcement step, not just hash integrity.
    //
    // We parse the plan as the real type to get a valid hash.
    let mut plan: latchgate_core::ApprovedExecutionPlan =
        serde_json::from_value(payload["plan"].clone()).unwrap();
    plan.finalize();
    payload["plan"]["plan_hash"] = serde_json::json!(plan.plan_hash);
    write_payload_to_redis(&approval_id, &payload).await;

    let (status, json) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "expired plan must be rejected: {json}"
    );
}

// ===========================================================================
// Plan hash integrity
// ===========================================================================

/// SECURITY: plan_hash is verified before any plan field is used.
/// A plan with a valid structure but zeroed hash is rejected.
#[tokio::test]
async fn approve_rejects_plan_with_empty_hash() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let mut payload = read_plan_from_redis(&approval_id).await;
    payload["plan"]["plan_hash"] = serde_json::json!("");
    write_payload_to_redis(&approval_id, &payload).await;

    let (status, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "empty plan_hash must be rejected"
    );
}

/// SECURITY: plan fields survive Redis roundtrip with plan_hash intact.
/// This validates that JSON serialization in Lua/Redis does not alter
/// field values in a way that breaks the hash.
#[tokio::test]
async fn plan_survives_redis_roundtrip_with_valid_hash() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let payload = read_plan_from_redis(&approval_id).await;
    let plan: latchgate_core::ApprovedExecutionPlan =
        serde_json::from_value(payload["plan"].clone()).unwrap();

    assert!(
        plan.verify_hash(),
        "plan_hash must verify after Redis roundtrip"
    );
}

/// SECURITY: `action_digest` in the plan is a content digest of the
/// action definition, distinct from `provider_module_digest`.
#[tokio::test]
async fn plan_action_digest_differs_from_provider_module_digest() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let payload = read_plan_from_redis(&approval_id).await;
    let plan = &payload["plan"];

    let action_digest = plan["action_digest"].as_str().unwrap();
    let provider_digest = plan["provider_module_digest"].as_str().unwrap();

    assert_ne!(
        action_digest, provider_digest,
        "action_digest (manifest content hash) must differ from \
         provider_module_digest (WASM binary hash or builtin identifier)"
    );
    assert!(action_digest.starts_with("sha256:"));
    assert!(
        provider_digest.starts_with("sha256:") || provider_digest.starts_with("builtin:"),
        "provider_module_digest must be sha256: or builtin:, got: {provider_digest}"
    );
}

// ===========================================================================
// Plan captures database_config
// ===========================================================================

/// SECURITY: for non-database actions, `database_config` must be absent
/// from the stored plan. Injecting a database_config post-hoc breaks the
/// plan hash, preventing an attacker from smuggling statement definitions
/// into an approval that was created without them.
#[tokio::test]
async fn plan_database_config_absent_for_non_database_action() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let payload = read_plan_from_redis(&approval_id).await;
    let plan = &payload["plan"];

    // http_delete has no database_config — field must be absent or null.
    assert!(
        plan.get("database_config").is_none() || plan["database_config"].is_null(),
        "non-database action must not have database_config in plan"
    );
}

/// SECURITY: injecting a database_config into a stored plan that was
/// created without one breaks the plan hash. This prevents an attacker
/// with Redis access from turning a non-database approval into one that
/// carries statement definitions, since the hash was computed without
/// the field and will no longer verify.
#[tokio::test]
async fn injected_database_config_detected_via_plan_hash() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let mut payload = read_plan_from_redis(&approval_id).await;

    // Inject a database_config into a plan that didn't have one.
    payload["plan"]["database_config"] = serde_json::json!({
        "mode": "strict",
        "statements": [{
            "id": "evil_statement",
            "sql": "UPDATE users SET admin = true WHERE id = $1"
        }],
        "rules": {}
    });
    // Do NOT update plan_hash — this makes the tampering detectable.
    write_payload_to_redis(&approval_id, &payload).await;

    let (status, _) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "injected database_config must cause plan hash verification failure"
    );
}

/// SECURITY: verifies that `database_config` is included in the plan
/// hash computation. A plan with database_config present yields a
/// different hash than the same plan without it. This is a structural
/// check that complements the tampering detection test above.
#[tokio::test]
async fn database_config_changes_plan_hash() {
    let (app, _) = test_router();
    let agent = Agent::new();
    let (lease_jwt, _) = issue_lease(&app, &agent).await;

    let approval_id = create_pending(&app, &agent, &lease_jwt).await;

    let payload = read_plan_from_redis(&approval_id).await;
    let original_plan: latchgate_core::ApprovedExecutionPlan =
        serde_json::from_value(payload["plan"].clone()).unwrap();

    assert!(
        original_plan.verify_hash(),
        "original plan must verify after Redis roundtrip"
    );
    let original_hash = original_plan.plan_hash.clone();

    // Clone and add a database_config, then recompute hash.
    let mut modified_plan = original_plan.clone();
    modified_plan.database_config = Some(Arc::new(serde_json::json!({
        "mode": "hybrid",
        "statements": [{
            "id": "update_order",
            "sql": "UPDATE orders SET status = $1 WHERE id = $2"
        }],
        "rules": {
            "blocked_operations": ["ddl", "grant_revoke", "copy_io", "transaction_control", "multi_statement", "unknown"],
            "require_approval_for": ["delete", "update"],
            "allow_without_approval": ["select", "insert"],
            "allow_parameterized": ["select"],
            "require_where_for": ["update", "delete"],
            "max_rows_affected_without_approval": 1
        }
    })));
    modified_plan.finalize();

    assert_ne!(
        original_hash, modified_plan.plan_hash,
        "adding database_config must produce a different plan hash"
    );
    assert!(
        modified_plan.verify_hash(),
        "modified plan with new database_config must self-verify"
    );
}
