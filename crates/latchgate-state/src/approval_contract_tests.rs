//! Shared contract tests for approval store backends.
//!
//! Every backend (InMemory, SQLite, Redis) must uphold the same state-machine
//! invariants. These functions encode those invariants once; each backend's
//! test module calls them with its own store constructor.
//!
//! # Security invariants tested
//!
//! - **One-shot execution**: at most one claim succeeds; all others are rejected.
//! - **Terminal state immutability**: completed approvals cannot be re-claimed.
//! - **Outcome marker crash safety**: a durable marker blocks re-claim even if
//!   `complete_*()` was never called (process crash after side effect).
//! - **Token-bound completion**: only the holder of the correct claim token can
//!   complete or write an outcome marker.
//! - **Data integrity**: plan hash, unresolved domains/paths, and auth context
//!   survive serialization roundtrips through every backend.

use std::time::Duration;

use crate::approval_types::*;
use crate::approvals::ApprovalStore;

// Helpers

/// Generate a fresh `PendingApproval` with a unique V7 UUID.
pub(crate) fn test_pending() -> PendingApproval {
    PendingApproval {
        approval_id: uuid::Uuid::now_v7().to_string(),
        trace_id: uuid::Uuid::now_v7().to_string().into(),
        action_id: "http_fetch".into(),
        auth_context: StoredAuthContext {
            principal: "agent:contract-test".into(),
            session_id: "sess-contract".into(),
            lease_jti: "jti-contract".into(),
            sender_thumbprint: "thumb-contract".into(),
            owner: Some("owner@test".into()),
        },
        request_hash: "sha256:deadbeef".into(),
        request_body: std::sync::Arc::new(serde_json::json!({"url": "https://example.com"})),
        policy_version: Some("v1.0.0".into()),
        created_at: chrono::Utc::now().to_rfc3339(),
        plan: latchgate_core::ApprovedExecutionPlan::test_default(),
        unresolved_domains: vec![],
        unresolved_paths: vec![],
    }
}

// Contract: create + get

/// Create a pending approval and retrieve it. The retrieved payload must
/// match the original.
pub(crate) async fn create_and_get(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let got = store.get_pending(&id).await.unwrap().unwrap();
    assert_eq!(got.approval_id, id);
    assert_eq!(&*got.action_id, "http_fetch");
    assert_eq!(&*got.auth_context.principal, "agent:contract-test");
    assert_eq!(got.auth_context.owner.as_deref(), Some("owner@test"));
}

/// Getting a nonexistent approval returns `None`, not an error.
pub(crate) async fn get_nonexistent_returns_none(store: &ApprovalStore) {
    let result = store.get_pending("nonexistent-contract-id").await.unwrap();
    assert!(result.is_none());
}

/// Creating a duplicate approval returns `AlreadyExists`.
pub(crate) async fn create_duplicate_returns_already_exists(store: &ApprovalStore) {
    let p = test_pending();
    store.create_pending(&p).await.unwrap();

    let err = store.create_pending(&p).await.unwrap_err();
    assert!(
        matches!(err, ApprovalError::AlreadyExists { .. }),
        "duplicate create must return AlreadyExists: {err:?}"
    );
}

// Contract: full lifecycle — approve, deny, fail

/// Full happy path: create → claim → complete_approved → get_status.
pub(crate) async fn full_approve_lifecycle(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "alice").await.unwrap();
    assert_eq!(claimed.pending.approval_id, id);
    assert!(!claimed.claim_token.is_empty());

    store
        .complete_approved(&id, &claimed.claim_token, "trace-approve", "rcpt-001")
        .await
        .unwrap();

    let status = store.get_status(&id).await.unwrap().unwrap();
    assert_eq!(status.state, ApprovalState::Approved);
    assert_eq!(status.claimed_by.as_deref(), Some("alice"));
    assert_eq!(status.receipt_id.as_deref(), Some("rcpt-001"));
}

/// Full deny path: create → claim → complete_denied → get_status.
pub(crate) async fn full_deny_lifecycle(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "bob").await.unwrap();
    store
        .complete_denied(&id, &claimed.claim_token, "trace-deny", "too_risky")
        .await
        .unwrap();

    let status = store.get_status(&id).await.unwrap().unwrap();
    assert_eq!(status.state, ApprovalState::Denied);
    assert_eq!(status.deny_reason.as_deref(), Some("too_risky"));
}

/// Full failure path: create → claim → complete_failed → get_status.
pub(crate) async fn full_failed_lifecycle(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "charlie").await.unwrap();
    store
        .complete_failed(&id, &claimed.claim_token, "trace-fail", "provider_timeout")
        .await
        .unwrap();

    let status = store.get_status(&id).await.unwrap().unwrap();
    assert_eq!(status.state, ApprovalState::Failed);
    assert_eq!(status.error_code.as_deref(), Some("provider_timeout"));
}

// Contract: one-shot execution (double-claim rejection)

/// SECURITY: a second claim on a pending approval must fail with
/// `AlreadyClaimed`. This is the one-shot execution invariant.
pub(crate) async fn double_claim_rejected(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    store.claim_pending(&id, "alice").await.unwrap();

    let err = store.claim_pending(&id, "bob").await.unwrap_err();
    assert!(
        matches!(err, ApprovalError::AlreadyClaimed { .. }),
        "second claim must return AlreadyClaimed: {err:?}"
    );
}

/// SECURITY: claiming an already-completed approval must fail with
/// `AlreadyCompleted`.
pub(crate) async fn terminal_state_blocks_reclaim(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "alice").await.unwrap();
    store
        .complete_approved(&id, &claimed.claim_token, "t", "r")
        .await
        .unwrap();

    let err = store.claim_pending(&id, "bob").await.unwrap_err();
    assert!(
        matches!(err, ApprovalError::AlreadyCompleted { .. }),
        "claim after terminal state must return AlreadyCompleted: {err:?}"
    );
}

// Contract: token-bound completion

/// SECURITY: completing with a wrong claim token must fail with
/// `TokenMismatch`.
pub(crate) async fn wrong_claim_token_rejected(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();
    store.claim_pending(&id, "alice").await.unwrap();

    let err = store
        .complete_approved(&id, "wrong-token", "trace", "rcpt")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApprovalError::TokenMismatch { .. }),
        "wrong token must be rejected: {err:?}"
    );
}

// Contract: expired claim re-claimable

/// A claim that has expired (process crash) must allow re-claim.
/// The old claim token must no longer be valid.
///
/// Requires a store with a short claim TTL (1 second).
pub(crate) async fn expired_claim_can_be_reclaimed(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let old_claim = store.claim_pending(&id, "alice").await.unwrap();

    // Wait for claim TTL (1s) to expire.
    // Uses wall-clock sleep because claim expiry is checked against
    // chrono::Utc::now(), not tokio's internal clock.
    std::thread::sleep(Duration::from_secs(3));

    // Re-claim must succeed.
    let new_claim = store.claim_pending(&id, "bob").await.unwrap();

    // Old token must be invalid.
    let err = store
        .complete_approved(&id, &old_claim.claim_token, "t", "r")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApprovalError::TokenMismatch { .. }),
        "old claim token must be rejected after re-claim: {err:?}"
    );

    // New token works.
    store
        .complete_approved(&id, &new_claim.claim_token, "t", "r")
        .await
        .unwrap();
}

// Contract: outcome marker crash safety

/// SECURITY (02): a durable outcome marker written after the side effect
/// must permanently block re-claim, even if `complete_*()` was never called
/// (simulates process crash between side-effect execution and terminal
/// state persistence).
///
/// Requires a store with a short claim TTL (1 second).
pub(crate) async fn outcome_marker_blocks_reclaim(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "alice").await.unwrap();
    store
        .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-crash")
        .await
        .unwrap();

    // Simulate crash: claim TTL expires, complete_approved never called.
    std::thread::sleep(Duration::from_secs(3));

    // Re-claim MUST be blocked by the durable outcome marker.
    let err = store.claim_pending(&id, "bob").await.unwrap_err();
    assert!(
        matches!(err, ApprovalError::AlreadyCompleted { .. }),
        "CRITICAL: re-claim after outcome marker must be impossible: {err:?}"
    );
}

/// Outcome marker is idempotent: writing the same marker twice succeeds.
pub(crate) async fn outcome_marker_is_idempotent(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "alice").await.unwrap();
    store
        .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
        .await
        .unwrap();
    store
        .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
        .await
        .unwrap();
}

/// Outcome marker with wrong claim token must be rejected.
pub(crate) async fn outcome_marker_rejects_wrong_token(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();
    let _claimed = store.claim_pending(&id, "alice").await.unwrap();

    let err = store
        .write_outcome_marker(&id, "wrong-token", "approved", "rcpt-001")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApprovalError::TokenMismatch { .. }),
        "wrong token must be rejected: {err:?}"
    );
}

/// Outcome marker on an unclaimed approval must be rejected.
pub(crate) async fn outcome_marker_rejects_unclaimed(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let err = store
        .write_outcome_marker(&id, "any-token", "approved", "rcpt-001")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApprovalError::NotClaimed { .. }),
        "unclaimed approval must reject outcome marker: {err:?}"
    );
}

/// `get_status` must synthesize the effective terminal state from the
/// outcome marker even if `complete_*()` was never called.
pub(crate) async fn get_status_synthesizes_from_outcome_marker(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "alice").await.unwrap();
    store
        .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
        .await
        .unwrap();

    let status = store.get_status(&id).await.unwrap().unwrap();
    assert_eq!(
        status.state,
        ApprovalState::Approved,
        "get_status must synthesize effective state from outcome marker"
    );
    assert_eq!(status.receipt_id.as_deref(), Some("rcpt-001"));
}

/// `complete_approved` must still succeed after an outcome marker is written
/// (normal happy path: marker → complete).
pub(crate) async fn complete_after_outcome_marker(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let claimed = store.claim_pending(&id, "alice").await.unwrap();
    store
        .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
        .await
        .unwrap();
    store
        .complete_approved(&id, &claimed.claim_token, "trace-1", "rcpt-001")
        .await
        .unwrap();

    let status = store.get_status(&id).await.unwrap().unwrap();
    assert_eq!(status.state, ApprovalState::Approved);
    assert_eq!(status.receipt_id.as_deref(), Some("rcpt-001"));
}

// Contract: list

/// `list_approvals` returns all created approvals.
pub(crate) async fn list_returns_all(store: &ApprovalStore) {
    for _ in 0..3 {
        store.create_pending(&test_pending()).await.unwrap();
    }

    let results = store.list_approvals(None, 100).await.unwrap();
    assert!(results.len() >= 3);
}

/// `list_approvals` filters by state.
pub(crate) async fn list_filters_by_state(store: &ApprovalStore) {
    let p_pending = test_pending();
    let p_done = test_pending();
    let done_id = p_done.approval_id.clone();
    store.create_pending(&p_pending).await.unwrap();
    store.create_pending(&p_done).await.unwrap();

    let claimed = store.claim_pending(&done_id, "alice").await.unwrap();
    store
        .complete_approved(&done_id, &claimed.claim_token, "t", "r")
        .await
        .unwrap();

    let pending = store
        .list_approvals(Some(ApprovalState::Pending), 100)
        .await
        .unwrap();
    assert!(
        pending.iter().all(|s| s.state == ApprovalState::Pending),
        "filter must return only Pending entries"
    );

    let approved = store
        .list_approvals(Some(ApprovalState::Approved), 100)
        .await
        .unwrap();
    assert!(
        approved.iter().all(|s| s.state == ApprovalState::Approved),
        "filter must return only Approved entries"
    );
    assert!(
        approved.iter().any(|s| s.approval_id == done_id),
        "approved list must contain the completed approval"
    );
}

/// `list_approvals` respects the limit parameter.
pub(crate) async fn list_respects_limit(store: &ApprovalStore) {
    for _ in 0..5 {
        store.create_pending(&test_pending()).await.unwrap();
    }

    let results = store.list_approvals(None, 2).await.unwrap();
    assert_eq!(results.len(), 2);
}

// Contract: data integrity (serialization roundtrip)

/// Plan hash must verify after a create → get roundtrip through the backend.
pub(crate) async fn plan_hash_survives_roundtrip(store: &ApprovalStore) {
    let p = test_pending();
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let got = store.get_pending(&id).await.unwrap().unwrap();
    assert!(
        got.plan.verify_hash(),
        "plan_hash must verify after serialization roundtrip"
    );
}

/// Unresolved domains survive the create → get roundtrip.
pub(crate) async fn unresolved_domains_survive_roundtrip(store: &ApprovalStore) {
    let mut p = test_pending();
    p.unresolved_domains = vec!["newsite.com".into(), "api.other.dev".into()];
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let got = store.get_pending(&id).await.unwrap().unwrap();
    assert_eq!(got.unresolved_domains, vec!["newsite.com", "api.other.dev"]);
}

/// Unresolved paths survive the create → get roundtrip.
pub(crate) async fn unresolved_paths_survive_roundtrip(store: &ApprovalStore) {
    let mut p = test_pending();
    p.unresolved_paths = vec!["/opt/data".into(), "/var/log/app.log".into()];
    let id = p.approval_id.clone();
    store.create_pending(&p).await.unwrap();

    let got = store.get_pending(&id).await.unwrap().unwrap();
    assert_eq!(got.unresolved_paths, vec!["/opt/data", "/var/log/app.log"]);
}
