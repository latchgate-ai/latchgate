//! Regression guard for the approval-path budget-rollback invariant.
//!
//! `prepare_approved_execution` debits the session budget in step 7 and
//! then builds the signed grant, RunTask, and `AuthorizedExecution`.
//! Every error after the debit and before a successful return MUST
//! refund the debited call — otherwise the session silently loses one
//! credit without any execution, and the caller's one-shot authorisation
//! is effectively destroyed rather than consumed.
//!
//! Today the build steps between debit and return are structurally
//! infallible, so the rollback branch is unreachable through ordinary
//! configuration. The guard exists to keep a future edit (a new
//! validation, an added async call, anything introducing a `?`) from
//! silently regressing the invariant. This test uses the
//! `AppState::arm_fault_after_budget_debit` fault-injection API to force
//! the synthetic failure in exactly that position and asserts, through
//! the real HTTP + Redis + OPA surface, that the debited call is
//! restored to the session budget.

use axum::http::StatusCode;
use latchgate_state::BudgetManager;

use crate::harness::{
    action_url, post_json, post_json_operator, post_with_auth, test_redis_url,
    test_router_with_probe, Agent, PROBE_APPROVAL_ACTION_ID,
};

/// Call allowance for the probe lease. Must be ≥ 2 so an unintended
/// debit would be visible in the snapshot and a second call from the
/// session would still be possible after the rollback (proving the
/// credit was truly restored, not consumed-and-restored-via-some-other-path).
const PROBE_BUDGET_CALLS: u64 = 5;

async fn issue_probe_lease(app: &axum::Router, agent: &Agent) -> (String, String) {
    let body = serde_json::json!({
        "dpop_jwk": agent.jwk_json(),
        "scopes": ["tools:call"],
        "budgets": {
            "max_calls": PROBE_BUDGET_CALLS,
        },
    });
    let (status, json) = post_json(app, "/v1/leases", &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "probe lease issuance failed: {json}"
    );
    let jwt = json["lease_jwt"].as_str().unwrap().to_string();
    let sid = json["session_id"].as_str().unwrap().to_string();
    (jwt, sid)
}

/// SECURITY: when `prepare_approved_execution` fails after debiting the
/// budget and before returning a successful `AuthorizedExecution`, the
/// debited call MUST be refunded. Silently losing the credit would
/// destroy the caller's one-shot authorisation without producing any
/// execution — a policy-invariant violation in the opposite direction
/// from the post-dispatch evidence-failure case (which must NOT refund
/// because the side effect is already out).
#[tokio::test]
async fn approval_path_rolls_back_budget_on_post_debit_failure() {
    let (app, _ledger, state) = test_router_with_probe();
    let agent = Agent::new();

    let (lease_jwt, session_id) = issue_probe_lease(&app, &agent).await;

    let budget_probe =
        BudgetManager::new(&test_redis_url()).expect("budget manager connects to test redis");
    let before = budget_probe
        .get_snapshot(&session_id)
        .await
        .expect("snapshot before pending");
    assert_eq!(
        before.calls_remaining, PROBE_BUDGET_CALLS as i64,
        "lease issuance must set the initial call allowance: {before:?}"
    );

    // -- Step 1: pending creation. High-risk action => 202 pending.
    //    No budget debit on this path; the debit happens only after the
    //    operator claims + approves.
    let htu_exec = action_url(PROBE_APPROVAL_ACTION_ID);
    let proof_exec = agent.dpop_proof("POST", &htu_exec, &lease_jwt);
    let (status_exec, body_exec) = post_with_auth(
        &app,
        &format!("/v1/actions/{PROBE_APPROVAL_ACTION_ID}/execute"),
        &lease_jwt,
        &proof_exec,
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status_exec,
        StatusCode::ACCEPTED,
        "high-risk action must return 202 pending, got body: {body_exec}"
    );
    let approval_id = body_exec["approval_id"]
        .as_str()
        .expect("202 response must carry approval_id")
        .to_string();

    // Sanity: pending creation did not touch the budget.
    let after_pending = budget_probe
        .get_snapshot(&session_id)
        .await
        .expect("snapshot after pending");
    assert_eq!(
        after_pending.calls_remaining, before.calls_remaining,
        "pending creation must not debit the budget \
         (before={before:?}, after_pending={after_pending:?})"
    );

    // -- Step 2: arm the one-shot fault on this test's AppState. The next
    //    approval flow debits the budget in step 7, then the synthetic
    //    failure fires at the head of the build block, forcing the rollback
    //    branch. Instance-scoped so parallel tests cannot interfere.
    state.arm_fault_after_budget_debit();

    // -- Step 3: approve. The approval handler must surface the injected
    //    Internal failure as 500.
    let (status_approve, body_approve) = post_json_operator(
        &app,
        &format!("/v1/approvals/{approval_id}/approve"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status_approve,
        StatusCode::INTERNAL_SERVER_ERROR,
        "fault-injected approval must surface as 500, got body: {body_approve}"
    );

    // -- Property 1: the debited call was refunded.
    let after_approval = budget_probe
        .get_snapshot(&session_id)
        .await
        .expect("snapshot after approval");
    assert_eq!(
        after_approval.calls_remaining, before.calls_remaining,
        "post-debit failure must refund the call — regression to a missing \
         rollback branch would leave the session short one credit with no \
         matching execution. before={before:?}, after_approval={after_approval:?}"
    );
}
