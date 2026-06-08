//! Individual pipeline steps extracted from `run_action_call`.
//!
//! Each step is a `pub(crate) async fn` that takes `&AppState` and
//! `&mut RequestCtx` plus any step-specific inputs, and returns a typed
//! output struct on success or `PipelineError` on failure. The
//! orchestrator in `pipeline::run_action_call` is a thin driver that
//! threads outputs from one step into the next.
//!
//! # Security invariants (shared across all steps)
//!
//! 1. **Fail-closed.** Every error path writes an audit event via
//!    [`RequestCtx::audit`](crate::request::RequestCtx::audit)
//!    before returning. The terminal `PipelineError` is mapped to an
//!    HTTP status by `PipelineError::into_response` at the API boundary.
//! 2. **Audit-before-return.** A step that denies or errors MUST flush
//!    its audit record before returning. Losing an audit event would
//!    create an "unauditable denial" — a security hole.
//! 3. **Budget discipline.** Steps after `step_debit_budget` must not leak a debited call on error.
//! 4. **Metrics.** Every terminal path records exactly one call metric.
//! 5. **No panics.** Steps return `Result`; `unwrap` is forbidden.

mod auth;
mod evaluate;
mod execute;
mod precheck;
mod resolve;
mod types;
mod validate;

// Re-export all public-to-crate items so callers can continue to
// write `steps::step_drain_guard`, `steps::ResolveActionOutput`, etc.
pub(crate) use auth::{step_authenticate, step_drain_guard};
pub(crate) use evaluate::step_evaluate_policy;
pub(crate) use execute::{step_build_run_task, step_debit_budget, step_store_pending_approval};
pub(crate) use precheck::{step_domain_precheck, step_path_precheck};
pub(crate) use resolve::{step_resolve_action, step_verify_trust};
pub(crate) use types::*;
pub(crate) use validate::step_validate_and_hash;

use std::sync::Arc;

use latchgate_ledger::Decision;

use crate::pipeline::PipelineError;
use crate::request::RequestCtx;
use crate::state::AppState;

/// Record a deny or error metric, write the audit event, and return the
/// pipeline error for the caller to propagate.
///
/// This is the single implementation of the "metric + audit + deny" pattern
/// used across pipeline steps. Consolidating it here ensures every denial
/// path records metrics and writes audit consistently — a missed audit event
/// on a deny path would be a security gap ("unauditable denial").
///
/// Steps with additional side effects (DPoP sub-metrics, webhook emission)
/// perform those separately and call this for the common metric+audit part.
pub(super) async fn deny_and_audit(
    state: &AppState,
    ctx: &mut RequestCtx,
    decision: Decision,
    metric_label: &str,
    policy_version: Option<Arc<str>>,
    reason: String,
    err: PipelineError,
) -> PipelineError {
    state.metrics.record_call(&ctx.action_id, metric_label);
    ctx.audit
        .write(
            &state.ledger,
            &state.metrics,
            decision,
            policy_version,
            Some(reason),
        )
        .await;
    err
}
