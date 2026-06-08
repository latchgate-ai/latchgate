//! Shared mutable state threaded through the request pipeline.

use std::sync::Arc;
use std::time::Instant;

use crate::pipeline_audit::PipelineAudit;

/// Shared mutable state threaded through `run_action_call`.
///
/// Constructed at pipeline entry, passed by `&mut` to every step that
/// needs to read immutable fields or mutate the audit/budget state.
pub(crate) struct RequestCtx {
    /// Request-scoped trace ID. Immutable after construction.
    pub(crate) trace_id: Arc<str>,

    /// Action identifier from the request path. Immutable after construction.
    pub(crate) action_id: Arc<str>,

    /// Wall-clock start of this pipeline invocation. Drives the
    /// `pipeline_duration_ms` metric recorded by `execution::*`.
    pub(crate) pipeline_start: Instant,

    /// Progressive audit event builder. Steps enrich it via
    /// `ctx.audit.with_auth_context(...)`, `with_action(...)`, etc.,
    /// and the terminal error/success paths flush it via
    /// [`crate::pipeline_audit::write_audit`].
    ///
    /// SECURITY: this is the authoritative audit state for the
    /// request. No step may write a separate audit event; all audit
    /// records originate here.
    pub(crate) audit: PipelineAudit,

    /// Whether the per-session budget has been debited for this
    /// request. Set to `true` exactly once after a successful
    /// `budget_manager.get_and_debit(...)`; consulted on every error
    /// path to decide whether a rollback is owed.
    ///
    /// SECURITY: the "debit with no matching execution or rollback"
    /// failure mode is a budget leak — the operator loses a credit
    /// with no side effect to show for it. Every `?`-propagated error
    /// that follows a debit MUST check this flag and issue a
    /// rollback (or record an audit decision that explicitly
    /// acknowledges the leak, as in evidence-persistence failure).
    pub(crate) budget_debited: bool,
}

impl RequestCtx {
    /// Construct a fresh context at pipeline entry.
    ///
    /// Only `trace_id` and `action_id` are known here; everything else
    /// starts in its "nothing has happened yet" state: `budget_debited = false`
    /// and a freshly initialised [`PipelineAudit`]
    /// with no enrichment yet applied.
    ///
    /// `dev_mode` is passed through to `PipelineAudit` (where it affects
    /// how the final audit record is formatted) but is NOT cached on the
    /// context — steps that need it read `state.config.dev_mode` directly
    /// at their call site, keeping the context minimal.
    pub(crate) fn new(trace_id: Arc<str>, action_id: Arc<str>, dev_mode: bool) -> Self {
        let audit = PipelineAudit::new(Arc::clone(&trace_id), dev_mode);
        Self {
            trace_id,
            action_id,
            pipeline_start: Instant::now(),
            audit,
            budget_debited: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SECURITY: a freshly-constructed context MUST have `budget_debited = false`.
    /// Any non-zero initial state would let a later
    /// rollback decrement budget that was never debited (financial bug) or
    /// skip a rollback that IS owed (budget leak).
    #[test]
    fn new_context_has_no_debit_state() {
        let ctx = RequestCtx::new(Arc::from("t-1"), Arc::from("act"), false);
        assert!(
            !ctx.budget_debited,
            "new context must not claim a debit has happened"
        );
    }

    /// `pipeline_start` MUST be captured at construction. Using a later
    /// timestamp would under-report request duration in metrics.
    #[test]
    fn pipeline_start_is_captured_at_construction() {
        let before = Instant::now();
        let ctx = RequestCtx::new(Arc::from("t"), Arc::from("a"), false);
        let after = Instant::now();
        assert!(
            ctx.pipeline_start >= before && ctx.pipeline_start <= after,
            "pipeline_start must be captured during new()"
        );
    }

    /// `trace_id` and `action_id` survive construction unchanged — they are
    /// the correlation keys for logs, audit events, and metrics. Any mangling
    /// would break operator traceability.
    #[test]
    fn identifiers_survive_construction() {
        let ctx = RequestCtx::new(Arc::from("trace-abc-123"), Arc::from("send_email"), false);
        assert_eq!(&*ctx.trace_id, "trace-abc-123");
        assert_eq!(&*ctx.action_id, "send_email");
    }

    /// log spans and the RunTask are O(1) refcount bumps, not heap allocs.
    /// Regression guard: changing to `String` would silently tank hot-path
    /// throughput. Strong_count on the original confirms shared ownership.
    #[test]
    fn trace_id_clone_shares_allocation() {
        let original: Arc<str> = Arc::from("trace-1");
        let ctx = RequestCtx::new(Arc::clone(&original), Arc::from("a"), false);
        // 3 refs: `original` + `ctx.trace_id` + `ctx.audit.trace_id`.
        assert_eq!(Arc::strong_count(&original), 3);
        let _cloned = Arc::clone(&ctx.trace_id);
        // 4 refs: no new allocation happened.
        assert_eq!(Arc::strong_count(&original), 4);
    }

    /// Mutating `budget_debited` works as expected. This field is the
    /// authoritative rollback-owed flag; the orchestrator reads it from
    /// `ctx` after `step_debit_budget`.
    #[test]
    fn budget_debited_flag_is_mutable() {
        let mut ctx = RequestCtx::new(Arc::from("t"), Arc::from("a"), false);
        assert!(!ctx.budget_debited);
        ctx.budget_debited = true;
        assert!(ctx.budget_debited);
    }
}
