//! Pipeline audit context and write helpers.

use std::sync::Arc;

use latchgate_core::BudgetSnapshot;
use latchgate_ledger::{AuditEventBuilder, Decision, EventType, LedgerStore, Metrics};

use crate::state::AppState;

/// Rollback a budget debit if one was charged.
///
/// Shared implementation for the auto-allow pipeline (`pipeline.rs`),
/// shared execution tail (`execution.rs`), and human-approval path
/// (`approved_execution.rs`). Every post-debit error path that did NOT
/// dispatch the provider must call this to refund the operator's budget.
///
/// Records `budget_rollback` Redis duration metric. On failure, the
/// orphaned debit is recorded three ways so it cannot be lost: a
/// `budget_rollback_failure` metric, a `BudgetRollbackFailed` domain event,
/// and — authoritatively — a `BudgetRollbackFailed` entry in the
/// tamper-evident ledger keyed by session so the affected operator is
/// queryable for reconciliation. Rollback failure remains non-fatal to the
/// response path; the caller still returns the original pipeline error.
pub async fn rollback_budget_if_debited(
    state: &AppState,
    session_id: &str,
    budget_debited: bool,
    trace_id: &str,
    label: &str,
) {
    if !budget_debited {
        return;
    }
    let start = std::time::Instant::now();
    let result = state.enforcement.budget_manager.rollback(session_id).await;
    state
        .metrics
        .record_redis_duration("budget_rollback", start.elapsed());
    if let Err(e) = result {
        state.metrics.record_budget_rollback_failure();
        tracing::warn!(
            trace_id = %trace_id,
            label,
            error = %e,
            "budget rollback failed — orphaned debit requires reconciliation"
        );

        // Authoritative, queryable record of the orphaned debit. Written
        // before the domain event so the durable ledger entry exists even if
        // the in-process event bus drops the notification.
        let event = AuditEventBuilder::new(Arc::from(trace_id), EventType::BudgetRollbackFailed)
            .principal(Arc::from(""), Arc::from(session_id), Arc::from(""))
            .policy(
                Decision::Error,
                None,
                Some(format!("budget rollback failed at {label}: {e}")),
            )
            .flags(state.config.dev_mode(), false);
        write_audit(&state.ledger, &state.metrics, event).await;

        state.emit(latchgate_core::DomainEvent::BudgetRollbackFailed {
            session_id: std::sync::Arc::from(session_id),
            error: std::sync::Arc::from(e.to_string()),
            trace_id: std::sync::Arc::from(trace_id),
            label: std::sync::Arc::from(label),
        });
    }
}

/// Serialize a budget snapshot to JSON for audit events.
///
/// Returns `Value::Null` on serialization failure (should never happen for
/// well-formed snapshots, but fail-open here is acceptable — this is audit
/// metadata, not an authorization decision).
pub fn serialize_budgets(budgets: &BudgetSnapshot) -> serde_json::Value {
    serde_json::to_value(budgets).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "budget serialization failed for audit — using null");
        serde_json::Value::Null
    })
}

/// Persist an audit event via `spawn_blocking`.
///
/// Errors are logged but do not propagate — audit write failure must not
/// block the caller's response path. For protected actions, the shared
/// execution tail in `execution.rs` handles evidence durability separately
/// via its transactional receipt+audit write.
pub async fn write_audit(
    ledger: &Arc<LedgerStore>,
    metrics: &Arc<Metrics>,
    builder: AuditEventBuilder,
) {
    let ledger = Arc::clone(ledger);
    let metrics = Arc::clone(metrics);
    let mut event = builder.build();
    let trace_id = event.trace_id.clone();

    let result = tokio::task::spawn_blocking(move || ledger.write_event(&mut event)).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            metrics.record_audit_write_error();
            tracing::error!(
                trace_id = %trace_id,
                error = %e,
                "failed to write audit event"
            );
        }
        Err(e) => {
            metrics.record_audit_write_error();
            tracing::error!(
                trace_id = %trace_id,
                error = %e,
                "audit spawn_blocking task panicked"
            );
        }
    }
}

/// Accumulated audit context, enriched as the pipeline progresses.
///
/// Each step of `run_action_call` calls `set_*` methods as new context
/// becomes available. `event()` / `write()` produce an `AuditEventBuilder`
/// with all fields accumulated so far — stages not yet reached contribute
/// their default (empty string / `None`), matching the pre-refactor behavior.
///
/// This replaces 11 inline `AuditEventBuilder::new(...)` blocks in
/// `pipeline.rs` with a single enrichable context object.
pub struct PipelineAudit {
    trace_id: Arc<str>,
    dev_mode: bool,

    // Stage 1: after authentication
    principal: Arc<str>,
    session_id: Arc<str>,
    lease_jti: Arc<str>,
    owner: Option<Arc<str>>,

    // Stage 2: after registry lookup + trust verification
    //
    // `Arc<str>` instead of `String`: `event()` is called on every pipeline
    // termination and clones these fields into the AuditEventBuilder. With
    // `Arc<str>` each clone is a refcount bump (no heap allocation).
    action_id: Arc<str>,
    action_version: Option<Arc<str>>,
    action_digest: Arc<str>,
    trust_verdict: Arc<str>,
    risk_level: Option<Arc<str>>,

    // Stage 3: after request parsing + canonical hash
    request_hash: Arc<str>,
    schema_id: Option<Arc<str>>,

    // Stage 4: after budget snapshot
    budgets_before: Option<serde_json::Value>,

    // Stage 5 (optional): after pending approval creation
    approval_id: Option<Arc<str>>,
}

impl PipelineAudit {
    /// Create a new audit context. Only `trace_id` and `dev_mode` are known
    /// at pipeline entry — everything else is populated progressively.
    pub fn new(trace_id: Arc<str>, dev_mode: bool) -> Self {
        Self {
            trace_id,
            dev_mode,
            principal: Arc::from(""),
            session_id: Arc::from(""),
            lease_jti: Arc::from(""),
            owner: None,
            action_id: Arc::from(""),
            action_version: None,
            action_digest: Arc::from(""),
            trust_verdict: Arc::from(""),
            risk_level: None,
            request_hash: Arc::from(""),
            schema_id: None,
            budgets_before: None,
            approval_id: None,
        }
    }

    /// Construct from a pending approval with all stages pre-populated.
    ///
    /// Used by the human-approval enforcement path (`approved_execution.rs`)
    /// where the full context is available from the stored plan rather than
    /// being accumulated step by step.
    ///
    /// `trust_verdict` is the result of re-verifying the plan's digest
    /// against the live registry (e.g. `"digest_ok"`, `"mismatch"`).
    pub fn from_pending(
        pending: &latchgate_state::approvals::PendingApproval,
        trust_verdict: &str,
        dev_mode: bool,
    ) -> Self {
        Self {
            trace_id: pending.trace_id.clone(),
            dev_mode,
            principal: pending.auth_context.principal.clone(),
            session_id: pending.auth_context.session_id.clone(),
            lease_jti: pending.auth_context.lease_jti.clone(),
            owner: pending.auth_context.owner.clone(),
            action_id: pending.action_id.clone(),
            action_version: Some(pending.plan.action_version.clone()),
            action_digest: Arc::clone(&pending.plan.core.provider_module_digest),
            trust_verdict: Arc::from(trust_verdict),
            risk_level: Some(Arc::from(pending.plan.risk_level.as_str())),
            request_hash: pending.request_hash.clone(),
            schema_id: None,
            budgets_before: None,
            approval_id: Some(Arc::from(pending.approval_id.as_str())),
        }
    }

    /// Enrich with caller identity (after successful authentication).
    pub fn set_principal(
        &mut self,
        principal: Arc<str>,
        session_id: Arc<str>,
        lease_jti: Arc<str>,
        owner: Option<Arc<str>>,
    ) {
        self.principal = principal;
        self.session_id = session_id;
        self.lease_jti = lease_jti;
        self.owner = owner;
    }

    /// Enrich with action metadata (after registry lookup + trust check).
    pub fn set_action(
        &mut self,
        action_id: Arc<str>,
        action_version: Option<Arc<str>>,
        action_digest: Arc<str>,
        trust_verdict: Arc<str>,
    ) {
        self.action_id = action_id;
        self.action_version = action_version;
        self.action_digest = action_digest;
        self.trust_verdict = trust_verdict;
    }

    /// Enrich with action risk level (after registry lookup).
    pub fn set_risk_level(&mut self, level: latchgate_core::RiskLevel) {
        self.risk_level = Some(Arc::from(level.as_str()));
    }

    /// Enrich with approval identifier (after pending approval creation).
    pub fn set_approval_id(&mut self, id: &str) {
        self.approval_id = Some(Arc::from(id));
    }

    /// Enrich with request context (after schema validation + canonical hash).
    pub fn set_request(&mut self, request_hash: Arc<str>, schema_id: Option<Arc<str>>) {
        self.request_hash = request_hash;
        self.schema_id = schema_id;
    }

    /// Enrich with pre-execution budget snapshot.
    pub fn set_budgets_before(&mut self, snapshot: &BudgetSnapshot) {
        self.budgets_before = Some(serialize_budgets(snapshot));
    }

    /// Access the trace_id (needed by callers for non-audit purposes).
    #[cfg(test)]
    pub(crate) fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Build an `AuditEventBuilder` with all accumulated context.
    ///
    /// Fields not yet populated via `set_*` methods contribute their
    /// defaults (empty string / `None`), which matches the behavior of
    /// the inline builders that were replaced by this struct.
    pub fn event(
        &self,
        decision: Decision,
        policy_version: Option<Arc<str>>,
        reason: Option<String>,
    ) -> AuditEventBuilder {
        let mut builder = AuditEventBuilder::new(Arc::clone(&self.trace_id), EventType::ActionCall)
            .principal(
                Arc::clone(&self.principal),
                Arc::clone(&self.session_id),
                Arc::clone(&self.lease_jti),
            )
            .owner(self.owner.as_ref().map(Arc::clone))
            .action(
                Arc::clone(&self.action_id),
                self.action_version.clone(),
                Arc::clone(&self.action_digest),
                Arc::clone(&self.trust_verdict),
            )
            .request(Arc::clone(&self.request_hash), self.schema_id.clone())
            .policy(decision, policy_version, reason)
            .flags(self.dev_mode, false);

        if let Some(ref level) = self.risk_level {
            builder = builder.risk_level(Arc::clone(level));
        }

        if let Some(ref aid) = self.approval_id {
            builder = builder.approval_id(Arc::clone(aid));
        }

        if let Some(ref budgets) = self.budgets_before {
            builder = builder.budgets(Some(budgets.clone()), None);
        }

        builder
    }

    /// Build and write an audit event in one call.
    ///
    /// Convenience wrapper around `event()` + `write_audit()`. Use `event()`
    /// directly when you need to add extra fields to the builder before writing.
    pub async fn write(
        &self,
        ledger: &Arc<LedgerStore>,
        metrics: &Arc<Metrics>,
        decision: Decision,
        policy_version: Option<Arc<str>>,
        reason: Option<String>,
    ) {
        write_audit(
            ledger,
            metrics,
            self.event(decision, policy_version, reason),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latchgate_core::BudgetSnapshot;
    use latchgate_ledger::Decision;

    #[test]
    fn serialize_budgets_produces_valid_json() {
        let snap = BudgetSnapshot {
            calls_remaining: 42,
        };
        let val = serialize_budgets(&snap);
        assert_eq!(val["calls_remaining"], 42);
    }

    #[test]
    fn serialize_budgets_handles_zero() {
        let snap = BudgetSnapshot { calls_remaining: 0 };
        let val = serialize_budgets(&snap);
        assert_eq!(val["calls_remaining"], 0);
    }

    #[test]
    fn serialize_budgets_handles_max() {
        let snap = BudgetSnapshot {
            calls_remaining: i64::MAX,
        };
        let val = serialize_budgets(&snap);
        assert_eq!(val["calls_remaining"], i64::MAX);
    }

    #[test]
    fn new_audit_has_trace_id_and_dev_mode() {
        let audit = PipelineAudit::new(Arc::from("trace-001"), true);
        assert_eq!(audit.trace_id(), "trace-001");
        assert!(audit.dev_mode);
    }

    #[test]
    fn event_before_enrichment_builds_with_empty_defaults() {
        let audit = PipelineAudit::new(Arc::from("trace-empty"), false);
        let builder = audit.event(Decision::Deny, None, Some("early deny".into()));
        let event = builder.build();

        assert_eq!(&*event.trace_id, "trace-empty");
        assert_eq!(&*event.subject.principal, "");
        assert_eq!(&*event.action.action_id, "");
        assert_eq!(&*event.request.request_hash, "");
    }

    #[test]
    fn set_principal_enriches_identity_fields() {
        let mut audit = PipelineAudit::new(Arc::from("trace-auth"), false);
        audit.set_principal(
            Arc::from("agent:test"),
            Arc::from("sess-001"),
            Arc::from("jti-abc"),
            Some(Arc::from("alice@corp.com")),
        );

        let event = audit.event(Decision::Deny, None, None).build();
        assert_eq!(&*event.subject.principal, "agent:test");
        assert_eq!(&*event.subject.session_id, "sess-001");
        assert_eq!(&*event.subject.lease_jti, "jti-abc");
        assert_eq!(event.subject.owner.as_deref(), Some("alice@corp.com"));
    }

    #[test]
    fn set_action_enriches_action_fields() {
        let mut audit = PipelineAudit::new(Arc::from("trace-action"), false);
        audit.set_action(
            "http_fetch".into(),
            Some("1.0.0".into()),
            "sha256:abcd".into(),
            "digest_ok".into(),
        );
        audit.set_risk_level(latchgate_core::RiskLevel::Medium);

        let event = audit.event(Decision::Allow, None, None).build();
        assert_eq!(&*event.action.action_id, "http_fetch");
        assert_eq!(event.action.action_version.as_deref(), Some("1.0.0"));
        assert_eq!(&*event.action.action_digest, "sha256:abcd");
        assert_eq!(&*event.action.action_trust_verdict, "digest_ok");
        assert_eq!(event.action.risk_level.as_deref(), Some("medium"));
    }

    #[test]
    fn risk_level_none_when_not_set() {
        let audit = PipelineAudit::new(Arc::from("trace-no-risk"), false);
        let event = audit.event(Decision::Allow, None, None).build();
        assert!(
            event.action.risk_level.is_none(),
            "risk_level must be None when not set"
        );
    }

    #[test]
    fn set_request_enriches_request_fields() {
        let mut audit = PipelineAudit::new(Arc::from("trace-req"), false);
        audit.set_request("sha256:req123".into(), Some("schema-v1".into()));

        let event = audit.event(Decision::Allow, None, None).build();
        assert_eq!(&*event.request.request_hash, "sha256:req123");
        assert_eq!(
            event.request.request_schema_id.as_deref(),
            Some("schema-v1")
        );
    }

    #[test]
    fn set_budgets_before_populates_budgets() {
        let mut audit = PipelineAudit::new(Arc::from("trace-budget"), false);
        audit.set_budgets_before(&BudgetSnapshot {
            calls_remaining: 10,
        });

        let event = audit.event(Decision::Allow, None, None).build();
        assert!(
            event.budgets_before.is_some(),
            "budgets_before must be populated after set_budgets_before"
        );
    }

    #[test]
    fn full_enrichment_produces_complete_event() {
        let mut audit = PipelineAudit::new(Arc::from("trace-full"), true);
        audit.set_principal(
            Arc::from("agent:full"),
            Arc::from("sess-full"),
            Arc::from("jti-full"),
            None,
        );
        audit.set_action(
            "github_pr_create".into(),
            Some("2.0.0".into()),
            "sha256:full".into(),
            "digest_ok".into(),
        );
        audit.set_risk_level(latchgate_core::RiskLevel::High);
        audit.set_request("sha256:reqfull".into(), None);
        audit.set_budgets_before(&BudgetSnapshot { calls_remaining: 5 });

        let event = audit
            .event(
                Decision::Allow,
                Some("policy-v3".into()),
                Some("auto-allowed".into()),
            )
            .build();

        assert_eq!(&*event.trace_id, "trace-full");
        assert_eq!(&*event.subject.principal, "agent:full");
        assert_eq!(&*event.action.action_id, "github_pr_create");
        assert_eq!(event.action.risk_level.as_deref(), Some("high"));
        assert_eq!(&*event.request.request_hash, "sha256:reqfull");
        assert_eq!(event.policy.policy_version.as_deref(), Some("policy-v3"));
        assert_eq!(event.policy.deny_reason.as_deref(), Some("auto-allowed"));
        assert!(event.dev_mode);
    }

    #[test]
    fn event_policy_version_and_reason_are_passed_through() {
        let audit = PipelineAudit::new(Arc::from("trace-pv"), false);
        let event = audit
            .event(
                Decision::Deny,
                Some("v2.1.0".into()),
                Some("not in ACL".into()),
            )
            .build();

        assert_eq!(event.policy.policy_version.as_deref(), Some("v2.1.0"));
        assert_eq!(event.policy.deny_reason.as_deref(), Some("not in ACL"));
    }

    #[test]
    fn event_without_budgets_has_none() {
        let audit = PipelineAudit::new(Arc::from("trace-nobudget"), false);
        let event = audit.event(Decision::Allow, None, None).build();
        assert!(event.budgets_before.is_none());
    }

    #[test]
    fn owner_none_when_not_set() {
        let mut audit = PipelineAudit::new(Arc::from("trace-noowner"), false);
        audit.set_principal(Arc::from("agent:x"), Arc::from("s"), Arc::from("j"), None);
        let event = audit.event(Decision::Allow, None, None).build();
        assert!(event.subject.owner.is_none());
    }
}
