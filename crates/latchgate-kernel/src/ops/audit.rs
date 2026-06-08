//! Audit event persistence and query — kernel facade.
//!
//! Provides `write_admin_event` to replace the 15-line boilerplate pattern
//! repeated across admin, domain, path, policy, and lease handlers. Also
//! exposes `query_events` so the API layer never imports `latchgate-ledger`.

use std::sync::Arc;

use latchgate_auth::OperatorAuthnMethod;
use latchgate_ledger::{AuditEventBuilder, Decision, EventType, LedgerStore, Metrics};

use crate::AppState;

/// Persist an admin audit event with operator identity.
///
/// Generates a fresh trace_id, builds the event, and writes it via
/// `spawn_blocking`. Errors are logged but never propagated — audit
/// write failure must not block the caller's response path.
pub async fn write_admin_event(
    state: &AppState,
    event_type: EventType,
    operator_id: &str,
    detail: Option<String>,
) {
    let trace_id = latchgate_core::TraceId::new().to_string();
    let builder = AuditEventBuilder::new(trace_id, event_type)
        .principal(operator_id, operator_id, "")
        .policy(Decision::Allow, None, detail);
    crate::pipeline_audit::write_audit(&state.ledger, &state.metrics, builder).await;
}

/// Persist an admin audit event with operator identity and custom decision.
pub async fn write_admin_event_with_decision(
    state: &AppState,
    event_type: EventType,
    operator_id: &str,
    decision: Decision,
    detail: Option<String>,
) {
    let trace_id = latchgate_core::TraceId::new().to_string();
    let builder = AuditEventBuilder::new(trace_id, event_type)
        .principal(operator_id, operator_id, "")
        .policy(decision, None, detail);
    crate::pipeline_audit::write_audit(&state.ledger, &state.metrics, builder).await;
}

/// Parameters for an approval denial audit event.
pub struct ApprovalDenyAudit {
    pub trace_id: String,
    pub principal: Arc<str>,
    pub session_id: Arc<str>,
    pub lease_jti: Arc<str>,
    pub action_id: Arc<str>,
    pub request_hash: Arc<str>,
    pub policy_version: Option<Arc<str>>,
    pub approval_id: String,
    pub reason: String,
    pub operator_id: Arc<str>,
    pub operator_authn_method: OperatorAuthnMethod,
    pub sender_binding: Option<Arc<str>>,
    pub proof_jti: Option<Arc<str>>,
    /// Action risk level from the pending approval's plan.
    pub risk_level: Option<String>,
}

/// Build and write a deny audit event for an approval denial.
///
/// Includes full operator provenance (authn method, sender binding, proof
/// jti) for forensic reconstruction.
pub async fn write_approval_deny_audit(state: &AppState, params: ApprovalDenyAudit) {
    let mut builder = AuditEventBuilder::new(params.trace_id, EventType::ActionCall)
        .principal(params.principal, params.session_id, params.lease_jti)
        .action(params.action_id, None, "", "")
        .request(params.request_hash, None)
        .policy(
            Decision::Deny,
            params.policy_version,
            Some(format!(
                "denied via {}: {}",
                params.approval_id, params.reason
            )),
        )
        .approved_by(params.operator_id)
        .approval_id(params.approval_id.as_str())
        .operator_authn_method(params.operator_authn_method.as_str())
        .operator_sender_binding(params.sender_binding.as_deref().unwrap_or(""))
        .operator_proof_jti(params.proof_jti.as_deref().unwrap_or(""))
        .flags(state.config.dev_mode(), false);
    if let Some(ref level) = params.risk_level {
        builder = builder.risk_level(level.as_str());
    }
    crate::pipeline_audit::write_audit(&state.ledger, &state.metrics, builder).await;
}

/// Build and write a lease-issued audit event with identity provenance.
pub async fn write_lease_audit(
    state: &AppState,
    principal: String,
    session_id: String,
    lease_jti: String,
    identity_method: String,
    owner: Option<String>,
) {
    let builder = AuditEventBuilder::new(
        latchgate_core::TraceId::new().to_string(),
        EventType::LeaseIssued,
    )
    // LeaseIssued is a successful lifecycle event. The builder defaults
    // decision to Decision::Error so any event reaching the ledger without
    // an explicit decision is conspicuous; a successful lease must record
    // Decision::Allow (there is no policy version for a lease lifecycle
    // event, hence None).
    .policy(Decision::Allow, None, None)
    .principal(principal, session_id, lease_jti)
    .identity_method(identity_method)
    .owner(owner.map(Arc::from));
    crate::pipeline_audit::write_audit(&state.ledger, &state.metrics, builder).await;
}

/// Query audit events from the evidence ledger.
///
/// Runs the SQLite query via `spawn_blocking` to avoid blocking the
/// async runtime. Returns the event list or an error string.
pub async fn query_events(
    state: &AppState,
    filter: latchgate_ledger::EventFilter,
) -> Result<Vec<latchgate_ledger::AuditEvent>, String> {
    let ledger = Arc::clone(&state.ledger);
    tokio::task::spawn_blocking(move || ledger.query_events(&filter))
        .await
        .map_err(|e| format!("audit query task panicked: {e}"))?
        .map_err(|e| format!("audit query failed: {e}"))
}

/// Verify the integrity of the ledger's hash-chain.
///
/// Walks all events in insertion order and checks that each `prev_hash`
/// matches the SHA-256 of the preceding event's JSON. Runs via
/// `spawn_blocking` — the full scan can be expensive for large ledgers.
pub async fn verify_chain(state: &AppState) -> Result<latchgate_ledger::ChainVerification, String> {
    let ledger = Arc::clone(&state.ledger);
    tokio::task::spawn_blocking(move || ledger.verify_chain())
        .await
        .map_err(|e| format!("verify_chain task panicked: {e}"))?
        .map_err(|e| format!("verify_chain failed: {e}"))
}

/// Write a pre-built audit event. Used by callers that need custom fields
/// beyond what the `write_admin_event` helpers provide.
pub async fn write_event(
    ledger: &Arc<LedgerStore>,
    metrics: &Arc<Metrics>,
    builder: AuditEventBuilder,
) {
    crate::pipeline_audit::write_audit(ledger, metrics, builder).await;
}
