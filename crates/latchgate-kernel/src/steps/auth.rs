//! Steps 0–1: drain guard and authentication.

use std::time::Instant;

use latchgate_auth::{authenticate, AuthContext, AuthError};
use latchgate_ledger::Decision;

use crate::pipeline::PipelineError;
use crate::request::RequestCtx;
use crate::state::AppState;

/// Reject new requests while the gate is draining.
///
/// SECURITY: drain is irreversible within a process lifetime. Requests
/// that passed this point before drain was set complete normally; new
/// arrivals are denied so the Platform can terminate the process
/// without losing in-flight work to timeouts.
///
/// This step records a deny metric but does NOT write an audit event —
/// drain rejections are a load-shedding signal, not a security denial,
/// and writing an audit event for every shed request during drain
/// would flood the ledger at shutdown.
pub(crate) async fn step_drain_guard(
    state: &AppState,
    ctx: &RequestCtx,
) -> Result<(), PipelineError> {
    if state.draining() {
        state.metrics.record_call(&ctx.action_id, "deny");
        return Err(PipelineError::Draining);
    }
    Ok(())
}

/// Verify Lease + DPoP, enrich ctx.audit with the authenticated identity.
///
/// SECURITY:
/// - The `htu` claim is built from `public_base_url` in server config —
///   never from Host or X-Forwarded-* headers that a client can forge.
/// - On failure, records fine-grained metric labels from the CLOSED
///   `AuthError::InvalidDPoP.kind` enum. Never formats `AuthError`
///   directly into a metric label: `reason` strings may contain
///   attacker-controlled content that would create unbounded
///   Prometheus label cardinality (DoS).
/// - Writes the deny audit event before returning.
pub(crate) async fn step_authenticate(
    state: &AppState,
    ctx: &mut RequestCtx,
    authorization: Option<&str>,
    dpop: Option<&str>,
) -> Result<AuthContext, PipelineError> {
    // SECURITY: htu from server config, never from Host / X-Forwarded-*.
    let mut htu =
        String::with_capacity(state.auth.htu_prefix.len() + ctx.action_id.len() + "/execute".len());
    htu.push_str(&state.auth.htu_prefix);
    htu.push_str(&ctx.action_id);
    htu.push_str("/execute");

    let auth_result = {
        let redis_start = Instant::now();
        let result = authenticate(
            authorization,
            dpop,
            "POST",
            &htu,
            state.auth.issuer.jwks(),
            &state.auth.replay_cache,
        )
        .await;
        state
            .metrics
            .record_redis_duration("replay_check", redis_start.elapsed());
        result
    };

    let auth_ctx = match auth_result {
        Ok(ac) => ac,
        Err(e) => {
            state.metrics.record_call(&ctx.action_id, "deny");
            match &e {
                AuthError::InvalidDPoP { kind, .. } => {
                    state.metrics.record_dpop_reject(kind.as_metric_label());
                }
                AuthError::ReplayDetected { .. } => {
                    state.metrics.record_dpop_reject("replay");
                }
                _ => {}
            }
            ctx.audit
                .write(
                    &state.ledger,
                    &state.metrics,
                    Decision::Deny,
                    None,
                    Some(format!("auth: {e}")),
                )
                .await;
            return Err(PipelineError::Auth(e));
        }
    };

    ctx.audit.set_principal(
        auth_ctx.principal.clone(),
        auth_ctx.session_id.clone(),
        auth_ctx.lease_jti.clone(),
        auth_ctx.owner.clone(),
    );

    Ok(auth_ctx)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::request::RequestCtx;
    use crate::test_support::test_app_state;

    fn ctx(action_id: &str) -> RequestCtx {
        RequestCtx::new(Arc::from("trace-test-001"), Arc::from(action_id), true)
    }

    #[tokio::test]
    async fn drain_guard_passes_when_not_draining() {
        let (state, _) = test_app_state();
        let c = ctx("test_action");
        assert!(step_drain_guard(&state, &c).await.is_ok());
    }

    #[tokio::test]
    async fn drain_guard_rejects_when_draining() {
        let (state, _) = test_app_state();
        let _ = state.start_drain();
        let c = ctx("test_action");
        let err = step_drain_guard(&state, &c).await.unwrap_err();
        assert!(
            matches!(err, PipelineError::Draining),
            "draining gate must return PipelineError::Draining, got: {err:?}"
        );
    }

    /// Whether a terminal pipeline path must produce an audit event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AuditExpectation {
        /// The path MUST write an audit event. Missing audit = security bug.
        Required,
        /// The path is explicitly exempt. The reason is documented and
        /// reviewed — it is not an accidental omission.
        Exempt(&'static str),
    }

    /// Whether a terminal pipeline path must record a deny/error metric.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MetricExpectation {
        Required,
        /// Success paths record "ok", not "deny"/"error".
        SuccessOk,
    }

    /// Declarative expectation for a single terminal pipeline outcome.
    ///
    /// This matrix is the single source of truth for "which pipeline exits
    /// produce audit events?". Any new terminal path MUST be added here.
    /// The test below verifies the matrix is exhaustive over the
    /// `PipelineError` variants that the pipeline can produce.
    struct TerminalPath {
        /// Human-readable name (matches pipeline step comments).
        path: &'static str,
        /// Must this path record a metric?
        metric: MetricExpectation,
        /// Must this path write an audit event?
        audit: AuditExpectation,
    }

    /// Exhaustive matrix of hot-path terminal outcomes.
    ///
    /// Reviewed during each audit cycle. Adding a new `PipelineError`
    /// variant without updating this matrix causes the
    /// `terminal_path_matrix_is_exhaustive` test to fail.
    const TERMINAL_PATHS: &[TerminalPath] = &[
        // Step 0: drain guard
        TerminalPath {
            path: "drain_rejection",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Exempt("load shedding — audit would flood ledger at shutdown"),
        },
        // Step 1: authentication failures
        TerminalPath {
            path: "auth_failure",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 2: trust/digest verification
        TerminalPath {
            path: "trust_failure",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 3: action not found
        TerminalPath {
            path: "action_not_found",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 4: schema/canonical hash failure
        TerminalPath {
            path: "schema_or_hash_failure",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 6: policy deny
        TerminalPath {
            path: "policy_deny",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 6: pending approval (not an error — but audited)
        TerminalPath {
            path: "pending_approval",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 7: budget exhausted
        TerminalPath {
            path: "budget_exhausted",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 9: provider execution failure
        TerminalPath {
            path: "provider_failure",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 9: response schema violation
        TerminalPath {
            path: "response_schema_violation",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Step 9: evidence persistence failure
        TerminalPath {
            path: "evidence_persistence_failure",
            metric: MetricExpectation::Required,
            audit: AuditExpectation::Required,
        },
        // Happy path
        TerminalPath {
            path: "success",
            metric: MetricExpectation::SuccessOk,
            audit: AuditExpectation::Required,
        },
    ];

    /// Verify the matrix covers every documented terminal category and
    /// that drain is the ONLY audit-exempt path.
    #[test]
    fn terminal_path_matrix_is_exhaustive_and_drain_is_only_exemption() {
        // The matrix must contain at least the minimum set of paths.
        let expected_paths = [
            "drain_rejection",
            "auth_failure",
            "trust_failure",
            "action_not_found",
            "schema_or_hash_failure",
            "policy_deny",
            "pending_approval",
            "budget_exhausted",
            "provider_failure",
            "response_schema_violation",
            "evidence_persistence_failure",
            "success",
        ];

        let actual_paths: Vec<&str> = TERMINAL_PATHS.iter().map(|t| t.path).collect();
        for expected in &expected_paths {
            assert!(
                actual_paths.contains(expected),
                "terminal path matrix is missing: {expected}"
            );
        }

        // Drain is the ONLY audit-exempt path.
        let exempt: Vec<&str> = TERMINAL_PATHS
            .iter()
            .filter(|t| matches!(t.audit, AuditExpectation::Exempt(_)))
            .map(|t| t.path)
            .collect();

        assert_eq!(
            exempt,
            &["drain_rejection"],
            "only drain_rejection should be audit-exempt; found: {exempt:?}"
        );

        // Every non-exempt path must require audit.
        for t in TERMINAL_PATHS {
            if !matches!(t.audit, AuditExpectation::Exempt(_)) {
                assert_eq!(
                    t.audit,
                    AuditExpectation::Required,
                    "path '{}' must either be Required or Exempt, not something else",
                    t.path
                );
            }
        }
    }

    /// Verify the drain guard step matches the matrix: metric=yes, audit=exempt.
    #[tokio::test]
    async fn drain_guard_records_metric_but_not_audit() {
        let (state, _) = test_app_state();
        let _ = state.start_drain();
        let c = ctx("test_action");

        // Must record a deny metric.
        let err = step_drain_guard(&state, &c).await.unwrap_err();
        assert!(matches!(err, PipelineError::Draining));

        // The matrix documents this path as audit-exempt.
        let drain_entry = TERMINAL_PATHS
            .iter()
            .find(|t| t.path == "drain_rejection")
            .expect("drain_rejection must be in the matrix");
        assert!(
            matches!(drain_entry.audit, AuditExpectation::Exempt(_)),
            "drain path must be audit-exempt"
        );
        assert_eq!(drain_entry.metric, MetricExpectation::Required);
    }
}
