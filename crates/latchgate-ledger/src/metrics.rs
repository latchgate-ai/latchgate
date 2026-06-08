//! Prometheus metrics for LatchGate observability.
//!
//! All metrics are prefixed with `latchgate_` and served by `GET /metrics`
//! in OpenMetrics/Prometheus text exposition format.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct CallLabels {
    pub action: String,
    pub decision: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct ReasonLabels {
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct DecisionLabels {
    pub decision: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct ActionLabels {
    pub action: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct ProviderErrorLabels {
    pub action: String,
    pub error_type: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct DependencyLabels {
    pub operation: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// Prometheus metrics for the Gate pipeline.
///
/// Constructed once at startup, shared via `Arc<Metrics>` in `AppState`.
/// All counter/histogram operations are internally atomic.
pub struct Metrics {
    registry: Registry,

    calls_total: Family<CallLabels, Counter>,
    dpop_rejects_total: Family<ReasonLabels, Counter>,
    policy_decisions_total: Family<DecisionLabels, Counter>,
    budget_exhausted_total: Counter,
    budget_rollback_failures_total: Counter,
    provider_timeouts_total: Family<ActionLabels, Counter>,
    provider_errors_total: Family<ProviderErrorLabels, Counter>,
    action_duration_seconds: Family<ActionLabels, Histogram>,

    /// Audit write failures — the one place where failure does not mean DENY.
    audit_write_errors_total: Counter,

    /// Response schema validation failures (regardless of enforcement mode).
    response_schema_violations_total: Family<ActionLabels, Counter>,

    // --- Operational metrics ---
    /// Number of execution intents without matching receipts.
    unresolved_intents: Gauge,

    /// Age in seconds of the oldest pending approval.
    oldest_pending_approval_seconds: Gauge,

    /// Pending webhook outbox entries awaiting delivery.
    webhook_outbox_pending: Gauge,

    /// Ledger write duration (events + receipts + intents).
    ledger_write_duration_seconds: Histogram,

    /// OPA policy evaluation request duration.
    opa_request_duration_seconds: Family<DependencyLabels, Histogram>,

    /// Redis request duration (replay cache, budget manager).
    redis_request_duration_seconds: Family<DependencyLabels, Histogram>,

    /// Readyz degraded events by reason.
    readyz_degraded_total: Family<ReasonLabels, Counter>,

    /// Webhook delivery drops (async mode channel full).
    webhook_drops_total: Counter,

    /// Most recent second published by the coarse-clock ticker (Unix epoch).
    ///
    /// Advances once per second while the ticker is healthy. A value that
    /// stops advancing relative to scrape time indicates a stalled ticker,
    /// which degrades rate-limit refill — alert on it.
    coarse_clock_unix_seconds: Gauge,
}

/// Histogram buckets for action execution duration.
const DURATION_BUCKETS: [f64; 8] = [0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

/// Register a metric with the registry, returning the metric for struct storage.
///
/// Eliminates the three-site repetition (field, `registry.register`, struct
/// literal) that adding a new metric previously required. Each metric is now
/// a single line in `Metrics::new`.
macro_rules! register {
    ($registry:expr, $name:expr, $help:expr, $metric:expr) => {{
        let m = $metric;
        $registry.register($name, $help, m.clone());
        m
    }};
}

impl Metrics {
    /// Create and register all metrics. Called once at startup.
    pub fn new() -> Result<Self, MetricsError> {
        let mut registry = Registry::default();

        let calls_total = register!(
            registry,
            "latchgate_calls_total",
            "Total action calls",
            Family::<CallLabels, Counter>::default()
        );
        let dpop_rejects_total = register!(
            registry,
            "latchgate_dpop_rejects_total",
            "DPoP proof rejections",
            Family::<ReasonLabels, Counter>::default()
        );
        let policy_decisions_total = register!(
            registry,
            "latchgate_policy_decisions_total",
            "OPA policy decisions",
            Family::<DecisionLabels, Counter>::default()
        );
        let budget_exhausted_total = register!(
            registry,
            "latchgate_budget_exhausted_total",
            "Budget exhaustion events",
            Counter::default()
        );
        let budget_rollback_failures_total = register!(
            registry,
            "latchgate_budget_rollback_failures_total",
            "Budget rollback failures (orphaned debits requiring reconciliation)",
            Counter::default()
        );
        let provider_timeouts_total = register!(
            registry,
            "latchgate_provider_timeouts_total",
            "Provider execution timeouts",
            Family::<ActionLabels, Counter>::default()
        );
        let provider_errors_total = register!(
            registry,
            "latchgate_provider_errors_total",
            "Provider execution errors",
            Family::<ProviderErrorLabels, Counter>::default()
        );
        let action_duration_seconds = register!(
            registry,
            "latchgate_action_duration_seconds",
            "Tool execution duration in seconds",
            Family::<ActionLabels, Histogram>::new_with_constructor(|| Histogram::new(
                DURATION_BUCKETS.iter().copied()
            ))
        );
        let audit_write_errors_total = register!(
            registry,
            "latchgate_audit_write_errors_total",
            "Audit ledger write failures (events may be lost)",
            Counter::default()
        );
        let response_schema_violations_total = register!(
            registry,
            "latchgate_response_schema_violations_total",
            "Tool responses that failed schema validation",
            Family::<ActionLabels, Counter>::default()
        );
        let unresolved_intents = register!(
            registry,
            "latchgate_unresolved_intents",
            "Execution intents without matching receipts",
            Gauge::default()
        );
        let oldest_pending_approval_seconds = register!(
            registry,
            "latchgate_oldest_pending_approval_seconds",
            "Age of the oldest pending approval in seconds",
            Gauge::default()
        );
        let webhook_outbox_pending = register!(
            registry,
            "latchgate_webhook_outbox_pending",
            "Webhook outbox entries awaiting delivery",
            Gauge::default()
        );
        let ledger_write_duration_seconds = register!(
            registry,
            "latchgate_ledger_write_duration_seconds",
            "Ledger write duration (events, receipts, intents)",
            Histogram::new(DURATION_BUCKETS.iter().copied())
        );
        let opa_request_duration_seconds = register!(
            registry,
            "latchgate_opa_request_duration_seconds",
            "OPA policy evaluation request duration",
            Family::<DependencyLabels, Histogram>::new_with_constructor(|| Histogram::new(
                DURATION_BUCKETS.iter().copied()
            ))
        );
        let redis_request_duration_seconds = register!(
            registry,
            "latchgate_redis_request_duration_seconds",
            "Redis request duration (replay cache, budget manager)",
            Family::<DependencyLabels, Histogram>::new_with_constructor(|| Histogram::new(
                DURATION_BUCKETS.iter().copied()
            ))
        );
        let readyz_degraded_total = register!(
            registry,
            "latchgate_readyz_degraded_total",
            "Readyz degraded events by reason",
            Family::<ReasonLabels, Counter>::default()
        );
        let webhook_drops_total = register!(
            registry,
            "latchgate_webhook_drops_total",
            "Webhook events dropped due to full channel (async mode)",
            Counter::default()
        );
        let coarse_clock_unix_seconds = register!(registry, "latchgate_coarse_clock_unix_seconds", "Most recent second published by the coarse-clock ticker (stalls if it stops advancing)", Gauge::default());

        Ok(Self {
            registry,
            calls_total,
            dpop_rejects_total,
            policy_decisions_total,
            budget_exhausted_total,
            budget_rollback_failures_total,
            provider_timeouts_total,
            provider_errors_total,
            action_duration_seconds,
            audit_write_errors_total,
            response_schema_violations_total,
            unresolved_intents,
            oldest_pending_approval_seconds,
            webhook_outbox_pending,
            ledger_write_duration_seconds,
            opa_request_duration_seconds,
            redis_request_duration_seconds,
            readyz_degraded_total,
            webhook_drops_total,
            coarse_clock_unix_seconds,
        })
    }

    // -- Convenience methods --------------------------------------------------

    pub fn record_call(&self, action: &str, decision: &str) {
        self.calls_total
            .get_or_create(&CallLabels {
                action: action.to_owned(),
                decision: decision.to_owned(),
            })
            .inc();
    }

    pub fn record_duration(&self, action: &str, duration: std::time::Duration) {
        self.action_duration_seconds
            .get_or_create(&ActionLabels {
                action: action.to_owned(),
            })
            .observe(duration.as_secs_f64());
    }

    pub fn record_dpop_reject(&self, reason: &str) {
        self.dpop_rejects_total
            .get_or_create(&ReasonLabels {
                reason: reason.to_owned(),
            })
            .inc();
    }

    pub fn record_policy_decision(&self, decision: &str) {
        self.policy_decisions_total
            .get_or_create(&DecisionLabels {
                decision: decision.to_owned(),
            })
            .inc();
    }

    pub fn record_budget_exhausted(&self) {
        self.budget_exhausted_total.inc();
    }

    pub fn record_budget_rollback_failure(&self) {
        self.budget_rollback_failures_total.inc();
    }

    pub fn record_provider_timeout(&self, action: &str) {
        self.provider_timeouts_total
            .get_or_create(&ActionLabels {
                action: action.to_owned(),
            })
            .inc();
    }

    pub fn record_provider_error(&self, action: &str, error_type: &str) {
        self.provider_errors_total
            .get_or_create(&ProviderErrorLabels {
                action: action.to_owned(),
                error_type: error_type.to_owned(),
            })
            .inc();
    }

    pub fn record_audit_write_error(&self) {
        self.audit_write_errors_total.inc();
    }

    pub fn record_response_schema_violation(&self, action: &str) {
        self.response_schema_violations_total
            .get_or_create(&ActionLabels {
                action: action.to_owned(),
            })
            .inc();
    }

    // --- Operational metrics ---

    /// Set the current count of unresolved intents.
    pub fn set_unresolved_intents(&self, count: i64) {
        self.unresolved_intents.set(count);
    }

    /// Set the age of the oldest pending approval in seconds.
    pub fn set_oldest_pending_approval_seconds(&self, seconds: i64) {
        self.oldest_pending_approval_seconds.set(seconds);
    }

    /// Set the current webhook outbox pending count.
    pub fn set_webhook_outbox_pending(&self, count: i64) {
        self.webhook_outbox_pending.set(count);
    }

    /// Publish the most recent second seen by the coarse-clock ticker.
    pub fn set_coarse_clock_unix_seconds(&self, seconds: i64) {
        self.coarse_clock_unix_seconds.set(seconds);
    }

    /// Record a ledger write duration.
    pub fn record_ledger_write_duration(&self, duration: std::time::Duration) {
        self.ledger_write_duration_seconds
            .observe(duration.as_secs_f64());
    }

    /// Record an OPA request duration.
    ///
    /// `operation` distinguishes call types (e.g. `"evaluate"`, `"health"`).
    pub fn record_opa_duration(&self, operation: &str, duration: std::time::Duration) {
        self.opa_request_duration_seconds
            .get_or_create(&DependencyLabels {
                operation: operation.to_owned(),
            })
            .observe(duration.as_secs_f64());
    }

    /// Record a Redis request duration.
    ///
    /// `operation` distinguishes call types (e.g. `"replay_check"`,
    /// `"budget_debit"`, `"budget_init"`, `"budget_rollback"`).
    pub fn record_redis_duration(&self, operation: &str, duration: std::time::Duration) {
        self.redis_request_duration_seconds
            .get_or_create(&DependencyLabels {
                operation: operation.to_owned(),
            })
            .observe(duration.as_secs_f64());
    }

    /// Record a readyz degraded event.
    pub fn record_readyz_degraded(&self, reason: &str) {
        self.readyz_degraded_total
            .get_or_create(&ReasonLabels {
                reason: reason.to_string(),
            })
            .inc();
    }

    /// Record a webhook drop (async mode channel full).
    pub fn record_webhook_drop(&self) {
        self.webhook_drops_total.inc();
    }

    /// Encode all metrics in OpenMetrics text format.
    pub fn encode(&self) -> Result<String, MetricsError> {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).map_err(|e| MetricsError::Encoding(e.to_string()))?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_metrics() -> Metrics {
        Metrics::new().expect("metrics construction must succeed")
    }

    #[test]
    fn record_call_increments_counter() {
        let m = new_metrics();
        m.record_call("http_fetch", "allow");
        m.record_call("http_fetch", "allow");

        let val = m
            .calls_total
            .get_or_create(&CallLabels {
                action: "http_fetch".into(),
                decision: "allow".into(),
            })
            .get();
        assert_eq!(val, 2);
    }

    #[test]
    fn record_duration_populates_histogram() {
        let m = new_metrics();
        m.record_duration("http_fetch", std::time::Duration::from_millis(1500));

        let output = m.encode().unwrap();
        assert!(output.contains("latchgate_action_duration_seconds"));
        assert!(output.contains("http_fetch"));
    }

    #[test]
    fn different_labels_independent() {
        let m = new_metrics();
        m.record_call("action_a", "allow");
        m.record_call("action_a", "allow");
        m.record_call("action_b", "deny");

        let a = m
            .calls_total
            .get_or_create(&CallLabels {
                action: "action_a".into(),
                decision: "allow".into(),
            })
            .get();
        let b = m
            .calls_total
            .get_or_create(&CallLabels {
                action: "action_b".into(),
                decision: "deny".into(),
            })
            .get();
        assert_eq!(a, 2);
        assert_eq!(b, 1);
    }

    #[test]
    fn encode_produces_valid_output() {
        let m = new_metrics();
        m.record_call("http_fetch", "allow");

        let output = m.encode().expect("encode must succeed");
        assert!(output.contains("latchgate_calls_total"));
        assert!(output.contains("http_fetch"));
    }

    #[test]
    fn all_metrics_registered() {
        let m = new_metrics();

        m.record_call("_probe", "allow");
        m.record_dpop_reject("_probe");
        m.record_policy_decision("_probe");
        m.record_budget_exhausted();
        m.record_provider_timeout("_probe");
        m.record_provider_error("_probe", "_probe");
        m.record_duration("_probe", std::time::Duration::from_millis(1));
        m.record_audit_write_error();
        m.record_response_schema_violation("_probe");
        m.record_opa_duration("_probe", std::time::Duration::from_millis(1));
        m.record_redis_duration("_probe", std::time::Duration::from_millis(1));

        let output = m.encode().expect("encode must succeed");

        let expected = [
            "latchgate_calls_total",
            "latchgate_dpop_rejects_total",
            "latchgate_policy_decisions_total",
            "latchgate_budget_exhausted_total",
            "latchgate_provider_timeouts_total",
            "latchgate_provider_errors_total",
            "latchgate_action_duration_seconds",
            "latchgate_audit_write_errors_total",
            "latchgate_response_schema_violations_total",
            "latchgate_opa_request_duration_seconds",
            "latchgate_redis_request_duration_seconds",
        ];

        for name in &expected {
            assert!(
                output.contains(name),
                "missing metric in encode output: {name}"
            );
        }
    }

    #[test]
    fn dpop_reject_counter_works() {
        let m = new_metrics();
        m.record_dpop_reject("wrong_key");
        m.record_dpop_reject("expired");
        m.record_dpop_reject("wrong_key");

        let wk = m
            .dpop_rejects_total
            .get_or_create(&ReasonLabels {
                reason: "wrong_key".into(),
            })
            .get();
        let exp = m
            .dpop_rejects_total
            .get_or_create(&ReasonLabels {
                reason: "expired".into(),
            })
            .get();
        assert_eq!(wk, 2);
        assert_eq!(exp, 1);
    }

    #[test]
    fn provider_error_counter_works() {
        let m = new_metrics();
        m.record_provider_error("shell_exec", "oom");
        m.record_provider_timeout("shell_exec");

        let err = m
            .provider_errors_total
            .get_or_create(&ProviderErrorLabels {
                action: "shell_exec".into(),
                error_type: "oom".into(),
            })
            .get();
        let tout = m
            .provider_timeouts_total
            .get_or_create(&ActionLabels {
                action: "shell_exec".into(),
            })
            .get();
        assert_eq!(err, 1);
        assert_eq!(tout, 1);
    }

    #[test]
    fn audit_write_error_counter_works() {
        let m = new_metrics();
        m.record_audit_write_error();
        m.record_audit_write_error();
        assert_eq!(m.audit_write_errors_total.get(), 2);
    }

    #[test]
    fn histogram_buckets_in_output() {
        let m = new_metrics();
        m.record_duration("t", std::time::Duration::from_millis(50));
        m.record_duration("t", std::time::Duration::from_millis(300));
        m.record_duration("t", std::time::Duration::from_secs(15));

        let output = m.encode().unwrap();
        assert!(output.contains("0.1"));
        assert!(output.contains("0.25"));
        assert!(output.contains("30"));
    }
}
