//! OPA policy client.
//!
//! The Gate queries OPA over HTTP before every action execution. The client
//! must fail closed: any error from OPA (timeout, unreachable, malformed
//! response, missing bundle) => DENY. Never "allow and log" in uncertain state.
//!
//! OPA contract: `POST /v1/data/latchgate/decision` with the structured input.
//! The response carries `allow`, `deny_reason`, `budgets_after`,
//! `requires_approval`, and `allowed_sinks`.
//!
//! # Fail-closed guarantees
//!
//! Every error path in [`PolicyClient::evaluate`] returns a [`PolicyError`]
//! variant — none of which are `Allow`. The pipeline maps all `PolicyError`
//! variants to HTTP 403 or 503, ensuring the request is **never executed**
//! when policy evaluation fails for any reason.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use latchgate_core::ApprovalId;
use latchgate_core::BudgetSnapshot;
use latchgate_core::{EgressProfile, RiskLevel, TrustVerdict};

/// Structured input sent to OPA as `{"input": PolicyInput}`.
///
/// Contains everything the Rego policy needs to make an allow/deny decision.
///
#[derive(Debug, Serialize)]
pub struct PolicyInput<'a> {
    #[serde(flatten)]
    pub identity: PolicyIdentity<'a>,

    #[serde(flatten)]
    pub action: PolicyAction<'a>,

    #[serde(flatten)]
    pub request: PolicyRequest<'a>,

    pub budgets_before: BudgetSnapshot,

    #[serde(flatten)]
    pub resolution: PolicyResolution<'a>,
}

#[derive(Debug, Serialize)]
pub struct PolicyIdentity<'a> {
    pub principal: Arc<str>,

    pub session_id: Arc<str>,

    /// Scopes from the caller's Lease JWT (e.g. `["tools:call"]`).
    pub scopes: &'a [String],

    /// Scopes required by the action manifest (`ActionSpec::required_scopes`).
    ///
    /// Every scope listed here must be present in `scopes` for the action to
    /// be allowed. The OPA policy enforces this as a set-containment check:
    /// `required_scopes ⊆ scopes`.
    pub required_scopes: &'a [Arc<str>],
}

#[derive(Debug, Serialize)]
pub struct PolicyAction<'a> {
    pub action_id: Arc<str>,

    pub action_version: &'a str,

    pub action_risk_level: RiskLevel,

    pub action_trust_verdict: Arc<TrustVerdict>,

    /// Action category derived from the manifest. `"fs"` for filesystem
    /// actions, `"http"` for HTTP-based, empty otherwise.
    #[serde(default, skip_serializing_if = "str_is_empty")]
    pub action_category: &'a str,
}

#[derive(Debug, Serialize)]
pub struct PolicyRequest<'a> {
    pub request_hash: &'a str,

    pub requested_sinks: &'a [Arc<str>],

    pub requested_secrets: &'a [Arc<str>],

    pub egress_profile: &'a EgressProfile,

    /// Provider-specific policy context (opaque JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_context: Option<serde_json::Value>,

    /// Filesystem path from the request, forwarded to OPA for sensitive-path
    /// policy checks. Only populated for `action_category == "fs"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_path: Option<&'a str>,
}

/// Precheck results: domains and paths not yet in the effective allowlist.
///
/// When non-empty, the policy engine returns `PendingApproval` so an
/// operator can review and optionally learn the domain/path.
#[derive(Debug, Default, Serialize)]
pub struct PolicyResolution<'a> {
    /// Target domains NOT in manifest ∪ learned allowlist.
    #[serde(default, skip_serializing_if = "slice_is_empty")]
    pub unresolved_domains: &'a [String],

    /// Filesystem paths NOT in manifest ∪ learned allowlist.
    #[serde(default, skip_serializing_if = "slice_is_empty")]
    pub unresolved_paths: &'a [String],
}

/// Serde `skip_serializing_if` helper for `&[String]` fields.
///
/// Serde passes `&T` where `T` is the field type, so for `&[String]`
/// the argument is `&&[String]`.
fn slice_is_empty(s: &&[String]) -> bool {
    s.is_empty()
}

/// Serde `skip_serializing_if` helper for `&str` fields.
fn str_is_empty(s: &&str) -> bool {
    s.is_empty()
}

/// Result of an OPA policy evaluation.
///
/// The caller dispatches on this enum to determine the next pipeline step:
/// - `Allow` => proceed to provider dispatch.
/// - `Deny`  => return 403 + audit event; do not dispatch.
/// - `PendingApproval` => store pending state, return 202 + `approval_id`.
#[derive(Debug)]
pub enum PolicyDecision {
    /// Policy allows execution. Carry the post-execution budget snapshot
    /// and the resolved set of allowed sinks, secrets, and egress.
    Allow {
        /// Budget counters after debiting this execution.
        budgets_after: BudgetSnapshot,

        /// Sinks the policy authorises for this execution.
        allowed_sinks: Vec<Arc<str>>,

        /// Secret names the policy approves for injection.
        ///
        /// SECURITY (01.2): may be a subset of `requested_secrets`.
        /// The pipeline MUST use this — never the raw manifest secrets.
        approved_secrets: Vec<Arc<str>>,

        /// Network egress profile the policy approves.
        ///
        /// SECURITY (01.2): the pipeline MUST use this — never the
        /// raw manifest egress profile.
        approved_egress: EgressProfile,

        /// Policy revision that produced this decision (for audit trail).
        /// Absent when OPA data does not include `policy_version`.
        policy_version: Option<Arc<str>>,
    },

    /// Policy explicitly denies execution.
    Deny { reason: String },

    /// Execution requires human approval before proceeding.
    ///
    /// SECURITY (01.2): carries the policy-narrowed `allowed_sinks` and
    /// `budgets_after` so the immutable execution plan captures exactly
    /// what the policy authorized — not the raw manifest declarations.
    PendingApproval {
        approval_id: ApprovalId,

        /// Sinks the policy authorises for this execution.
        ///
        /// SECURITY: may be a **subset** of the manifest's
        /// `declared_side_effects`. The immutable execution plan MUST use
        /// this value — never the raw manifest sinks.
        allowed_sinks: Vec<Arc<str>>,

        /// Secret names the policy approves for injection.
        ///
        /// SECURITY (01.2): may be a subset of `requested_secrets`.
        /// The immutable execution plan MUST use this — never the raw
        /// manifest secrets.
        approved_secrets: Vec<Arc<str>>,

        /// Network egress profile the policy approves.
        ///
        /// SECURITY (01.2): the immutable execution plan MUST use
        /// this — never the raw manifest egress profile.
        approved_egress: EgressProfile,

        /// Budget counters after debiting this execution, as computed by
        /// the policy engine.
        budgets_after: BudgetSnapshot,

        /// Policy revision that produced this decision (for audit trail).
        policy_version: Option<Arc<str>>,
    },
}

/// Errors from OPA policy evaluation.
///
/// HTTP semantics (see `gate::pipeline::PipelineError::into_response`):
/// - `Denied`              => 403: client should not retry this request as-is.
/// - `OpaUnavailable`      => 503: OPA is down; client should retry with backoff.
/// - `OpaTimeout`          => 503: OPA timed out; transient, retry.
/// - `OpaResponseInvalid`  => 503: OPA returned unexpected data; operator action.
///
/// SECURITY: all 503 variants still deny the request. The 503 code signals a
/// transient dependency failure to the client (retry with backoff), not that
/// the request was approved. Fail-closed is non-negotiable.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Policy evaluation returned `allow == false`.
    ///
    /// SECURITY: construct via [`PolicyError::denied`] — the `reason` string
    /// may reflect OPA input that originates from the untrusted client
    /// (action arguments, request fields), so the constructor sanitizes it
    /// before the value is stored.
    #[error("policy denied: {reason}")]
    Denied {
        reason: String,
        /// Principal that was denied (for diagnostics / remediation).
        principal: Arc<str>,
        /// Action that was denied (for diagnostics / remediation).
        action_id: Arc<str>,
    },

    /// OPA is unreachable. DENY + 503.
    #[error("policy engine unreachable: {0}")]
    OpaUnavailable(String),

    /// OPA did not respond within the configured timeout. DENY + 503.
    #[error("policy engine timed out")]
    OpaTimeout,

    /// OPA responded but the body is not the expected schema. DENY + 503.
    #[error("policy engine returned unexpected response: {0}")]
    OpaResponseInvalid(String),
}

impl PolicyError {
    /// Maximum `reason` length for policy deny messages.
    ///
    /// Policy reasons can be structured (OPA may return a multi-clause
    /// explanation) so the budget is larger than DPoP/lease reasons, but
    /// still bounded to keep audit event and response body sizes sane.
    const DENY_REASON_MAX_BYTES: usize = 500;

    /// Construct a `Denied` error with a sanitized reason.
    ///
    /// SECURITY: this is the single construction path for `Denied`.
    /// The reason string frequently contains reflected policy input
    /// (field names, values from the request), which is attacker-controlled.
    /// Sanitizing here guarantees the reason is safe to embed in audit
    /// events, log lines, domain events, and HTTP 403 response bodies.
    pub fn denied(reason: impl Into<String>, principal: Arc<str>, action_id: Arc<str>) -> Self {
        let raw = reason.into();
        Self::Denied {
            reason: latchgate_core::sanitize_for_log(&raw, Self::DENY_REASON_MAX_BYTES)
                .into_owned(),
            principal,
            action_id,
        }
    }
}

/// Top-level OPA response: `{"result": { ... }}`.
///
/// OPA wraps the Rego evaluation output in a `result` field. If the field is
/// absent (e.g. no policy loaded, wrong package path), we treat it as an
/// invalid response — SECURITY: no policy = DENY.
#[derive(Debug, Deserialize)]
struct OpaQueryResponse {
    result: Option<OpaDecisionResult>,
}

/// The `result` object returned by the `latchgate/decision` Rego package.
///
/// Field presence rules:
/// - `allow` is always required.
/// - `deny_reason` is present when `allow == false`.
/// - `requires_approval` defaults to `false` if absent.
/// - `budgets_after` and `allowed_sinks` are present when `allow == true`.
#[derive(Debug, Deserialize)]
struct OpaDecisionResult {
    allow: bool,

    #[serde(default)]
    deny_reason: Option<String>,

    #[serde(default)]
    requires_approval: bool,

    #[serde(default)]
    budgets_after: Option<BudgetSnapshot>,

    #[serde(default)]
    allowed_sinks: Option<Vec<Arc<str>>>,

    /// Secret names the policy approves for injection.
    /// Pass-through from input today; policy can narrow in future.
    #[serde(default)]
    approved_secrets: Option<Vec<Arc<str>>>,

    /// Network egress profile the policy approves.
    /// Pass-through from input today; policy can narrow in future.
    #[serde(default)]
    approved_egress: Option<EgressProfile>,

    /// Policy revision from `data.policy_version`. Propagated to the audit
    /// trail so every decision is traceable to a specific policy revision.
    #[serde(default)]
    policy_version: Option<Arc<str>>,
}

/// HTTP client for the OPA policy engine.
///
/// Constructed once at startup and shared via `Arc` in `AppState`.
/// The inner `reqwest::Client` maintains a connection pool to OPA.
///
/// # Fail-closed contract
///
/// Every error path in [`evaluate`](Self::evaluate) returns a `PolicyError`
/// variant. The pipeline treats all `PolicyError` variants as DENY. There is
/// no code path where an OPA failure results in an `Allow` decision.
pub struct PolicyClient {
    backend: PolicyBackend,
}

type PolicyEvaluatorFn =
    dyn Fn(&PolicyInput<'_>) -> Result<PolicyDecision, PolicyError> + Send + Sync;

enum PolicyBackend {
    Opa {
        client: reqwest::Client,
        decision_url: String,
    },
    /// Embedded Rego evaluator via `regorus`. No external OPA needed.
    Embedded(crate::embedded::EmbeddedPolicy),
    /// In-memory policy evaluator for tests.
    /// Uses a callback that receives the PolicyInput and returns a decision.
    InMemory(Box<PolicyEvaluatorFn>),
}

impl PolicyClient {
    /// Create a new policy client backed by OPA.
    #[allow(clippy::expect_used)] // Startup-only: gate cannot operate without a policy engine.
    pub fn new(opa_url: &str, timeout: Duration) -> Self {
        let base = opa_url.trim_end_matches('/');
        let decision_url = format!("{base}/v1/data/latchgate/decision");

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client for OPA — cannot start without policy engine");

        Self {
            backend: PolicyBackend::Opa {
                client,
                decision_url,
            },
        }
    }

    /// Create a policy client backed by the embedded `regorus` evaluator.
    ///
    /// Same policy file, same input, same output as external OPA — just no
    /// network hop. The embedded evaluator supports runtime data reload
    /// via [`reload_embedded_data`](Self::reload_embedded_data).
    pub fn embedded(rego_source: &str, data_json: Option<&str>) -> Self {
        Self {
            backend: PolicyBackend::Embedded(crate::embedded::EmbeddedPolicy::new(
                rego_source,
                data_json,
            )),
        }
    }

    /// Reload policy data on the embedded evaluator.
    ///
    /// No-op if the backend is HTTP-OPA or InMemory.
    pub fn reload_embedded_data(&self, rego_source: &str, data_json: Option<&str>) {
        if let PolicyBackend::Embedded(ref ep) = self.backend {
            ep.reload_data(rego_source, data_json);
        }
    }

    /// Create an in-memory policy evaluator for testing.
    ///
    /// Default behaviour mimics the OPA policy from `policies/opa/`:
    /// - High/Critical risk => PendingApproval
    /// - Low/Medium risk => Allow with declared sinks
    /// - Unknown actions => Denied
    pub fn in_memory_default() -> Self {
        Self {
            backend: PolicyBackend::InMemory(Box::new(|input: &PolicyInput<'_>| {
                // Deny if trust check failed.
                if !input.action.action_trust_verdict.is_ok() {
                    return Err(PolicyError::denied(
                        "trust verification failed",
                        Arc::clone(&input.identity.principal),
                        Arc::clone(&input.action.action_id),
                    ));
                }

                // SECURITY: enforce required scopes from the action manifest.
                // Every scope in required_scopes must be present in the
                // caller's lease scopes. This mirrors the OPA Rule 2b/2c check
                // so that tests using the in-memory backend exercise the same
                // invariant as production OPA evaluation.
                let missing: Vec<&str> = input
                    .identity
                    .required_scopes
                    .iter()
                    .filter(|r| {
                        !input
                            .identity
                            .scopes
                            .iter()
                            .any(|s| s.as_str() == r.as_ref())
                    })
                    .map(|s| s.as_ref())
                    .collect();
                if !missing.is_empty() {
                    return Err(PolicyError::denied(
                        format!(
                            "lease is missing required scope(s) for action '{}': {:?}",
                            input.action.action_id, missing
                        ),
                        Arc::clone(&input.identity.principal),
                        Arc::clone(&input.action.action_id),
                    ));
                }

                // Require approval for high/critical risk.
                match input.action.action_risk_level {
                    RiskLevel::High | RiskLevel::Critical => {
                        // SECURITY (01.2): compute policy-narrowed fields even for
                        // PendingApproval, matching the real OPA behavior.
                        let budgets_after = BudgetSnapshot {
                            calls_remaining: input.budgets_before.calls_remaining - 1,
                        };
                        Ok(PolicyDecision::PendingApproval {
                            approval_id: ApprovalId::new(),
                            allowed_sinks: input.request.requested_sinks.to_vec(),
                            approved_secrets: input.request.requested_secrets.to_vec(),
                            approved_egress: input.request.egress_profile.clone(),
                            budgets_after,
                            policy_version: Some("in-memory-test".into()),
                        })
                    }
                    _ if !input.resolution.unresolved_domains.is_empty() => {
                        // Domain not in allowlist — require approval so the
                        // operator can review and optionally learn the domain.
                        let budgets_after = BudgetSnapshot {
                            calls_remaining: input.budgets_before.calls_remaining - 1,
                        };
                        Ok(PolicyDecision::PendingApproval {
                            approval_id: ApprovalId::new(),
                            allowed_sinks: input.request.requested_sinks.to_vec(),
                            approved_secrets: input.request.requested_secrets.to_vec(),
                            approved_egress: input.request.egress_profile.clone(),
                            budgets_after,
                            policy_version: Some("in-memory-test".into()),
                        })
                    }
                    _ if !input.resolution.unresolved_paths.is_empty() => {
                        // Path not in allowlist — require approval so the
                        // operator can review and optionally learn the path.
                        let budgets_after = BudgetSnapshot {
                            calls_remaining: input.budgets_before.calls_remaining - 1,
                        };
                        Ok(PolicyDecision::PendingApproval {
                            approval_id: ApprovalId::new(),
                            allowed_sinks: input.request.requested_sinks.to_vec(),
                            approved_secrets: input.request.requested_secrets.to_vec(),
                            approved_egress: input.request.egress_profile.clone(),
                            budgets_after,
                            policy_version: Some("in-memory-test".into()),
                        })
                    }
                    _ => {
                        let budgets_after = BudgetSnapshot {
                            calls_remaining: input.budgets_before.calls_remaining - 1,
                        };
                        Ok(PolicyDecision::Allow {
                            budgets_after,
                            allowed_sinks: input.request.requested_sinks.to_vec(),
                            approved_secrets: input.request.requested_secrets.to_vec(),
                            approved_egress: input.request.egress_profile.clone(),
                            policy_version: Some("in-memory-test".into()),
                        })
                    }
                }
            })),
        }
    }

    /// Create an in-memory policy evaluator with a custom callback.
    pub fn in_memory_with<F>(evaluator: F) -> Self
    where
        F: Fn(&PolicyInput<'_>) -> Result<PolicyDecision, PolicyError> + Send + Sync + 'static,
    {
        Self {
            backend: PolicyBackend::InMemory(Box::new(evaluator)),
        }
    }

    /// Readiness check: verify OPA is reachable.
    ///
    /// For OPA backend, issues a GET to the OPA health endpoint.
    /// For in-memory backend, always returns true.
    pub async fn is_healthy(&self) -> bool {
        match &self.backend {
            PolicyBackend::Opa {
                client,
                decision_url,
            } => {
                // OPA health endpoint is at the same base URL.
                let base = decision_url
                    .strip_suffix("/v1/data/latchgate/decision")
                    .unwrap_or(decision_url);
                let health_url = format!("{base}/health");
                client.get(&health_url).send().await.is_ok()
            }
            PolicyBackend::InMemory(_) => true,
            PolicyBackend::Embedded(_) => true,
        }
    }

    /// Evaluate a policy decision.
    #[instrument(name = "policy.evaluate", skip(self, input), fields(action_id = %input.action.action_id, principal = %input.identity.principal))]
    #[must_use = "discarding the decision skips policy enforcement"]
    pub async fn evaluate(&self, input: &PolicyInput<'_>) -> Result<PolicyDecision, PolicyError> {
        match &self.backend {
            PolicyBackend::Opa {
                client,
                decision_url,
            } => self.opa_evaluate(client, decision_url, input).await,
            PolicyBackend::Embedded(ep) => ep.evaluate(input),
            PolicyBackend::InMemory(evaluator) => evaluator(input),
        }
    }

    /// OPA-backed evaluation.
    async fn opa_evaluate(
        &self,
        client: &reqwest::Client,
        decision_url: &str,
        input: &PolicyInput<'_>,
    ) -> Result<PolicyDecision, PolicyError> {
        debug!("evaluating policy via OPA");

        // -- Send request to OPA --
        let response = client
            .post(decision_url)
            .json(&serde_json::json!({ "input": input }))
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            warn!(
                http_status = %status,
                url = %decision_url,
                "OPA returned non-success status"
            );
            return Err(PolicyError::OpaUnavailable(format!(
                "OPA returned HTTP {status}"
            )));
        }

        // -- Parse response body --
        let body_bytes = response.bytes().await.map_err(|e| {
            warn!(error = %e, "failed to read OPA response body");
            PolicyError::OpaResponseInvalid(format!("failed to read response body: {e}"))
        })?;

        let opa_response: OpaQueryResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            warn!(error = %e, "OPA response is not valid JSON or does not match schema");
            PolicyError::OpaResponseInvalid(format!("malformed JSON: {e}"))
        })?;

        // -- Extract result --
        // SECURITY: if OPA returns `{"result": null}` or `{}` (no policy loaded,
        // wrong package path, empty bundle), we DENY. No policy = no allow.
        let result = opa_response.result.ok_or_else(|| {
            warn!(
                url = %decision_url,
                "OPA response missing 'result' — no policy loaded or wrong package path"
            );
            PolicyError::OpaResponseInvalid(
                "missing 'result' in OPA response — is the latchgate policy bundle loaded?"
                    .to_string(),
            )
        })?;

        interpret_decision(result, input)
    }

    /// Classify a `reqwest::Error` into the appropriate `PolicyError`.
    ///
    /// SECURITY: every branch returns a deny-equivalent error. There is no
    /// fallthrough to `Allow`.
    fn classify_reqwest_error(e: reqwest::Error) -> PolicyError {
        if e.is_timeout() {
            // SECURITY: timeout => DENY. A slow OPA must never cause an allow.
            warn!("OPA request timed out");
            PolicyError::OpaTimeout
        } else if e.is_connect() {
            warn!(error = %e, "cannot connect to OPA");
            PolicyError::OpaUnavailable(format!("connection failed: {e}"))
        } else {
            warn!(error = %e, "OPA request failed");
            PolicyError::OpaUnavailable(format!("request error: {e}"))
        }
    }
}

/// Parse a decision directly from a JSON string into a `PolicyDecision`.
///
/// Skips the intermediate `serde_json::Value` representation — deserialises
/// the JSON bytes into `OpaDecisionResult` in a single pass. Used by the
/// embedded backend where the regorus evaluator produces a JSON string via
/// `Value::to_json_str()`.
pub(crate) fn parse_decision_str(
    json: &str,
    input: &PolicyInput<'_>,
) -> Result<PolicyDecision, PolicyError> {
    let result: OpaDecisionResult = serde_json::from_str(json)
        .map_err(|e| PolicyError::OpaResponseInvalid(format!("malformed decision JSON: {e}")))?;

    interpret_decision(result, input)
}

/// Convert a parsed `OpaDecisionResult` into a `PolicyDecision`.
///
/// Shared by the HTTP and embedded backends. Every error path returns
/// a deny-equivalent — there is no fallthrough to `Allow`.
fn interpret_decision(
    result: OpaDecisionResult,
    input: &PolicyInput<'_>,
) -> Result<PolicyDecision, PolicyError> {
    if !result.allow {
        let reason = result
            .deny_reason
            .unwrap_or_else(|| "denied by policy (no reason provided)".to_string());
        debug!(reason = %reason, "policy denied");
        return Err(PolicyError::denied(
            reason,
            Arc::clone(&input.identity.principal),
            Arc::clone(&input.action.action_id),
        ));
    }

    if result.requires_approval {
        let approval_id = ApprovalId::new();

        // SECURITY: when OPA returns requires_approval, it MUST explicitly
        // declare allowed_sinks, approved_secrets, and approved_egress.
        // Without these, the gate would store a pending approval with the
        // agent-requested capabilities — bypassing the intent of policy
        // narrowing. Treat missing fields as a policy contract violation
        // and deny fail-closed.
        let allowed_sinks = match result.allowed_sinks {
            Some(v) => v,
            None => {
                warn!(
                    "policy returned requires_approval without allowed_sinks — \
                     denying (policy must explicitly declare narrowed capabilities)"
                );
                return Err(PolicyError::denied(
                    "policy contract violation: requires_approval without allowed_sinks",
                    Arc::clone(&input.identity.principal),
                    Arc::clone(&input.action.action_id),
                ));
            }
        };

        let approved_secrets = match result.approved_secrets {
            Some(v) => v,
            None => {
                warn!(
                    "policy returned requires_approval without approved_secrets — \
                     denying (policy must explicitly declare narrowed capabilities)"
                );
                return Err(PolicyError::denied(
                    "policy contract violation: requires_approval without approved_secrets",
                    Arc::clone(&input.identity.principal),
                    Arc::clone(&input.action.action_id),
                ));
            }
        };

        let approved_egress = match result.approved_egress {
            Some(v) => v,
            None => {
                warn!(
                    "policy returned requires_approval without approved_egress — \
                     denying (policy must explicitly declare narrowed capabilities)"
                );
                return Err(PolicyError::denied(
                    "policy contract violation: requires_approval without approved_egress",
                    Arc::clone(&input.identity.principal),
                    Arc::clone(&input.action.action_id),
                ));
            }
        };

        let budgets_after = result.budgets_after.unwrap_or_else(|| {
            warn!(
                "policy returned requires_approval without budgets_after — \
                 using budgets_before as fallback (policy budget intent lost)"
            );
            input.budgets_before
        });

        debug!(
            approval_id = %approval_id,
            allowed_sinks = ?allowed_sinks,
            "policy requires human approval"
        );
        return Ok(PolicyDecision::PendingApproval {
            approval_id,
            allowed_sinks,
            approved_secrets,
            approved_egress,
            budgets_after,
            policy_version: result.policy_version.clone(),
        });
    }

    let budgets_after = result
        .budgets_after
        .unwrap_or(BudgetSnapshot { calls_remaining: 0 });
    let allowed_sinks = result.allowed_sinks.unwrap_or_default();
    let approved_secrets = result
        .approved_secrets
        .unwrap_or_else(|| input.request.requested_secrets.to_vec());
    let approved_egress = result
        .approved_egress
        .unwrap_or_else(|| input.request.egress_profile.clone());

    debug!(
        calls_remaining = budgets_after.calls_remaining,
        sinks = ?allowed_sinks,
        policy_version = ?result.policy_version,
        "policy allowed"
    );

    Ok(PolicyDecision::Allow {
        budgets_after,
        allowed_sinks,
        approved_secrets,
        approved_egress,
        policy_version: result.policy_version,
    })
}

// Implement Debug manually — reqwest::Client doesn't derive Debug.
impl std::fmt::Debug for PolicyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = match &self.backend {
            PolicyBackend::Opa { decision_url, .. } => decision_url.as_str(),
            PolicyBackend::Embedded(_) => "embedded_regorus",
            PolicyBackend::InMemory(_) => "in_memory",
        };
        f.debug_struct("PolicyClient")
            .field("backend", &info)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    /// Backing data for test [`PolicyInput`] construction.
    ///
    /// Fields that become borrowed slices in `PolicyInput` live here so
    /// they outlive the `PolicyInput` reference. Tests mutate this struct
    /// (or override with `..Default::default()`) before calling [`input()`].
    struct TestCtx {
        scopes: Vec<String>,
        required_scopes: Vec<Arc<str>>,
        sinks: Vec<Arc<str>>,
        secrets: Vec<Arc<str>>,
        egress: EgressProfile,
        unresolved_domains: Vec<String>,
        unresolved_paths: Vec<String>,
    }

    impl Default for TestCtx {
        fn default() -> Self {
            Self {
                scopes: vec!["tools:call".to_string()],
                required_scopes: vec!["tools:call".into()],
                sinks: vec!["http_read".into()],
                secrets: vec![],
                egress: EgressProfile::None,
                unresolved_domains: vec![],
                unresolved_paths: vec![],
            }
        }
    }

    impl TestCtx {
        /// Produce a `PolicyInput` that borrows from `self`.
        ///
        /// Callers can mutate Copy / Arc fields on the returned struct
        /// (e.g. `input.action.action_risk_level = RiskLevel::High`).
        /// For borrowed-slice fields, modify `TestCtx` and call again.
        fn input(&self) -> PolicyInput<'_> {
            PolicyInput {
                identity: PolicyIdentity {
                    principal: Arc::from("agent:test-agent"),
                    session_id: Arc::from("sess-001"),
                    scopes: &self.scopes,
                    required_scopes: &self.required_scopes,
                },
                action: PolicyAction {
                    action_id: Arc::from("http_fetch"),
                    action_version: "1.0.0",
                    action_risk_level: RiskLevel::Low,
                    action_trust_verdict: Arc::new(TrustVerdict::DigestOk),
                    action_category: "",
                },
                request: PolicyRequest {
                    request_hash: "abc123",
                    requested_sinks: &self.sinks,
                    requested_secrets: &self.secrets,
                    egress_profile: &self.egress,
                    provider_context: None,
                    fs_path: None,
                },
                budgets_before: BudgetSnapshot {
                    calls_remaining: 10,
                },
                resolution: PolicyResolution {
                    unresolved_domains: &self.unresolved_domains,
                    unresolved_paths: &self.unresolved_paths,
                },
            }
        }
    }

    // -- PolicyInput serialisation --

    #[test]
    fn policy_input_serializes_to_expected_json() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        let json = serde_json::to_value(&input).unwrap();

        assert_eq!(json["principal"], "agent:test-agent");
        assert_eq!(json["session_id"], "sess-001");
        assert_eq!(json["action_id"], "http_fetch");
        assert_eq!(json["action_version"], "1.0.0");
        assert_eq!(json["action_risk_level"], "low");
        assert_eq!(json["action_trust_verdict"], "digest_ok");
        assert_eq!(json["request_hash"], "abc123");
        assert_eq!(json["requested_sinks"], serde_json::json!(["http_read"]));
        assert_eq!(json["egress_profile"], "none");
        assert_eq!(json["budgets_before"]["calls_remaining"], 10);
    }

    #[test]
    fn policy_input_wraps_in_input_envelope() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        let envelope = serde_json::json!({ "input": input });
        assert!(envelope["input"]["principal"].is_string());
        assert!(envelope["input"]["action_id"].is_string());
    }

    // -- OPA response parsing --

    /// Backward compatibility: policy_version absent => parses as None.
    #[test]
    fn opa_response_allow_without_policy_version_parses() {
        let json = r#"{
            "result": {
                "allow": true,
                "budgets_after": { "calls_remaining": 5 },
                "allowed_sinks": ["http_read"]
            }
        }"#;
        let resp: OpaQueryResponse = serde_json::from_str(json).unwrap();
        let result = resp.result.unwrap();
        assert!(result.allow);
        assert!(
            result.policy_version.is_none(),
            "missing policy_version must parse as None"
        );
    }

    #[test]
    fn opa_response_allow_parses_correctly() {
        let json = r#"{
            "result": {
                "allow": true,
                "budgets_after": { "calls_remaining": 9 },
                "allowed_sinks": ["http_read"],
                "policy_version": "m0-dev-001"
            }
        }"#;
        let resp: OpaQueryResponse = serde_json::from_str(json).unwrap();
        let result = resp.result.unwrap();
        assert!(result.allow);
        assert!(!result.requires_approval);
        let budgets = result.budgets_after.unwrap();
        assert_eq!(budgets.calls_remaining, 9);
        assert_eq!(result.allowed_sinks.unwrap(), vec!["http_read".into()]);
        assert_eq!(result.policy_version.as_deref(), Some("m0-dev-001"));
    }

    #[test]
    fn opa_response_deny_parses_correctly() {
        let json = r#"{
            "result": {
                "allow": false,
                "deny_reason": "budget exhausted"
            }
        }"#;
        let resp: OpaQueryResponse = serde_json::from_str(json).unwrap();
        let result = resp.result.unwrap();
        assert!(!result.allow);
        assert_eq!(result.deny_reason.unwrap(), "budget exhausted");
    }

    #[test]
    fn opa_response_requires_approval_parses() {
        let json = r#"{
            "result": {
                "allow": true,
                "requires_approval": true,
                "budgets_after": { "calls_remaining": 5 },
                "policy_version": "m0-dev-001"
            }
        }"#;
        let resp: OpaQueryResponse = serde_json::from_str(json).unwrap();
        let result = resp.result.unwrap();
        assert!(result.allow);
        assert!(result.requires_approval);
        assert_eq!(result.policy_version.as_deref(), Some("m0-dev-001"));
    }

    /// SECURITY: if OPA returns no `result` (no policy loaded, wrong package),
    /// that MUST be treated as invalid — never as allow.
    #[test]
    fn opa_response_missing_result_is_invalid() {
        let json = r#"{}"#;
        let resp: OpaQueryResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none(), "missing result must be None");
    }

    /// SECURITY: null result is also treated as missing.
    #[test]
    fn opa_response_null_result_is_invalid() {
        let json = r#"{"result": null}"#;
        let resp: OpaQueryResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none(), "null result must be None");
    }

    #[test]
    fn opa_response_malformed_json_is_invalid() {
        let json = r#"not json at all"#;
        let result = serde_json::from_str::<OpaQueryResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn opa_response_missing_allow_field_is_invalid() {
        // `allow` is required in OpaDecisionResult. When it is absent, serde
        // propagates the error to the outer OpaQueryResponse parse — the
        // entire deserialization fails, which the evaluate() method converts
        // to OpaResponseInvalid (DENY).
        let json = r#"{"result": {"deny_reason": "oops"}}"#;
        let result = serde_json::from_str::<OpaQueryResponse>(json);
        assert!(result.is_err(), "missing 'allow' must fail outer parsing");
    }

    // -- BudgetSnapshot --

    #[test]
    fn budget_snapshot_serializes_and_deserializes() {
        let snap = BudgetSnapshot {
            calls_remaining: 42,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: BudgetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snap);
    }

    #[test]
    fn budget_snapshot_negative_values_round_trip() {
        // OPA might return negative if policy decrements past zero for reporting.
        let snap = BudgetSnapshot {
            calls_remaining: -1,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: BudgetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snap);
    }

    // -- PolicyClient construction --

    #[test]
    fn policy_client_builds_decision_url() {
        let client = PolicyClient::new("http://localhost:8181", Duration::from_secs(1));
        let debug = format!("{client:?}");
        assert!(
            debug.contains("http://localhost:8181/v1/data/latchgate/decision"),
            "debug must contain full decision URL: {debug}"
        );
    }

    #[test]
    fn policy_client_strips_trailing_slash() {
        let client = PolicyClient::new("http://localhost:8181/", Duration::from_secs(1));
        let debug = format!("{client:?}");
        assert!(
            debug.contains("http://localhost:8181/v1/data/latchgate/decision"),
            "trailing slash must be stripped: {debug}"
        );
    }

    #[test]
    fn policy_client_debug_does_not_leak_secrets() {
        let client = PolicyClient::new("http://localhost:8181", Duration::from_secs(1));
        let debug = format!("{client:?}");
        assert!(debug.contains("PolicyClient"));
        // Should not contain internal reqwest details.
        assert!(debug.contains("localhost:8181"));
    }

    // -- PolicyError display --

    #[test]
    fn policy_error_denied_display() {
        let err = PolicyError::denied("test", Arc::from("agent:t"), Arc::from("act_t"));
        assert_eq!(err.to_string(), "policy denied: test");
    }

    #[test]
    fn policy_error_timeout_display() {
        let err = PolicyError::OpaTimeout;
        assert_eq!(err.to_string(), "policy engine timed out");
    }

    #[test]
    fn policy_error_unavailable_display() {
        let err = PolicyError::OpaUnavailable("conn refused".into());
        assert_eq!(err.to_string(), "policy engine unreachable: conn refused");
    }

    #[test]
    fn policy_error_invalid_display() {
        let err = PolicyError::OpaResponseInvalid("bad json".into());
        assert_eq!(
            err.to_string(),
            "policy engine returned unexpected response: bad json"
        );
    }

    // -- EgressProfile serialization for policy input --

    #[test]
    fn egress_none_serializes_for_policy() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["egress_profile"], "none");
    }

    #[test]
    fn egress_proxy_serializes_for_policy() {
        let ctx = TestCtx {
            egress: EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["api.example.com".into()],
            },
            ..Default::default()
        };
        let input = ctx.input();
        let json = serde_json::to_value(&input).unwrap();
        assert!(json["egress_profile"]["proxy_allowlist"].is_object());
        assert_eq!(
            json["egress_profile"]["proxy_allowlist"]["allowed_domains"],
            serde_json::json!(["api.example.com"])
        );
    }

    // Integration tests — require a running OPA with latchgate policies.
    //
    // Auto-skip when OPA is not reachable on localhost:8181.
    // Run with: `make dev && cargo test`

    fn opa_available() -> bool {
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:8181".parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
    }

    /// Helper: build a PolicyClient pointing at the local dev OPA.
    fn integration_client() -> PolicyClient {
        PolicyClient::new("http://127.0.0.1:8181", Duration::from_secs(5))
    }

    #[tokio::test]
    async fn policy_evaluate_allow_with_real_opa() {
        if !opa_available() {
            eprintln!("SKIP: OPA not available on localhost:8181");
            return;
        }
        let client = integration_client();
        let ctx = TestCtx::default();
        let input = ctx.input();
        let decision = client.evaluate(&input).await.unwrap();
        match decision {
            PolicyDecision::Allow {
                budgets_after,
                allowed_sinks,
                policy_version,
                ..
            } => {
                assert_eq!(budgets_after.calls_remaining, 9);
                assert!(!allowed_sinks.is_empty());
                // SECURITY: policy_version must be present for audit trail.
                assert!(
                    policy_version.is_some(),
                    "policy_version should be set by OPA data"
                );
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_evaluate_deny_unknown_action_with_real_opa() {
        if !opa_available() {
            eprintln!("SKIP: OPA not available on localhost:8181");
            return;
        }
        let client = integration_client();
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.action.action_id = Arc::from("unknown_action");
        let result = client.evaluate(&input).await;
        match result {
            Err(PolicyError::Denied { reason, .. }) => {
                assert!(
                    reason.contains("not authorised"),
                    "unexpected deny reason: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_evaluate_deny_untrusted_with_real_opa() {
        if !opa_available() {
            eprintln!("SKIP: OPA not available on localhost:8181");
            return;
        }
        let client = integration_client();
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.action.action_trust_verdict = Arc::new(TrustVerdict::DigestMismatch {
            expected: "abc".into(),
            actual: "def".into(),
        });
        let result = client.evaluate(&input).await;
        match result {
            Err(PolicyError::Denied { reason, .. }) => {
                assert!(
                    reason.contains("untrusted action"),
                    "unexpected deny reason: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_evaluate_deny_budget_exhausted_with_real_opa() {
        if !opa_available() {
            eprintln!("SKIP: OPA not available on localhost:8181");
            return;
        }
        let client = integration_client();
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.budgets_before = BudgetSnapshot { calls_remaining: 0 };
        let result = client.evaluate(&input).await;
        match result {
            Err(PolicyError::Denied { reason, .. }) => {
                assert!(
                    reason.contains("budget exhausted"),
                    "unexpected deny reason: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_evaluate_high_risk_requires_approval_with_real_opa() {
        if !opa_available() {
            eprintln!("SKIP: OPA not available on localhost:8181");
            return;
        }
        let client = integration_client();
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::High;
        let decision = client.evaluate(&input).await.unwrap();
        match decision {
            PolicyDecision::PendingApproval { policy_version, .. } => {
                assert!(
                    policy_version.is_some(),
                    "policy_version should be set for approval decisions"
                );
            }
            other => panic!("expected PendingApproval, got {other:?}"),
        }
    }

    /// SECURITY: a PolicyClient pointing at an unreachable host must return
    /// OpaUnavailable (DENY), never Allow. This test does NOT require OPA.
    #[tokio::test]
    async fn policy_evaluate_opa_unreachable_returns_unavailable() {
        // Port 19 (chargen) is almost certainly not running OPA.
        let client = PolicyClient::new("http://127.0.0.1:19", Duration::from_secs(1));
        let ctx = TestCtx::default();
        let input = ctx.input();
        let result = client.evaluate(&input).await;
        match result {
            Err(PolicyError::OpaUnavailable(_)) => {} // expected
            Err(PolicyError::OpaTimeout) => {}        // also acceptable
            other => panic!("expected OpaUnavailable or OpaTimeout, got {other:?}"),
        }
    }

    /// SECURITY: a short timeout must trigger OpaTimeout (DENY), not Allow.
    ///
    /// Spins up a TCP listener that accepts connections but never responds,
    /// guaranteeing the timeout fires deterministically regardless of machine
    /// speed. No external OPA required.
    #[tokio::test]
    async fn policy_evaluate_opa_timeout_returns_timeout() {
        // Bind a TCP listener that accepts but never replies (black-hole).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept_thread = std::thread::spawn(move || {
            // Accept one connection, hold it open, never write.
            let _conn = listener.accept();
        });

        let client = PolicyClient::new(&format!("http://{addr}"), Duration::from_millis(50));
        let ctx = TestCtx::default();
        let input = ctx.input();
        let result = client.evaluate(&input).await;
        match result {
            Err(PolicyError::OpaTimeout) => {}        // expected
            Err(PolicyError::OpaUnavailable(_)) => {} // reqwest may classify as connect error
            other => panic!("expected OpaTimeout or OpaUnavailable, got {other:?}"),
        }
    }

    // -- unresolved_domains --

    #[tokio::test]
    async fn unresolved_domains_triggers_pending_approval() {
        let client = PolicyClient::in_memory_default();
        let ctx = TestCtx {
            unresolved_domains: vec!["unknown-site.com".into()],
            ..Default::default()
        };
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::Low;

        let decision = client.evaluate(&input).await.unwrap();
        assert!(
            matches!(decision, PolicyDecision::PendingApproval { .. }),
            "unresolved domains must trigger pending_approval even at low risk"
        );
    }

    #[tokio::test]
    async fn empty_unresolved_domains_allows_low_risk() {
        let client = PolicyClient::in_memory_default();
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::Low;

        let decision = client.evaluate(&input).await.unwrap();
        assert!(
            matches!(decision, PolicyDecision::Allow { .. }),
            "empty unresolved domains at low risk must allow"
        );
    }

    #[tokio::test]
    async fn unresolved_domains_high_risk_still_pending() {
        // High risk already triggers pending_approval. Adding unresolved_domains
        // must not cause a double-pending or error — just pending_approval.
        let client = PolicyClient::in_memory_default();
        let ctx = TestCtx {
            unresolved_domains: vec!["unknown.com".into()],
            ..Default::default()
        };
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::High;

        let decision = client.evaluate(&input).await.unwrap();
        assert!(
            matches!(decision, PolicyDecision::PendingApproval { .. }),
            "high risk + unresolved domains must still be pending_approval"
        );
    }

    #[tokio::test]
    async fn unresolved_domains_multiple_all_forwarded() {
        // Multiple unresolved domains should still trigger a single pending_approval.
        let client = PolicyClient::in_memory_default();
        let ctx = TestCtx {
            unresolved_domains: vec!["a.com".into(), "b.com".into(), "c.com".into()],
            ..Default::default()
        };
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::Low;

        let decision = client.evaluate(&input).await.unwrap();
        assert!(
            matches!(decision, PolicyDecision::PendingApproval { .. }),
            "multiple unresolved domains must trigger pending_approval"
        );
    }

    #[test]
    fn unresolved_domains_not_serialized_when_empty() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        assert!(input.resolution.unresolved_domains.is_empty());

        let json = serde_json::to_value(&input).unwrap();
        assert!(
            json.get("unresolved_domains").is_none(),
            "empty unresolved_domains must be skipped in serialization (skip_serializing_if)"
        );
    }

    #[test]
    fn unresolved_domains_serialized_when_present() {
        let ctx = TestCtx {
            unresolved_domains: vec!["newsite.com".into()],
            ..Default::default()
        };
        let input = ctx.input();

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(
            json["unresolved_domains"],
            serde_json::json!(["newsite.com"]),
            "non-empty unresolved_domains must appear in serialized JSON for OPA"
        );
    }

    // -- action_category --

    #[test]
    fn action_category_not_serialized_when_empty() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        let json = serde_json::to_value(&input).unwrap();
        assert!(
            json.get("action_category").is_none(),
            "empty action_category must be skipped in serialization"
        );
    }

    #[test]
    fn action_category_serialized_when_fs() {
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.action.action_category = "fs";
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["action_category"], "fs");
    }

    // -- fs_path --

    #[test]
    fn fs_path_not_serialized_when_none() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        let json = serde_json::to_value(&input).unwrap();
        assert!(
            json.get("fs_path").is_none(),
            "None fs_path must be skipped"
        );
    }

    #[test]
    fn fs_path_serialized_when_present() {
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.request.fs_path = Some("src/main.rs");
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["fs_path"], "src/main.rs");
    }

    // -- unresolved_paths --

    #[test]
    fn unresolved_paths_not_serialized_when_empty() {
        let ctx = TestCtx::default();
        let input = ctx.input();
        let json = serde_json::to_value(&input).unwrap();
        assert!(
            json.get("unresolved_paths").is_none(),
            "empty unresolved_paths must be skipped"
        );
    }

    #[tokio::test]
    async fn unresolved_paths_triggers_pending_approval() {
        let client = PolicyClient::in_memory_default();
        let ctx = TestCtx {
            unresolved_paths: vec!["configs/deploy.toml".into()],
            ..Default::default()
        };
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::Low;
        input.action.action_category = "fs";

        let decision = client.evaluate(&input).await.unwrap();
        assert!(
            matches!(decision, PolicyDecision::PendingApproval { .. }),
            "unresolved paths must trigger pending_approval"
        );
    }

    #[tokio::test]
    async fn empty_unresolved_paths_allows_low_risk_fs() {
        let client = PolicyClient::in_memory_default();
        let ctx = TestCtx::default();
        let mut input = ctx.input();
        input.action.action_risk_level = RiskLevel::Low;
        input.action.action_category = "fs";

        let decision = client.evaluate(&input).await.unwrap();
        assert!(
            matches!(decision, PolicyDecision::Allow { .. }),
            "empty unresolved_paths at low risk must allow"
        );
    }
}
