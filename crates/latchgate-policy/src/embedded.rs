//! Embedded Rego evaluator backed by `regorus`.
//!
//! Same policy file, same input, same output as external OPA — just no
//! network hop. Used when `opa_url` is absent from the configuration.
//!
//! # Thread safety and engine caching
//!
//! `regorus::Engine` is not `Send + Sync` (it uses `Rc` internally), so it
//! cannot live inside a value shared across threads. [`EmbeddedPolicy`] is
//! shared (it is part of `AppState`), so it must stay `Send + Sync`; it
//! therefore stores only the policy *sources* (`Arc<str>`), which are cheap
//! to clone and trivially `Send + Sync`.
//!
//! Compilation is amortized with a per-thread engine cache. Each worker
//! thread compiles the policy once into a [`thread_local`] `regorus::Engine`
//! and reuses it for every subsequent evaluation on that thread. This keeps
//! the request hot path free of the lex/parse/compile cost that a
//! per-request `Engine::new()` would incur, without requiring the engine to
//! cross a thread boundary.
//!
//! Each `(EmbeddedPolicy, reload)` pair is tagged with a process-global,
//! monotonically increasing *generation*. A cached engine records the
//! generation it was built for; when an evaluation observes a newer
//! generation (a different policy instance, or a data reload) it rebuilds.
//! This guarantees a thread never serves a decision from a stale policy.
//!
//! # Fail-closed guarantees
//!
//! - Parse/compile errors at startup => hard panic (cannot start without policy).
//! - Parse/compile errors on reload => reload rejected, prior policy stays active.
//! - Evaluation panics => caught via `catch_unwind`, the thread's cached
//!   engine is discarded, and the request is DENIED.
//! - Undefined result => DENY.
//! - Poisoned lock => DENY.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tracing::{debug, warn};

use crate::policy::{PolicyDecision, PolicyError, PolicyInput};

/// Rule path evaluated for every decision. The embedded policy must expose
/// `decision` in `package latchgate`.
const DECISION_RULE: &str = "data.latchgate.decision";

/// Process-global generation counter.
///
/// Every constructed [`EmbeddedPolicy`] and every successful data reload
/// claims a fresh value. Generations are globally unique so the per-thread
/// engine cache — which is shared across all `EmbeddedPolicy` instances on a
/// thread — can never confuse one policy's compiled engine for another's.
/// `0` is reserved as "no engine built yet".
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

thread_local! {
    /// Per-thread compiled engine. Built lazily on first evaluation and
    /// rebuilt when the policy generation changes.
    static ENGINE_CACHE: RefCell<Option<CachedEngine>> = const { RefCell::new(None) };
}

/// A compiled engine together with the generation it was built for.
struct CachedEngine {
    generation: u64,
    engine: regorus::Engine,
}

/// Policy sources plus the generation that identifies this exact
/// (source, data) pair. Stored as `Arc<str>` so reads under the lock are
/// refcount bumps, not heap-cloning `String`s.
struct PolicySources {
    rego: Arc<str>,
    data_json: Option<Arc<str>>,
    generation: u64,
}

/// In-process Rego evaluator.
///
/// Holds only the policy sources; compiled engines are cached per thread.
/// `Send + Sync`, so it can be shared via `Arc` across the async runtime.
pub struct EmbeddedPolicy {
    sources: RwLock<PolicySources>,
}

impl EmbeddedPolicy {
    /// Build an embedded evaluator from Rego source and optional data JSON.
    ///
    /// The policy is compiled once here to validate it; the resulting engine
    /// is discarded, and worker threads each compile their own on first use.
    ///
    /// # Panics
    ///
    /// Panics if the Rego policy or data JSON cannot be parsed or compiled.
    /// This is intentional: a broken policy is a hard failure — the gate must
    /// not start.
    #[allow(clippy::expect_used)] // Startup-only: the gate must not run a broken policy.
    pub fn new(rego_source: &str, data_json: Option<&str>) -> Self {
        // Validate up front — fail fast if the policy is broken.
        Self::try_build_engine(rego_source, data_json)
            .expect("embedded Rego policy failed to load — cannot start gate");

        Self {
            sources: RwLock::new(PolicySources {
                rego: Arc::from(rego_source),
                data_json: data_json.map(Arc::from),
                generation: next_generation(),
            }),
        }
    }

    /// Reload policy data (ACL changes from `latchgate policy grant/revoke`).
    ///
    /// The new sources are compiled and validated before being committed, so
    /// a malformed reload is rejected and the previously compiled policy stays
    /// active. On success the generation is bumped; each thread rebuilds its
    /// cached engine lazily on its next evaluation.
    ///
    pub fn reload_data(&self, rego_source: &str, data_json: Option<&str>) {
        // Validate before taking the lock so a bad reload never crashes the
        // gate and never holds the write lock.
        if let Err(e) = Self::try_build_engine(rego_source, data_json) {
            warn!("embedded policy reload rejected: {e} — existing policy remains active");
            return;
        }

        let Ok(mut guard) = self.sources.write() else {
            warn!("policy sources lock poisoned — reload skipped, existing policy remains active");
            return;
        };
        guard.rego = Arc::from(rego_source);
        guard.data_json = data_json.map(Arc::from);
        guard.generation = next_generation();
        debug!(
            generation = guard.generation,
            "embedded policy sources reloaded"
        );
    }

    /// Evaluate the policy decision for a given input.
    ///
    /// SECURITY: evaluation panics are caught and mapped to DENY; the thread's
    /// cached engine is discarded after a panic so it is never reused in a
    /// possibly-inconsistent state.
    pub fn evaluate(&self, input: &PolicyInput<'_>) -> Result<PolicyDecision, PolicyError> {
        // Serialize the PolicyInput directly — regorus `set_input` sets the
        // Rego `input` variable, so `input.principal` in Rego maps to
        // PolicyInput.principal. No `{"input": ...}` wrapper (that's an
        // OPA HTTP API convention, not a Rego convention).
        let input_json = serde_json::to_string(input).map_err(|e| {
            PolicyError::OpaResponseInvalid(format!("failed to serialize policy input: {e}"))
        })?;

        // Snapshot the current sources + generation under the read lock.
        let (rego, data_json, generation) = {
            let guard = self
                .sources
                .read()
                .map_err(|_| PolicyError::OpaUnavailable("policy sources lock poisoned".into()))?;
            (
                Arc::clone(&guard.rego),
                guard.data_json.as_ref().map(Arc::clone),
                guard.generation,
            )
        };

        // Evaluate on this thread's cached engine, rebuilding it if the policy
        // generation has advanced. The closure returns the raw regorus value;
        // decision parsing happens outside the thread-local borrow.
        let value = ENGINE_CACHE.with(|cell| -> Result<regorus::Value, PolicyError> {
            let mut slot = cell.borrow_mut();

            let needs_build = match slot.as_ref() {
                Some(cached) => cached.generation != generation,
                None => true,
            };
            if needs_build {
                let engine = Self::try_build_engine(&rego, data_json.as_deref())
                    .map_err(PolicyError::OpaUnavailable)?;
                *slot = Some(CachedEngine { generation, engine });
            }

            // SECURITY: a panic inside regorus must not unwind across the
            // evaluation boundary. Catch it, discard the (possibly
            // inconsistent) cached engine, and surface a fail-closed error.
            // The `&mut` borrow of the cached engine is confined to this
            // block so the slot can be cleared afterwards on the panic path.
            let outcome = {
                let cached = slot.as_mut().ok_or_else(|| {
                    PolicyError::OpaUnavailable("policy engine cache unexpectedly empty".into())
                })?;
                let engine = &mut cached.engine;
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    engine.set_input(regorus::Value::from_json_str(&input_json).map_err(|e| {
                        PolicyError::OpaResponseInvalid(format!(
                            "failed to parse input as regorus Value: {e}"
                        ))
                    })?);
                    engine.eval_rule(DECISION_RULE.to_string()).map_err(|e| {
                        PolicyError::OpaUnavailable(format!("regorus evaluation failed: {e}"))
                    })
                }))
            };

            match outcome {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(e)) => Err(e),
                Err(_panic) => {
                    *slot = None;
                    warn!("embedded policy evaluator panicked — DENY");
                    Err(PolicyError::OpaUnavailable(
                        "embedded policy evaluator panicked".into(),
                    ))
                }
            }
        })?;

        // Undefined result => no matching rule => DENY.
        if value == regorus::Value::Undefined {
            return Err(PolicyError::denied(
                "embedded policy returned undefined (no matching rule)",
                Arc::clone(&input.identity.principal),
                Arc::clone(&input.action.action_id),
            ));
        }

        // Convert regorus::Value => JSON string => OpaDecisionResult in a
        // single serde pass, bypassing the intermediate serde_json::Value
        // allocation that the external OPA backend uses.
        let json_str = value.to_json_str().map_err(|e| {
            PolicyError::OpaResponseInvalid(format!(
                "regorus result cannot be serialized to JSON: {e}"
            ))
        })?;

        crate::policy::parse_decision_str(&json_str, input)
    }

    /// Compile a fully prepared engine from Rego source and optional data.
    ///
    fn try_build_engine(
        rego_source: &str,
        data_json: Option<&str>,
    ) -> Result<regorus::Engine, String> {
        let mut engine = regorus::Engine::new();

        engine
            .add_policy("latchgate.rego".to_string(), rego_source.to_string())
            .map_err(|e| format!("Rego policy failed to parse: {e}"))?;

        if let Some(data) = data_json {
            let data_value = regorus::Value::from_json_str(data)
                .map_err(|e| format!("policy data.json failed to parse: {e}"))?;
            engine
                .add_data(data_value)
                .map_err(|e| format!("policy data failed to load: {e}"))?;
        }

        // Warm the engine: one evaluation forces the analyze/schedule/hoist
        // pass and flips regorus's internal `prepared` flag, so subsequent
        // evaluations on this engine skip the front-end. The decision value
        // itself is discarded; an empty input is sufficient to trigger
        // preparation.
        engine.set_input(regorus::Value::new_object());
        engine
            .eval_rule(DECISION_RULE.to_string())
            .map_err(|e| format!("policy failed to evaluate during warmup: {e}"))?;

        Ok(engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyAction, PolicyIdentity, PolicyRequest, PolicyResolution};
    use latchgate_core::{BudgetSnapshot, EgressProfile, RiskLevel, TrustVerdict};
    use std::sync::Arc;

    fn test_rego() -> &'static str {
        r#"
package latchgate

import rego.v1

default decision := {
    "allow": false,
    "deny_reason": "default deny"
}

decision := d if {
    input.action_trust_verdict == "digest_ok"
    input.action_risk_level == "low"
    d := {
        "allow": true,
        "budgets_after": {"calls_remaining": input.budgets_before.calls_remaining - 1},
        "allowed_sinks": input.requested_sinks,
        "approved_secrets": input.requested_secrets,
        "approved_egress": input.egress_profile,
        "policy_version": "test-embedded-v1",
    }
}

decision := d if {
    input.action_trust_verdict == "digest_ok"
    input.action_risk_level == "high"
    d := {
        "allow": true,
        "requires_approval": true,
        "approval_id": "test-approval-id",
        "allowed_sinks": input.requested_sinks,
        "approved_secrets": input.requested_secrets,
        "approved_egress": input.egress_profile,
        "budgets_after": {"calls_remaining": input.budgets_before.calls_remaining - 1},
        "policy_version": "test-embedded-v1",
    }
}
"#
    }

    /// Backing data for test PolicyInput construction (same pattern as
    /// the policy.rs test helper).
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
                scopes: vec!["tools:call".into()],
                required_scopes: vec![],
                sinks: vec!["api.example.com".into()],
                secrets: vec![],
                egress: EgressProfile::None,
                unresolved_domains: vec![],
                unresolved_paths: vec![],
            }
        }
    }

    impl TestCtx {
        fn input(&self, risk: RiskLevel) -> PolicyInput<'_> {
            PolicyInput {
                identity: PolicyIdentity {
                    principal: Arc::from("agent-1"),
                    session_id: Arc::from("sess-1"),
                    scopes: &self.scopes,
                    required_scopes: &self.required_scopes,
                },
                action: PolicyAction {
                    action_id: Arc::from("test_action"),
                    action_version: "0.1.0",
                    action_risk_level: risk,
                    action_trust_verdict: Arc::new(TrustVerdict::DigestOk),
                    action_category: "http",
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

    #[test]
    fn embedded_allow_low_risk() {
        let policy = EmbeddedPolicy::new(test_rego(), None);
        let ctx = TestCtx::default();
        let input = ctx.input(RiskLevel::Low);
        let decision = policy.evaluate(&input).unwrap();
        match decision {
            PolicyDecision::Allow { budgets_after, .. } => {
                assert_eq!(budgets_after.calls_remaining, 9);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn embedded_approval_high_risk() {
        let policy = EmbeddedPolicy::new(test_rego(), None);
        let ctx = TestCtx::default();
        let input = ctx.input(RiskLevel::High);
        let decision = policy.evaluate(&input).unwrap();
        assert!(
            matches!(decision, PolicyDecision::PendingApproval { .. }),
            "high risk must require approval"
        );
    }

    #[test]
    fn embedded_deny_untrusted() {
        let policy = EmbeddedPolicy::new(test_rego(), None);
        let ctx = TestCtx::default();
        let mut input = ctx.input(RiskLevel::Low);
        input.action.action_trust_verdict = Arc::new(TrustVerdict::DigestMismatch {
            expected: "abc".into(),
            actual: "xyz".into(),
        });
        let result = policy.evaluate(&input);
        assert!(result.is_err(), "untrusted action must be denied");
    }

    #[test]
    fn reload_data_updates_decisions() {
        let rego = r#"
package latchgate
import rego.v1

decision := d if {
    input.action_id in data.acl.allowed_actions
    d := {
        "allow": true,
        "budgets_after": {"calls_remaining": 9},
        "allowed_sinks": [],
        "approved_secrets": [],
        "approved_egress": "none",
        "policy_version": "test",
    }
}

default decision := {"allow": false, "deny_reason": "not in ACL"}
"#;
        let data_v1 = r#"{"acl": {"allowed_actions": ["other_action"]}}"#;
        let policy = EmbeddedPolicy::new(rego, Some(data_v1));

        let ctx = TestCtx::default();
        let input = ctx.input(RiskLevel::Low);
        assert!(policy.evaluate(&input).is_err(), "must deny before reload");

        let data_v2 = r#"{"acl": {"allowed_actions": ["test_action"]}}"#;
        policy.reload_data(rego, Some(data_v2));

        let decision = policy.evaluate(&input).unwrap();
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    /// A malformed reload must be rejected, leaving the previously compiled
    /// policy active rather than crashing the gate.
    #[test]
    fn malformed_reload_is_rejected_and_keeps_previous_policy() {
        let policy = EmbeddedPolicy::new(test_rego(), None);
        let ctx = TestCtx::default();

        // Reload with un-parseable Rego — must be rejected.
        policy.reload_data("this is not valid rego {{{", None);

        // The original policy is still in force.
        let decision = policy.evaluate(&ctx.input(RiskLevel::Low)).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Allow { .. }),
            "previous policy must remain active after a rejected reload"
        );
    }

    /// Repeated evaluations reuse the per-thread engine. They must be fully
    /// independent — no interpreter scratch state may bleed between calls.
    #[test]
    fn repeated_evaluations_are_independent() {
        let policy = EmbeddedPolicy::new(test_rego(), None);
        let ctx = TestCtx::default();

        for _ in 0..256 {
            let input = ctx.input(RiskLevel::Low);
            match policy.evaluate(&input).unwrap() {
                PolicyDecision::Allow { budgets_after, .. } => {
                    assert_eq!(budgets_after.calls_remaining, 9);
                }
                other => panic!("expected stable Allow, got {other:?}"),
            }
        }
    }

    /// Concurrent evaluations across threads must each build and use their own
    /// thread-local engine without interference. Exercises the `Send + Sync`
    /// facade and the per-thread cache under contention.
    #[test]
    fn concurrent_evaluations_do_not_interfere() {
        let policy = Arc::new(EmbeddedPolicy::new(test_rego(), None));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let policy = Arc::clone(&policy);
            handles.push(std::thread::spawn(move || {
                let ctx = TestCtx::default();
                for _ in 0..128 {
                    let input = ctx.input(RiskLevel::Low);
                    assert!(matches!(
                        policy.evaluate(&input).unwrap(),
                        PolicyDecision::Allow { .. }
                    ));
                }
            }));
        }

        for h in handles {
            h.join().expect("evaluation thread panicked");
        }
    }

    /// The shipped policy detects sensitive filesystem paths with `glob.match`.
    /// That builtin is only registered when regorus is compiled with the
    /// `glob` feature; without it, evaluation of any `fs` action aborts and is
    /// reported as an engine failure. This guards that the embedded evaluator
    /// actually has `glob.match` and that it carries OPA-equivalent semantics.
    fn glob_rego() -> &'static str {
        r#"
package latchgate

import rego.v1

default decision := {
    "allow": false,
    "deny_reason": "default deny"
}

_fs_path_sensitive if {
    input.action_category == "fs"
    glob.match("**/.env", [], object.get(input, "fs_path", ""))
}

_fs_path_sensitive if {
    input.action_category == "fs"
    glob.match("**/.ssh/**", [], object.get(input, "fs_path", ""))
}

# Sensitive path => approval, regardless of risk.
decision := d if {
    input.action_category == "fs"
    _fs_path_sensitive
    d := {
        "allow": true,
        "requires_approval": true,
        "approval_id": "fs-sensitive",
        "allowed_sinks": [],
        "approved_secrets": [],
        "approved_egress": input.egress_profile,
        "budgets_after": {"calls_remaining": input.budgets_before.calls_remaining - 1},
        "policy_version": "test-glob-v1",
    }
}

# Benign fs path => allow.
decision := d if {
    input.action_category == "fs"
    not _fs_path_sensitive
    d := {
        "allow": true,
        "allowed_sinks": [],
        "approved_secrets": [],
        "approved_egress": input.egress_profile,
        "budgets_after": {"calls_remaining": input.budgets_before.calls_remaining - 1},
        "policy_version": "test-glob-v1",
    }
}
"#
    }

    /// Build a PolicyInput for an `fs` action at the given path.
    fn fs_input<'a>(ctx: &'a TestCtx, fs_path: &'a str) -> PolicyInput<'a> {
        let mut input = ctx.input(RiskLevel::Low);
        input.action.action_category = "fs";
        input.request.fs_path = Some(fs_path);
        input
    }

    #[test]
    fn embedded_glob_match_allows_benign_fs_path() {
        let policy = EmbeddedPolicy::new(glob_rego(), None);
        let ctx = TestCtx::default();
        let decision = policy
            .evaluate(&fs_input(&ctx, "src/main.rs"))
            .expect("benign fs path must evaluate without engine failure");
        assert!(
            matches!(decision, PolicyDecision::Allow { .. }),
            "benign fs path must be allowed, got {decision:?}"
        );
    }

    #[test]
    fn embedded_glob_match_gates_sensitive_fs_path() {
        let policy = EmbeddedPolicy::new(glob_rego(), None);
        let ctx = TestCtx::default();

        for sensitive in ["config/.env", "home/user/.ssh/id_ed25519"] {
            let decision = policy
                .evaluate(&fs_input(&ctx, sensitive))
                .expect("sensitive fs path must evaluate without engine failure");
            assert!(
                matches!(decision, PolicyDecision::PendingApproval { .. }),
                "sensitive path '{sensitive}' must require approval, got {decision:?}"
            );
        }
    }
}
