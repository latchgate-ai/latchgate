//! Input and output types for pipeline steps.

use std::sync::Arc;

use latchgate_core::{BudgetSnapshot, EgressProfile, TrustVerdict};
use latchgate_policy::PolicyDecision;
use latchgate_providers::RunTask;
use latchgate_registry::ActionSpec;

/// Output of [`super::step_resolve_action`].
#[derive(Debug)]
pub(crate) struct ResolveActionOutput<'a> {
    /// Action manifest borrowed from the registry. The registry holds
    /// manifests for the entire request lifecycle, so borrowing here
    /// avoids an `Arc` clone per request on the hot path.
    pub(crate) manifest: &'a ActionSpec,
    /// Canonical egress profile derived from the manifest.
    pub(crate) egress_profile: EgressProfile,
}

/// Output of [`super::step_verify_trust`].
///
/// The trust verdict is carried forward as a pre-formatted `&'static str`
/// because it is written into audit events and the eventual
/// [`AuthorizedExecution`], and every caller wants the same string form.
pub(crate) struct VerifyTrustOutput {
    pub(crate) trust_verdict_str: &'static str,
}

/// Output of [`super::step_validate_and_hash`].
#[derive(Debug)]
pub(crate) struct ValidateAndHashOutput {
    /// Parsed request body after schema validation. Wrapped in `Arc` so
    /// downstream steps that need the value (approval plan, domain event)
    /// clone via refcount bump instead of deep-copying the JSON tree.
    pub(crate) request_body: Arc<serde_json::Value>,
    /// SHA-256 of the canonicalised (JCS) request body.
    pub(crate) request_hash: Arc<str>,
    /// Schema identifier for audit / receipt binding. `None` when the
    /// action has no declared request schema.
    pub(crate) schema_id: Option<String>,
}

/// Output of [`super::step_domain_precheck`].
pub(crate) struct DomainPrecheckOutput {
    /// Unresolved domain templates found in the request (pre-policy).
    /// Forwarded to OPA so policy can deny or trigger learned-domain flow.
    pub(crate) unresolved_domains: Vec<String>,
}

/// Output of [`super::step_path_precheck`].
///
/// Carries compiled glob patterns so `step_build_run_task` can reuse them
/// for `FsHostConfig` construction without re-querying learned paths from
/// SQLite or re-compiling globs.
pub(crate) struct PathPrecheckOutput {
    /// Filesystem path extracted from the request body.
    pub(crate) fs_path: Option<String>,
    /// Paths not in the effective allowlist (manifest allowed_paths only
    /// for now; learned paths added in a later commit).
    pub(crate) unresolved_paths: Vec<String>,
    /// Compiled allowed-path patterns (manifest ∪ learned). `None` when
    /// the action has no `fs` config.
    pub(crate) compiled_allowed: Option<Vec<latchgate_core::fs_path::GlobPattern>>,
    /// Compiled denied-path patterns. `None` when the action has no `fs`
    /// config.
    pub(crate) compiled_denied: Option<Vec<latchgate_core::fs_path::GlobPattern>>,
}

/// Output of [`super::step_evaluate_policy`].
///
/// Holds the policy decision plus the budget snapshot taken immediately
/// before OPA evaluation, which is needed later for `BudgetReservation`.
pub(crate) struct EvaluatePolicyOutput {
    pub(crate) decision: PolicyDecision,
    pub(crate) budgets_before: BudgetSnapshot,
    pub(crate) budgets_after_opa: BudgetSnapshot,
}

/// Output of [`super::step_debit_budget`].
pub(crate) struct DebitBudgetOutput {
    pub(crate) budgets_after: BudgetSnapshot,
}

/// Output of [`super::step_build_run_task`].
pub(crate) struct BuildRunTaskOutput {
    pub(crate) grant: latchgate_core::ExecutionGrant,
    pub(crate) task: RunTask,
    /// Concrete sink domains (manifest + learned merged) for the dispatched execution.
    pub(crate) concrete_sinks: Vec<Arc<str>>,
}

/// Policy-approved capabilities for an execution. Groups the three
/// capability fields that always travel together (sinks, secrets, egress).
pub(crate) struct PolicyApproved {
    pub(crate) allowed_sinks: Vec<Arc<str>>,
    pub(crate) approved_secrets: Vec<Arc<str>>,
    pub(crate) approved_egress: EgressProfile,
}

/// Input to [`super::step_evaluate_policy`].
pub(crate) struct EvaluatePolicyInput<'a> {
    pub(crate) trust_verdict: Arc<TrustVerdict>,
    pub(crate) request_hash: &'a str,
    pub(crate) request_body: &'a serde_json::Value,
    pub(crate) egress_profile: &'a EgressProfile,
    pub(crate) unresolved_domains: &'a [String],
    pub(crate) fs_path: Option<String>,
    pub(crate) unresolved_paths: &'a [String],
}

/// Input to [`super::step_store_pending_approval`].
pub(crate) struct StorePendingApprovalInput {
    pub(crate) request_hash: Arc<str>,
    pub(crate) request_body: Arc<serde_json::Value>,
    pub(crate) budgets_before: BudgetSnapshot,
    pub(crate) trust_verdict: Arc<TrustVerdict>,
    pub(crate) approval_id: Arc<str>,
    pub(crate) policy: PolicyApproved,
    pub(crate) policy_budgets_after: BudgetSnapshot,
    pub(crate) policy_version: Option<Arc<str>>,
    pub(crate) unresolved_domains: Vec<String>,
    pub(crate) unresolved_paths: Vec<String>,
}

/// Input to [`super::step_build_run_task`].
pub(crate) struct BuildRunTaskInput<'a> {
    pub(crate) request_body: &'a serde_json::Value,
    pub(crate) request_hash: &'a str,
    pub(crate) policy: &'a PolicyApproved,
    pub(crate) budgets_before: &'a BudgetSnapshot,
    pub(crate) budgets_after: &'a BudgetSnapshot,
    pub(crate) policy_version: Option<Arc<str>>,
    /// Pre-compiled fs allowed-path patterns from [`super::step_path_precheck`].
    /// `None` when the action has no `fs` config. Avoids re-querying
    /// learned paths and re-compiling globs on the hot path.
    pub(crate) compiled_fs_allowed: Option<Vec<latchgate_core::fs_path::GlobPattern>>,
    /// Pre-compiled fs denied-path patterns from [`super::step_path_precheck`].
    pub(crate) compiled_fs_denied: Option<Vec<latchgate_core::fs_path::GlobPattern>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_action_output_fields_accessible() {
        fn _accepts(_manifest: &ActionSpec, _egress: EgressProfile) {}
        fn _prove_destructurable(out: ResolveActionOutput<'_>) {
            let ResolveActionOutput {
                manifest,
                egress_profile,
            } = out;
            _accepts(manifest, egress_profile);
        }
    }

    #[test]
    fn validate_and_hash_output_fields_accessible() {
        fn _prove_destructurable(out: ValidateAndHashOutput) {
            let ValidateAndHashOutput {
                request_body,
                request_hash,
                schema_id,
            } = out;
            let _ = (request_body, request_hash, schema_id);
        }
    }

    #[test]
    fn evaluate_policy_output_fields_accessible() {
        fn _prove_destructurable(out: EvaluatePolicyOutput) {
            let EvaluatePolicyOutput {
                decision,
                budgets_before,
                budgets_after_opa,
            } = out;
            let _ = (decision, budgets_before, budgets_after_opa);
        }
    }

    #[test]
    fn build_run_task_output_fields_accessible() {
        fn _prove_destructurable(out: BuildRunTaskOutput) {
            let BuildRunTaskOutput {
                grant,
                task,
                concrete_sinks,
            } = out;
            let _ = (grant, task, concrete_sinks);
        }
    }

    #[test]
    fn debit_budget_output_exposes_budgets_after() {
        fn _prove_field(out: DebitBudgetOutput) -> BudgetSnapshot {
            out.budgets_after
        }
    }
}
