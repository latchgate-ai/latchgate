#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Enforcement pipeline orchestrator — the security kernel for LatchGate.
//!
//! The kernel owns the request lifecycle: authentication => registry lookup =>
//! trust verification => schema validation => policy evaluation => budget debit =>
//! grant issuance => provider dispatch => response validation => effect
//! verification => receipt signing => evidence write. Every step is fail-closed.
//!
//! # Public API
//!
//! - [`PipelineError`] — typed pipeline errors.
//! - [`run_action_call`] — the enforcement pipeline entry point.
//!
//! # Dependencies
//!
//! The kernel pulls together all other crates:
//! - `latchgate-core` — canonical hashing, config, domain types,
//!   `ExecutionGrant`, `ExecutionReceipt`
//! - `latchgate-auth` — Lease/DPoP authentication, replay detection
//! - `latchgate-registry` — manifest lookup, trust digest, schema validation
//! - `latchgate-policy` — OPA policy, budgets, approvals, trust enforcement
//! - `latchgate-providers` — sandboxed action execution (WASM)
//! - effect verification (http_status, fs_hash) — inline [`verification`] module
//! - `latchgate-ledger` — audit events, metrics

pub(crate) mod approved_execution;
pub(crate) mod coarse_clock;
pub(crate) mod execution;
pub mod init;
#[cfg(feature = "http")]
pub(crate) mod json_response;
pub(crate) mod learned_allowlist;
pub mod ops;
pub(crate) mod pipeline;
pub(crate) mod pipeline_audit;
pub(crate) mod rate_limit;
pub(crate) mod request;
pub(crate) mod state;
pub(crate) mod steps;
pub(crate) mod template;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub(crate) mod verification;

pub use approved_execution::{prepare_approved_execution, OperatorContext};
pub use coarse_clock::CoarseClock;
pub use execution::{
    execute_authorized_plan, ActionMetadata, ApprovalProvenance, AuthorizedExecution,
    BudgetContext, DecisionSource, ExecutionIdentity, ExecutionResponse, RequestContext,
    RuntimeInfo, VerificationInfo,
};
pub use pipeline::{run_action_call, ApprovalResponse, PipelineError};
pub use rate_limit::TokenBucketRateLimiter;
pub use rate_limit::{ExecuteRateLimitMap, LimiterKey, PeerId};
pub use state::{
    AppState, AppStateInit, AuthServices, AuthServicesInit, CryptoServices, CryptoServicesInit,
    EnforcementServices, EnforcementServicesInit, LifecycleInit, LifecycleState, RuntimeServices,
    RuntimeServicesInit, SessionFsRoot,
};
pub use template::{resolve_template, TemplateError};
pub use verification::{VerificationInput, VerifierRegistry};
