#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Core domain types, canonical hashing, and security primitives for LatchGate.
//!
//! This is the **leaf crate** — it has no dependencies on other LatchGate
//! crates. Every other crate in the workspace depends on `latchgate-core`
//! for shared types and utilities.

pub(crate) mod atomic;
pub mod crypto;
pub(crate) mod domain_event;
pub mod fs_path;
pub mod host_observed;
pub(crate) mod manifest_types;
pub mod net;
pub mod paths;
pub(crate) mod pipeline;
pub(crate) mod policy_data;
pub(crate) mod sanitize;
pub mod security_constants;
pub(crate) mod sqlite_init;
pub mod types;

// ── Typed identifiers ───────────────────────────────────────────────────────

pub use types::{ApprovalId, GrantId, LeaseJti, ReceiptId, SessionId, TraceId};

// ── Core contracts ──────────────────────────────────────────────────────────

pub use pipeline::{
    ApprovedExecutionPlan, BudgetReservation, BudgetSnapshot, ExecutionGrant,
    ExecutionGrantBuilder, ExecutionPlanCore, ExecutionReceipt, FailureClass, GrantIdentity,
    NormalizedResult, ReceiptSignatureStatus, TrustError, VerificationOutcome,
};

// ── Domain events ───────────────────────────────────────────────────────────

pub use domain_event::{ApprovalPendingEvent, DomainEvent, EventKind, EventSink};
pub use host_observed::FsOperation;

// ── Input validation ────────────────────────────────────────────────────────

pub use fs_path::validate_path_glob_entry;
pub use net::{
    domain_in_allowlist, find_matching_entry, is_private_ip, parse_host_from_url,
    validate_domain_entry, validate_manifest_domain_entry,
};

// ── Manifest domain types ───────────────────────────────────────────────────

pub use manifest_types::{
    EgressProfile, ResourceLimits, ResourceLimitsError, RiskLevel, SecretDecl, TrustVerdict,
    VerifierKind,
};

// ── Cryptographic utilities ─────────────────────────────────────────────────

pub use crypto::{constant_time_eq, sha256_digest, sha256_hex, sha256_raw};

// ── Sanitization ────────────────────────────────────────────────────────────

pub use sanitize::sanitize_for_log;

// ── JSON serialization primitives ──────────────────────────────────────

pub use crypto::json::json_escape_into;

// ── SQLite PRAGMA configuration ─────────────────────────────────────────

pub use sqlite_init::SqliteInit;

// ── Atomic file I/O ─────────────────────────────────────────────────────

pub use atomic::{atomic_write, atomic_write_str};

// ── Policy data manipulation ────────────────────────────────────────────

pub use policy_data::{ensure_acl_object, increment_version};
