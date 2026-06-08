//! Domain events emitted by the enforcement kernel.
//!
//! These are the kernel's outbound signals about security-relevant state
//! changes. The webhook layer formats them directly into JSON payloads
//! (with secret redaction for `ApprovalPending`); other consumers (metrics,
//! audit enrichment) can subscribe independently.
//!
//! # Design

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Canonical event type identifier.
///
/// Serializes to the dotted string form used in TOML config and JSON
/// payloads (e.g., `"approval.pending"`, `"action.denied"`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "approval.pending")]
    ApprovalPending,
    #[serde(rename = "approval.granted")]
    ApprovalGranted,
    #[serde(rename = "approval.denied")]
    ApprovalDenied,
    #[serde(rename = "approval.expired")]
    ApprovalExpired,
    #[serde(rename = "action.denied")]
    ActionDenied,
    #[serde(rename = "action.executed")]
    ActionExecuted,
    #[serde(rename = "action.failed")]
    ActionFailed,
    #[serde(rename = "revocation")]
    Revocation,
    #[serde(rename = "budget.exhausted")]
    BudgetExhausted,
    #[serde(rename = "budget.rollback_failed")]
    BudgetRollbackFailed,
}

impl EventKind {
    /// All event kinds.
    pub const ALL: &[EventKind] = &[
        Self::ApprovalPending,
        Self::ApprovalGranted,
        Self::ApprovalDenied,
        Self::ApprovalExpired,
        Self::ActionDenied,
        Self::ActionExecuted,
        Self::ActionFailed,
        Self::Revocation,
        Self::BudgetExhausted,
        Self::BudgetRollbackFailed,
    ];

    // Compile-time guard: adding a variant to `EventKind` without
    // extending `ALL` is a silent subscription gap. Bump when adding.
    const _VARIANT_COUNT_CHECK: () = assert!(Self::ALL.len() == 10);

    /// Canonical dotted string form (e.g., `"approval.pending"`).
    ///
    /// Matches the `#[serde(rename)]` values — suitable for log lines,
    /// metrics labels, and JSON `type` fields.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApprovalPending => "approval.pending",
            Self::ApprovalGranted => "approval.granted",
            Self::ApprovalDenied => "approval.denied",
            Self::ApprovalExpired => "approval.expired",
            Self::ActionDenied => "action.denied",
            Self::ActionExecuted => "action.executed",
            Self::ActionFailed => "action.failed",
            Self::Revocation => "revocation",
            Self::BudgetExhausted => "budget.exhausted",
            Self::BudgetRollbackFailed => "budget.rollback_failed",
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Security-relevant event emitted by the enforcement kernel.
///
/// Each variant carries only the data the kernel already has at the emit
/// site. Formatting, redaction, and delivery are the webhook layer's job.
///
/// # `Arc<str>` fields
///
/// Event fields are `Arc<str>` because they are cloned from kernel types
/// (`ExecutionGrant`, `AuthContext`) that already store `Arc<str>`. This
/// makes event construction a series of `Arc::clone` calls (pointer-width
/// atomic increments) rather than heap allocations. The events are created
/// once, borrowed by `EventSink::emit`, and dropped — they are *not*
/// shared across threads. The `Arc` is inherited for zero-copy construction,
/// not for shared ownership.
/// Payload for [`DomainEvent::ApprovalPending`].
///
/// Extracted into a named struct because the approval-pending path carries
/// significantly more context than other events (request body for operator
/// review, secret names for redaction, unresolved domains/paths for
/// learned-allowlist prompts). A 12-field enum variant forces every match
/// arm to destructure all fields; a struct allows field access by name.
#[must_use]
#[derive(Debug, Clone)]
pub struct ApprovalPendingEvent {
    pub approval_id: Arc<str>,
    pub action_id: Arc<str>,
    pub principal: Arc<str>,
    pub owner: Option<Arc<str>>,
    pub risk_level: Arc<str>,
    pub request_hash: Arc<str>,
    pub expires_at: Arc<str>,
    /// Raw request body — the formatter redacts sensitive fields.
    pub request_body: serde_json::Value,
    /// Declared secret names for redaction.
    pub secret_names: Vec<String>,
    /// Domains in the request that are not in the manifest allowlist.
    pub unresolved_domains: Vec<String>,
    /// Paths in the request that are not in the manifest allowlist.
    pub unresolved_paths: Vec<String>,
    pub trace_id: Arc<str>,
}

#[must_use = "domain events must be emitted — dropping one loses audit and webhook delivery"]
#[non_exhaustive]
#[derive(Debug, Clone)]
/// Domain events emitted by the enforcement pipeline.
///
/// # Why `Arc<str>` fields
///
/// All string fields use `Arc<str>` inherited from the kernel's
/// `ExecutionGrant` and `ExecutionPlanCore` types. This is **not** just
/// zero-copy convenience — `WebhookDispatcher::emit` clones the event to
/// send it across a bounded channel (`dispatcher.rs`), so the `Arc<str>`
/// fields are amortised by that clone. Without `Arc<str>`, every webhook
/// delivery would deep-copy every string in the event.
pub enum DomainEvent {
    /// Policy denied an action call.
    ActionDenied {
        action_id: Arc<str>,
        principal: Arc<str>,
        owner: Option<Arc<str>>,
        deny_reason: Arc<str>,
        trace_id: Arc<str>,
    },

    /// Action dispatched and completed (success or provider failure recorded).
    ActionExecuted {
        action_id: Arc<str>,
        principal: Arc<str>,
        owner: Option<Arc<str>>,
        receipt_id: Arc<str>,
        verification_outcome: Arc<str>,
        trace_id: Arc<str>,
    },

    /// Action dispatch or post-dispatch step failed.
    ActionFailed {
        action_id: Arc<str>,
        principal: Arc<str>,
        owner: Option<Arc<str>>,
        error_class: Arc<str>,
        trace_id: Arc<str>,
    },

    /// OPA returned pending_approval — action awaits human decision.
    ApprovalPending(ApprovalPendingEvent),

    /// Operator approved an action — execution completed.
    ApprovalGranted {
        approval_id: Arc<str>,
        action_id: Arc<str>,
        approved_by: Arc<str>,
        receipt_id: Arc<str>,
        trace_id: Arc<str>,
    },

    /// Operator denied a pending approval.
    ApprovalDenied {
        approval_id: Arc<str>,
        action_id: Arc<str>,
        denied_by: Arc<str>,
        reason: Arc<str>,
        trace_id: Arc<str>,
    },

    /// Session budget exhausted — action denied.
    BudgetExhausted {
        action_id: Arc<str>,
        principal: Arc<str>,
        owner: Option<Arc<str>>,
        session_id: Arc<str>,
    },

    /// Budget rollback failed after a post-debit error.
    ///
    /// The debit was charged but the execution did not complete. The
    /// rollback attempt to refund the operator's budget failed (typically
    /// due to Redis unavailability). This creates a budget discrepancy
    /// that operators must reconcile.
    BudgetRollbackFailed {
        session_id: Arc<str>,
        error: Arc<str>,
        trace_id: Arc<str>,
        /// Label identifying which post-debit error path triggered the
        /// rollback (e.g. `"build_run_task_error"`, `"dispatch_error"`).
        label: Arc<str>,
    },

    /// Revocation epoch advanced — all outstanding grants invalidated.
    Revocation {
        old_epoch: u64,
        new_epoch: u64,
        operator_id: Arc<str>,
    },

    /// Pending approval expired without operator action.
    ApprovalExpired {
        approval_id: Arc<str>,
        action_id: Arc<str>,
        principal: Arc<str>,
        owner: Option<Arc<str>>,
        created_at: Arc<str>,
        expired_at: Arc<str>,
    },
}

impl DomainEvent {
    /// The canonical event kind for this event.
    ///
    /// Used for subscription matching, payload type fields, and metrics labels.
    pub fn kind(&self) -> EventKind {
        match self {
            Self::ActionDenied { .. } => EventKind::ActionDenied,
            Self::ActionExecuted { .. } => EventKind::ActionExecuted,
            Self::ActionFailed { .. } => EventKind::ActionFailed,
            Self::ApprovalPending(..) => EventKind::ApprovalPending,
            Self::ApprovalGranted { .. } => EventKind::ApprovalGranted,
            Self::ApprovalDenied { .. } => EventKind::ApprovalDenied,
            Self::ApprovalExpired { .. } => EventKind::ApprovalExpired,
            Self::BudgetExhausted { .. } => EventKind::BudgetExhausted,
            Self::BudgetRollbackFailed { .. } => EventKind::BudgetRollbackFailed,
            Self::Revocation { .. } => EventKind::Revocation,
        }
    }
}

/// Trait for dispatching domain events to external consumers.
///
/// Implemented by `WebhookDispatcher` (in `latchgate-webhooks`). The kernel
/// dispatches through this trait, keeping the webhook HTTP stack out of the
/// kernel's dependency tree.
///
/// # Contract
///
/// - `emit` is non-blocking and infallible from the caller's perspective.
///   Implementations must handle errors internally (log, drop, queue).
/// - Implementations must be `Send + Sync` for use inside `Arc<dyn EventSink>`.
pub trait EventSink: Send + Sync {
    /// Dispatch a domain event. Non-blocking, fire-and-forget.
    fn emit(&self, event: &DomainEvent);
}
