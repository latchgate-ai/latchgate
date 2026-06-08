//! Typed identifiers used throughout the LatchGate pipeline.
//!
//! Newtype wrappers over `Arc<str>` prevent mixing up `TraceId` with `SessionId`
//! with `LeaseJti` — the compiler catches mistakes at zero runtime cost.
//!
//! All IDs are backed by UUID v7 (time-ordered, monotonic), which is suitable
//! for trace correlation and audit log ordering. Do NOT use these as
//! cryptographic secrets — for nonces/jti use `rand::OsRng` directly.
//!
//! The `Arc<str>` backing makes clones a pointer-width atomic increment
//! instead of a heap allocation — the right trade-off for write-once,
//! clone-many identifiers that appear in every audit event and log line.

use std::sync::Arc;

/// Define a typed string ID backed by `Arc<str>`.
///
/// Generated IDs are time-sortable and unique within the lifetime of the
/// system. The `Display` impl writes the inner string, making them safe to
/// embed in log lines and JSON without any extra formatting.
macro_rules! define_id {
    ($name:ident, $doc:literal) => {
        #[must_use]
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub struct $name(Arc<str>);

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Generate a new time-ordered ID using UUID v7.
            ///
            /// Uses a stack buffer for the hyphenated format, then allocates
            /// a single `Arc<str>` — one heap allocation total.
            pub fn new() -> Self {
                let uuid = uuid::Uuid::now_v7();
                let mut buf = [0u8; uuid::fmt::Hyphenated::LENGTH];
                let s = uuid.as_hyphenated().encode_lower(&mut buf);
                Self(Arc::from(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Clone the inner `Arc<str>` — a pointer-width atomic increment,
            /// not a heap allocation. Use this when passing the ID into a
            /// context that stores `Arc<str>` (e.g. `DomainEvent` fields).
            pub fn to_arc_str(&self) -> Arc<str> {
                Arc::clone(&self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(Arc::from(s))
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(Arc::from(s))
            }
        }

        impl From<Arc<str>> for $name {
            fn from(arc: Arc<str>) -> Self {
                Self(arc)
            }
        }
    };
}

define_id!(
    TraceId,
    "Trace identifier propagated through the full pipeline. \
     Appears in every audit event, log line, and API response header."
);

define_id!(
    SessionId,
    "Agent session identifier. Scopes stateful budgets and approval context. \
     Carried in the Lease JWT as a custom claim."
);

define_id!(
    LeaseJti,
    "JWT ID (`jti`) of a Lease token. Used as the key in the anti-replay \
     cache (Redis SETNX) and the revocation denylist."
);

define_id!(
    ApprovalId,
    "Identifier for a pending human-approval request. \
     Returned in the `PENDING_APPROVAL` response and used by `latch approve`."
);

define_id!(
    GrantId,
    "Identifier for an issued ExecutionGrant. \
     Binds the approved execution plan and correlates grant => receipt => evidence."
);

define_id!(
    ReceiptId,
    "Identifier for a signed ExecutionReceipt. \
     Correlates the durable outcome record with its originating grant."
);
