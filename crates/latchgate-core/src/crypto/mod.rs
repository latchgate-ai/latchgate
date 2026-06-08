//! Cryptographic hashing, canonicalization, and JSON structure primitives.
//!
//! Groups the crate's data-integrity facilities:
//!
//! - [`hash`] — SHA-256 and timing-safe comparison.
//! - [`canonical`] — JCS (RFC 8785) canonicalization with DoS limits.
//! - [`json`] — JSON tree inspection and RFC 8259 §7 string escaping.

mod hash;

pub mod canonical;
pub mod json;

// Re-export hash primitives at the `crypto::` level so existing paths
// like `latchgate_core::crypto::sha256_digest` continue to resolve.
pub use hash::{constant_time_eq, sha256_digest, sha256_hex, sha256_raw};
