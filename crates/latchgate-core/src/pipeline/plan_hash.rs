//! Shared plan-hash primitives for deterministic, collision-resistant hashing.
//!
//! Both `ApprovedExecutionPlan::compute_hash()` and
//! `ExecutionGrant::compute_plan_hash()` use `PlanHasher` to build their
//! respective hashes. This module is the **single source of truth** for the
//! hashing algorithm — field order, length-prefixing, JSON serialization,
//! and separator conventions.
//!
//! # Design constraints
//!
//! - **No `unwrap_or_default()` on serialization.** A serialization failure
//!   in a hash input silently changes the hash value, which means a tampered
//!   or corrupt field produces a valid (but wrong) hash instead of a hard
//!   error. All JSON serialization goes through [`PlanHasher::hash_json`],
//!   which treats serialization failure as a hash-poisoning event.
//!
//! - **Length-prefixed lists.** `["ab","cd"]` and `["abc","d"]` must hash
//!   differently. Every list element is preceded by its byte length as a
//!   little-endian u32.
//!
//! - **Explicit separators.** A `|` byte separates logical field groups to
//!   prevent adjacent fields from bleeding into each other.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Accumulates SHA-256 hash state with typed methods for plan-level hashing.
///
/// Callers create a hasher with a domain-separation prefix, feed fields
/// through the typed methods, and call `finalize()` to get the hex digest.
pub struct PlanHasher {
    inner: Sha256,
}

impl PlanHasher {
    /// Create a new hasher with the given domain-separation prefix.
    ///
    /// SECURITY: the prefix MUST be unique across all SHA-256 consumers in
    /// the codebase. Different artifact types (plan vs grant) MUST use
    /// different prefixes.
    pub fn new(domain_prefix: &[u8]) -> Self {
        let mut inner = Sha256::new();
        inner.update(domain_prefix);
        Self { inner }
    }

    /// Hash a string field, followed by a `|` separator.
    pub fn hash_str(&mut self, value: &str) {
        self.inner.update(value.as_bytes());
        self.inner.update(b"|");
    }

    /// Hash an optional string field with a tag prefix.
    ///
    /// If `Some`, hashes `tag + value + |`. If `None`, hashes only `|`.
    /// The tag provides domain separation within the hash to distinguish
    /// "field is None" from "field is empty string".
    pub fn hash_optional_tagged(&mut self, tag: &[u8], value: Option<&str>) {
        if let Some(v) = value {
            self.inner.update(tag);
            self.inner.update(v.as_bytes());
        }
        self.inner.update(b"|");
    }

    /// Hash a length-prefixed list of strings.
    ///
    /// Format: `len(list) as u32 LE` then for each element:
    /// `len(element) as u32 LE + element bytes`.
    ///
    /// Followed by a `|` separator.
    pub fn hash_string_list<S: AsRef<str>>(&mut self, items: &[S]) {
        self.inner.update((items.len() as u32).to_le_bytes());
        for item in items {
            let s = item.as_ref();
            self.inner.update((s.len() as u32).to_le_bytes());
            self.inner.update(s.as_bytes());
        }
        self.inner.update(b"|");
    }

    /// Hash a serializable value as JSON, followed by a `|` separator.
    ///
    /// SECURITY: serialization failure poisons the hash with an
    /// unambiguous sentinel that cannot collide with valid JSON output.
    /// This is strictly better than `unwrap_or_default()`, which produces
    /// `""` or `"null"` — values that COULD appear in legitimate data and
    /// would silently produce a "valid" but wrong hash.
    pub fn hash_json<T: Serialize>(&mut self, value: &T) {
        match serde_json::to_string(value) {
            Ok(json) => self.inner.update(json.as_bytes()),
            Err(e) => {
                tracing::error!(
                    "SECURITY: JSON serialization failed in plan hash — \
                     hash is poisoned and will not match any legitimate value: {e}"
                );
                // Poison prefix that cannot appear in valid serde_json output.
                self.inner
                    .update(b"\xff\xfePLAN_HASH_SERIALIZATION_FAILURE\xff\xfe");
            }
        }
        self.inner.update(b"|");
    }

    /// Hash an optional JSON value. `None` hashes as the empty group `|`.
    pub fn hash_optional_json<T: Serialize>(&mut self, value: Option<&T>) {
        if let Some(v) = value {
            self.hash_json(v);
        } else {
            self.inner.update(b"|");
        }
    }

    /// Hash a `usize` as little-endian u64 bytes, followed by `|`.
    pub fn hash_usize(&mut self, value: usize) {
        self.inner.update((value as u64).to_le_bytes());
        self.inner.update(b"|");
    }

    /// Hash an `i64` as little-endian bytes (no separator — call
    /// consecutively for adjacent integer fields).
    pub fn hash_i64(&mut self, value: i64) {
        self.inner.update(value.to_le_bytes());
    }

    /// Hash a `DateTime<Utc>` in RFC 3339 format, followed by `|`.
    pub fn hash_datetime(&mut self, dt: &chrono::DateTime<chrono::Utc>) {
        self.inner.update(dt.to_rfc3339().as_bytes());
        self.inner.update(b"|");
    }

    /// Hash a boolean as a single byte (`0x01` / `0x00`).
    pub fn hash_bool(&mut self, value: bool) {
        self.inner.update([u8::from(value)]);
    }

    /// Hash a u32 length prefix.
    pub fn hash_u32_len(&mut self, len: usize) {
        self.inner.update((len as u32).to_le_bytes());
    }

    /// Hash raw bytes without any separator.
    pub fn hash_raw(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the hasher and return the hex-encoded SHA-256 digest.
    #[must_use]
    pub fn finalize(self) -> String {
        hex::encode(self.inner.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let mut h1 = PlanHasher::new(b"test:");
        h1.hash_str("hello");
        let mut h2 = PlanHasher::new(b"test:");
        h2.hash_str("hello");
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn domain_prefix_changes_hash() {
        let mut h1 = PlanHasher::new(b"prefix-a:");
        h1.hash_str("data");
        let mut h2 = PlanHasher::new(b"prefix-b:");
        h2.hash_str("data");
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn length_prefixed_lists_prevent_collisions() {
        let mut h1 = PlanHasher::new(b"test:");
        h1.hash_string_list(&["ab", "cd"]);
        let mut h2 = PlanHasher::new(b"test:");
        h2.hash_string_list(&["abc", "d"]);
        assert_ne!(
            h1.finalize(),
            h2.finalize(),
            "different element splits of the same bytes must hash differently"
        );
    }

    #[test]
    fn empty_list_differs_from_single_empty_element() {
        let mut h1 = PlanHasher::new(b"test:");
        h1.hash_string_list::<&str>(&[]);
        let mut h2 = PlanHasher::new(b"test:");
        h2.hash_string_list(&[""]);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn optional_tagged_none_vs_empty() {
        let mut h1 = PlanHasher::new(b"test:");
        h1.hash_optional_tagged(b"tag:", None);
        let mut h2 = PlanHasher::new(b"test:");
        h2.hash_optional_tagged(b"tag:", Some(""));
        assert_ne!(
            h1.finalize(),
            h2.finalize(),
            "None and Some(\"\") must hash differently"
        );
    }

    #[test]
    fn json_serialization_failure_poisons_hash() {
        // f64::NAN is not valid JSON — serde_json::to_string returns Err.
        let mut h1 = PlanHasher::new(b"test:");
        h1.hash_json(&f64::NAN);
        let mut h2 = PlanHasher::new(b"test:");
        h2.hash_json(&0.0_f64);
        assert_ne!(
            h1.finalize(),
            h2.finalize(),
            "serialization failure must produce a different hash"
        );
    }

    #[test]
    fn hex_encoded_sha256_length() {
        let h = PlanHasher::new(b"test:");
        assert_eq!(h.finalize().len(), 64);
    }
}
