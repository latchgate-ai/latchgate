//! Cryptographic hashing utilities.
//!
//! - [`constant_time_eq`] — timing-safe byte comparison (single implementation,
//!   used by all secret-comparing call sites).
//! - [`sha256_raw`] — compute SHA-256 and return raw `[u8; 32]` bytes.
//! - [`sha256_hex`] — format pre-computed hash bytes as `sha256:<hex>`.
//! - [`sha256_digest`] — compute SHA-256 and return `sha256:<hex>`.
//!
//! Ed25519 key management (signing, key-file permissions) has moved to
//! `latchgate-crypto`.

/// Constant-time byte comparison. Prevents timing side-channels when
/// comparing secrets (operator API keys, HMAC digests, etc.).
///
/// Returns `true` iff `a` and `b` have identical content.
///
/// SECURITY: this is the single implementation. `latchgate-api` modules
/// import this instead of maintaining local copies. `subtle::ConstantTimeEq`
/// for `[u8]` handles differing-length inputs correctly (returns `false` in
/// constant time), so no pre-hashing is needed.
#[inline]
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Compute SHA-256 of `data` and return the raw 32-byte digest.
///
/// Use when callers need the raw bytes (e.g. storing content hashes in
/// struct fields for later comparison). For the prefixed hex string
/// representation (`sha256:<hex>`), use [`sha256_digest`] instead.
#[inline]
#[must_use]
pub fn sha256_raw(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Format pre-computed hash bytes as `sha256:<hex>`.
///
/// Use when the SHA-256 hash is already computed (e.g. from a multi-step
/// `Sha256::new()` / `.update()` / `.finalize()` chain or from
/// host-observed effect data).
#[inline]
#[must_use]
pub fn sha256_hex(hash_bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", hex::encode(hash_bytes))
}

/// Compute SHA-256 of `data` and return `sha256:<hex>`.
///
/// Single canonical implementation for the common pattern of hashing raw
/// bytes and formatting the result as a prefixed hex digest string. All
/// call sites that previously inlined `format!("sha256:{}", hex::encode(Sha256::digest(...)))`
/// should use this function.
#[must_use]
pub fn sha256_digest(data: &[u8]) -> String {
    sha256_hex(sha256_raw(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_equal_values() {
        assert!(constant_time_eq(b"secret", b"secret"));
    }

    #[test]
    fn constant_time_eq_different_values_same_length() {
        assert!(!constant_time_eq(b"secret", b"secreT"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer-value"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_one_empty() {
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn sha256_raw_returns_32_bytes() {
        let hash = sha256_raw(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn sha256_raw_deterministic() {
        assert_eq!(sha256_raw(b"hello"), sha256_raw(b"hello"));
    }

    #[test]
    fn sha256_raw_known_vector() {
        // SHA-256("") = e3b0c442...
        let hash = sha256_raw(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }

    #[test]
    fn sha256_digest_deterministic() {
        let d1 = sha256_digest(b"hello");
        let d2 = sha256_digest(b"hello");
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn sha256_digest_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let d = sha256_digest(b"");
        assert_eq!(
            d,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_digest_matches_sha256_raw() {
        let raw = sha256_raw(b"test data");
        let from_raw = sha256_hex(raw);
        let direct = sha256_digest(b"test data");
        assert_eq!(from_raw, direct);
    }

    #[test]
    fn sha256_hex_formats_raw_bytes() {
        let raw = [0xab, 0xcd];
        assert_eq!(sha256_hex(raw), "sha256:abcd");
    }
}
