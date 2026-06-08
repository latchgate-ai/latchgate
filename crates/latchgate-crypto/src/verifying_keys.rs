//! Shared kid-indexed Ed25519 verifying key logic.
//!
//! Both [`GrantVerifyingKeyStore`](crate::grant_signer::GrantVerifyingKeyStore)
//! and [`VerifyingKeyStore`](crate::receipt_signer::VerifyingKeyStore) delegate
//! their kid-lookup → verify path here. A single implementation of the
//! security-critical scan-then-verify logic eliminates divergence risk.

use crate::ed25519::{verify_ed25519_sig, UnknownKeyId};

/// Entry in a kid-indexed verifying key collection.
///
/// `verifying_key()` returns `None` for entries whose key material failed to
/// parse at load time (e.g. corrupted JWKS hex). [`verify_by_kid`] treats
/// such entries as `Ok(false)` — the kid is known but verification cannot
/// succeed. This is fail-closed: the entry does not verify, and the caller
/// sees "invalid signature" rather than "unknown key".
pub(crate) trait HasVerifyingKey {
    fn kid(&self) -> &str;
    fn verifying_key(&self) -> Option<&ed25519_dalek::VerifyingKey>;
}

/// Verify an Ed25519 signature by kid lookup over a slice of entries.
///
/// Returns:
/// - `Ok(true)` — kid found, signature valid.
/// - `Ok(false)` — kid found, signature invalid or key unparseable.
/// - `Err(UnknownKeyId)` — kid not in the store (fail-closed).
///
pub(crate) fn verify_by_kid<E: HasVerifyingKey>(
    entries: &[E],
    kid: &str,
    message: &str,
    sig_hex: &str,
) -> Result<bool, UnknownKeyId> {
    let entry = entries
        .iter()
        .find(|e| e.kid() == kid)
        .ok_or(UnknownKeyId)?;
    match entry.verifying_key() {
        Some(key) => Ok(verify_ed25519_sig(key, message, sig_hex)),
        None => Ok(false),
    }
}

pub(crate) fn contains_kid<E: HasVerifyingKey>(entries: &[E], kid: &str) -> bool {
    entries.iter().any(|e| e.kid() == kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal entry for testing the shared logic in isolation.
    struct TestEntry {
        kid: String,
        key: Option<ed25519_dalek::VerifyingKey>,
    }

    impl HasVerifyingKey for TestEntry {
        fn kid(&self) -> &str {
            &self.kid
        }
        fn verifying_key(&self) -> Option<&ed25519_dalek::VerifyingKey> {
            self.key.as_ref()
        }
    }

    fn make_entry(signer: &crate::ed25519::Ed25519Signer<crate::ed25519::Grant>) -> TestEntry {
        TestEntry {
            kid: signer.kid(),
            key: Some(*signer.verifying_key()),
        }
    }

    fn corrupt_entry(kid: &str) -> TestEntry {
        TestEntry {
            kid: kid.to_string(),
            key: None,
        }
    }

    #[test]
    fn verify_valid_signature() {
        let signer = crate::GrantSigner::generate();
        let entries = [make_entry(&signer)];
        let hash = "test-hash";
        let sig = signer.sign(hash);
        assert_eq!(verify_by_kid(&entries, &signer.kid(), hash, &sig), Ok(true));
    }

    #[test]
    fn verify_tampered_signature_returns_false() {
        let signer = crate::GrantSigner::generate();
        let entries = [make_entry(&signer)];
        let hash = "test-hash";
        let sig = signer.sign(hash);
        let tampered = format!("ff{}", &sig[2..]);
        assert_eq!(
            verify_by_kid(&entries, &signer.kid(), hash, &tampered),
            Ok(false)
        );
    }

    #[test]
    fn unknown_kid_returns_err() {
        let signer = crate::GrantSigner::generate();
        let entries = [make_entry(&signer)];
        assert!(verify_by_kid(&entries, "nonexistent", "hash", "aabb").is_err());
    }

    #[test]
    fn corrupt_key_returns_ok_false() {
        let signer = crate::GrantSigner::generate();
        let entries = [corrupt_entry(&signer.kid())];
        let sig = signer.sign("hash");
        assert_eq!(
            verify_by_kid(&entries, &signer.kid(), "hash", &sig),
            Ok(false)
        );
    }

    #[test]
    fn empty_entries_returns_err() {
        let entries: Vec<TestEntry> = vec![];
        assert!(verify_by_kid(&entries, "any-kid", "hash", "aabb").is_err());
    }

    #[test]
    fn contains_kid_present() {
        let signer = crate::GrantSigner::generate();
        let entries = [make_entry(&signer)];
        assert!(contains_kid(&entries, &signer.kid()));
    }

    #[test]
    fn contains_kid_absent() {
        let entries: Vec<TestEntry> = vec![];
        assert!(!contains_kid(&entries, "absent"));
    }

    #[test]
    fn multiple_entries_finds_correct_one() {
        let signer_a = crate::GrantSigner::generate();
        let signer_b = crate::GrantSigner::generate();
        let entries = [make_entry(&signer_a), make_entry(&signer_b)];

        let hash = "multi-key-test";
        let sig_a = signer_a.sign(hash);
        let sig_b = signer_b.sign(hash);

        assert_eq!(
            verify_by_kid(&entries, &signer_a.kid(), hash, &sig_a),
            Ok(true)
        );
        assert_eq!(
            verify_by_kid(&entries, &signer_b.kid(), hash, &sig_b),
            Ok(true)
        );
        // Cross-verify must fail.
        assert_eq!(
            verify_by_kid(&entries, &signer_a.kid(), hash, &sig_b),
            Ok(false)
        );
    }
}
