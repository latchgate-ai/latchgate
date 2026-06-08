//! Grant signing and the grant verifying key store.
//!
//! The signing implementation lives in [`crate::ed25519::Ed25519Signer`].
//! This module provides the [`GrantSigner`] type alias and the
//! [`GrantVerifyingKeyStore`] for kid-based grant signature verification.

use crate::ed25519::{Ed25519Signer, Grant, UnknownKeyId};
use crate::verifying_keys::{self, HasVerifyingKey};

/// Uses a **separate key** from receipt signing (defense-in-depth).
pub type GrantSigner = Ed25519Signer<Grant>;

#[derive(Debug, Clone)]
pub struct GrantVerifyingKeyEntry {
    pub kid: String,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl HasVerifyingKey for GrantVerifyingKeyEntry {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn verifying_key(&self) -> Option<&ed25519_dalek::VerifyingKey> {
        Some(&self.verifying_key)
    }
}

/// In-memory store of Ed25519 verifying keys for grant signature verification.
///
/// Grants are verified by `kid` lookup rather than against the current signer,
/// ensuring that key rotation between sign and verify does not silently
/// invalidate grants.
#[derive(Debug, Clone)]
pub struct GrantVerifyingKeyStore {
    entries: Vec<GrantVerifyingKeyEntry>,
}

impl GrantVerifyingKeyStore {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a signer's verifying key. Idempotent — duplicate `kid`s are
    /// silently ignored.
    pub fn register(&mut self, signer: &GrantSigner) {
        let kid = signer.kid();
        if verifying_keys::contains_kid(&self.entries, &kid) {
            return;
        }
        self.entries.push(GrantVerifyingKeyEntry {
            kid,
            verifying_key: *signer.verifying_key(),
        });
    }

    /// Verify an Ed25519 signature using the key identified by `kid`.
    ///
    /// Returns `Ok(true)` if `kid` is found and signature is valid,
    /// `Ok(false)` if `kid` is found but signature is invalid/malformed,
    /// `Err(UnknownKeyId)` if `kid` is not in the store — fail-closed.
    pub fn verify_by_kid(
        &self,
        kid: &str,
        message: &str,
        sig_hex: &str,
    ) -> Result<bool, UnknownKeyId> {
        verifying_keys::verify_by_kid(&self.entries, kid, message, sig_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_store_verify_by_kid_roundtrip() {
        let signer = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer);

        let hash = "a1b2c3d4";
        let sig = signer.sign(hash);
        assert_eq!(store.verify_by_kid(&signer.kid(), hash, &sig), Ok(true));
    }

    #[test]
    fn key_store_unknown_kid_returns_err() {
        let store = GrantVerifyingKeyStore::empty();
        assert!(store.verify_by_kid("nonexistent", "hash", "aabb").is_err());
    }

    #[test]
    fn key_store_wrong_signer_not_in_store_returns_err() {
        let signer1 = GrantSigner::generate();
        let signer2 = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer2);

        let hash = "deadbeef";
        let sig = signer1.sign(hash);
        assert!(store.verify_by_kid(&signer1.kid(), hash, &sig).is_err());
    }

    #[test]
    fn key_store_tampered_signature_returns_ok_false() {
        let signer = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer);

        let hash = "deadbeef";
        let sig = signer.sign(hash);
        let tampered = format!("ff{}", &sig[2..]);
        assert_eq!(
            store.verify_by_kid(&signer.kid(), hash, &tampered),
            Ok(false)
        );
    }

    #[test]
    fn key_store_register_is_idempotent() {
        let signer = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer);
        store.register(&signer);
        assert_eq!(store.entries.len(), 1);
    }

    #[test]
    fn key_store_retains_old_key_after_rotation() {
        let signer_old = GrantSigner::generate();
        let signer_new = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer_old);
        store.register(&signer_new);

        let hash = "test-hash";
        let sig_old = signer_old.sign(hash);
        let sig_new = signer_new.sign(hash);

        assert_eq!(
            store.verify_by_kid(&signer_old.kid(), hash, &sig_old),
            Ok(true)
        );
        assert_eq!(
            store.verify_by_kid(&signer_new.kid(), hash, &sig_new),
            Ok(true)
        );
    }
}
