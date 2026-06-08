//! Generic Ed25519 signing with purpose-based key separation.
//!
//! One implementation serves all signing purposes (grants, receipts). The
//! [`SigningPurpose`] marker trait provides compile-time key separation —
//! a `Ed25519Signer<Grant>` and `Ed25519Signer<Receipt>` are distinct types
//! that cannot be accidentally interchanged.
//!
//! # Key lifecycle
//!
//! `load_or_generate(path)` persists the key as a raw 32-byte Ed25519 seed
//! with 0o600 permissions. Ephemeral keys via `generate()` are acceptable
//! for single-process dev/test but should not be used in production.

use std::marker::PhantomData;
use std::path::Path;

use ed25519_dalek::Signer;
use tracing::{error, info};

/// Compile-time marker for Ed25519 signing purpose.
///
/// Each purpose uses a separate key — compromise of one key does not allow
/// forgery of the other (defense-in-depth).
pub trait SigningPurpose: Send + Sync + 'static {
    /// Human-readable name for log messages and error strings
    /// (e.g. `"grant"`, `"receipt"`).
    const PURPOSE: &'static str;
}

/// Grant signing purpose. Signs [`ExecutionGrant`](latchgate_core::ExecutionGrant)s.
#[derive(Clone)]
pub struct Grant;

impl SigningPurpose for Grant {
    const PURPOSE: &'static str = "grant";
}

/// Receipt signing purpose. Signs [`ExecutionReceipt`](latchgate_core::ExecutionReceipt)s.
#[derive(Clone)]
pub struct Receipt;

impl SigningPurpose for Receipt {
    const PURPOSE: &'static str = "receipt";
}

/// Ed25519 signer parameterized by [`SigningPurpose`].
///
/// Created once at startup and shared via `Arc`. Provides `sign` (hex-encoded
/// Ed25519 signature) and `verify` (fail-closed verification).
#[derive(Clone)]
pub struct Ed25519Signer<P: SigningPurpose> {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    _purpose: PhantomData<P>,
}

impl<P: SigningPurpose> Ed25519Signer<P> {
    /// Generate a fresh ephemeral keypair (dev/test only).
    ///
    /// SECURITY: key is not persisted — signatures produced by this instance
    /// cannot be verified after process restart. Use `load_or_generate`
    /// in production.
    pub fn generate() -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            _purpose: PhantomData,
        }
    }

    /// Load a persisted keypair from `path`, or generate and save a new one.
    ///
    /// The key is stored as raw 32-byte Ed25519 seed with 0o600 permissions.
    pub fn load_or_generate(path: &Path) -> Result<Self, String> {
        if path.exists() {
            Self::load_from_file(path)
        } else {
            let signer = Self::generate();
            signer.save_to_file(path)?;
            info!(
                path = %path.display(),
                kid = %signer.kid(),
                purpose = P::PURPOSE,
                "{} signer: generated new key and persisted", P::PURPOSE
            );
            Ok(signer)
        }
    }

    fn load_from_file(path: &Path) -> Result<Self, String> {
        let seed = crate::key_file::load_ed25519_seed(path, P::PURPOSE)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let signer = Self {
            signing_key,
            verifying_key,
            _purpose: PhantomData,
        };
        info!(
            path = %path.display(),
            kid = %signer.kid(),
            purpose = P::PURPOSE,
            "{} signer: loaded persisted key", P::PURPOSE
        );
        Ok(signer)
    }

    fn save_to_file(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("{} key dir create failed: {e}", P::PURPOSE))?;
        }

        let tmp_path = path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                format!(
                    "{} key write failed ({}): {e}",
                    P::PURPOSE,
                    tmp_path.display()
                )
            })?;

        // SECURITY: restrict permissions before writing key material.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("{} key chmod failed: {e}", P::PURPOSE))?;
        }

        file.write_all(self.signing_key.as_bytes())
            .map_err(|e| format!("{} key write failed: {e}", P::PURPOSE))?;
        drop(file);

        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("{} key rename failed: {e}", P::PURPOSE))?;

        Ok(())
    }

    /// Sign a hex-encoded hash and return the hex-encoded Ed25519 signature.
    #[must_use]
    pub fn sign(&self, signable_hash: &str) -> String {
        let signature = self.signing_key.sign(signable_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    /// Verify a hex-encoded Ed25519 signature against a hash.
    ///
    /// Returns `false` on any error (bad hex, wrong length, bad sig) —
    /// fail-closed.
    #[must_use]
    pub fn verify(&self, signable_hash: &str, signature_hex: &str) -> bool {
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(e) => {
                error!(
                    error = %e,
                    purpose = P::PURPOSE,
                    "{} signature hex decode failed", P::PURPOSE
                );
                return false;
            }
        };
        let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = %e,
                    purpose = P::PURPOSE,
                    "{} signature parse failed", P::PURPOSE
                );
                return false;
            }
        };
        self.verifying_key
            .verify_strict(signable_hash.as_bytes(), &signature)
            .is_ok()
    }

    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    #[must_use]
    pub fn kid(&self) -> String {
        self.verifying_key_hex()[..16].to_string()
    }
}

impl<P: SigningPurpose> std::fmt::Debug for Ed25519Signer<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("purpose", &P::PURPOSE)
            .field("kid", &self.kid())
            .field("verifying_key", &self.verifying_key_hex())
            .finish()
    }
}

/// Verify a hex-encoded Ed25519 signature against a message using a raw key.
///
/// Shared implementation used by both [`GrantVerifyingKeyStore`] and
/// [`VerifyingKeyStore`] after their respective key lookups. Having one
/// code path for decode => parse => `verify_strict` eliminates the risk
/// of the two stores diverging on error handling or verification mode.
///
/// Returns `true` if the signature is valid, `false` on any failure
/// (bad hex, wrong length, invalid signature). Fail-closed.
///
/// [`GrantVerifyingKeyStore`]: crate::grant_signer::GrantVerifyingKeyStore
/// [`VerifyingKeyStore`]: crate::receipt_signer::VerifyingKeyStore
pub fn verify_ed25519_sig(
    verifying_key: &ed25519_dalek::VerifyingKey,
    message: &str,
    sig_hex: &str,
) -> bool {
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .is_ok()
}

/// Decode a hex-encoded Ed25519 verifying key into a [`VerifyingKey`].
///
/// Returns `None` on bad hex, wrong length, or invalid key bytes.
///
/// [`VerifyingKey`]: ed25519_dalek::VerifyingKey
pub fn decode_verifying_key(hex_key: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = hex::decode(hex_key).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&array).ok()
}

/// Error returned when the requested `kid` is not present in a verifying
/// key store (grant or receipt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKeyId;

impl std::fmt::Display for UnknownKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("signing key id not found in verifying key store")
    }
}

impl std::error::Error for UnknownKeyId {}

#[cfg(test)]
mod tests {
    use super::*;

    // All core signer behavior is purpose-independent. Test once with Grant;
    // the Receipt path is structurally identical (same monomorphized code).

    type TestSigner = Ed25519Signer<Grant>;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = TestSigner::generate();
        let hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let sig = signer.sign(hash);
        assert!(signer.verify(hash, &sig));
    }

    #[test]
    fn verify_rejects_tampered_hash() {
        let signer = TestSigner::generate();
        let hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let sig = signer.sign(hash);
        let tampered = "ffb2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(!signer.verify(tampered, &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer1 = TestSigner::generate();
        let signer2 = TestSigner::generate();
        let hash = "deadbeef";
        let sig = signer1.sign(hash);
        assert!(!signer2.verify(hash, &sig));
    }

    #[test]
    fn verify_rejects_invalid_hex() {
        let signer = TestSigner::generate();
        assert!(!signer.verify("hash", "not-valid-hex-zzzz"));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let signer = TestSigner::generate();
        assert!(!signer.verify("hash", "aabb"));
    }

    #[test]
    fn signature_is_128_hex_chars() {
        let signer = TestSigner::generate();
        let sig = signer.sign("test-hash");
        assert_eq!(sig.len(), 128);
    }

    #[test]
    fn verifying_key_hex_is_64_chars() {
        let signer = TestSigner::generate();
        assert_eq!(signer.verifying_key_hex().len(), 64);
    }

    #[test]
    fn kid_is_16_hex_chars() {
        let signer = TestSigner::generate();
        assert_eq!(signer.kid().len(), 16);
    }

    #[test]
    fn kid_is_prefix_of_verifying_key() {
        let signer = TestSigner::generate();
        assert!(signer.verifying_key_hex().starts_with(&signer.kid()));
    }

    #[test]
    fn each_signer_has_unique_key() {
        let s1 = TestSigner::generate();
        let s2 = TestSigner::generate();
        assert_ne!(s1.verifying_key_hex(), s2.verifying_key_hex());
    }

    #[test]
    fn debug_does_not_leak_signing_key() {
        let signer = TestSigner::generate();
        let debug = format!("{signer:?}");
        assert!(debug.contains("verifying_key"));
        assert!(debug.contains("purpose"));
        assert!(!debug.contains("signing_key"));
    }

    #[test]
    fn sign_is_deterministic_for_same_input() {
        let signer = TestSigner::generate();
        let hash = "determinism-test";
        assert_eq!(signer.sign(hash), signer.sign(hash));
    }

    #[test]
    fn load_or_generate_persists_and_reloads() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key_path = std::env::temp_dir().join(format!("latchgate-test-ed25519-{nanos}.key"));

        let s1 = TestSigner::load_or_generate(&key_path).unwrap();
        assert!(key_path.exists(), "key file must be created");

        let s2 = TestSigner::load_or_generate(&key_path).unwrap();
        assert_eq!(
            s1.verifying_key_hex(),
            s2.verifying_key_hex(),
            "reloaded signer must have same key"
        );
    }

    #[test]
    fn load_rejects_wrong_length_file() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key_path = std::env::temp_dir().join(format!("latchgate-test-ed25519-bad-{nanos}.key"));
        std::fs::write(&key_path, b"too short").unwrap();
        assert!(TestSigner::load_or_generate(&key_path).is_err());
    }

    #[test]
    fn signatures_valid_after_reload() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key_path = std::env::temp_dir().join(format!("latchgate-test-ed25519-sig-{nanos}.key"));

        let s1 = TestSigner::load_or_generate(&key_path).unwrap();
        let hash = "test-hash-for-reload";
        let sig = s1.sign(hash);

        let s2 = TestSigner::load_or_generate(&key_path).unwrap();
        assert!(
            s2.verify(hash, &sig),
            "reloaded signer must verify signature"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key_path =
            std::env::temp_dir().join(format!("latchgate-test-ed25519-perms-{nanos}.key"));

        let _s1 = TestSigner::load_or_generate(&key_path).unwrap();

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // SECURITY: load must fail — group/world-readable key is rejected.
        let err = TestSigner::load_or_generate(&key_path).unwrap_err();
        assert!(
            err.contains("group or world readable"),
            "expected permission error, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_key_file_permissions_rejects_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("latchgate-test-ed25519-perm-check-{nanos}.key"));
        std::fs::write(&path, b"x".repeat(32)).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(crate::key_file::check_key_file_permissions(&path).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(crate::key_file::check_key_file_permissions(&path).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(crate::key_file::check_key_file_permissions(&path).is_err());
    }

    // Verify that Grant and Receipt signers are distinct types at compile time.
    #[test]
    fn grant_and_receipt_signers_are_distinct_types() {
        let grant = Ed25519Signer::<Grant>::generate();
        let receipt = Ed25519Signer::<Receipt>::generate();
        // They produce signatures of the same format but with independent keys.
        let hash = "same-hash";
        let sig_g = grant.sign(hash);
        let sig_r = receipt.sign(hash);
        // Cross-verification must fail (different keys).
        assert!(!grant.verify(hash, &sig_r));
        assert!(!receipt.verify(hash, &sig_g));
    }
}
