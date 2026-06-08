//! Receipt signing and the JWKS-backed verifying key store.
//!
//! The signing implementation lives in [`crate::ed25519::Ed25519Signer`].
//! This module provides the [`ReceiptSigner`] type alias and the
//! [`VerifyingKeyStore`] — an append-only JWKS registry of historical
//! public keys so receipts remain verifiable after key rotation.
//!
//! # Key lifecycle
//!
//! ```text
//! First start:
//!   - generate key => write receipt-signing.key
//!   - append verifying key to receipt-keys.jwks
//!
//! After rotation (delete .key, restart):
//!   - generate new key => write receipt-signing.key
//!   - OLD entry is already in receipt-keys.jwks (kept for historical verification)
//!   - NEW entry is appended to receipt-keys.jwks
//! ```

use std::path::Path;

use tracing::{info, warn};

use crate::ed25519::{Ed25519Signer, Receipt};
use crate::verifying_keys::{self, HasVerifyingKey};

pub type ReceiptSigner = Ed25519Signer<Receipt>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VerifyingKeyEntry {
    pub kid: String,
    pub x_hex: String,
    pub kty: String,
    pub crv: String,
    pub alg: String,
    pub added_at: String,
}

impl VerifyingKeyEntry {
    fn from_signer(signer: &ReceiptSigner) -> Self {
        Self {
            kid: signer.kid(),
            x_hex: signer.verifying_key_hex(),
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            added_at: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
        }
    }
}

/// A JWKS entry paired with its pre-parsed Ed25519 verifying key.
///
/// Verifying keys are parsed from hex at load/register time. `verify_by_kid`
/// uses the cached key directly — no `hex::decode` + `VerifyingKey::from_bytes`
#[derive(Debug, Clone)]
struct CachedReceiptKey {
    entry: VerifyingKeyEntry,
    parsed: Option<ed25519_dalek::VerifyingKey>,
}

impl HasVerifyingKey for CachedReceiptKey {
    fn kid(&self) -> &str {
        &self.entry.kid
    }

    fn verifying_key(&self) -> Option<&ed25519_dalek::VerifyingKey> {
        self.parsed.as_ref()
    }
}

impl CachedReceiptKey {
    /// Parse a JWKS entry's hex key into a cached verifying key.
    ///
    fn from_entry(entry: VerifyingKeyEntry) -> Self {
        let parsed = crate::ed25519::decode_verifying_key(&entry.x_hex);
        if parsed.is_none() {
            tracing::error!(
                kid = %entry.kid,
                "verifying key hex decode failed at load time — \
                 verify_by_kid will return Ok(false) for this kid"
            );
        }
        Self { entry, parsed }
    }

    /// Create a cached entry directly from a signer (no hex round-trip).
    fn from_signer(signer: &ReceiptSigner) -> Self {
        Self {
            entry: VerifyingKeyEntry::from_signer(signer),
            parsed: Some(*signer.verifying_key()),
        }
    }
}

/// Append-only store of Ed25519 verifying keys, persisted as a JWKS JSON file.
///
/// Allows verification of receipts signed by any past key, not only the
/// current one. External auditors can fetch all historical keys from the
/// `/v1/receipt-keys` endpoint, which reads from this store.
#[derive(Debug, Clone)]
pub struct VerifyingKeyStore {
    keys: Vec<CachedReceiptKey>,
}

impl VerifyingKeyStore {
    /// Create an empty in-memory store (no persistence).
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// Load from a JWKS file, or create an empty store if the file does not
    /// exist. Malformed files log a warning and return an empty store rather
    /// than aborting startup.
    pub fn load_or_empty(path: &Path) -> Self {
        if !path.exists() {
            return Self::empty();
        }
        match std::fs::read_to_string(path) {
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "receipt JWKS file unreadable — starting with empty key store"
                );
                Self::empty()
            }
            Ok(contents) => match serde_json::from_str::<serde_json::Value>(&contents) {
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "receipt JWKS file malformed — starting with empty key store"
                    );
                    Self::empty()
                }
                Ok(v) => {
                    let entries: Vec<VerifyingKeyEntry> = v
                        .get("keys")
                        .and_then(|k| serde_json::from_value(k.clone()).ok())
                        .unwrap_or_default();
                    let keys: Vec<CachedReceiptKey> = entries
                        .into_iter()
                        .map(CachedReceiptKey::from_entry)
                        .collect();
                    info!(
                        path = %path.display(),
                        count = keys.len(),
                        "receipt JWKS loaded"
                    );
                    Self { keys }
                }
            },
        }
    }

    /// Ensure `signer`'s verifying key is present in the store.
    ///
    /// If the `kid` is not already present, appends the entry and persists
    /// to `path`. No-ops if the key is already in the store.
    pub fn ensure_contains(&mut self, signer: &ReceiptSigner, path: &Path) {
        let kid = signer.kid();
        if verifying_keys::contains_kid(&self.keys, &kid) {
            return;
        }
        self.keys.push(CachedReceiptKey::from_signer(signer));
        if let Err(e) = self.persist(path) {
            warn!(
                path = %path.display(),
                kid = %kid,
                error = %e,
                "failed to persist receipt JWKS — current key is not in the historical store"
            );
        } else {
            info!(
                path = %path.display(),
                kid = %kid,
                total_keys = self.keys.len(),
                "receipt JWKS updated with current verifying key"
            );
        }
    }

    fn persist(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("receipt JWKS dir create failed: {e}"))?;
            }
        }
        let entries: Vec<&VerifyingKeyEntry> = self.keys.iter().map(|k| &k.entry).collect();
        let jwks = serde_json::json!({ "keys": entries });
        let json =
            serde_json::to_string_pretty(&jwks).map_err(|e| format!("JWKS serialize: {e}"))?;
        let tmp = path.with_extension("jwks.tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("JWKS write open failed ({}): {e}", tmp.display()))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("JWKS write failed: {e}"))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|e| format!("JWKS rename failed: {e}"))?;
        Ok(())
    }

    /// Create a store containing exactly one entry for the given signer.
    ///
    /// Used when no JWKS path is configured (dev/test). The store lives only
    /// in memory — no file I/O is performed.
    pub fn single(signer: &ReceiptSigner) -> Self {
        Self {
            keys: vec![CachedReceiptKey::from_signer(signer)],
        }
    }

    /// Number of keys in the store (current + historical).
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate over the JWKS entries (current + historical).
    pub fn entries(&self) -> ReceiptKeyEntries<'_> {
        ReceiptKeyEntries {
            inner: self.keys.iter(),
        }
    }

    /// Look up a verifying key entry by `kid`.
    pub fn find_by_kid(&self, kid: &str) -> Option<&VerifyingKeyEntry> {
        self.keys
            .iter()
            .find(|k| k.entry.kid == kid)
            .map(|k| &k.entry)
    }
}

pub use crate::ed25519::UnknownKeyId;

impl VerifyingKeyStore {
    /// Verify an Ed25519 signature using the public key identified by `kid`.
    ///
    /// Returns `Ok(true)` if the kid is found and the signature is valid,
    /// `Ok(false)` if the kid is found but the signature is invalid or
    /// malformed (including keys that failed to parse at load time).
    /// Returns `Err(UnknownKeyId)` if the kid is not in the store — the
    /// caller must distinguish "unknown key" from "invalid signature".
    ///
    /// Uses the pre-parsed key cache populated at load/register time.
    /// No hex decoding or key parsing occurs on this path.
    pub fn verify_by_kid(
        &self,
        kid: &str,
        message: &str,
        sig_hex: &str,
    ) -> Result<bool, UnknownKeyId> {
        verifying_keys::verify_by_kid(&self.keys, kid, message, sig_hex)
    }
}

/// Iterator over [`VerifyingKeyEntry`] references in a [`VerifyingKeyStore`].
pub struct ReceiptKeyEntries<'a> {
    inner: std::slice::Iter<'a, CachedReceiptKey>,
}

impl<'a> Iterator for ReceiptKeyEntries<'a> {
    type Item = &'a VerifyingKeyEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|k| &k.entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for ReceiptKeyEntries<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::UnknownKeyId;

    fn tmp_jwks_path() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("latchgate-test-jwks-{nanos}.json"))
    }

    #[test]
    fn store_empty_when_no_file() {
        let path = tmp_jwks_path();
        let store = VerifyingKeyStore::load_or_empty(&path);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn ensure_contains_adds_and_persists_key() {
        let path = tmp_jwks_path();
        let signer = ReceiptSigner::generate();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer, &path);

        assert_eq!(store.len(), 1);
        assert!(store.keys[0].parsed.is_some());
        assert!(path.exists(), "JWKS file must be created");

        let entry = &store.keys[0].entry;
        assert_eq!(entry.kid, signer.kid());
        assert_eq!(entry.x_hex, signer.verifying_key_hex());
        assert_eq!(entry.kty, "OKP");
        assert_eq!(entry.crv, "Ed25519");
        assert_eq!(entry.alg, "EdDSA");
    }

    #[test]
    fn ensure_contains_is_idempotent() {
        let path = tmp_jwks_path();
        let signer = ReceiptSigner::generate();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer, &path);
        store.ensure_contains(&signer, &path);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_survives_reload_with_old_key_retained() {
        let path = tmp_jwks_path();
        let signer_a = ReceiptSigner::generate();
        let signer_b = ReceiptSigner::generate();

        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer_a, &path);

        let mut store2 = VerifyingKeyStore::load_or_empty(&path);
        store2.ensure_contains(&signer_b, &path);

        assert_eq!(store2.len(), 2, "both keys must be in the store");
        assert!(store2.keys.iter().all(|k| k.parsed.is_some()));
        assert!(store2.find_by_kid(&signer_a.kid()).is_some());
        assert!(store2.find_by_kid(&signer_b.kid()).is_some());
    }

    /// Reloaded keys must have their parsed cache populated from hex.
    #[test]
    fn reload_populates_parsed_cache() {
        let path = tmp_jwks_path();
        let signer = ReceiptSigner::generate();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer, &path);

        // Reload from file — parsed keys populated from hex decode.
        let reloaded = VerifyingKeyStore::load_or_empty(&path);
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.keys[0].parsed.is_some());

        // Verification must work with the reloaded cache.
        let hash = "reload-test-hash";
        let sig = signer.sign(hash);
        assert_eq!(reloaded.verify_by_kid(&signer.kid(), hash, &sig), Ok(true));
    }

    #[test]
    fn find_by_kid_returns_correct_entry() {
        let path = tmp_jwks_path();
        let signer = ReceiptSigner::generate();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer, &path);

        let found = store.find_by_kid(&signer.kid()).unwrap();
        assert_eq!(found.x_hex, signer.verifying_key_hex());
    }

    #[test]
    fn store_returns_empty_on_malformed_file() {
        let path = tmp_jwks_path();
        std::fs::write(&path, b"not json").unwrap();
        let store = VerifyingKeyStore::load_or_empty(&path);
        assert!(store.is_empty());
    }

    #[test]
    fn jwks_file_is_valid_json_with_keys_array() {
        let path = tmp_jwks_path();
        let signer = ReceiptSigner::generate();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer, &path);

        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(v["keys"].is_array());
        assert_eq!(v["keys"].as_array().unwrap().len(), 1);
        assert_eq!(v["keys"][0]["kid"], signer.kid().as_str());
        assert_eq!(v["keys"][0]["alg"], "EdDSA");
    }

    #[test]
    fn verify_by_kid_valid_signature() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);
        let hash = "some-result-hash";
        let sig = signer.sign(hash);
        assert_eq!(store.verify_by_kid(&signer.kid(), hash, &sig), Ok(true));
    }

    #[test]
    fn verify_by_kid_tampered_message() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);
        let sig = signer.sign("original-hash");
        assert_eq!(
            store.verify_by_kid(&signer.kid(), "tampered-hash", &sig),
            Ok(false)
        );
    }

    #[test]
    fn verify_by_kid_unknown_kid_returns_err() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);
        let sig = signer.sign("hash");
        assert_eq!(
            store.verify_by_kid("unknown-kid-value", "hash", &sig),
            Err(UnknownKeyId)
        );
    }

    #[test]
    fn verify_by_kid_malformed_signature_hex() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);
        assert_eq!(
            store.verify_by_kid(&signer.kid(), "hash", "not-hex-zzzz"),
            Ok(false)
        );
    }

    #[test]
    fn verify_by_kid_wrong_length_signature() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);
        assert_eq!(
            store.verify_by_kid(&signer.kid(), "hash", "aabb"),
            Ok(false)
        );
    }

    #[test]
    fn verify_by_kid_after_rotation_old_key_still_works() {
        let path = tmp_jwks_path();
        let signer_old = ReceiptSigner::generate();
        let signer_new = ReceiptSigner::generate();

        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer_old, &path);
        store.ensure_contains(&signer_new, &path);

        let hash = "historical-receipt-hash";
        let sig = signer_old.sign(hash);
        assert_eq!(store.verify_by_kid(&signer_old.kid(), hash, &sig), Ok(true));

        let sig_new = signer_new.sign(hash);
        assert_eq!(
            store.verify_by_kid(&signer_new.kid(), hash, &sig_new),
            Ok(true)
        );
    }

    /// Entries iterator yields correct JWKS entries in insertion order.
    #[test]
    fn entries_iterator_yields_jwks_entries() {
        let path = tmp_jwks_path();
        let signer_a = ReceiptSigner::generate();
        let signer_b = ReceiptSigner::generate();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        store.ensure_contains(&signer_a, &path);
        store.ensure_contains(&signer_b, &path);

        let kids: Vec<&str> = store.entries().map(|e| e.kid.as_str()).collect();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0], signer_a.kid());
        assert_eq!(kids[1], signer_b.kid());
    }

    /// ExactSizeIterator contract: len() matches actual count.
    #[test]
    fn entries_iterator_exact_size() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);
        let iter = store.entries();
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.count(), 1);
    }

    /// Cached key invariant: every key entry has a parsed key after
    /// construction and after reload from disk.
    #[test]
    fn parsed_keys_invariant_across_lifecycle() {
        let path = tmp_jwks_path();
        let mut store = VerifyingKeyStore::load_or_empty(&path);
        assert_eq!(store.len(), 0);

        for _ in 0..5 {
            let signer = ReceiptSigner::generate();
            store.ensure_contains(&signer, &path);
            assert!(
                store.keys.iter().all(|k| k.parsed.is_some()),
                "all entries must have parsed keys after insert"
            );
        }

        let reloaded = VerifyingKeyStore::load_or_empty(&path);
        assert_eq!(reloaded.len(), 5);
        assert!(
            reloaded.keys.iter().all(|k| k.parsed.is_some()),
            "all entries must have parsed keys after reload"
        );
    }
}
