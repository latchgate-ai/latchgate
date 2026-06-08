//! Receipt key rotation — on-disk persistence and multi-generation scenarios.
//!
//! Validates that receipt signing keys survive disk persistence across
//! simulated restarts and that receipts signed by any historical key
//! remain verifiable after multiple rotation cycles.
//!
//! Lower-level signing/verification, kid stability, and tamper detection
//! are covered by unit tests in `latchgate-core::receipt_signer`,
//! `latchgate-core::receipt`, and `latchgate-core::ed25519`.

use latchgate_core::types::{GrantId, ReceiptId};
use latchgate_core::{ExecutionReceipt, NormalizedResult, VerificationOutcome};
use latchgate_crypto::{ReceiptSigner, VerifyingKeyStore};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_receipt() -> ExecutionReceipt {
    let now = chrono::Utc::now();
    let mut r = ExecutionReceipt {
        receipt_id: ReceiptId::new(),
        grant_id: GrantId::new(),
        provider_module_digest: "sha256:aabbccdd".into(),
        provider_receipt: std::sync::Arc::new(serde_json::json!({"status": 200})),
        normalized_result: NormalizedResult::Success {
            summary: "OK".into(),
        },
        verification_outcome: VerificationOutcome::Verified {
            evidence: serde_json::json!({"verified": true}),
        },
        effect_evidence: vec![],
        result_hash: String::new(),
        receipt_signature: None,
        signing_key_id: None,
        started_at: now - chrono::Duration::seconds(1),
        finished_at: now,
        failure_class: None,
    };
    r.result_hash = r.compute_result_hash();
    r
}

fn sign_receipt(receipt: &mut ExecutionReceipt, signer: &ReceiptSigner) {
    receipt.signing_key_id = Some(signer.kid());
    receipt.receipt_signature = Some(signer.sign(&receipt.result_hash));
}

// ---------------------------------------------------------------------------
// Multi-generation key rotation via on-disk JWKS
// ---------------------------------------------------------------------------

/// Three successive "startups" each add a new signer to the JWKS file.
/// After reload, all three keys are present and receipts signed by any
/// generation verify correctly.
#[test]
fn three_generation_rotation_all_keys_verify() {
    let dir = tempfile::tempdir().unwrap();
    let jwks_path = dir.path().join("receipt-keys.jwks");

    let signer_a = ReceiptSigner::generate();
    let signer_b = ReceiptSigner::generate();
    let signer_c = ReceiptSigner::generate();

    // Simulate three server startups, each adding a new key.
    {
        let mut store = VerifyingKeyStore::load_or_empty(&jwks_path);
        store.ensure_contains(&signer_a, &jwks_path);
    }
    {
        let mut store = VerifyingKeyStore::load_or_empty(&jwks_path);
        store.ensure_contains(&signer_b, &jwks_path);
    }
    {
        let mut store = VerifyingKeyStore::load_or_empty(&jwks_path);
        store.ensure_contains(&signer_c, &jwks_path);
    }

    // Reload from disk — all three must be present.
    let store = VerifyingKeyStore::load_or_empty(&jwks_path);
    assert_eq!(store.len(), 3);

    // Sign receipts with each generation and verify via the store.
    for signer in [&signer_a, &signer_b, &signer_c] {
        let mut receipt = sample_receipt();
        sign_receipt(&mut receipt, signer);

        let result = store.verify_by_kid(
            &signer.kid(),
            &receipt.result_hash,
            receipt.receipt_signature.as_ref().unwrap(),
        );
        assert_eq!(
            result,
            Ok(true),
            "receipt signed by {} must verify after rotation",
            signer.kid()
        );
    }
}

/// A receipt signed before rotation remains verifiable after the JWKS
/// file is reloaded with the new key added.
#[test]
fn receipt_signed_before_rotation_verifies_after() {
    let dir = tempfile::tempdir().unwrap();
    let jwks_path = dir.path().join("receipt-keys.jwks");

    let old_signer = ReceiptSigner::generate();
    let new_signer = ReceiptSigner::generate();

    // Sign a receipt with the old key before rotation.
    let mut receipt = sample_receipt();
    sign_receipt(&mut receipt, &old_signer);

    // Simulate rotation: add both keys to the store.
    let mut store = VerifyingKeyStore::load_or_empty(&jwks_path);
    store.ensure_contains(&old_signer, &jwks_path);
    store.ensure_contains(&new_signer, &jwks_path);

    // Reload from disk.
    let store = VerifyingKeyStore::load_or_empty(&jwks_path);

    let result = store.verify_by_kid(
        &old_signer.kid(),
        &receipt.result_hash,
        receipt.receipt_signature.as_ref().unwrap(),
    );
    assert_eq!(result, Ok(true));
}

/// A corrupted key file on disk is rejected at load time.
#[test]
fn corrupted_key_file_rejected_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("bad-receipt.key");
    std::fs::write(&key_path, b"too short").unwrap();

    assert!(
        ReceiptSigner::load_or_generate(&key_path).is_err(),
        "corrupted key file must be rejected"
    );
}

/// Signatures created before a key is persisted to disk remain valid
/// after reloading the key from disk.
#[test]
fn signatures_survive_key_persistence_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("receipt.key");

    let signer = ReceiptSigner::load_or_generate(&key_path).unwrap();
    let mut receipt = sample_receipt();
    sign_receipt(&mut receipt, &signer);

    // Reload the same key from disk.
    let reloaded = ReceiptSigner::load_or_generate(&key_path).unwrap();
    assert!(
        reloaded.verify(
            &receipt.result_hash,
            receipt.receipt_signature.as_ref().unwrap()
        ),
        "signature must verify after key reload from disk"
    );
}
