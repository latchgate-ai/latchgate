//! Extension trait adding Ed25519 signing to [`ExecutionReceipt`].
//!

use latchgate_core::{ExecutionReceipt, ReceiptSignatureStatus};

use crate::receipt_signer::{ReceiptSigner, VerifyingKeyStore};

/// Ed25519 signing and key-store verification for [`ExecutionReceipt`].
pub trait ReceiptExt {
    /// Sign the receipt's `result_hash` using the provided [`ReceiptSigner`].
    ///
    /// SECURITY: must be called after `compute_result_hash()`. Sets the
    /// `receipt_signature` field to the hex-encoded Ed25519 signature.
    fn sign(&mut self, signer: &ReceiptSigner);

    /// Verify the receipt's Ed25519 signature using the historical verifying
    /// key store, resolving the correct public key by `signing_key_id`.
    ///
    /// SECURITY: the only `Valid` outcome requires a present signature, a
    /// known kid, and a cryptographically correct Ed25519 verification.
    /// Everything else fails closed.
    fn verify_with_key_store(&self, store: &VerifyingKeyStore) -> ReceiptSignatureStatus;
}

impl ReceiptExt for ExecutionReceipt {
    fn sign(&mut self, signer: &ReceiptSigner) {
        self.receipt_signature = Some(signer.sign(&self.result_hash));
        self.signing_key_id = Some(signer.kid());
    }

    fn verify_with_key_store(&self, store: &VerifyingKeyStore) -> ReceiptSignatureStatus {
        let sig_hex = match &self.receipt_signature {
            Some(s) if !s.is_empty() => s,
            _ => return ReceiptSignatureStatus::MissingSignature,
        };

        let kid = match &self.signing_key_id {
            Some(k) if !k.is_empty() => k,
            _ => return ReceiptSignatureStatus::MissingKeyId,
        };

        match store.verify_by_kid(kid, &self.result_hash, sig_hex) {
            Err(_) => ReceiptSignatureStatus::UnknownKeyId,
            Ok(true) => ReceiptSignatureStatus::Valid,
            Ok(false) => match hex::decode(sig_hex) {
                Err(_) => ReceiptSignatureStatus::MalformedSignature,
                Ok(bytes) if bytes.len() != 64 => ReceiptSignatureStatus::MalformedSignature,
                Ok(_) => ReceiptSignatureStatus::Invalid,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use latchgate_core::types::{GrantId, ReceiptId};
    use latchgate_core::{NormalizedResult, VerificationOutcome};

    fn sample_receipt() -> ExecutionReceipt {
        ExecutionReceipt {
            receipt_id: ReceiptId::new(),
            grant_id: GrantId::new(),
            provider_module_digest: "sha256:aabb".into(),
            provider_receipt: std::sync::Arc::new(serde_json::json!({"status": 200})),
            normalized_result: NormalizedResult::Success {
                summary: "ok".into(),
            },
            verification_outcome: VerificationOutcome::Skipped,
            effect_evidence: vec![],
            result_hash: String::new(),
            receipt_signature: None,
            signing_key_id: None,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            failure_class: None,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);

        let mut receipt = sample_receipt();
        receipt.result_hash = receipt.compute_result_hash();
        receipt.sign(&signer);

        assert_eq!(
            receipt.verify_with_key_store(&store),
            ReceiptSignatureStatus::Valid
        );
    }

    #[test]
    fn unsigned_receipt_returns_missing() {
        let signer = ReceiptSigner::generate();
        let store = VerifyingKeyStore::single(&signer);

        let receipt = sample_receipt();
        assert_eq!(
            receipt.verify_with_key_store(&store),
            ReceiptSignatureStatus::MissingSignature
        );
    }
}
