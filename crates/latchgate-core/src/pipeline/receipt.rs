//! `ExecutionReceipt` - the durable, signed result envelope.
//!
//! Produced by the kernel after provider dispatch and (optional) verification.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{GrantId, ReceiptId};

/// Precise outcome of receipt signature verification.
///
/// Returned by `ExecutionReceipt::verify_with_key_store`. Distinguishes
/// unsigned receipts from tampered receipts from rotated-away keys.
///
/// SECURITY: every variant except `Valid` means the receipt's integrity cannot
/// be confirmed. Callers must treat all non-`Valid` variants as untrusted.
#[must_use = "ignoring a signature status defeats receipt integrity checking"]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptSignatureStatus {
    /// Signature is present, kid resolves to a known key, and verification
    /// succeeded. The receipt has not been tampered with.
    Valid,

    /// Signature is present and kid resolves, but the signature does not
    /// verify against the stored public key. The receipt was tampered with
    /// or corrupted.
    Invalid,

    /// The receipt has no `receipt_signature` field. This is expected for
    /// legacy receipts created before signing was enabled.
    MissingSignature,

    /// The receipt has no `signing_key_id` field despite having a signature.
    /// Should not happen in normal operation — indicates a partial write or
    /// a code bug in the signing path.
    MissingKeyId,

    /// The `signing_key_id` does not match any entry in the verifying key
    /// store. Either the JWKS was not carried forward during rotation, or
    /// the receipt was signed by a different instance.
    UnknownKeyId,

    /// The signature or key hex is malformed (wrong length, non-hex chars).
    /// Distinct from `Invalid` because the cryptographic verification could
    /// not even be attempted.
    MalformedSignature,
}

impl ReceiptSignatureStatus {
    /// Returns `true` only for `Valid`. All other states are untrusted.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Stable string representation for API responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::MissingSignature => "missing_signature",
            Self::MissingKeyId => "missing_key_id",
            Self::UnknownKeyId => "unknown_key_id",
            Self::MalformedSignature => "malformed_signature",
        }
    }
}

impl std::fmt::Display for ReceiptSignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[must_use = "ignoring a verification outcome bypasses effect verification"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum VerificationOutcome {
    Verified { evidence: serde_json::Value },
    VerificationFailed { reason: String },
    UnverifiableDeclared,
    ProviderFailedBeforeVerification,
    Skipped,
}

impl VerificationOutcome {
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, VerificationOutcome::Verified { .. })
    }
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, VerificationOutcome::VerificationFailed { .. })
    }
}

#[must_use = "ignoring a normalized result loses execution outcome information"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NormalizedResult {
    Success { summary: String },
    ProviderFailure { reason: String },
    Timeout,
    Cancelled,
    InternalError { reason: String },
}

impl NormalizedResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, NormalizedResult::Success { .. })
    }
}

#[must_use = "ignoring a failure class loses error categorization"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    ProviderError,
    Timeout,
    PolicyViolation,
    VerificationFailed,
    Cancelled,
    InternalError,
}

#[must_use = "receipts are tamper-evident records — dropping one loses audit evidence"]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: ReceiptId,
    pub grant_id: GrantId,
    /// SHA-256 digest of the .wasm provider module that executed.
    ///
    /// `Arc` to avoid heap allocation when cloned from the kernel's
    /// `ActionMetadata::provider_module_digest` (already `Arc<str>`).
    pub provider_module_digest: Arc<str>,
    /// Raw receipt from the provider. Untrusted data.
    ///
    /// `Arc` to avoid deep-cloning the JSON tree — the same value lives
    /// in the `VerificationInput` and the final `ExecutionResponse`.
    pub provider_receipt: Arc<serde_json::Value>,
    pub normalized_result: NormalizedResult,
    pub verification_outcome: VerificationOutcome,
    pub effect_evidence: Vec<serde_json::Value>,
    pub result_hash: String,
    /// Ed25519 signature over `result_hash`, hex-encoded.
    ///
    /// SECURITY: without this, anyone with SQLite write access can forge a
    /// receipt and recompute its SHA-256 hash. The signature binds the hash
    /// to the Gate's signing key, making forgery detectable.
    ///
    /// `None` for receipts created before signing was enabled, or when the
    /// signer is unavailable (should not happen in production).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_signature: Option<String>,

    /// Key identifier of the signer that produced `receipt_signature`.
    ///
    /// Set to `ReceiptSigner::kid()` at sign time. Allows external verifiers
    /// to identify which public key to use after key rotation or restart.
    /// `None` for unsigned receipts or receipts signed before this field was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub failure_class: Option<FailureClass>,
}

impl ExecutionReceipt {
    #[must_use]
    pub fn compute_result_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let hashable = serde_json::json!({
            "receipt_id": self.receipt_id.as_str(),
            "grant_id": self.grant_id.as_str(),
            "provider_module_digest": self.provider_module_digest,
            "provider_receipt": self.provider_receipt,
            "normalized_result": self.normalized_result,
            "verification_outcome": self.verification_outcome,
            "effect_evidence": self.effect_evidence,
            "started_at": self.started_at.to_rfc3339(),
            "finished_at": self.finished_at.to_rfc3339(),
            "failure_class": self.failure_class,
        });
        let canonical = serde_json_canonicalizer::to_string(&hashable).unwrap_or_else(|e| {
            // SECURITY: canonicalization of valid serde_json::Value should never
            // fail. If it does, produce a clearly-invalid hash prefix so
            // downstream integrity checks detect the anomaly rather than
            // silently accepting an empty-string hash.
            tracing::error!("SECURITY: receipt canonicalization failed: {e}");
            format!("CANONICALIZATION_FAILED:{e}")
        });
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn duration(&self) -> chrono::Duration {
        self.finished_at - self.started_at
    }

    #[must_use]
    pub fn is_fully_successful(&self) -> bool {
        self.normalized_result.is_success()
            && matches!(
                self.verification_outcome,
                VerificationOutcome::Verified { .. } | VerificationOutcome::UnverifiableDeclared
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn sample_receipt(
        result: NormalizedResult,
        verification: VerificationOutcome,
    ) -> ExecutionReceipt {
        let now = Utc::now();
        ExecutionReceipt {
            receipt_id: ReceiptId::new(),
            grant_id: GrantId::new(),
            provider_module_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            provider_receipt: Arc::new(serde_json::json!({"status": 200})),
            normalized_result: result,
            verification_outcome: verification,
            effect_evidence: vec![serde_json::json!({"message_id": "msg-001"})],
            result_hash: String::new(),
            receipt_signature: None,
            signing_key_id: None,
            started_at: now - Duration::seconds(2),
            finished_at: now,
            failure_class: None,
        }
    }

    #[test]
    fn verified_success_is_fully_successful() {
        let r = sample_receipt(
            NormalizedResult::Success {
                summary: "HTTP 200 OK".into(),
            },
            VerificationOutcome::Verified {
                evidence: serde_json::json!({"status": 200}),
            },
        );
        assert!(r.is_fully_successful());
    }

    #[test]
    fn unverifiable_success_is_fully_successful() {
        let r = sample_receipt(
            NormalizedResult::Success {
                summary: "sent".into(),
            },
            VerificationOutcome::UnverifiableDeclared,
        );
        assert!(r.is_fully_successful());
    }

    #[test]
    fn provider_failure_is_not_successful() {
        let r = sample_receipt(
            NormalizedResult::ProviderFailure {
                reason: "HTTP 503".into(),
            },
            VerificationOutcome::ProviderFailedBeforeVerification,
        );
        assert!(!r.is_fully_successful());
    }

    #[test]
    fn result_hash_is_deterministic() {
        let r = sample_receipt(
            NormalizedResult::Success {
                summary: "ok".into(),
            },
            VerificationOutcome::UnverifiableDeclared,
        );
        let h1 = r.compute_result_hash();
        let h2 = r.compute_result_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn result_hash_changes_with_content() {
        let mut r = sample_receipt(
            NormalizedResult::Success {
                summary: "ok".into(),
            },
            VerificationOutcome::UnverifiableDeclared,
        );
        let h1 = r.compute_result_hash();
        r.provider_receipt = Arc::new(serde_json::json!({"status": 500}));
        let h2 = r.compute_result_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn receipt_serialization_roundtrips() {
        let r = sample_receipt(
            NormalizedResult::Success {
                summary: "ok".into(),
            },
            VerificationOutcome::Verified {
                evidence: serde_json::json!({"id": "ext-123"}),
            },
        );
        let json = serde_json::to_string(&r).unwrap();
        let parsed: ExecutionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.receipt_id, r.receipt_id);
        assert_eq!(parsed.provider_module_digest, r.provider_module_digest);
        assert!(parsed.is_fully_successful());
    }

    #[test]
    fn unsigned_receipt_serialization_omits_signature() {
        let r = sample_receipt(
            NormalizedResult::Success {
                summary: "ok".into(),
            },
            VerificationOutcome::UnverifiableDeclared,
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("receipt_signature"),
            "None signature should be skipped"
        );
    }

    #[test]
    fn verification_outcome_predicates() {
        assert!(VerificationOutcome::Verified {
            evidence: serde_json::json!(null)
        }
        .is_verified());
        assert!(!VerificationOutcome::UnverifiableDeclared.is_verified());
        assert!(VerificationOutcome::VerificationFailed { reason: "x".into() }.is_failed());
        assert!(!VerificationOutcome::Skipped.is_failed());
    }

    #[test]
    fn signature_status_as_str_is_stable() {
        assert_eq!(ReceiptSignatureStatus::Valid.as_str(), "valid");
        assert_eq!(ReceiptSignatureStatus::Invalid.as_str(), "invalid");
        assert_eq!(
            ReceiptSignatureStatus::MissingSignature.as_str(),
            "missing_signature"
        );
        assert_eq!(
            ReceiptSignatureStatus::MissingKeyId.as_str(),
            "missing_key_id"
        );
        assert_eq!(
            ReceiptSignatureStatus::UnknownKeyId.as_str(),
            "unknown_key_id"
        );
        assert_eq!(
            ReceiptSignatureStatus::MalformedSignature.as_str(),
            "malformed_signature"
        );
    }
}
