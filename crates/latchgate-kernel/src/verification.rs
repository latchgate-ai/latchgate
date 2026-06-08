//! Effect verification — built-in verifiers for LatchGate.
//!
//! After a provider executes an action, the kernel runs the matching verifier
//! to independently check whether the intended effect actually occurred. This
//! is what turns LatchGate from a guardrail into a control product.
//!
//! # Built-in verifiers
//!
//! - [`HttpStatusVerifier`] — HTTP response status + optional body assertions
//! - [`FsHashVerifier`] — filesystem operation via host-observed SHA-256 hash
//!
//! # Honest semantics
//!
//! A verifier MUST NOT return `Verified` unless it has positive evidence that
//! the intended effect occurred. "No news" is NOT "good news". If the verifier
//! cannot confirm, it returns `VerificationFailed` or the caller uses
//! `UnverifiableDeclared` when no verifier is configured.

use std::sync::Arc;

use latchgate_core::host_observed::{FsOperation, HostObservedEffect};
use latchgate_core::VerificationOutcome;
use latchgate_core::VerifierKind;
use serde::Deserialize;
use tracing::{debug, instrument};

/// Everything a verifier needs to decide whether the intended effect occurred.
///
/// Constructed by the kernel after provider dispatch. The verifier uses this
/// to independently check the outcome — it never trusts the provider's
/// self-report alone.
#[derive(Debug)]
pub struct VerificationInput<'a> {
    /// Which action was executed (for logging / context).
    ///
    /// `Arc` to avoid a heap allocation when cloned from `ActionMetadata`.
    pub action_id: Arc<str>,

    /// The provider's self-reported output. Treated as **untrusted** — the
    /// verifier cross-checks this against independent evidence.
    ///
    /// `Arc` to avoid deep-cloning the JSON tree when shared with the
    /// `ExecutionReceipt` and `ExecutionResponse`.
    pub provider_output: Arc<serde_json::Value>,

    /// Provider's exit code or status (0 = process-level success).
    pub exit_code: i64,

    /// Targets (sinks) that were approved for this execution.
    /// The verifier may use these to scope its checks.
    ///
    /// Borrowed from the `ExecutionGrant` that is alive for the entire
    /// dispatch scope — no per-request allocation.
    pub approved_targets: &'a [Arc<str>],

    /// Optional verification config from the action manifest.
    /// Schema depends on the verifier kind. Examples:
    /// - HttpStatus: `{"expected_status": [200, 201]}`
    pub verification_config: Option<Arc<serde_json::Value>>,

    /// Effects independently observed by the host during I/O execution.
    /// Verifiers cross-check these against the provider's self-reported
    /// output — a compromised provider cannot lie about what happened.
    ///
    /// Borrowed from the `RunOutput` that is alive for the entire
    /// dispatch scope — no per-request allocation.
    pub host_observed: &'a [HostObservedEffect],
}

/// Errors from verifier execution (distinct from verification *outcomes*).
///
/// A `VerifierError` means the verifier itself failed to run — not that
/// verification concluded negatively. Verification failures are expressed
/// through `VerificationOutcome::VerificationFailed`.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// Provider output is missing fields the verifier needs.
    #[error("verifier input incomplete: {reason}")]
    IncompleteInput { reason: String },

    /// Verifier encountered an internal error (e.g. I/O, network).
    #[error("verifier internal error: {0}")]
    Internal(String),
}

/// Parse optional verification config from the input.
fn parse_config<T: serde::de::DeserializeOwned>(
    input: &VerificationInput<'_>,
    verifier_name: &str,
) -> Result<Option<T>, VerifierError> {
    input
        .verification_config
        .as_deref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| VerifierError::IncompleteInput {
            reason: format!("invalid {verifier_name} verification config: {e}"),
        })
}

/// Core verifier abstraction.
///
/// Every built-in verifier implements this trait. The kernel dispatches to
/// the correct verifier based on `VerifierKind` from the action manifest.
///
/// # Contract
///
/// - `verify` MUST return `Verified` only with positive evidence.
/// - `verify` MUST return `VerificationFailed` when evidence contradicts
///   the expected outcome.
/// - `verify` SHOULD return `VerificationFailed` (not panic) on ambiguous
///   evidence.
/// - The verifier MUST NOT perform side effects beyond read-only checks.
pub trait Verifier: Send + Sync {
    /// Independently check whether the intended effect occurred.
    fn verify(
        &self,
        input: &VerificationInput<'_>,
    ) -> impl std::future::Future<Output = Result<VerificationOutcome, VerifierError>> + Send;

    /// Human-readable name for logging and metrics.
    fn name(&self) -> &'static str;
}

/// Dispatches verification to the correct built-in verifier based on
/// `VerifierKind`.
///
/// Constructed once at server startup and shared (via `Arc`) across requests.
/// All built-in verifiers are stateless, so the registry is cheap to clone.
pub struct VerifierRegistry {
    http_status: HttpStatusVerifier,
    fs_hash: FsHashVerifier,
}

impl VerifierRegistry {
    /// Create a registry with all built-in verifiers.
    pub fn new() -> Self {
        Self {
            http_status: HttpStatusVerifier,
            fs_hash: FsHashVerifier,
        }
    }

    /// Run the verifier matching the given kind. Returns
    /// `UnverifiableDeclared` for `VerifierKind::None`.
    #[instrument(name = "verifier.dispatch", skip(self, input), fields(action_id = %input.action_id, verifier_kind = ?kind))]
    pub async fn verify(
        &self,
        kind: VerifierKind,
        input: &VerificationInput<'_>,
    ) -> Result<VerificationOutcome, VerifierError> {
        #[allow(unreachable_patterns)]
        match kind {
            VerifierKind::None => Ok(VerificationOutcome::UnverifiableDeclared),
            VerifierKind::HttpStatus => self.http_status.verify(input).await,
            VerifierKind::FsHash => self.fs_hash.verify(input).await,
            _ => Ok(VerificationOutcome::UnverifiableDeclared),
        }
    }

    /// Get the verifier name for a given kind (for metrics / logging).
    pub fn verifier_name(&self, kind: VerifierKind) -> &'static str {
        #[allow(unreachable_patterns)]
        match kind {
            VerifierKind::None => "none",
            VerifierKind::HttpStatus => self.http_status.name(),
            VerifierKind::FsHash => self.fs_hash.name(),
            _ => "unknown",
        }
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize a typed evidence struct into a [`serde_json::Value`].
///
/// Infallible for the evidence types in this module (all fields are
/// primitives, strings, or optionals thereof). The `Err` arm exists only
/// because `serde_json::to_value` returns `Result`; hitting it would be a
/// bug introduced by a future field change, logged at `error` level.
fn evidence_value(v: &impl serde::Serialize) -> serde_json::Value {
    match serde_json::to_value(v) {
        Ok(val) => val,
        Err(e) => {
            tracing::error!("BUG: evidence serialization failed: {e}");
            serde_json::Value::Null
        }
    }
}

/// Evidence payload for [`HttpStatusVerifier`].
#[derive(serde::Serialize)]
struct HttpStatusEvidence {
    http_status: u16,
    host_corroborated: bool,
}

/// Evidence payload for [`FsHashVerifier`].
#[derive(serde::Serialize)]
struct FsHashEvidence<'a> {
    operation: &'a FsOperation,
    path: &'a std::path::Path,
    before_hash: Option<String>,
    after_hash: Option<String>,
    bytes_before: u64,
    bytes_after: u64,
    host_corroborated: bool,
}

// ===========================================================================
// HttpStatusVerifier
// ===========================================================================

/// Checks whether the provider's HTTP response status indicates success and
/// optionally validates response body fields.
///
/// # Verification config
///
/// Optional JSON in `verification_config`:
/// ```json
/// {
///   "expected_status": [200, 201, 204],
///   "required_fields": ["id", "created_at"]
/// }
/// ```
///
/// If no config is provided, any 2xx status is considered verified.

#[derive(Debug, Deserialize)]
struct HttpVerificationConfig {
    /// Acceptable HTTP status codes. If empty or absent, any 2xx is accepted.
    #[serde(default)]
    expected_status: Vec<u16>,

    /// Top-level fields that must be present in the response body.
    #[serde(default)]
    required_fields: Vec<String>,
}

/// Verifies HTTP API actions by checking response status and body structure.
pub struct HttpStatusVerifier;

impl Verifier for HttpStatusVerifier {
    async fn verify(
        &self,
        input: &VerificationInput<'_>,
    ) -> Result<VerificationOutcome, VerifierError> {
        let output = &input.provider_output;

        // Extract status code from provider output.
        // Supports both flat format ({"status": 200}) and envelope
        // format ({"ok": true, "data": {"status_code": 200}}).
        let status = output
            .get("status")
            .or_else(|| output.get("status_code"))
            .or_else(|| output.get("data").and_then(|d| d.get("status_code")))
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);

        let Some(status) = status else {
            debug!(
                action_id = %input.action_id,
                "http_status verifier: no status code in provider output"
            );
            return Ok(VerificationOutcome::VerificationFailed {
                reason: "provider output missing HTTP status code".into(),
            });
        };

        // Parse optional verification config.
        let config: Option<HttpVerificationConfig> = parse_config(input, "http_status")?;

        // Check status code.
        let status_ok = match &config {
            Some(c) if !c.expected_status.is_empty() => c.expected_status.contains(&status),
            _ => (200..300).contains(&status),
        };

        if !status_ok {
            return Ok(VerificationOutcome::VerificationFailed {
                reason: format!("HTTP status {status} is not in the accepted set"),
            });
        }

        // Check required fields in response body.
        if let Some(ref config) = config {
            let body = output.get("body").unwrap_or(output);
            for field in &config.required_fields {
                if body.get(field.as_str()).is_none() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: format!("required field '{field}' missing from response body"),
                    });
                }
            }
        }

        // Cross-check: compare provider-reported status against host observation.
        // A compromised provider cannot lie about the HTTP status because the
        // host independently recorded it at the transport layer.
        let host_status = input
            .host_observed
            .iter()
            .filter_map(|e| match e {
                HostObservedEffect::HttpStatus { status, .. } => Some(*status),
                HostObservedEffect::Fs { .. } => None,
            })
            .next();

        let host_corroborated = match host_status {
            Some(observed) if observed == status => true,
            Some(observed) => {
                return Ok(VerificationOutcome::VerificationFailed {
                    reason: format!(
                        "provider reported HTTP {status} but host observed HTTP {observed}"
                    ),
                });
            }
            // No host observation (e.g. template action or test). Verification
            // proceeds on provider output alone — host_corroborated = false
            // signals the weaker evidence to downstream consumers.
            None => false,
        };

        Ok(VerificationOutcome::Verified {
            evidence: evidence_value(&HttpStatusEvidence {
                http_status: status,
                host_corroborated,
            }),
        })
    }

    fn name(&self) -> &'static str {
        "http_status"
    }
}

// ===========================================================================
// FsHashVerifier
// ===========================================================================

/// Verifies filesystem operations via host-observed SHA-256 hash evidence.
///
/// Audit-grade verification: confirms the host recorded evidence of the
/// filesystem operation. The user's real verification is `git diff`.
///
/// Per-operation evidence requirements:
/// - **Read**: `after_hash` must be present (content was hashed).
/// - **Create**: `after_hash` must be present; `before_hash` must be absent.
/// - **Overwrite**: both `before_hash` and `after_hash` must be present.
/// - **Delete**: `before_hash` must be present; `after_hash` must be absent.
pub struct FsHashVerifier;

impl Verifier for FsHashVerifier {
    async fn verify(
        &self,
        input: &VerificationInput<'_>,
    ) -> Result<VerificationOutcome, VerifierError> {
        let observed = input.host_observed.iter().find_map(|e| match e {
            HostObservedEffect::Fs {
                operation,
                path,
                before_hash,
                after_hash,
                bytes_before,
                bytes_after,
                ..
            } => Some((
                operation,
                path,
                before_hash,
                after_hash,
                bytes_before,
                bytes_after,
            )),
            _ => None,
        });

        let Some((op, path, before_hash, after_hash, bytes_before, bytes_after)) = observed else {
            return Ok(VerificationOutcome::VerificationFailed {
                reason: "no host-observed filesystem evidence".into(),
            });
        };

        match op {
            FsOperation::Read => {
                if after_hash.is_none() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "read operation missing after_hash".into(),
                    });
                }
            }
            FsOperation::Create => {
                if before_hash.is_some() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "create operation must not have before_hash".into(),
                    });
                }
                if after_hash.is_none() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "create operation missing after_hash".into(),
                    });
                }
            }
            FsOperation::Overwrite => {
                if before_hash.is_none() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "overwrite operation missing before_hash".into(),
                    });
                }
                if after_hash.is_none() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "overwrite operation missing after_hash".into(),
                    });
                }
            }
            FsOperation::Delete => {
                if before_hash.is_none() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "delete operation missing before_hash".into(),
                    });
                }
                if after_hash.is_some() {
                    return Ok(VerificationOutcome::VerificationFailed {
                        reason: "delete operation must not have after_hash".into(),
                    });
                }
            }
        }

        Ok(VerificationOutcome::Verified {
            evidence: evidence_value(&FsHashEvidence {
                operation: op,
                path,
                before_hash: before_hash.map(latchgate_core::crypto::sha256_hex),
                after_hash: after_hash.map(latchgate_core::crypto::sha256_hex),
                bytes_before: *bytes_before,
                bytes_after: *bytes_after,
                host_corroborated: true,
            }),
        })
    }

    fn name(&self) -> &'static str {
        "fs_hash"
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -- Registry --------------------------------------------------------

    fn sample_input() -> VerificationInput<'static> {
        VerificationInput {
            action_id: "test_action".into(),
            provider_output: Arc::new(serde_json::json!({"status": 200})),
            exit_code: 0,
            approved_targets: &[],
            verification_config: None,
            host_observed: &[],
        }
    }

    #[tokio::test]
    async fn none_kind_returns_unverifiable_declared() {
        let registry = VerifierRegistry::new();
        let input = sample_input();
        let outcome = registry.verify(VerifierKind::None, &input).await.unwrap();
        assert_eq!(outcome, VerificationOutcome::UnverifiableDeclared);
    }

    #[tokio::test]
    async fn all_kinds_dispatch_without_panic() {
        let registry = VerifierRegistry::new();
        let input = sample_input();

        for kind in [
            VerifierKind::HttpStatus,
            VerifierKind::FsHash,
            VerifierKind::None,
        ] {
            let result = registry.verify(kind, &input).await;
            assert!(
                result.is_ok(),
                "verifier {kind} should not error on basic input"
            );
        }
    }

    // -- HttpStatusVerifier ----------------------------------------------

    fn http_input<'a>(
        output: serde_json::Value,
        config: Option<serde_json::Value>,
        host_observed: &'a [HostObservedEffect],
    ) -> VerificationInput<'a> {
        VerificationInput {
            action_id: "http_fetch".into(),
            provider_output: Arc::new(output),
            exit_code: 0,
            approved_targets: &[],
            verification_config: config.map(Arc::new),
            host_observed,
        }
    }

    #[tokio::test]
    async fn http_status_200_verified() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"status": 200}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_verified());
    }

    #[tokio::test]
    async fn http_status_201_verified() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"status": 201}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_verified());
    }

    #[tokio::test]
    async fn http_status_500_fails() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"status": 500}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn http_status_404_fails() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"status": 404}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn http_missing_status_fails() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"data": "ok"}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn http_custom_expected_status() {
        let v = HttpStatusVerifier;
        let config = serde_json::json!({"expected_status": [202, 204]});
        let input = http_input(serde_json::json!({"status": 204}), Some(config), &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_verified());
    }

    #[tokio::test]
    async fn http_custom_expected_status_rejects_200() {
        let v = HttpStatusVerifier;
        let config = serde_json::json!({"expected_status": [204]});
        let input = http_input(serde_json::json!({"status": 200}), Some(config), &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn http_required_fields_present() {
        let v = HttpStatusVerifier;
        let config = serde_json::json!({"required_fields": ["id"]});
        let output = serde_json::json!({"status": 200, "body": {"id": "abc"}});
        let input = http_input(output, Some(config), &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_verified());
    }

    #[tokio::test]
    async fn http_required_fields_missing() {
        let v = HttpStatusVerifier;
        let config = serde_json::json!({"required_fields": ["id"]});
        let output = serde_json::json!({"status": 200, "body": {"name": "test"}});
        let input = http_input(output, Some(config), &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn http_status_code_alias() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"status_code": 200}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_verified());
    }

    #[tokio::test]
    async fn http_host_corroborated_when_matching() {
        let v = HttpStatusVerifier;
        let observed = [HostObservedEffect::HttpStatus {
            status: 200,
            target: "https://api.example.com".into(),
        }];
        let input = http_input(serde_json::json!({"status": 200}), None, &observed);
        let outcome = v.verify(&input).await.unwrap();
        if let VerificationOutcome::Verified { evidence } = &outcome {
            assert_eq!(evidence["host_corroborated"], true);
        } else {
            panic!("expected Verified");
        }
    }

    #[tokio::test]
    async fn http_host_mismatch_fails_verification() {
        let v = HttpStatusVerifier;
        let observed = [HostObservedEffect::HttpStatus {
            status: 500,
            target: "https://api.example.com".into(),
        }];
        let input = http_input(serde_json::json!({"status": 200}), None, &observed);
        let outcome = v.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn http_no_host_observation_still_verifies() {
        let v = HttpStatusVerifier;
        let input = http_input(serde_json::json!({"status": 200}), None, &[]);
        let outcome = v.verify(&input).await.unwrap();
        if let VerificationOutcome::Verified { evidence } = &outcome {
            assert_eq!(evidence["host_corroborated"], false);
        } else {
            panic!("expected Verified");
        }
    }

    // -- FsHashVerifier --------------------------------------------------

    fn fs_input<'a>(host_observed: &'a [HostObservedEffect]) -> VerificationInput<'a> {
        VerificationInput {
            action_id: "fs_write".into(),
            provider_output: Arc::new(serde_json::json!({})),
            exit_code: 0,
            approved_targets: &[],
            verification_config: None,
            host_observed,
        }
    }

    #[tokio::test]
    async fn fs_fails_without_evidence() {
        let input = fs_input(&[]);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        match outcome {
            VerificationOutcome::VerificationFailed { reason } => {
                assert!(reason.contains("no host-observed filesystem evidence"));
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_fails_when_only_http_evidence() {
        let observed = [HostObservedEffect::HttpStatus {
            status: 200,
            target: "https://example.com".into(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        match outcome {
            VerificationOutcome::VerificationFailed { reason } => {
                assert!(reason.contains("no host-observed filesystem evidence"));
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_verifies_read_with_after_hash() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Read,
            path: PathBuf::from("src/lib.rs"),
            before_hash: None,
            after_hash: Some([0xcd; 32]),
            bytes_before: 0,
            bytes_after: 512,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
    }

    #[tokio::test]
    async fn fs_fails_read_without_after_hash() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Read,
            path: PathBuf::from("src/lib.rs"),
            before_hash: None,
            after_hash: None,
            bytes_before: 0,
            bytes_after: 0,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn fs_verifies_create() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Create,
            path: PathBuf::from("src/new.rs"),
            before_hash: None,
            after_hash: Some([0xef; 32]),
            bytes_before: 0,
            bytes_after: 256,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        match outcome {
            VerificationOutcome::Verified { evidence } => {
                assert_eq!(evidence["operation"], "create");
                assert!(evidence["before_hash"].is_null());
                assert!(evidence["after_hash"].is_string());
                assert_eq!(evidence["host_corroborated"], true);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_fails_create_with_spurious_before_hash() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Create,
            path: PathBuf::from("src/new.rs"),
            before_hash: Some([0xaa; 32]),
            after_hash: Some([0xef; 32]),
            bytes_before: 0,
            bytes_after: 256,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn fs_verifies_overwrite() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Overwrite,
            path: PathBuf::from("src/main.rs"),
            before_hash: Some([0xa1; 32]),
            after_hash: Some([0xd4; 32]),
            bytes_before: 1632,
            bytes_after: 1847,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        match outcome {
            VerificationOutcome::Verified { evidence } => {
                assert_eq!(evidence["operation"], "overwrite");
                assert!(evidence["before_hash"].is_string());
                assert!(evidence["after_hash"].is_string());
                assert_eq!(evidence["host_corroborated"], true);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_fails_overwrite_without_before_hash() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Overwrite,
            path: PathBuf::from("src/main.rs"),
            before_hash: None,
            after_hash: Some([0xd4; 32]),
            bytes_before: 0,
            bytes_after: 1847,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn fs_verifies_delete() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Delete,
            path: PathBuf::from("src/old.rs"),
            before_hash: Some([0xab; 32]),
            after_hash: None,
            bytes_before: 512,
            bytes_after: 0,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        match outcome {
            VerificationOutcome::Verified { evidence } => {
                assert_eq!(evidence["operation"], "delete");
                assert!(evidence["before_hash"].is_string());
                assert!(evidence["after_hash"].is_null());
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_fails_delete_without_before_hash() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Delete,
            path: PathBuf::from("src/old.rs"),
            before_hash: None,
            after_hash: None,
            bytes_before: 0,
            bytes_after: 0,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[tokio::test]
    async fn fs_fails_delete_with_spurious_after_hash() {
        let observed = [HostObservedEffect::Fs {
            operation: FsOperation::Delete,
            path: PathBuf::from("src/old.rs"),
            before_hash: Some([0xab; 32]),
            after_hash: Some([0xcd; 32]),
            bytes_before: 512,
            bytes_after: 0,
            observed_at: chrono::Utc::now(),
        }];
        let input = fs_input(&observed);
        let outcome = FsHashVerifier.verify(&input).await.unwrap();
        assert!(outcome.is_failed());
    }

    #[test]
    fn fs_hash_name() {
        assert_eq!(FsHashVerifier.name(), "fs_hash");
    }
}
