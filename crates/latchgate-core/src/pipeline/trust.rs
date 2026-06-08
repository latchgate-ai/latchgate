//! Tool trust verification via digest allowlist.
//!
//! The Registry maintains a mapping `action_id => sha256:digest`. Before any
//! action is dispatched to the provider, the Gate verifies that the image the
//! provider will pull matches the allowlisted digest exactly.
//!
//! Missing entry => DENY. Digest mismatch => DENY. No exceptions.
//!
//! # Relationship with `registry`
//!
//! The registry returns a `TrustVerdict`
//! (pure data — what the allowlist says). This module defines [`TrustError`]
//! (enforcement — the Gate's response to a non-ok verdict). The conversion
//! is explicit via [`TrustError::from_verdict`], keeping the Registry as a
//! data layer and the Gate as the enforcement boundary.

use std::sync::Arc;

use crate::TrustVerdict;

/// Errors from action trust verification.
///
/// HTTP semantics (see `gate::pipeline::PipelineError::into_response`):
/// - All variants => 403 Forbidden.
///   The request cannot proceed with the given action. The agent/operator must
///   register the correct digest before retrying.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// No allowlist entry exists for this action ID. DENY.
    #[error("action '{action_id}' is not registered in the trust allowlist")]
    NotRegistered { action_id: String },

    /// An allowlist entry exists but the image's actual digest does not match.
    ///
    /// SECURITY: a mismatch means the image was replaced since the allowlist
    /// was last updated. This could be accidental (a push) or malicious
    /// (supply chain attack). Fail closed regardless of intent.
    #[error(
        "action '{action_id}' image digest mismatch: allowlist has {expected}, image has {actual}"
    )]
    DigestMismatch {
        action_id: String,
        expected: Arc<str>,
        actual: Arc<str>,
    },
}

impl TrustError {
    /// Convert a [`TrustVerdict`] into a trust enforcement result.
    ///
    /// - `DigestOk` => `Ok(())` — proceed with execution.
    /// - `NotRegistered` | `DigestMismatch` => `Err(TrustError)` — DENY.
    ///
    /// SECURITY: this is the single point where Registry data becomes a Gate
    /// enforcement decision. Both non-ok verdicts produce a 403 via
    /// `PipelineError::Trust`.
    pub fn from_verdict(action_id: &str, verdict: &TrustVerdict) -> Result<(), Self> {
        match verdict {
            TrustVerdict::DigestOk => Ok(()),
            TrustVerdict::NotRegistered => Err(TrustError::NotRegistered {
                action_id: action_id.to_owned(),
            }),
            TrustVerdict::DigestMismatch { expected, actual } => Err(TrustError::DigestMismatch {
                action_id: action_id.to_owned(),
                expected: Arc::clone(expected),
                actual: Arc::clone(actual),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_ok_passes() {
        assert!(TrustError::from_verdict("http_fetch", &TrustVerdict::DigestOk).is_ok());
    }

    #[test]
    fn not_registered_is_error() {
        let result = TrustError::from_verdict("unknown_action", &TrustVerdict::NotRegistered);
        assert!(matches!(
            result,
            Err(TrustError::NotRegistered { ref action_id }) if action_id == "unknown_action"
        ));
    }

    #[test]
    fn digest_mismatch_is_error() {
        let verdict = TrustVerdict::DigestMismatch {
            expected: "sha256:aaa".into(),
            actual: "sha256:bbb".into(),
        };
        let result = TrustError::from_verdict("http_fetch", &verdict);
        assert!(matches!(
            result,
            Err(TrustError::DigestMismatch {
                ref action_id,
                ref expected,
                ref actual,
            }) if action_id == "http_fetch" && &**expected == "sha256:aaa" && &**actual == "sha256:bbb"
        ));
    }
}
