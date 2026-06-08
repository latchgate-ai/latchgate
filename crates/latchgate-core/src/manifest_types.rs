//! Domain types declared in action manifests and consumed by the registry,
//! kernel, and policy crates.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Result of digest verification against the trust allowlist.
///
/// This is a *data type* — the Registry returns it without making enforcement
/// decisions. The policy layer inspects the verdict and denies on anything
/// other than `DigestOk`.
///
/// SECURITY: `NotRegistered` and `DigestMismatch` are both deny conditions.
/// The distinction exists for observability (audit events, metrics) — the
/// enforcement outcome is identical: DENY.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustVerdict {
    /// Action digest matches the allowlisted value. Proceed.
    DigestOk,

    /// Action ID exists in the allowlist but the digest does not match.
    ///
    /// SECURITY: a mismatch means the action definition was replaced since the
    /// allowlist was last updated. This could be accidental (a push without
    /// updating the allowlist) or malicious (supply chain attack). The kernel
    /// MUST deny regardless of intent.
    DigestMismatch {
        expected: Arc<str>,
        actual: Arc<str>,
    },

    /// Action ID is not present in the Registry at all.
    ///
    /// SECURITY: unknown actions are never executed. Fail-closed by design.
    NotRegistered,
}

impl TrustVerdict {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, TrustVerdict::DigestOk)
    }
}

/// Network egress profile declared in an action manifest.
///
/// Determines the network configuration applied to the execution environment.
/// Default is `None` (no network at all).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EgressProfile {
    /// No network connectivity. Execution runs with no egress.
    /// SECURITY: this is the default — actions have zero egress unless the
    /// manifest explicitly declares otherwise.
    #[default]
    None,

    /// Egress only through the allowlist proxy on the internal network.
    /// The action cannot reach the Internet directly — only via the proxy,
    /// which enforces a domain allowlist.
    ProxyAllowlist {
        /// Domains the proxy will allow. Stored in the manifest, enforced by
        /// both the proxy ACL and the OPA policy.
        allowed_domains: Vec<Arc<str>>,
    },
}

impl EgressProfile {
    /// Return the concrete domain allowlist for runtime sink validation.
    ///
    /// OPA validates abstract side-effect labels (e.g. `"http_read"`);
    /// the host I/O layer validates actual target URLs against these
    /// concrete domains.
    pub fn concrete_allowed_domains(&self) -> &[Arc<str>] {
        match self {
            EgressProfile::None => &[],
            EgressProfile::ProxyAllowlist { allowed_domains } => allowed_domains,
        }
    }
}

/// Action risk classification, declared in the manifest.
///
/// OPA policy uses this to gate approval requirements:
/// - `Low` / `Medium` — auto-allow (if policy permits).
/// - `High` / `Critical` — `requires_approval` in policy response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Lowercase string matching `#[serde(rename_all = "snake_case")]`.
    ///
    /// Used in domain events, audit records, and OPA policy input.
    /// Replaces `format!("{:?}", level).to_lowercase()` which heap-allocates
    /// two `String`s per call.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Resource limits for WASM provider execution.
///
/// Declared in the action manifest. The `WasmRuntime` enforces these at the
/// host level — providers cannot override or bypass them.
///
/// SECURITY: defaults are conservative. If an operator omits a field, the
/// provider gets tight limits — not unlimited resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceLimits {
    /// Fuel budget for wasmtime execution (CPU metering).
    ///
    /// Every fuel-consuming WASM operation debits from this budget; on reach
    /// zero the execution traps with `FuelExhausted`. Fuel metering is always
    /// enabled in the runtime (`Config::consume_fuel(true)`), so this field
    /// is not an enable/disable toggle — it is the ceiling.
    ///
    /// SECURITY: must be `> 0`. Enforced at manifest load by
    /// [`ResourceLimits::validate`]; a zero value would make every call trap
    /// on the first fuel-consuming instruction (operational DoS, not a
    /// bypass, but never a legitimate configuration).
    pub fuel: u64,

    /// Maximum linear memory in megabytes.
    ///
    /// SECURITY: must be `> 0`. Enforced at manifest load.
    pub memory_mb: u32,

    /// Maximum wall-clock execution time in seconds.
    ///
    /// SECURITY: must be `> 0`. Enforced at manifest load.
    pub timeout_seconds: u32,

    /// Maximum number of host I/O calls (HTTP, SMTP, DB, etc.) per execution.
    /// Prevents runaway providers from hammering external systems.
    ///
    /// Zero is a legitimate value (the action performs no host I/O); no lower
    /// bound is enforced.
    pub max_io_calls: u32,

    /// Maximum response body size in bytes for a single host I/O call.
    /// Prevents OOM from malicious or misconfigured upstreams returning
    /// unbounded responses. Applied per-call, not cumulative.
    ///
    /// SECURITY: must be `> 0`. A zero ceiling would reject every response
    /// (breaking the action unconditionally); enforced at manifest load.
    pub max_host_response_bytes: usize,
}

/// Errors produced by [`ResourceLimits::validate`].
///
/// Surfaces through the registry manifest error via `#[from]` so a bad
/// manifest fails fast at load with the offending field named.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResourceLimitsError {
    #[error("resource_limits.{field} must be > 0")]
    MustBeNonZero { field: &'static str },
}

impl ResourceLimits {
    /// Reject any configuration the runtime cannot honour.
    ///
    /// Called at manifest load so misconfigurations fail fast with a clear
    /// error rather than surfacing as uniform execution failures for every
    /// request to that action.
    #[must_use = "discarding the result skips resource limit validation"]
    pub fn validate(&self) -> Result<(), ResourceLimitsError> {
        if self.fuel == 0 {
            return Err(ResourceLimitsError::MustBeNonZero { field: "fuel" });
        }
        if self.memory_mb == 0 {
            return Err(ResourceLimitsError::MustBeNonZero { field: "memory_mb" });
        }
        if self.timeout_seconds == 0 {
            return Err(ResourceLimitsError::MustBeNonZero {
                field: "timeout_seconds",
            });
        }
        if self.max_host_response_bytes == 0 {
            return Err(ResourceLimitsError::MustBeNonZero {
                field: "max_host_response_bytes",
            });
        }
        Ok(())
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fuel: 1_000_000,
            memory_mb: 64,
            timeout_seconds: 30,
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024, // 10 MiB
        }
    }
}

/// Which verifier checks the outcome of an action execution.
///
/// Declared in the action manifest alongside `provider module`. The kernel
/// runs the matching verifier after the provider returns. If `None`, the
/// receipt will carry `VerificationOutcome::UnverifiableDeclared`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKind {
    /// Check HTTP response status and optional response-body assertions.
    HttpStatus,

    /// Verify filesystem operation via host-observed SHA-256 hash evidence.
    ///
    /// The host records the content hash after every read/write. The verifier
    /// confirms the host recorded evidence of the operation. The user's real
    /// verification is `git diff`.
    FsHash,

    /// No independent verification possible or configured.
    /// SECURITY: this is an honest declaration — the receipt will say
    /// `unverifiable_declared`, never `verified`.
    #[default]
    None,
}

impl VerifierKind {
    /// Canonical lowercase string matching `#[serde(rename_all = "snake_case")]`.
    ///
    /// Used in domain events, audit records, and OPA policy input.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpStatus => "http_status",
            Self::FsHash => "fs_hash",
            Self::None => "none",
        }
    }
}

impl std::fmt::Display for VerifierKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Secret declaration in an action manifest.
///
/// Only secrets declared here are injected into the execution environment at
/// runtime (JIT, via SOPS). Undeclared secrets are never available — least
/// privilege.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDecl {
    /// Environment variable name (e.g. `"GITHUB_TOKEN"`).
    pub name: Arc<str>,

    /// Whether the action can run without this secret.
    /// If `true` and the secret is missing, the provider refuses to start.
    #[serde(default)]
    pub required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_verdict_is_ok_only_for_digest_ok() {
        assert!(TrustVerdict::DigestOk.is_ok());
        assert!(!TrustVerdict::NotRegistered.is_ok());
        assert!(!(TrustVerdict::DigestMismatch {
            expected: "a".into(),
            actual: "b".into(),
        })
        .is_ok());
    }

    #[test]
    fn default_egress_profile_is_none() {
        assert_eq!(EgressProfile::default(), EgressProfile::None);
    }

    #[test]
    fn default_risk_level_is_low() {
        assert_eq!(RiskLevel::default(), RiskLevel::Low);
    }

    #[test]
    fn secret_decl_required_defaults_to_false() {
        // SECURITY: the default posture for a declared secret is NOT required,
        // so a manifest omitting the field does not accidentally harden the
        // action against callers that never present the secret. Pinned.
        let json = r#"{"name": "API_KEY"}"#;
        let decl: SecretDecl = serde_json::from_str(json).unwrap();
        assert_eq!(&*decl.name, "API_KEY");
        assert!(!decl.required);
    }

    #[test]
    fn resource_limits_defaults_are_conservative() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.fuel, 1_000_000);
        assert_eq!(limits.memory_mb, 64);
        assert_eq!(limits.timeout_seconds, 30);
        assert_eq!(limits.max_io_calls, 10);
        assert_eq!(limits.max_host_response_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn resource_limits_default_passes_validation() {
        // SECURITY: the default posture must itself be a legal configuration —
        // a regression that ships a zero default would slip past manifest
        // validation because manifests inherit defaults for omitted fields.
        ResourceLimits::default().validate().unwrap();
    }

    #[test]
    fn resource_limits_zero_fuel_rejected() {
        let limits = ResourceLimits {
            fuel: 0,
            ..ResourceLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ResourceLimitsError::MustBeNonZero { field: "fuel" })
        );
    }

    #[test]
    fn resource_limits_zero_memory_rejected() {
        let limits = ResourceLimits {
            memory_mb: 0,
            ..ResourceLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ResourceLimitsError::MustBeNonZero { field: "memory_mb" })
        );
    }

    #[test]
    fn resource_limits_zero_timeout_rejected() {
        let limits = ResourceLimits {
            timeout_seconds: 0,
            ..ResourceLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ResourceLimitsError::MustBeNonZero {
                field: "timeout_seconds"
            })
        );
    }

    #[test]
    fn resource_limits_zero_max_host_response_bytes_rejected() {
        let limits = ResourceLimits {
            max_host_response_bytes: 0,
            ..ResourceLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ResourceLimitsError::MustBeNonZero {
                field: "max_host_response_bytes"
            })
        );
    }

    #[test]
    fn resource_limits_zero_io_calls_accepted() {
        // A no-I/O action is a legitimate configuration (pure computation) —
        // the runtime must not reject it. Regression guard.
        let limits = ResourceLimits {
            max_io_calls: 0,
            ..ResourceLimits::default()
        };
        limits.validate().unwrap();
    }

    #[test]
    fn verifier_kind_as_str_matches_display() {
        for kind in [
            VerifierKind::HttpStatus,
            VerifierKind::FsHash,
            VerifierKind::None,
        ] {
            assert_eq!(kind.as_str(), kind.to_string());
        }
    }

    #[test]
    fn verifier_kind_default_is_none() {
        // SECURITY: omitting verifier_kind in a manifest must yield None
        // (which writes `unverifiable_declared` in receipts), never a
        // silent default that claims verification.
        assert_eq!(VerifierKind::default(), VerifierKind::None);
    }
}
