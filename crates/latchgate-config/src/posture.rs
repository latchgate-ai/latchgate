//! Security posture types and per-protection status reporting.
//!
//! [`SecurityPosture`] tracks which production validations are relaxed.
//! [`PostureDetail`] provides per-protection human-readable status for
//! CLI banners and TUI badges.

use serde::{Deserialize, Serialize};

use super::{Config, IdentityProviderKind, ResponseSchemaEnforcement};

/// Single protection status line for posture tables and TUI badges.
///
#[derive(Debug, Clone)]
pub struct PostureDetail {
    /// Short protection name (e.g. `"identity"`, `"signing"`).
    pub name: &'static str,
    /// Human-readable status derived from the active config
    /// (e.g. `"peercred (3 principals)"`, `"ephemeral"`).
    pub status: String,
    /// `true` when this protection is enforced (production-grade).
    pub enforced: bool,
    /// CLI flag that relaxes this protection.
    pub flag: &'static str,
}

/// Per-protection security relaxation flags.
///
/// Each flag disables one specific production validator.  All default to
/// `false` (secure).  Set explicitly by CLI flags (`--insecure-identity`,
/// etc.) or by code paths that need to relax specific protections.
///
/// `any_relaxed()` returns `true` when at least one protection is disabled,
/// which is what [`Config::dev_mode()`] now delegates to for the
/// "are we running in a relaxed posture?" question.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Skip caller identity provider validation.
    pub identity_insecure: bool,
    /// Skip persistent signing key / JWKS validation.
    pub signing_insecure: bool,
    /// Skip operator authentication (DPoP) validation.
    pub operator_auth_insecure: bool,
    /// Skip response-schema enforcement validation (allow `warn` mode).
    pub schema_insecure: bool,
    /// Skip storage-scheme validation (allow `file://`).
    pub storage_insecure: bool,
    /// Skip webhook delivery-mode validation (allow `async`).
    pub webhooks_insecure: bool,
    /// Skip egress proxy coverage validation.
    pub egress_insecure: bool,
    /// Skip wildcard ACL risk validation.
    pub acl_insecure: bool,
}

impl SecurityPosture {
    /// All protections relaxed.  Convenience constructor for tests and
    /// internal tooling — production code should never use this.
    pub fn all_insecure() -> Self {
        Self {
            identity_insecure: true,
            signing_insecure: true,
            operator_auth_insecure: true,
            schema_insecure: true,
            storage_insecure: true,
            webhooks_insecure: true,
            egress_insecure: true,
            acl_insecure: true,
        }
    }

    /// Returns `true` when at least one protection is relaxed.
    pub fn any_relaxed(&self) -> bool {
        self.identity_insecure
            || self.signing_insecure
            || self.operator_auth_insecure
            || self.schema_insecure
            || self.storage_insecure
            || self.webhooks_insecure
            || self.egress_insecure
            || self.acl_insecure
    }
}

impl Config {
    /// Whether the gate is running in a relaxed (development) posture.
    pub fn dev_mode(&self) -> bool {
        self.posture.any_relaxed() || super::loader::is_unsafe_dev()
    }

    /// Build the full posture detail table from the active configuration.
    ///
    /// Combines each [`SecurityPosture`] flag with the corresponding config
    /// section to produce a human-readable status string.  Used by the CLI
    /// startup banner and the TUI dashboard badge.
    pub fn posture_details(&self) -> Vec<PostureDetail> {
        let mut out = Vec::with_capacity(8);

        // ── Identity ─────────────────────────────────────────────────
        out.push(PostureDetail {
            name: "identity",
            status: if self.posture.identity_insecure {
                "NONE (unauthenticated)".into()
            } else {
                match self.identity.provider {
                    IdentityProviderKind::None => "none (⚠ requires --insecure-identity)".into(),
                    IdentityProviderKind::Peercred => {
                        let n = self.identity.peercred.principals.len();
                        format!("peercred ({n} principal{})", if n == 1 { "" } else { "s" })
                    }
                }
            },
            enforced: !self.posture.identity_insecure,
            flag: "--insecure-identity",
        });

        // ── Signing ──────────────────────────────────────────────────
        let has_persistent_keys = self.signing.receipt_signing_key_path.is_some()
            && self.signing.grant_signing_key_path.is_some();
        let has_jwks = self.signing.receipt_keys_jwks_path.is_some();
        out.push(PostureDetail {
            name: "signing",
            status: if self.posture.signing_insecure {
                "ephemeral (non-persistent)".into()
            } else if has_persistent_keys && has_jwks {
                "persistent keys + JWKS".into()
            } else if has_persistent_keys {
                "persistent keys (no JWKS)".into()
            } else {
                "ephemeral (⚠ missing key paths)".into()
            },
            enforced: !self.posture.signing_insecure,
            flag: "--insecure-signing",
        });

        // ── Operator auth ────────────────────────────────────────────
        let creds_with_dpop = self
            .operator_credentials
            .values()
            .filter(|c| c.dpop_jkt.is_some())
            .count();
        let total_creds = self.operator_credentials.len();
        out.push(PostureDetail {
            name: "operator",
            status: if self.posture.operator_auth_insecure {
                "NONE (no DPoP)".into()
            } else if total_creds == 0 {
                "no credentials configured".into()
            } else {
                format!("{creds_with_dpop}/{total_creds} with DPoP")
            },
            enforced: !self.posture.operator_auth_insecure,
            flag: "--insecure-operator-auth",
        });

        // ── Schema enforcement ───────────────────────────────────────
        out.push(PostureDetail {
            name: "schema",
            status: match self.response_schema_enforcement {
                ResponseSchemaEnforcement::Deny => "enforce".into(),
                ResponseSchemaEnforcement::Warn => "warn (non-strict)".into(),
            },
            enforced: !self.posture.schema_insecure,
            flag: "--schema-warn",
        });

        // ── Storage ──────────────────────────────────────────────────
        out.push(PostureDetail {
            name: "storage",
            status: if let Some(ref url) = self.storage.redis_url {
                if url.contains("rediss://") {
                    "redis (TLS)".into()
                } else {
                    "redis".into()
                }
            } else {
                "file-backed (SQLite)".into()
            },
            enforced: !self.posture.storage_insecure,
            flag: "--insecure-storage",
        });

        // ── Transport ────────────────────────────────────────────────
        let has_http_addr = self.listener.listen_http_addr.is_some();
        let has_http = self.listener.unsafe_expose_http;
        out.push(PostureDetail {
            name: "transport",
            status: if has_http && has_http_addr {
                format!(
                    "HTTP {} + UDS",
                    self.listener
                        .listen_http_addr
                        .map(|a| a.to_string())
                        .unwrap_or_default()
                )
            } else if has_http_addr {
                "TCP + UDS".into()
            } else {
                "UDS only".into()
            },
            enforced: !has_http,
            flag: "--expose-http",
        });

        out
    }
}
