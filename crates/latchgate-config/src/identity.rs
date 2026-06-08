//! Caller identity verification configuration.

use std::collections::HashMap;

use serde::Deserialize;

/// Identity verification at lease issuance time.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// Which identity provider to use.
    #[serde(default)]
    pub provider: IdentityProviderKind,
    /// Peercred-specific configuration (Unix socket credential passing).
    #[serde(default)]
    pub peercred: PeercredConfig,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            provider: IdentityProviderKind::None,
            peercred: PeercredConfig::default(),
        }
    }
}

/// Supported identity provider backends.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum IdentityProviderKind {
    /// No identity verification. Any process with socket access gets a lease.
    #[default]
    None,
    /// Unix SO_PEERCRED — verifies caller PID/UID via kernel.
    Peercred,
}

/// Peercred identity provider configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PeercredConfig {
    /// UID => principal mapping.
    #[serde(default)]
    pub principals: HashMap<String, PeercredPrincipal>,
    /// Allow unmapped UIDs (assigned a synthetic principal).
    #[serde(default)]
    pub allow_unmapped: bool,
}

/// A mapped peercred principal.
#[derive(Debug, Clone, Deserialize)]
pub struct PeercredPrincipal {
    /// Human-readable principal name.
    pub principal: String,
    /// Permitted scopes for this principal.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Owner/responsible person.
    #[serde(default)]
    pub owner: Option<String>,
}
