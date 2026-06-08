//! Signing key configuration (receipt + grant Ed25519 keys).

use serde::Deserialize;

/// Signing key paths for receipts and grants.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SigningConfig {
    /// Ed25519 receipt signing key path. Unset = ephemeral.
    #[serde(default)]
    pub receipt_signing_key_path: Option<String>,

    /// Ed25519 grant signing key path. Separate from receipt key for
    /// defense-in-depth.
    #[serde(default)]
    pub grant_signing_key_path: Option<String>,

    /// JWKS file accumulating historical receipt verifying keys.
    #[serde(default)]
    pub receipt_keys_jwks_path: Option<String>,
}
