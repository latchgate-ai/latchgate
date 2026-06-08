//! Secrets decryption configuration (SOPS).

use serde::Deserialize;

/// SOPS-based secrets injection configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SecretsConfig {
    /// Age key file path for SOPS decryption.
    #[serde(default)]
    pub sops_key_file: Option<String>,

    /// SOPS-encrypted secrets file. When set, the Gate decrypts on each
    /// action call and injects only manifest-declared secrets.
    #[serde(default)]
    pub sops_secrets_file: Option<String>,
}
