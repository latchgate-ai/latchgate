//! Layered configuration for LatchGate.
//!
//! Loads from TOML (`latchgate.toml`) with environment variable overrides.
//! Validates operator credentials, listener addresses, storage backends,
//! identity providers, rate limits, and sandbox settings at startup.
//!
//! Every sub-module owns one configuration section. The top-level [`Config`]
//! struct composes them and provides the single validation entry point.

pub(crate) mod egress;
mod env;
pub(crate) mod error;
mod fs_root_validation;
pub(crate) mod identity;
pub(crate) mod listener;
pub(crate) mod loader;
pub(crate) mod logging;
pub(crate) mod paths;
pub(crate) mod policy;
pub(crate) mod posture;
pub(crate) mod rate_limits;
pub(crate) mod sandbox;
pub(crate) mod secrets;
pub(crate) mod signing;
pub(crate) mod storage;
mod validate;

pub use egress::EgressConfig;
pub use error::ConfigError;
pub use fs_root_validation::{validate_session_fs_root, FsRootError};
pub use identity::{IdentityConfig, IdentityProviderKind, PeercredConfig, PeercredPrincipal};
pub use listener::ListenerConfig;
pub use logging::{LogFormat, LogRotation, LoggingConfig};
pub use paths::{ConfigSource, UserDirs};
pub use policy::PolicyConfig;
pub use posture::{PostureDetail, SecurityPosture};
pub use rate_limits::RateLimitsConfig;
pub use sandbox::{AgentSandboxConfig, CredentialRouteConfig, SandboxConfig, SandboxMode};
pub use secrets::SecretsConfig;
pub use signing::SigningConfig;
pub use storage::StorageConfig;
pub use validate::EgressCoverageResult;

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

/// Per-operator credential with optional DPoP proof-of-possession binding.
///
/// SECURITY (04): in production, `dpop_jkt` MUST be set. Without it, operator
/// identity is only knowledge-of-secret — a stolen `api_key` gives full
/// operator access. With `dpop_jkt`, the operator must also prove possession
/// of the corresponding private key via a DPoP proof JWT.
///
/// # TOML example
///
/// ```toml
/// [operator_credentials.alice]
/// api_key = "key-alice-random-secret"
/// dpop_jkt = "base64url-sha256-thumbprint"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct OperatorCredential {
    /// Bearer token or access token for this operator.
    pub api_key: String,

    /// JWK SHA-256 thumbprint (RFC 7638) of the operator's DPoP public key.
    ///
    /// When set, the operator must present a DPoP proof JWT whose embedded
    /// JWK thumbprint matches this value. The proof binds the request to the
    /// operator's private key — a stolen `api_key` alone is useless.
    ///
    /// Compute with: `latchgate-cli operator keygen` (outputs the thumbprint).
    #[serde(default)]
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Logging: level, format, file output, rotation.
    #[serde(flatten, default)]
    pub logging: LoggingConfig,

    pub sandbox: SandboxConfig,

    /// Root directory for filesystem provider operations.
    ///
    /// All fs_read, fs_write, and fs_delete paths are resolved relative to
    /// this directory. The gate opens an `O_PATH` fd at startup and all
    /// subsequent operations use `openat2` beneath it.
    ///
    /// SECURITY: must be an absolute path to an existing directory. Symlinks
    /// in the path are resolved at open time. If unset, fs actions fail at
    /// dispatch with "no fs_root_path configured".
    #[serde(default)]
    pub fs_root_path: Option<String>,

    /// Allowed prefixes for per-session filesystem roots.
    ///
    /// When an MCP client requests a per-session `fs_root` at lease time,
    /// the gate validates the canonicalized path starts with one of these
    /// prefixes. Paths outside all prefixes are rejected with 403.
    ///
    /// Default: `[$HOME]` (resolved and canonicalized at config load time).
    /// Empty list: per-session roots disabled entirely (fail-closed).
    ///
    #[serde(default = "default_fs_root_allowed_prefixes")]
    pub fs_root_allowed_prefixes: Vec<PathBuf>,

    /// Listener transport configuration (UDS, TCP, public URL).
    #[serde(flatten, default)]
    pub listener: ListenerConfig,

    /// Policy engine configuration.
    #[serde(flatten, default)]
    pub policy: PolicyConfig,

    /// Directory containing action manifest YAML files.
    /// User overlay manifests are loaded from this directory and merged with
    /// the built-in embedded manifests. Empty string = resolved at load time
    /// from the install context (project-local or user-global).
    pub manifests_dir: String,

    /// Named operator credentials with DPoP proof-of-possession binding.
    ///
    /// Maps operator_id -> OperatorCredential. Every credential must have
    /// `dpop_jkt` in production; bearer-only (no `dpop_jkt`) is accepted
    /// only in dev mode.
    ///
    #[serde(default)]
    pub operator_credentials: HashMap<String, OperatorCredential>,

    /// Storage backend configuration (Redis, ledger paths).
    #[serde(flatten, default)]
    pub storage: StorageConfig,

    /// Signing key paths (receipt + grant Ed25519 keys).
    #[serde(flatten, default)]
    pub signing: SigningConfig,

    /// Per-protection security relaxation flags.
    ///
    /// Each flag disables one specific production validator.  Secure by
    #[serde(default)]
    pub posture: SecurityPosture,

    /// Where this configuration was loaded from. Used to resolve default
    /// paths and for `config path` diagnostics.
    #[serde(skip)]
    pub source: crate::ConfigSource,

    /// How to handle action responses that fail schema validation.
    ///
    /// - `deny` (default): reject the response and return an error to the
    ///   caller. Required for Typed I/O compliance.
    /// - `warn`: log the violation and return the response anyway. Useful
    ///   during action onboarding when schemas are still being tuned.
    ///
    /// SECURITY: production deployments SHOULD use `deny`. The `warn` mode
    /// weakens output integrity guarantees.
    pub response_schema_enforcement: ResponseSchemaEnforcement,

    /// Directory containing user-supplied .wasm provider modules.
    /// Loaded at startup alongside the built-in embedded providers.
    /// Empty string = resolved at load time from the install context.
    pub wasm_providers_dir: String,

    /// Secrets decryption configuration (SOPS).
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// Host I/O backend connections.
    ///
    /// ```toml
    /// [host_io.database]
    /// url = "postgres://user:pass@localhost:5432/latchgate"
    ///
    /// [host_io.queue]
    /// url = "amqp://user:pass@localhost:5672/%2f"
    ///
    /// [host_io.storage]
    /// url = "s3://my-artifact-bucket"
    ///
    /// [host_io.smtp]
    /// url = "smtp://user:pass@smtp.example.com:587"
    /// ```
    ///
    /// Backends not listed are disabled — host import calls for that backend
    /// return an error at runtime. The WasmRuntime initialises a connection
    /// pool/client for each configured backend at startup.
    ///
    /// the parser for forward compatibility but have no effect — the
    /// providers that consume them are excluded from the v0.1 workspace
    /// build and ship in the next planned versions.
    ///
    /// SECURITY: connection targets are fixed at startup. Providers cannot
    /// influence which database/broker/store/relay is connected to — only
    /// the resource name (table, queue, path, recipient) is provider-controlled
    /// and validated against `allowed_sinks`.
    #[serde(default)]
    pub host_io: std::collections::HashMap<String, toml::Value>,

    /// Egress proxy and domain allowlist configuration.
    #[serde(flatten, default)]
    pub egress: EgressConfig,

    /// Caller identity verification at lease issuance time.
    ///
    /// Controls how `POST /v1/leases` authenticates the caller before
    /// issuing a Lease JWT. The verified principal becomes the `sub` claim.
    ///
    /// SECURITY: without identity verification, any process with socket
    /// access can obtain a lease with arbitrary (format-valid) scopes.
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Raw webhook endpoint configurations from `[[webhooks]]` TOML sections.
    ///
    ///
    /// Empty by default — webhooks are opt-in.
    #[serde(default)]
    pub webhooks: Vec<toml::Value>,

    /// - `async`: fire-and-forget via in-process channel (dev default).
    /// - `outbox`: transactional outbox in SQLite — no events lost under load.
    #[serde(default)]
    pub webhook_mode: WebhookMode,

    /// Per-endpoint rate limits (requests per second).
    ///
    /// Applied by the kernel's token bucket limiters. Defaults in
    /// [`RateLimitsConfig::default`] match historic kernel-embedded limits
    /// (20 / 100 / 50 rps).
    #[serde(default)]
    pub rate_limits: RateLimitsConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebhookMode {
    /// In-process bounded channel. Events dropped if buffer is full.
    /// Suitable for development only.
    Async,
    /// Transactional outbox: events persisted to SQLite before delivery.
    /// No events lost under load or crash.
    #[default]
    Outbox,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseSchemaEnforcement {
    #[default]
    Deny,
    Warn,
}

/// Resolve the default value for `fs_root_allowed_prefixes`.
///
/// Returns `[$HOME]` (canonicalized) when `$HOME` is available and
/// resolvable. Returns `[]` otherwise (fail-closed: per-session roots
/// disabled until the operator explicitly configures prefixes).
fn default_fs_root_allowed_prefixes() -> Vec<PathBuf> {
    let home = match directories::BaseDirs::new() {
        Some(base) => base.home_dir().to_path_buf(),
        None => {
            tracing::warn!(
                "fs_root_allowed_prefixes: $HOME not available; \
                 per-session fs_root disabled until explicitly configured"
            );
            return Vec::new();
        }
    };
    match home.canonicalize() {
        Ok(canonical) => vec![canonical],
        Err(e) => {
            tracing::warn!(
                home = %home.display(),
                error = %e,
                "fs_root_allowed_prefixes: $HOME failed to canonicalize; \
                 per-session fs_root disabled until explicitly configured"
            );
            Vec::new()
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            logging: LoggingConfig::default(),
            sandbox: SandboxConfig::default(),
            fs_root_path: None,
            fs_root_allowed_prefixes: default_fs_root_allowed_prefixes(),
            listener: ListenerConfig::default(),

            policy: PolicyConfig::default(),
            manifests_dir: String::new(),

            operator_credentials: HashMap::new(),
            storage: StorageConfig::default(),
            signing: SigningConfig::default(),
            posture: SecurityPosture::default(),
            source: Default::default(),
            response_schema_enforcement: ResponseSchemaEnforcement::default(),
            wasm_providers_dir: String::new(),
            secrets: SecretsConfig::default(),
            host_io: std::collections::HashMap::new(),
            egress: EgressConfig::default(),
            identity: IdentityConfig::default(),
            webhooks: vec![],
            webhook_mode: WebhookMode::Outbox,
            rate_limits: RateLimitsConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests;
