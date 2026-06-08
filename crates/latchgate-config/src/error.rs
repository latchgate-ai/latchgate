//! Configuration error types.
//!
//! Each variant contains an inline TOML-template error message that guides
//! the operator to the exact fix. SECURITY comments explain why a specific
//! misconfiguration is fail-closed.

use std::net::SocketAddr;

/// Errors from configuration loading and validation.
///
/// Every validation error is a hard failure (fail-closed). Silent fallback
/// to defaults would mask security-relevant misconfiguration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config: {source}")]
    Parse {
        #[source]
        source: toml::de::Error,
    },

    /// SECURITY: prevents silent TCP exposure. Operator must explicitly set
    /// `unsafe_expose_http = true` to acknowledge the security implication.
    #[error(
        "listen_http_addr ({addr}) is set but unsafe_expose_http is false; \
         set unsafe_expose_http = true to expose TCP (audited as unsafe_http_exposed=true)"
    )]
    HttpAddrWithoutUnsafeFlag { addr: SocketAddr },

    /// SECURITY: partial admin TLS configuration is ambiguous. Setting some
    /// but not all three fields (`admin_tls_cert`, `admin_tls_key`,
    /// `admin_tls_ca`) means the operator intended mTLS but misconfigured it.
    /// Fail-closed: refuse to start rather than silently falling back to plain
    /// HTTP on the admin listener.
    #[error(
        "incomplete admin TLS configuration: {present:?} set, {missing:?} missing;\n\
         all three fields are required for mTLS: admin_tls_cert, admin_tls_key, admin_tls_ca.\n\n\
         Either set all three (TOML or env LATCHGATE_ADMIN_TLS_{{CERT,KEY,CA}}) \
         or remove them all to use plain HTTP with unsafe_expose_http = true."
    )]
    AdminTlsIncomplete {
        present: Vec<String>,
        missing: Vec<String>,
    },

    /// SECURITY: production requires operator credentials so that every admin
    /// action is attributed to a specific operator identity in the tamper-evident
    /// audit ledger.
    #[error(
        "no operator_credentials configured;\n\
         configure operator credentials with DPoP binding in latchgate.toml:\n\n\
         \x20   [operator_credentials.alice]\n\
         \x20   api_key = \"key-alice-...\"\n\
         \x20   dpop_jkt = \"base64url-thumbprint-from-keygen\"\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    NoOperatorAuthConfigured,

    /// SECURITY: every operator credential in production MUST have `dpop_jkt`
    /// for proof-of-possession. Without it, a stolen `api_key` gives
    /// unrestricted operator access with no cryptographic binding.
    #[error(
        "operator credential '{operator_id}' is missing dpop_jkt;\n\
         every operator credential must have a DPoP key thumbprint in production.\n\n\
         Generate a keypair and add the thumbprint:\n\
         \x20   latchgate-cli operator keygen\n\n\
         \x20   [operator_credentials.{operator_id}]\n\
         \x20   api_key = \"...\"\n\
         \x20   dpop_jkt = \"<thumbprint from keygen>\"\n\n\
         If using LATCHGATE_OPERATOR_API_KEY, also set LATCHGATE_OPERATOR_DPOP_JKT.\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    OperatorCredentialMissingDpopJkt { operator_id: String },

    /// SECURITY: `IdentityProviderKind::None` accepts any caller without
    /// verification. In production, this allows any process with socket access
    /// to obtain a lease with arbitrary identity — defeating the entire
    /// identity bootstrapping model.
    #[error(
        "identity provider is set to 'none' (no caller verification);\n\
         production requires a real identity provider.\n\n\
         Configure peercred identity in latchgate.toml:\n\n\
         \x20   [identity]\n\
         \x20   provider = \"peercred\"\n\n\
         \x20   [identity.peercred]\n\
         \x20   allow_unmapped = false\n\n\
         \x20   [identity.peercred.principals]\n\
         \x20   1001 = {{ principal = \"my-agent\", scopes = [\"tools:call\"] }}\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    NoneIdentityProviderInProduction,

    /// SECURITY: `allow_unmapped = true` assigns a synthetic principal
    /// (`uid:<N>`) to any connecting process, bypassing the principal map.
    /// In production, this defeats UID=>principal accountability.
    #[error(
        "identity.peercred.allow_unmapped is true in production;\n\
         this allows any process to obtain a lease with a synthetic principal, \
         bypassing the UID=>principal map.\n\n\
         Set allow_unmapped = false and map all expected UIDs:\n\n\
         \x20   [identity.peercred]\n\
         \x20   allow_unmapped = false\n\n\
         \x20   [identity.peercred.principals]\n\
         \x20   1001 = {{ principal = \"my-agent\", scopes = [\"tools:call\"] }}\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    AllowUnmappedInProduction,

    /// SECURITY: `peercred` provider with an empty principal map means no
    /// caller can authenticate — every lease issuance will fail with 403.
    /// This is almost certainly a configuration mistake.
    #[error(
        "identity.peercred.principals is empty — no UID is mapped to a principal;\n\
         every lease issuance will be denied (no caller can authenticate).\n\n\
         Map at least one UID in latchgate.toml:\n\n\
         \x20   [identity.peercred.principals]\n\
         \x20   1001 = {{ principal = \"my-agent\", scopes = [\"tools:call\"] }}\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    EmptyPeercredPrincipalMap,

    /// SECURITY: without a persistent receipt signing key, receipts are signed
    /// with an ephemeral key that is lost on restart. Every receipt issued
    /// before a restart becomes unverifiable — defeating the evidence plane.
    #[error(
        "receipt_signing_key_path is not set;\n\
         production requires a persistent Ed25519 signing key for receipt integrity.\n\n\
         Generate and configure a key path in latchgate.toml:\n\n\
         \x20   receipt_signing_key_path = \"/etc/latchgate/receipt-signing.key\"\n\n\
         The key file is auto-generated on first run (32-byte Ed25519 seed, mode 0600).\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    MissingReceiptSigningKeyPath,

    /// SECURITY: without a persistent grant signing key, grant signatures use
    /// an ephemeral key. Cross-process or post-restart grant verification is
    /// impossible — weakening the signed execution contract.
    #[error(
        "grant_signing_key_path is not set;\n\
         production requires a persistent Ed25519 signing key for grant integrity.\n\n\
         Generate and configure a key path in latchgate.toml:\n\n\
         \x20   grant_signing_key_path = \"/etc/latchgate/grant-signing.key\"\n\n\
         The key file is auto-generated on first run (32-byte Ed25519 seed, mode 0600).\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    MissingGrantSigningKeyPath,

    /// SECURITY: without a JWKS path, historical verifying keys are lost on
    /// restart. After key rotation, all receipts signed with the previous key
    /// become unverifiable — breaking the evidence chain.
    #[error(
        "receipt_keys_jwks_path is not set;\n\
         production requires a JWKS file to retain historical verifying keys\n\
         across restarts and key rotations.\n\n\
         Configure a path in latchgate.toml:\n\n\
         \x20   receipt_keys_jwks_path = \"/etc/latchgate/receipt-keys.jwks\"\n\n\
         The JWKS file is created and updated automatically.\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    MissingReceiptKeysJwksPath,

    /// SECURITY: `response_schema_enforcement = "warn"` allows provider
    /// responses that violate the declared output schema to reach the caller.
    /// This weakens the Typed I/O guarantee: the caller cannot trust that
    /// the response matches the action's contract.
    #[error(
        "response_schema_enforcement is set to 'warn' in production;\n\
         responses that fail schema validation will be returned to callers,\n\
         weakening the output integrity guarantee.\n\n\
         Set enforcement to 'deny' in latchgate.toml:\n\n\
         \x20   response_schema_enforcement = \"deny\"\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    WarnResponseSchemaInProduction,

    /// SECURITY: `file://` object storage gives WASM providers read/write
    /// access to the local filesystem through the `latchgate:io/storage`
    /// host import. In production this is a sandbox escape.
    #[error(
        "host_io.storage.url uses the file:// scheme, which is not permitted in production;\n\
         use a cloud object store (s3://, gs://, az://) in production.\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    FileStorageInProduction,

    /// SECURITY: async webhook delivery uses a bounded in-process channel
    /// that drops events when full. In production this silently loses audit-
    /// critical delivery confirmations. Use the transactional outbox instead.
    #[error(
        "webhook_mode is set to 'async' with configured webhook endpoints;\n\
         async mode drops events under load — use 'outbox' in production.\n\n\
         Set webhook_mode = \"outbox\" in latchgate.toml, or remove webhook\n\
         endpoints, or or compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    AsyncWebhooksInProduction,

    /// SECURITY: the wildcard ACL entry (`*`) grants actions to every
    /// authenticated principal. Allowing high or critical risk actions in the
    /// wildcard means any agent can trigger destructive or approval-gated
    /// operations — defeating the principle of least privilege.
    #[error(
        "wildcard ACL ('*') contains high/critical-risk action(s) in production;\n\
         high and critical risk actions must be assigned to named principals only.\n\n\
         Move these actions to named principal ACL entries in data.json:\n\
         {actions:?}\n\n\
         Compile with `--features unsafe-dev` and set LATCHGATE_UNSAFE_DEV=1 to bypass (contributors only)."
    )]
    WildcardAclHighRiskInProduction { actions: Vec<String> },

    /// An environment variable override was present but contained an invalid
    /// value. Fail-closed: refuse to start with ambiguous configuration.
    ///
    /// SECURITY: silent fallback to a default when an operator explicitly set
    /// an env var would mask misconfiguration. Hard failure surfaces the
    /// problem immediately.
    #[error("invalid value for environment variable {name}={value:?}: {reason}")]
    InvalidEnvVar {
        name: String,
        value: String,
        reason: String,
    },
}
