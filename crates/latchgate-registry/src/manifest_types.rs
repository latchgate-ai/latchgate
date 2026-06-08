use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use latchgate_core::{
    EgressProfile, FsOperation, ResourceLimits, ResourceLimitsError, RiskLevel, SecretDecl,
    VerifierKind,
};

/// Errors from manifest parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed to read manifest file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse manifest YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error("manifest validation failed: {reason}")]
    Validation { reason: String },

    #[error("manifest resource_limits invalid: {0}")]
    ResourceLimits(#[from] ResourceLimitsError),
}

/// SECURITY: only these names are accepted in `builtin:<name>` provider_module_digest.
/// Adding a new builtin requires a code change, review, and release — there is
/// no runtime registration path.
const ALLOWED_BUILTINS: &[&str] = &["http_api", "fs"];

/// Returns `true` if `name` is a recognised built-in provider.
pub fn is_valid_builtin(name: &str) -> bool {
    ALLOWED_BUILTINS.contains(&name)
}

/// Parsed representation of the `provider_module_digest` manifest field.
///
/// Two forms are accepted:
/// - `sha256:<64-hex>` — content-addressed trust anchor (external WASM).
/// - `builtin:<name>` — built-in provider compiled into the server binary.
///
/// SECURITY: `Builtin` providers are trusted implicitly because the operator
/// controls the server image. The name is validated against a compile-time
/// allowlist (`ALLOWED_BUILTINS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderModule {
    /// SHA-256 digest of the `.wasm` binary. Full string incl. `sha256:` prefix.
    Digest(String),
    /// Built-in provider name (e.g. `"http_api"`). Full string incl. `builtin:` prefix.
    Builtin(String),
}

impl ProviderModule {
    /// Parse a `provider_module_digest` string into the typed enum.
    ///
    /// Validates format and, for builtins, checks the allowlist.
    pub fn parse(raw: &str) -> Result<Self, ManifestError> {
        if let Some(name) = raw.strip_prefix("builtin:") {
            if name.is_empty() {
                return Err(ManifestError::Validation {
                    reason: "provider_module_digest 'builtin:' has empty name".into(),
                });
            }
            if !is_valid_builtin(name) {
                return Err(ManifestError::Validation {
                    reason: format!(
                        "unknown builtin provider '{name}'; allowed: {ALLOWED_BUILTINS:?}"
                    ),
                });
            }
            Ok(Self::Builtin(raw.to_string()))
        } else if let Some(hex_part) = raw.strip_prefix("sha256:") {
            const SHA256_HEX_LEN: usize = 64;
            if hex_part.len() != SHA256_HEX_LEN {
                return Err(ManifestError::Validation {
                    reason: format!(
                        "provider_module_digest must be 'sha256:<{SHA256_HEX_LEN}-char-hex>' (got '{raw}')"
                    ),
                });
            }
            if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ManifestError::Validation {
                    reason: format!(
                        "provider_module_digest hex portion contains non-hex characters (got '{raw}')"
                    ),
                });
            }
            Ok(Self::Digest(raw.to_string()))
        } else {
            Err(ManifestError::Validation {
                reason: format!(
                    "provider_module_digest must start with 'sha256:' or 'builtin:' (got '{raw}')"
                ),
            })
        }
    }

    /// Is this a builtin provider?
    pub fn is_builtin(&self) -> bool {
        matches!(self, Self::Builtin(_))
    }

    /// The raw string as stored in the manifest.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Digest(s) | Self::Builtin(s) => s,
        }
    }
}

/// Validate that a scope string is well-formed.
///
/// Scopes use a `namespace:name` format with the following rules:
/// - Total length: 4–64 characters.
/// - Allowed characters: `[a-z0-9:_-]`.
/// - Must contain exactly the `:` separator (namespace:name).
/// - Must not start or end with `:`.
/// - First character must be `[a-z]`.
///
/// Valid examples: `tools:call`, `email:send`, `file:write`.
/// Invalid examples: `Tools:call` (uppercase), `toolscall` (no separator),
/// `:call` (starts with `:`), `tools:` (empty name).
pub fn validate_scope_format(scope: &str) -> Result<(), String> {
    if scope.len() < 4 || scope.len() > 64 {
        return Err(format!(
            "scope '{}' has invalid length ({} chars); must be 4–64 characters",
            scope,
            scope.len()
        ));
    }
    // First character must be lowercase alpha.
    if !scope.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(format!(
            "scope '{scope}' must start with a lowercase letter [a-z]"
        ));
    }
    // All characters must be in [a-z0-9:_-].
    if !scope
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ':' || c == '_' || c == '-')
    {
        return Err(format!(
            "scope '{scope}' contains invalid characters; only [a-z0-9:_-] are permitted"
        ));
    }
    // Must contain ':' separator.
    if !scope.contains(':') {
        return Err(format!(
            "scope '{scope}' must use 'namespace:name' format (missing ':' separator)"
        ));
    }
    // Must not end with ':'.
    if scope.ends_with(':') {
        return Err(format!(
            "scope '{scope}' must not end with ':' (name part must not be empty)"
        ));
    }
    Ok(())
}

fn default_required_scopes() -> Vec<Arc<str>> {
    vec!["tools:call".into()]
}

/// A JSON Schema reference: either a relative file path or an inline object.
///
/// Both forms are accepted in manifests:
///
/// ```yaml
/// # Form 1: file path (resolved relative to the manifest directory)
/// io:
///   request_schema: "../schemas/http_fetch_request.json"
///
/// # Form 2: inline JSON Schema object
/// io:
///   request_schema:
///     type: object
///     properties:
///       path: { type: string }
///     required: [path]
/// ```
///
/// SECURITY: inline schemas undergo the same compilation and validation as
/// file-based schemas. Both are compiled at startup — no lazy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IoSchema {
    /// Relative file path to a `.json` schema file.
    Path(String),
    /// Inline JSON Schema object embedded directly in the manifest.
    Inline(serde_json::Value),
}

// `FsOperation` is defined in `latchgate-core::host_observed` and re-exported
// above. Shared between manifest validation (this crate) and runtime
// enforcement (`latchgate-providers`).

/// Filesystem provider configuration declared in an action manifest.
///
/// Controls which paths and operations the `builtin:fs` provider may access.
/// Deny-overrides-allow: a path matching any `denied_paths` pattern is
/// rejected regardless of `allowed_paths`.
///
/// SECURITY: `denied_paths` is manifest-only and cannot be overridden by
/// path learning. Learned paths can only extend `allowed_paths`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsConfig {
    /// Operations this action is permitted to perform.
    pub allowed_operations: Vec<FsOperation>,

    /// Glob patterns for paths the action may access.
    /// Relative to the grant's configured root directory.
    #[serde(default)]
    pub allowed_paths: Vec<String>,

    /// Glob patterns for paths that are always denied.
    /// Deny overrides allow — a path matching any denied pattern is rejected
    /// even if it also matches an allowed pattern.
    #[serde(default)]
    pub denied_paths: Vec<String>,

    /// Maximum file size in bytes for read/write operations.
    /// Applied to **decoded** content (post-base64).
    /// Default: 10 MiB.
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,

    /// Pre-compiled glob matchers for `allowed_paths`.
    ///
    /// Populated once at manifest load via [`ActionSpec::from_yaml`] and
    /// reused for every request. Not serialized — recompiled on load.
    #[serde(skip)]
    pub compiled_allowed: Vec<latchgate_core::fs_path::GlobPattern>,

    /// Pre-compiled glob matchers for `denied_paths`.
    ///
    /// Same lifecycle as `compiled_allowed`.
    #[serde(skip)]
    pub compiled_denied: Vec<latchgate_core::fs_path::GlobPattern>,
}

fn default_max_file_bytes() -> u64 {
    10 * 1024 * 1024 // 10 MiB
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IoConfig {
    pub request_schema: Option<IoSchema>,
    pub response_schema: Option<IoSchema>,

    /// Maximum request body size in bytes (default 64 KB).
    pub max_request_bytes: usize,

    /// Maximum response body size in bytes (default 1 MB).
    pub max_response_bytes: usize,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            request_schema: None,
            response_schema: None,
            max_request_bytes: 64 * 1024,
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// Egress declaration as it appears in the YAML manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressConfig {
    pub profile: String,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            profile: "none".into(),
            allowed_domains: Vec::new(),
            allowed_methods: Vec::new(),
        }
    }
}

impl EgressConfig {
    pub fn to_profile(&self) -> Result<EgressProfile, ManifestError> {
        match self.profile.as_str() {
            "none" => Ok(EgressProfile::None),
            "proxy_allowlist" => Ok(EgressProfile::ProxyAllowlist {
                allowed_domains: self
                    .allowed_domains
                    .iter()
                    .map(|s| Arc::from(s.as_str()))
                    .collect(),
            }),
            other => Err(ManifestError::Validation {
                reason: format!(
                    "unknown egress profile: '{other}' (expected 'none' or 'proxy_allowlist')"
                ),
            }),
        }
    }
}

/// HTTP method constants accepted in template actions.
const ALLOWED_TEMPLATE_METHODS: &[&str] =
    &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Template configuration for parameterised HTTP actions.
///
/// Placeholders use `{{variable_name}}` syntax and are resolved from the
/// request body at execution time. Unresolved required placeholders cause
/// the action to fail before any HTTP call is made.
///
/// # Security
///
/// - URL template is validated at parse time (must be non-empty).
/// - Method is validated against an allowlist of HTTP methods.
/// - Template resolution happens inside the kernel before dispatch to the
///   provider — the WASM sandbox never sees raw template strings.
/// - Secret injection remains a host-layer concern (not embedded in templates).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
    pub method: String,

    /// URL template with `{{var}}` placeholders.
    ///
    /// Example: `"https://api.github.com/repos/{{owner}}/{{repo}}/issues"`
    pub url_template: String,

    /// Static headers to include in every request.
    /// Template placeholders in header values are NOT resolved (headers are
    /// static per-action, not per-call). Use secrets for credentials.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Body template — either a JSON object with `{{var}}` values, or a
    /// raw string template. `None` for bodyless methods (GET, HEAD, DELETE).
    #[serde(default)]
    pub body_template: Option<serde_json::Value>,
}

impl TemplateConfig {
    /// Validate template configuration invariants.
    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        // Method must be a known HTTP method.
        let method_upper = self.method.to_ascii_uppercase();
        if !ALLOWED_TEMPLATE_METHODS.contains(&method_upper.as_str()) {
            return Err(ManifestError::Validation {
                reason: format!(
                    "template method '{}' is not allowed; accepted: {:?}",
                    self.method, ALLOWED_TEMPLATE_METHODS
                ),
            });
        }

        // URL template must not be empty.
        if self.url_template.is_empty() {
            return Err(ManifestError::Validation {
                reason: "template url_template must not be empty".into(),
            });
        }

        // URL template must look like a URL (starts with https:// or contains
        // a {{var}} that might expand to a full URL).
        // We accept templates starting with `{{` for cases like webhook_notify
        // where the entire URL comes from the request body.
        if !self.url_template.starts_with("https://")
            && !self.url_template.starts_with("http://")
            && !self.url_template.starts_with("{{")
        {
            return Err(ManifestError::Validation {
                reason: format!(
                    "template url_template must start with 'https://', 'http://', or '{{{{' \
                     (got '{}')",
                    self.url_template
                ),
            });
        }

        Ok(())
    }
}

/// Complete action declaration loaded from a YAML file.
///
/// The manifest is the single source of truth for an action's identity,
/// trust anchor (provider module digest), runtime constraints, I/O schemas,
/// egress policy, secrets, risk classification, and required caller scopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSpec {
    pub action_id: String,

    ///
    /// `Arc<str>` because every auto-allow request clones this into the
    /// `ExecutionGrant`, audit event, and response (`ActionMetadata`,
    /// `PipelineAudit`, `ExecutionResponse`). With `Arc<str>` each clone
    /// is a refcount bump; with `String` each was a heap allocation.
    pub version: Arc<str>,

    /// Trust anchor for the `.wasm` provider module.
    ///
    /// Two forms accepted:
    /// - `sha256:<64-hex>` — content-addressed digest of external WASM.
    /// - `builtin:<name>` — built-in provider (e.g. `builtin:http_api`).
    ///
    /// SECURITY: for `sha256:` the WasmRuntime compares the actual module
    /// digest against this value before execution. Mismatch = DENY.
    /// For `builtin:` trust is implicit — the operator controls the server
    /// image and the builtin WASM is compiled in.
    ///
    /// `Arc<str>` for the same per-request clone savings as `version`.
    pub provider_module_digest: Arc<str>,

    /// Filename of the `.wasm` provider module in the providers directory.
    ///
    /// Build-time metadata used by `latchgate providers rehash` to map
    /// this manifest to its compiled `.wasm` file. Not used at runtime —
    /// the kernel matches modules by `provider_module_digest` digest only.
    /// Not required for `builtin:` providers.
    ///
    /// Example: `"http_api.wasm"`
    #[serde(default)]
    pub provider_source: Option<String>,

    /// Host I/O imports this provider requires.
    ///
    /// Examples: `["latchgate:io/http"]`, `["latchgate:io/http", "latchgate:io/log"]`.
    /// In v0.1 the runtime links only `latchgate:io/http` and `latchgate:io/log`;
    /// the other interfaces declared in the WIT package (`io/smtp`, `io/database`,
    /// `io/queue`, `io/storage`) become available with the v0.2 providers.
    ///
    /// SECURITY: the kernel links only these imports at WASM instantiation.
    /// If the provider calls an undeclared import, instantiation fails.
    ///
    /// `Arc<str>` elements: immutable after registry load, cloned into every
    /// `RunTask` and `ApprovedExecutionPlan`. Each clone is a refcount bump
    /// instead of a heap allocation.
    #[serde(default)]
    pub required_imports: Vec<Arc<str>>,

    /// WASM resource limits for this action.
    #[serde(default)]
    pub resource_limits: ResourceLimits,

    /// Which verifier checks the outcome. Defaults to `None` (unverifiable).
    #[serde(default)]
    pub verifier_kind: VerifierKind,

    /// Optional verifier-specific configuration.
    #[serde(default)]
    pub verification_config: Option<Arc<serde_json::Value>>,

    #[serde(default)]
    pub io: IoConfig,

    /// Egress profile (YAML representation).
    #[serde(default)]
    pub egress: EgressConfig,

    /// Secrets the action is allowed to receive.
    #[serde(default)]
    pub secrets: Vec<SecretDecl>,

    #[serde(default)]
    pub risk_level: RiskLevel,

    /// Declared side effects (informational; used by OPA policy).
    #[serde(default)]
    pub declared_side_effects: Vec<Arc<str>>,

    /// Scopes that must be present in the calling lease for this action to
    /// execute.
    ///
    /// Defaults to `["tools:call"]` — the base execution capability.
    #[serde(default = "default_required_scopes")]
    pub required_scopes: Vec<Arc<str>>,

    /// Database provider configuration (opaque JSON).
    ///
    /// Contains the `DatabaseConfig` (mode, statements, rules) for database
    /// actions. Validated at server startup by the providers crate. Core and
    /// registry treat this as opaque. `None` for non-database actions.
    #[serde(default)]
    pub database_config: Option<Arc<serde_json::Value>>,

    /// Template configuration for parameterised HTTP actions.
    ///
    /// When present, the kernel resolves `{{var}}` placeholders from the
    /// request body and builds the HTTP request before dispatching to the
    /// built-in `http_api` provider.
    ///
    /// SECURITY: template actions MUST use `builtin:http_api` as their
    /// `provider_module_digest`. This invariant is enforced at manifest load time.
    #[serde(default)]
    pub template: Option<TemplateConfig>,

    ///
    /// Used by `latchgate init` to select subsets of the embedded manifest
    /// catalog (e.g. `agent`). Not used at runtime.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Filesystem provider configuration.
    ///
    /// Present only for `builtin:fs` actions. Controls allowed operations,
    /// path allowlists/denylists, and file size limits.
    ///
    /// SECURITY: manifests with `fs` config must not declare `secrets` or
    /// non-None `egress`. Filesystem authority is the gate's own UID, not
    /// per-action credentials, and fs providers have no network capability.
    #[serde(default)]
    pub fs: Option<FsConfig>,

    /// Pre-computed database mode extracted from `database_config` at load time.
    ///
    /// Avoids deserializing the full `DatabaseConfig` on every `GET /v1/actions`
    /// request. The raw mode string (`"strict"`, `"parameterized"`, `"hybrid"`)
    /// is stored here and converted to the typed enum by the API layer.
    /// `None` when the action has no `database_config` or the config has no
    /// `mode` field.
    #[serde(skip)]
    pub database_mode: Option<String>,

    /// Pre-computed secret names for policy input construction.
    ///
    /// Derived from [`secrets`](Self::secrets) at manifest parse time so the
    /// enforcement pipeline can pass `&[Arc<str>]` to the policy evaluator
    /// without allocating a fresh `Vec` on every request.
    #[serde(skip)]
    pub secret_names: Vec<Arc<str>>,

    /// Pre-computed SHA-256 content digest of security-relevant fields.
    ///
    /// Computed once at manifest parse time and reused on every request.
    /// The digest covers action_id, version, provider_module_digest,
    /// required_imports, resource_limits, verifier_kind, risk_level,
    /// secrets, declared_side_effects, egress, required_scopes,
    /// database_config, template, and fs configuration.
    ///
    /// Immutable after construction — the manifest is never modified
    /// after [`from_yaml`](Self::from_yaml) returns.
    #[serde(skip)]
    pub content_digest: String,
}
