//! Action manifest: typed declaration of an action's identity, WASM provider
//! module, required host imports, resource limits, I/O schemas, egress profile,
//! secrets, risk level, and required caller scopes.
//!
//! Manifests are loaded from YAML files at startup and are the source of truth
//! for everything the kernel needs to know about an action before executing it.
//!
//! # Security properties
//!
//! - `provider_module_digest` is the trust anchor (SHA-256 digest of the .wasm module).
//!   The WasmRuntime refuses to execute a module whose digest does not match.
//!   `builtin:<name>` is accepted for built-in providers compiled into the
//!   server binary — trust is implicit (operator controls the server image).
//! - `required_imports` declares which host I/O interfaces the provider needs.
//!   The kernel links only these imports -- capability-based security.
//! - `egress` defaults to `None` (no network). Actions must explicitly declare
//!   egress needs, and both the manifest and OPA policy must agree.
//! - `risk_level` drives approval requirements in the OPA policy.
//! - `required_scopes` declares which scopes a calling lease must carry.
//!   Defaults to `["tools:call"]`. The OPA policy enforces this before dispatch.
//! - All limits have secure defaults (see `Default` impls).
//!
//! # Template actions
//!
//! Actions with a `template` field are *parameterised* HTTP actions. The
//! manifest declares url, method, headers, and body templates with `{{var}}`
//! placeholders. The kernel resolves placeholders from the request body before
//! dispatching to the built-in `http_api` provider. Template actions MUST use
//! a `builtin:` provider module — they share the same trusted WASM binary.

use std::path::Path;
use std::sync::Arc;

pub use crate::manifest_types::*;

impl ActionSpec {
    /// Parse a manifest from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self, ManifestError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_yaml(&contents)
    }

    /// Parse a manifest from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ManifestError> {
        let mut manifest: Self = serde_yaml_ng::from_str(yaml)?;
        manifest.validate()?;

        // Pre-compile filesystem glob patterns so the hot path never
        // pays compilation cost. Errors here are fatal — a manifest with
        // invalid globs must not reach the registry.
        if let Some(ref mut fs) = manifest.fs {
            fs.compiled_allowed = latchgate_core::fs_path::compile_patterns(&fs.allowed_paths)
                .map_err(|e| ManifestError::Validation {
                    reason: format!("action '{}' fs.allowed_paths: {e}", manifest.action_id),
                })?;
            fs.compiled_denied = latchgate_core::fs_path::compile_patterns(&fs.denied_paths)
                .map_err(|e| ManifestError::Validation {
                    reason: format!("action '{}' fs.denied_paths: {e}", manifest.action_id),
                })?;
        }

        // Pre-compute database mode from database_config to avoid
        // per-request deserialization in the action listing endpoint.
        manifest.database_mode = manifest
            .database_config
            .as_deref()
            .and_then(|v| v.get("mode"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        manifest.secret_names = manifest
            .secrets
            .iter()
            .map(|s| Arc::clone(&s.name))
            .collect();
        manifest.content_digest = manifest.compute_digest();

        Ok(manifest)
    }

    /// Compute and cache the content digest for a manually constructed spec.
    ///
    /// [`from_yaml`](Self::from_yaml) calls this automatically. Use this
    /// method when building an `ActionSpec` via struct literal (e.g. in the
    /// TUI action wizard) to ensure the digest is populated before the spec
    /// reaches the registry or kernel pipeline.
    pub fn finalize_digest(&mut self) {
        self.content_digest = self.compute_digest();
    }

    /// Resolve the egress config to the canonical [`EgressProfile`] enum.
    pub fn egress_profile(&self) -> Result<latchgate_core::EgressProfile, ManifestError> {
        self.egress.to_profile()
    }

    /// Parse the `provider_module` field into a typed [`ProviderModule`].
    pub fn parsed_provider_module(&self) -> Result<ProviderModule, ManifestError> {
        ProviderModule::parse(&self.provider_module_digest)
    }
    // -- Serialization -------------------------------------------------------

    /// Serialize this manifest to a YAML string.
    ///
    /// **Warning**: comments present in the original YAML file are NOT
    /// preserved. `serde_yaml_ng` round-trips through a typed struct, so
    /// all comments and formatting are discarded. The TUI warns the
    /// operator before the first save to a manifest that was originally
    /// hand-authored with comments.
    pub fn to_yaml(&self) -> Result<String, ManifestError> {
        // Prepend a machine-edit notice so operators know the file was
        // rewritten by the TUI and comments were stripped.
        let body = serde_yaml_ng::to_string(self).map_err(|e| ManifestError::Validation {
            reason: format!("YAML serialization failed: {e}"),
        })?;
        Ok(format!(
            "# Manifest for action: {}\n\
             # Edited by latchgate TUI — comments from previous versions were not preserved.\n\
             {body}",
            self.action_id,
        ))
    }

    /// Validate, serialize, and atomically write this manifest to `path`.
    ///
    /// The write is crash-safe: content goes to `{path}.tmp`, is fsynced,
    /// then renamed over the target. A partial write never corrupts the
    /// original file.
    ///
    /// Before writing, the manifest is serialized to YAML and then
    /// re-parsed to confirm round-trip integrity. If the re-parsed
    /// manifest fails validation, the write is aborted and the original
    /// file is untouched.
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<(), ManifestError> {
        // 1. Validate the in-memory struct.
        self.validate()?;

        // 2. Serialize.
        let yaml = self.to_yaml()?;

        // 3. Round-trip check: re-parse and re-validate.
        ActionSpec::from_yaml(&yaml).map_err(|e| ManifestError::Validation {
            reason: format!(
                "manifest round-trip check failed — serialized YAML does not \
                 re-parse cleanly: {e}"
            ),
        })?;

        // 4. Atomic write.
        latchgate_core::atomic_write_str(path, &yaml)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_DIGEST: &str =
        "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    fn minimal_yaml(overrides: &str) -> String {
        format!(
            r#"
action_id: "http_fetch"
version: "1.0.0"
provider_module_digest: "{VALID_DIGEST}"
{overrides}
"#
        )
    }

    fn builtin_yaml(overrides: &str) -> String {
        format!(
            r#"
action_id: "github_read"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: GET
  url_template: "https://api.github.com/{{{{path}}}}"
  headers:
    Accept: "application/vnd.github.v3+json"
{overrides}
"#
        )
    }

    // -- Happy path --

    #[test]
    fn minimal_manifest_parses_with_defaults() {
        let manifest = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();

        assert_eq!(manifest.action_id, "http_fetch");
        assert_eq!(&*manifest.version, "1.0.0");
        assert_eq!(&*manifest.provider_module_digest, VALID_DIGEST);

        // Verify secure defaults
        assert_eq!(manifest.resource_limits, ResourceLimits::default());
        assert_eq!(manifest.io.max_request_bytes, 64 * 1024);
        assert_eq!(manifest.io.max_response_bytes, 1024 * 1024);
        assert_eq!(manifest.risk_level, RiskLevel::Low);
        assert_eq!(manifest.egress_profile().unwrap(), EgressProfile::None);
        assert!(manifest.secrets.is_empty());
        assert!(manifest.required_imports.is_empty());
        assert!(manifest.declared_side_effects.is_empty());
        assert_eq!(manifest.verifier_kind, VerifierKind::None);
        assert_eq!(manifest.required_scopes, vec!["tools:call".into()]);
        assert!(manifest.template.is_none());
    }

    #[test]
    fn full_manifest_parses_correctly() {
        let yaml = format!(
            r#"
action_id: "http_fetch"
version: "1.0.0"
provider_module_digest: "{VALID_DIGEST}"

required_imports:
  - "latchgate:io/http"
  - "latchgate:io/log"

resource_limits:
  fuel: 5000000
  memory_mb: 128
  timeout_seconds: 60
  max_io_calls: 25

verifier_kind: http_status
io:
  request_schema: "./schemas/http_fetch_request.json"
  response_schema: "./schemas/http_fetch_response.json"
  max_request_bytes: 32768
  max_response_bytes: 2097152

egress:
  profile: "proxy_allowlist"
  allowed_domains:
    - "api.github.com"
    - "httpbin.org"

secrets:
  - name: "GITHUB_TOKEN"
    required: false

risk_level: "low"

declared_side_effects:
  - "http_read"
"#
        );

        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(
            m.required_imports,
            vec!["latchgate:io/http".into(), "latchgate:io/log".into()]
        );
        assert_eq!(m.resource_limits.fuel, 5_000_000);
        assert_eq!(m.resource_limits.memory_mb, 128);
        assert_eq!(m.resource_limits.timeout_seconds, 60);
        assert_eq!(m.resource_limits.max_io_calls, 25);
        assert_eq!(m.io.max_request_bytes, 32768);
        assert_eq!(
            m.egress_profile().unwrap(),
            EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["api.github.com".into(), "httpbin.org".into()],
            }
        );
        assert_eq!(m.secrets.len(), 1);
        assert_eq!(&*m.secrets[0].name, "GITHUB_TOKEN");
        assert!(!m.secrets[0].required);
        assert_eq!(m.declared_side_effects, vec!["http_read".into()]);
        assert_eq!(m.verifier_kind, VerifierKind::HttpStatus);
        assert_eq!(m.required_scopes, vec!["tools:call".into()]);

        // Schema paths should be parsed as IoSchema::Path
        match &m.io.request_schema {
            Some(IoSchema::Path(p)) => assert_eq!(p, "./schemas/http_fetch_request.json"),
            other => panic!("expected IoSchema::Path, got {other:?}"),
        }
    }

    #[test]
    fn high_risk_manifest_parses() {
        let yaml = minimal_yaml(
            r#"risk_level: high
verifier_kind: http_status
declared_side_effects:
  - "http_read"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(m.risk_level, RiskLevel::High);
    }

    // -- Builtin provider --

    #[test]
    fn builtin_provider_module_accepted() {
        let m = ActionSpec::from_yaml(&builtin_yaml("")).unwrap();
        assert_eq!(&*m.provider_module_digest, "builtin:http_api");
        assert!(m.parsed_provider_module().unwrap().is_builtin());
    }

    #[test]
    fn builtin_unknown_name_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "builtin:unknown_provider"
template:
  method: GET
  url_template: "https://example.com"
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown builtin provider"));
    }

    #[test]
    fn builtin_empty_name_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "builtin:"
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("empty name"));
    }

    // -- Template actions --

    #[test]
    fn template_action_parses_correctly() {
        let m = ActionSpec::from_yaml(&builtin_yaml("")).unwrap();
        let tmpl = m.template.as_ref().expect("template should be Some");
        assert_eq!(tmpl.method, "GET");
        assert_eq!(tmpl.url_template, "https://api.github.com/{{path}}");
        assert_eq!(
            tmpl.headers.get("Accept"),
            Some(&"application/vnd.github.v3+json".to_string())
        );
        assert!(tmpl.body_template.is_none());
    }

    #[test]
    fn template_with_body_parses() {
        let yaml = r#"
action_id: "github_create_issue"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: POST
  url_template: "https://api.github.com/repos/{{owner}}/{{repo}}/issues"
  headers:
    Accept: "application/vnd.github.v3+json"
  body_template:
    title: "{{title}}"
    body: "{{body}}"
"#;
        let m = ActionSpec::from_yaml(yaml).unwrap();
        let tmpl = m.template.as_ref().unwrap();
        assert_eq!(tmpl.method, "POST");
        assert!(tmpl.body_template.is_some());
        let body = tmpl.body_template.as_ref().unwrap();
        assert_eq!(body["title"], "{{title}}");
    }

    #[test]
    fn template_requires_builtin_provider() {
        let yaml = format!(
            r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "{VALID_DIGEST}"
template:
  method: GET
  url_template: "https://api.example.com/{{path}}"
"#
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("builtin"),
            "expected builtin error, got: {err}"
        );
    }

    #[test]
    fn template_invalid_method_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: DESTROY
  url_template: "https://example.com"
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("method"),
            "expected method error, got: {err}"
        );
    }

    #[test]
    fn template_empty_url_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: GET
  url_template: ""
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("url_template"),
            "expected url error, got: {err}"
        );
    }

    #[test]
    fn template_variable_url_accepted() {
        let yaml = r#"
action_id: "webhook_notify"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: POST
  url_template: "{{url}}"
  headers:
    Content-Type: "application/json"
"#;
        let m = ActionSpec::from_yaml(yaml).unwrap();
        assert_eq!(m.template.as_ref().unwrap().url_template, "{{url}}");
    }

    #[test]
    fn no_template_with_sha256_is_fine() {
        let m = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        assert!(m.template.is_none());
    }

    // -- Inline schemas --

    #[test]
    fn inline_request_schema_parses() {
        let yaml = r#"
action_id: "test_inline"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: GET
  url_template: "https://api.example.com/{{path}}"
io:
  request_schema:
    type: object
    properties:
      path:
        type: string
        description: "API path"
    required:
      - path
  max_request_bytes: 4096
  max_response_bytes: 1048576
"#;
        let m = ActionSpec::from_yaml(yaml).unwrap();
        match &m.io.request_schema {
            Some(IoSchema::Inline(v)) => {
                assert_eq!(v["type"], "object");
                assert_eq!(v["required"][0], "path");
            }
            other => panic!("expected IoSchema::Inline, got {other:?}"),
        }
    }

    #[test]
    fn file_path_schema_still_works() {
        let yaml = minimal_yaml(
            r#"
io:
  request_schema: "../schemas/http_fetch_request.json"
  response_schema: "../schemas/http_fetch_response.json"
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        match &m.io.request_schema {
            Some(IoSchema::Path(p)) => assert_eq!(p, "../schemas/http_fetch_request.json"),
            other => panic!("expected IoSchema::Path, got {other:?}"),
        }
    }

    // -- Provider module / imports --

    #[test]
    fn required_imports_parse() {
        let yaml = minimal_yaml(
            r#"
required_imports:
  - "latchgate:io/smtp"
  - "latchgate:io/log"
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(
            m.required_imports,
            vec!["latchgate:io/smtp".into(), "latchgate:io/log".into()]
        );
    }

    #[test]
    fn invalid_import_prefix_rejected() {
        let yaml = minimal_yaml(
            r#"
required_imports:
  - "wasi:filesystem/types"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("latchgate:io/"));
    }

    #[test]
    fn resource_limits_override_defaults() {
        let yaml = minimal_yaml(
            r#"
resource_limits:
  fuel: 10000000
  memory_mb: 256
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(m.resource_limits.fuel, 10_000_000);
        assert_eq!(m.resource_limits.memory_mb, 256);
        assert_eq!(m.resource_limits.timeout_seconds, 30);
        assert_eq!(m.resource_limits.max_io_calls, 10);
    }

    // -- Verifier / effect --

    #[test]
    fn verifier_kinds_parse() {
        for (input, expected) in [
            ("http_status", VerifierKind::HttpStatus),
            ("fs_hash", VerifierKind::FsHash),
            ("none", VerifierKind::None),
        ] {
            let yaml = minimal_yaml(&format!("verifier_kind: {input}"));
            let m = ActionSpec::from_yaml(&yaml).unwrap();
            assert_eq!(m.verifier_kind, expected);
        }
    }

    #[test]
    fn verification_config_defaults_to_none() {
        let yaml = minimal_yaml("verifier_kind: http_status");
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert!(m.verification_config.is_none());
    }

    #[test]
    fn verification_config_parses_from_manifest() {
        let yaml = minimal_yaml(
            r#"
verifier_kind: http_status
verification_config:
  expected_status: [200, 201]
  required_fields: ["id"]
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        let config = m.verification_config.expect("config should be Some");
        assert_eq!(config["expected_status"], serde_json::json!([200, 201]));
        assert_eq!(config["required_fields"], serde_json::json!(["id"]));
    }

    // -- required_scopes --

    #[test]
    fn required_scopes_default_to_tools_call() {
        let m = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        assert_eq!(m.required_scopes, vec!["tools:call".into()]);
    }

    #[test]
    fn required_scopes_with_additional_scope_parses() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "tools:call"
  - "email:send"
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(
            m.required_scopes,
            vec!["tools:call".into(), "email:send".into()]
        );
    }

    #[test]
    fn required_scopes_multiple_additional_parses() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "tools:call"
  - "email:send"
  - "file:write"
  - "db:mutate"
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(m.required_scopes.len(), 4);
        assert!(m.required_scopes.iter().any(|s| **s == *"tools:call"));
        assert!(m.required_scopes.iter().any(|s| **s == *"email:send"));
    }

    #[test]
    fn required_scopes_empty_is_rejected() {
        let yaml = minimal_yaml("required_scopes: []");
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("required_scopes must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn required_scopes_missing_tools_call_is_rejected() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "email:send"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("tools:call"),
            "error must mention tools:call: {err}"
        );
    }

    #[test]
    fn required_scopes_invalid_format_rejected() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "tools:call"
  - "Email:send"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("Email:send"),
            "error must name the offending scope: {err}"
        );
    }

    #[test]
    fn required_scopes_no_separator_rejected() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "tools:call"
  - "emailsend"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("emailsend"),
            "error must name the offending scope: {err}"
        );
    }

    #[test]
    fn required_scopes_empty_name_rejected() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "tools:call"
  - "email:"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("email:"),
            "error must name the offending scope: {err}"
        );
    }

    #[test]
    fn required_scopes_too_short_rejected() {
        let yaml = minimal_yaml(
            r#"
required_scopes:
  - "tools:call"
  - "a:b"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("a:b"),
            "error must name the offending scope: {err}"
        );
    }

    // -- Scope format validator unit tests --

    #[test]
    fn validate_scope_format_accepts_valid_scopes() {
        for scope in &[
            "tools:call",
            "email:send",
            "file:write",
            "db:mutate",
            "audit:read",
            "queue:publish",
            "http:fetch",
            "s3:put-object",
            "ci:trigger_build",
        ] {
            validate_scope_format(scope)
                .unwrap_or_else(|e| panic!("scope '{scope}' should be valid, got: {e}"));
        }
    }

    #[test]
    fn validate_scope_format_rejects_uppercase() {
        assert!(validate_scope_format("Tools:call").is_err());
        assert!(validate_scope_format("tools:Call").is_err());
        assert!(validate_scope_format("TOOLS:CALL").is_err());
    }

    #[test]
    fn validate_scope_format_rejects_missing_separator() {
        assert!(validate_scope_format("toolscall").is_err());
        assert!(validate_scope_format("emailsend").is_err());
    }

    #[test]
    fn validate_scope_format_rejects_leading_colon() {
        assert!(validate_scope_format(":call").is_err());
    }

    #[test]
    fn validate_scope_format_rejects_trailing_colon() {
        assert!(validate_scope_format("tools:").is_err());
    }

    #[test]
    fn validate_scope_format_rejects_too_short() {
        assert!(validate_scope_format("a:b").is_err());
    }

    #[test]
    fn validate_scope_format_rejects_too_long() {
        let scope = "a:".to_string() + &"b".repeat(63);
        assert_eq!(scope.len(), 65);
        assert!(validate_scope_format(&scope).is_err());
    }

    #[test]
    fn validate_scope_format_rejects_special_chars() {
        assert!(validate_scope_format("tools:call!").is_err());
        assert!(validate_scope_format("tools:call ").is_err());
        assert!(validate_scope_format("tools:call/read").is_err());
    }

    // -- database_config (was database_config) --

    #[test]
    fn database_config_parses_from_manifest_yaml() {
        let yaml = minimal_yaml(
            r#"
required_imports:
  - "latchgate:io/database"
  - "latchgate:io/log"
database_config:
  mode: "hybrid"
  statements:
    - id: "get_order"
      sql: "SELECT * FROM orders WHERE id = $1"
    - id: "update_order_status"
      sql: "UPDATE orders SET status = $1 WHERE id = $2"
  rules:
    blocked_operations: ["ddl", "grant_revoke", "copy_io", "transaction_control", "multi_statement"]
    allow_parameterized: ["select"]
    require_where_for: ["update", "delete"]
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        let cfg = m.database_config.expect("database_config should be Some");
        assert_eq!(cfg["mode"], "hybrid");
        let stmts = cfg["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0]["id"], "get_order");
        assert_eq!(stmts[1]["id"], "update_order_status");
    }

    #[test]
    fn database_config_absent_means_none() {
        let m = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        assert!(m.database_config.is_none());
    }

    #[test]
    fn database_config_included_in_content_digest() {
        let base = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();

        let with_db = ActionSpec::from_yaml(&minimal_yaml(
            r#"
required_imports:
  - "latchgate:io/database"
database_config:
  mode: "hybrid"
  statements:
    - id: "get_order"
      sql: "SELECT * FROM orders WHERE id = $1"
"#,
        ))
        .unwrap();

        assert_ne!(
            base.content_digest, with_db.content_digest,
            "database_config must affect content digest"
        );
    }

    // -- Validation failures --

    #[test]
    fn empty_action_id_rejected() {
        let yaml = format!(
            r#"
action_id: ""
version: "1.0.0"
provider_module_digest: "{VALID_DIGEST}"
"#
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("action_id must not be empty"));
    }

    #[test]
    fn missing_provider_module_digest_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "not-a-sha256"
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(err
            .to_string()
            .contains("provider_module_digest must start with"));
    }

    #[test]
    fn short_provider_module_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "sha256:tooshort"
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("provider_module_digest must be"));
    }

    #[test]
    fn non_hex_provider_module_rejected() {
        let yaml = r#"
action_id: "test"
version: "1.0.0"
provider_module_digest: "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("non-hex characters"));
    }

    #[test]
    fn zero_timeout_rejected() {
        let yaml = minimal_yaml("resource_limits:\n  timeout_seconds: 0");
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            matches!(err, ManifestError::ResourceLimits(_)),
            "expected ResourceLimits error, got {err:?}"
        );
        assert!(err.to_string().contains("timeout_seconds"));
    }

    #[test]
    fn zero_fuel_rejected() {
        let yaml = minimal_yaml("resource_limits:\n  fuel: 0");
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            matches!(err, ManifestError::ResourceLimits(_)),
            "expected ResourceLimits error, got {err:?}"
        );
        assert!(err.to_string().contains("fuel"));
    }

    #[test]
    fn zero_memory_rejected() {
        let yaml = minimal_yaml("resource_limits:\n  memory_mb: 0");
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            matches!(err, ManifestError::ResourceLimits(_)),
            "expected ResourceLimits error, got {err:?}"
        );
        assert!(err.to_string().contains("memory_mb"));
    }

    #[test]
    fn zero_max_host_response_bytes_rejected() {
        let yaml = minimal_yaml("resource_limits:\n  max_host_response_bytes: 0");
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            matches!(err, ManifestError::ResourceLimits(_)),
            "expected ResourceLimits error, got {err:?}"
        );
        assert!(err.to_string().contains("max_host_response_bytes"));
    }

    #[test]
    fn unknown_egress_profile_rejected() {
        let yaml = minimal_yaml("egress:\n  profile: \"allow_all\"");
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("unknown egress profile"));
    }

    #[test]
    fn invalid_yaml_produces_parse_error() {
        let err = ActionSpec::from_yaml("not: [valid: yaml: here").unwrap_err();
        assert!(matches!(err, ManifestError::Yaml(_)));
    }

    // -- Edge cases --

    #[test]
    fn egress_none_explicit() {
        let yaml = minimal_yaml("egress:\n  profile: \"none\"");
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(m.egress_profile().unwrap(), EgressProfile::None);
    }

    #[test]
    fn multiple_secrets_parse() {
        let yaml = minimal_yaml(
            r#"
secrets:
  - name: "API_KEY"
    required: true
  - name: "OPTIONAL_TOKEN"
    required: false
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert_eq!(m.secrets.len(), 2);
        assert!(m.secrets[0].required);
        assert!(!m.secrets[1].required);
    }

    #[test]
    fn default_secret_required_is_false() {
        let yaml = minimal_yaml(
            r#"
secrets:
  - name: "TOKEN"
"#,
        );
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        assert!(!m.secrets[0].required);
    }

    // -- content digest --

    #[test]
    fn content_digest_is_deterministic() {
        let yaml = minimal_yaml("");
        let m = ActionSpec::from_yaml(&yaml).unwrap();
        let d1 = &m.content_digest;
        let d2 = &m.content_digest;
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn content_digest_changes_with_version() {
        let m1 = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        let yaml2 = minimal_yaml("").replace("version: \"1.0.0\"", "version: \"2.0.0\"");
        let m2 = ActionSpec::from_yaml(&yaml2).unwrap();
        assert_ne!(
            m1.content_digest, m2.content_digest,
            "different version must produce different digest"
        );
    }

    #[test]
    fn content_digest_changes_with_risk_level() {
        let m1 = ActionSpec::from_yaml(&minimal_yaml("risk_level: \"low\"")).unwrap();
        let high_yaml = minimal_yaml(
            r#"risk_level: "high"
verifier_kind: http_status
declared_side_effects:
  - "http_read"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
"#,
        );
        let m2 = ActionSpec::from_yaml(&high_yaml).unwrap();
        assert_ne!(
            m1.content_digest, m2.content_digest,
            "different risk_level must produce different digest"
        );
    }

    #[test]
    fn content_digest_changes_with_targets() {
        let m1 = ActionSpec::from_yaml(&minimal_yaml("declared_side_effects:\n  - \"http_read\""))
            .unwrap();
        let m2 = ActionSpec::from_yaml(&minimal_yaml(
            "declared_side_effects:\n  - \"http_read\"\n  - \"http_write\"",
        ))
        .unwrap();
        assert_ne!(
            m1.content_digest, m2.content_digest,
            "widened targets must produce different digest"
        );
    }

    #[test]
    fn content_digest_differs_from_provider_module() {
        let m = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        assert_ne!(
            m.content_digest.as_str(),
            &*m.provider_module_digest,
            "content digest must not equal provider module digest"
        );
    }

    #[test]
    fn content_digest_changes_with_template() {
        let m1 = ActionSpec::from_yaml(&builtin_yaml("")).unwrap();

        let yaml2 = r#"
action_id: "github_read"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: POST
  url_template: "https://api.github.com/{{path}}"
"#;
        let m2 = ActionSpec::from_yaml(yaml2).unwrap();

        assert_ne!(
            m1.content_digest, m2.content_digest,
            "different template must produce different digest"
        );
    }

    // -- ProviderModule --

    #[test]
    fn provider_module_parse_digest() {
        let pm = ProviderModule::parse(VALID_DIGEST).unwrap();
        assert!(matches!(pm, ProviderModule::Digest(_)));
        assert!(!pm.is_builtin());
        assert_eq!(pm.as_str(), VALID_DIGEST);
    }

    #[test]
    fn provider_module_parse_builtin() {
        let pm = ProviderModule::parse("builtin:http_api").unwrap();
        assert!(matches!(pm, ProviderModule::Builtin(_)));
        assert!(pm.is_builtin());
        assert_eq!(pm.as_str(), "builtin:http_api");
    }

    #[test]
    fn provider_module_parse_invalid_prefix() {
        let err = ProviderModule::parse("ftp://module.wasm").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn provider_module_parse_unknown_builtin() {
        let err = ProviderModule::parse("builtin:evil").unwrap_err();
        assert!(err.to_string().contains("unknown builtin"));
    }

    // -- High/critical security gates --

    #[test]
    fn high_risk_none_verifier_rejected() {
        let yaml = minimal_yaml(
            "risk_level: \"high\"\nverifier_kind: none\ndeclared_side_effects:\n  - \"http_read\"",
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("must declare a verifier_kind"),
            "expected verifier_kind rejection, got: {err}"
        );
    }

    #[test]
    fn critical_risk_none_verifier_rejected() {
        let yaml = minimal_yaml(
            "risk_level: \"critical\"\nverifier_kind: none\ndeclared_side_effects:\n  - \"http_delete\"",
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("must declare a verifier_kind"));
    }

    #[test]
    fn low_risk_none_verifier_accepted() {
        let yaml = minimal_yaml("risk_level: \"low\"\nverifier_kind: none");
        assert!(ActionSpec::from_yaml(&yaml).is_ok());
    }

    #[test]
    fn high_risk_without_response_schema_rejected() {
        let yaml = minimal_yaml(
            "risk_level: \"high\"\nverifier_kind: http_status\ndeclared_side_effects:\n  - \"http_read\"",
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("must declare io.response_schema"),
            "expected response_schema rejection, got: {err}"
        );
    }

    #[test]
    fn high_risk_with_response_schema_accepted() {
        let yaml = minimal_yaml(
            r#"risk_level: "high"
verifier_kind: http_status
declared_side_effects:
  - "http_read"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
"#,
        );
        assert!(ActionSpec::from_yaml(&yaml).is_ok());
    }

    #[test]
    fn high_risk_write_bare_http_status_rejected() {
        let yaml = minimal_yaml(
            r#"risk_level: "high"
verifier_kind: http_status
declared_side_effects:
  - "http_write"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("verification_config.required_fields"),
            "expected required_fields rejection, got: {err}"
        );
    }

    #[test]
    fn high_risk_write_http_status_with_required_fields_accepted() {
        let yaml = minimal_yaml(
            r#"risk_level: "high"
verifier_kind: http_status
declared_side_effects:
  - "http_write"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
verification_config:
  required_fields: ["ok", "data"]
"#,
        );
        assert!(ActionSpec::from_yaml(&yaml).is_ok());
    }

    #[test]
    fn high_risk_write_empty_required_fields_rejected() {
        let yaml = minimal_yaml(
            r#"risk_level: "high"
verifier_kind: http_status
declared_side_effects:
  - "http_write"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
verification_config:
  required_fields: []
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err();
        assert!(err
            .to_string()
            .contains("verification_config.required_fields"),);
    }

    #[test]
    fn critical_risk_read_only_http_status_accepted() {
        // Read-only high/critical (e.g. sensitive reads) may use bare http_status.
        let yaml = minimal_yaml(
            r#"risk_level: "critical"
verifier_kind: http_status
declared_side_effects:
  - "http_read"
io:
  response_schema:
    type: object
    properties:
      ok: { type: boolean }
"#,
        );
        assert!(ActionSpec::from_yaml(&yaml).is_ok());
    }

    // -- Filesystem provider validation --

    fn fs_yaml(overrides: &str) -> String {
        format!(
            r#"
action_id: "fs_write"
version: "1.0.0"
provider_module_digest: "builtin:fs"
verifier_kind: fs_hash
risk_level: "medium"
fs:
  allowed_operations: [create, overwrite]
  allowed_paths:
    - "src/**"
  denied_paths:
    - "**/.env"
  max_file_bytes: 1048576
declared_side_effects:
  - "fs_write"
{overrides}
"#
        )
    }

    #[test]
    fn fs_manifest_parses_valid() {
        let m = ActionSpec::from_yaml(&fs_yaml("")).unwrap();
        let fs = m.fs.as_ref().unwrap();
        assert_eq!(fs.allowed_operations.len(), 2);
        assert_eq!(fs.allowed_paths, vec!["src/**"]);
        assert_eq!(fs.denied_paths, vec!["**/.env"]);
        assert_eq!(fs.max_file_bytes, 1_048_576);
        assert_eq!(m.verifier_kind, VerifierKind::FsHash);
    }

    #[test]
    fn fs_manifest_rejects_non_builtin_fs_provider() {
        let yaml = r#"
action_id: "fs_bad"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
verifier_kind: fs_hash
fs:
  allowed_operations: [read]
  allowed_paths: ["src/**"]
"#
        .to_string();
        let err = ActionSpec::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("must use 'builtin:fs'"), "got: {err}");
    }

    #[test]
    fn fs_manifest_rejects_secrets() {
        let yaml = fs_yaml(
            r#"secrets:
  - name: "API_KEY"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("fs actions do not use secrets"), "got: {err}");
    }

    #[test]
    fn fs_manifest_rejects_egress() {
        let yaml = fs_yaml(
            r#"egress:
  profile: "proxy_allowlist"
  allowed_domains:
    - "api.example.com"
"#,
        );
        let err = ActionSpec::from_yaml(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("fs providers have no network capability"),
            "got: {err}"
        );
    }

    #[test]
    fn fs_manifest_rejects_empty_operations() {
        let yaml = r#"
action_id: "fs_bad"
version: "1.0.0"
provider_module_digest: "builtin:fs"
verifier_kind: fs_hash
fs:
  allowed_operations: []
  allowed_paths: ["src/**"]
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err().to_string();
        assert!(
            err.contains("allowed_operations must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn fs_manifest_rejects_zero_max_file_bytes() {
        let yaml = r#"
action_id: "fs_bad"
version: "1.0.0"
provider_module_digest: "builtin:fs"
verifier_kind: fs_hash
fs:
  allowed_operations: [read]
  allowed_paths: ["src/**"]
  max_file_bytes: 0
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("max_file_bytes must be > 0"), "got: {err}");
    }

    #[test]
    fn fs_manifest_rejects_wrong_verifier() {
        let yaml = r#"
action_id: "fs_bad"
version: "1.0.0"
provider_module_digest: "builtin:fs"
verifier_kind: http_status
fs:
  allowed_operations: [read]
  allowed_paths: ["src/**"]
"#;
        let err = ActionSpec::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("must use 'fs_hash'"), "got: {err}");
    }

    #[test]
    fn fs_manifest_included_in_content_digest() {
        let m1 = ActionSpec::from_yaml(&fs_yaml("")).unwrap();
        // Change denied_paths and verify digest changes.
        let yaml2 = r#"
action_id: "fs_write"
version: "1.0.0"
provider_module_digest: "builtin:fs"
verifier_kind: fs_hash
risk_level: "medium"
fs:
  allowed_operations: [create, overwrite]
  allowed_paths:
    - "src/**"
  denied_paths:
    - "**/.env"
    - "**/secrets/**"
  max_file_bytes: 1048576
declared_side_effects:
  - "fs_write"
"#;
        let m2 = ActionSpec::from_yaml(yaml2).unwrap();
        assert_ne!(m1.content_digest, m2.content_digest);
    }

    #[test]
    fn builtin_fs_accepted_in_allowed_builtins() {
        assert!(is_valid_builtin("fs"));
        assert!(is_valid_builtin("http_api"));
        assert!(!is_valid_builtin("not_a_builtin"));
    }

    #[test]
    fn fs_critical_risk_accepted_without_response_schema() {
        // fs_delete is critical risk but has no response_schema — fs actions
        // verify via host-observed hashes, not response body inspection.
        let yaml = r#"
action_id: "fs_delete"
version: "1.0.0"
provider_module_digest: "builtin:fs"
verifier_kind: fs_hash
risk_level: "critical"
fs:
  allowed_operations: [delete]
  allowed_paths:
    - "src/**"
    - "tests/**"
  denied_paths:
    - "**/.git/**"
    - "Cargo.toml"
declared_side_effects:
  - "fs_delete"
"#;
        assert!(ActionSpec::from_yaml(yaml).is_ok());
    }

    // -- YAML serialization round-trip tests ---------------------------------

    #[test]
    fn to_yaml_minimal_roundtrips() {
        let original = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        let yaml = original.to_yaml().unwrap();
        let reparsed = ActionSpec::from_yaml(&yaml).unwrap();

        assert_eq!(original.action_id, reparsed.action_id);
        assert_eq!(original.version, reparsed.version);
        assert_eq!(
            original.provider_module_digest,
            reparsed.provider_module_digest
        );
        assert_eq!(original.risk_level, reparsed.risk_level);
        assert_eq!(original.resource_limits, reparsed.resource_limits);
    }

    #[test]
    fn to_yaml_full_manifest_roundtrips() {
        let yaml = format!(
            r#"
action_id: "http_fetch"
version: "2.1.0"
provider_module_digest: "{VALID_DIGEST}"
required_imports:
  - "latchgate:io/http"
  - "latchgate:io/log"
resource_limits:
  fuel: 5000000
  memory_mb: 128
  timeout_seconds: 60
  max_io_calls: 25
verifier_kind: http_status
io:
  max_request_bytes: 32768
  max_response_bytes: 2097152
egress:
  profile: "proxy_allowlist"
  allowed_domains:
    - "api.github.com"
    - "httpbin.org"
secrets:
  - name: "GITHUB_TOKEN"
    required: false
risk_level: "low"
declared_side_effects:
  - "http_read"
tags:
  - "agent"
  - "research"
"#
        );

        let original = ActionSpec::from_yaml(&yaml).unwrap();
        let serialized = original.to_yaml().unwrap();
        let reparsed = ActionSpec::from_yaml(&serialized).unwrap();

        assert_eq!(original.action_id, reparsed.action_id);
        assert_eq!(original.version, reparsed.version);
        assert_eq!(
            original.provider_module_digest,
            reparsed.provider_module_digest
        );
        assert_eq!(original.risk_level, reparsed.risk_level);
        assert_eq!(original.required_imports, reparsed.required_imports);
        assert_eq!(original.resource_limits, reparsed.resource_limits);
        assert_eq!(original.io.max_request_bytes, reparsed.io.max_request_bytes);
        assert_eq!(
            original.io.max_response_bytes,
            reparsed.io.max_response_bytes
        );
        assert_eq!(
            original.egress.allowed_domains,
            reparsed.egress.allowed_domains
        );
        assert_eq!(original.egress.profile, reparsed.egress.profile);
        assert_eq!(original.secrets.len(), reparsed.secrets.len());
        assert_eq!(original.secrets[0].name, reparsed.secrets[0].name);
        assert_eq!(
            original.declared_side_effects,
            reparsed.declared_side_effects
        );
        assert_eq!(original.tags, reparsed.tags);
    }

    #[test]
    fn to_yaml_builtin_template_roundtrips() {
        let original = ActionSpec::from_yaml(&builtin_yaml("")).unwrap();
        let serialized = original.to_yaml().unwrap();
        let reparsed = ActionSpec::from_yaml(&serialized).unwrap();

        assert_eq!(original.action_id, reparsed.action_id);
        assert!(reparsed.template.is_some());
        let orig_tmpl = original.template.unwrap();
        let repr_tmpl = reparsed.template.unwrap();
        assert_eq!(orig_tmpl.method, repr_tmpl.method);
        assert_eq!(orig_tmpl.url_template, repr_tmpl.url_template);
        assert_eq!(orig_tmpl.headers, repr_tmpl.headers);
    }

    #[test]
    fn to_yaml_includes_header_comment() {
        let original = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        let yaml = original.to_yaml().unwrap();
        assert!(yaml.starts_with("# Manifest for action: http_fetch\n"));
        assert!(yaml.contains("Edited by latchgate TUI"));
    }

    #[test]
    fn to_yaml_content_digest_stable() {
        let original = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        let d1 = &original.content_digest;
        let serialized = original.to_yaml().unwrap();
        let reparsed = ActionSpec::from_yaml(&serialized).unwrap();
        let d2 = &reparsed.content_digest;
        assert_eq!(d1, d2, "content digest must survive YAML round-trip");
    }

    #[test]
    fn write_to_file_creates_valid_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test_action.yaml");

        let spec = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        spec.write_to_file(&path).unwrap();

        // Verify file exists and can be re-parsed.
        let reparsed = ActionSpec::from_file(&path).unwrap();
        assert_eq!(spec.action_id, reparsed.action_id);
        assert_eq!(spec.version, reparsed.version);
    }

    #[test]
    fn write_to_file_rejects_invalid_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.yaml");

        // Construct an invalid spec (empty action_id).
        let mut spec = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        spec.action_id = String::new();

        let err = spec.write_to_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("action_id must not be empty"),
            "got: {err}"
        );
        assert!(
            !path.exists(),
            "file must not be written on validation failure"
        );
    }

    #[test]
    fn write_to_file_is_atomic() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("action.yaml");

        // Write initial version.
        let spec = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        spec.write_to_file(&path).unwrap();
        let original_content = std::fs::read_to_string(&path).unwrap();

        // Overwrite with a different version by mutating the parsed struct.
        let mut spec2 = spec.clone();
        spec2.version = "2.0.0".into();
        spec2.write_to_file(&path).unwrap();
        let updated = std::fs::read_to_string(&path).unwrap();

        assert_ne!(original_content, updated);
        assert!(updated.contains("2.0.0"));

        // Verify no .tmp residue.
        assert!(
            !tmp.path().join("action.tmp").exists(),
            ".tmp must not remain"
        );
    }

    #[test]
    fn validate_spec_public_matches_internal() {
        let spec = ActionSpec::from_yaml(&minimal_yaml("")).unwrap();
        assert!(spec.validate_spec().is_ok());

        let mut bad = spec.clone();
        bad.action_id = String::new();
        assert!(bad.validate_spec().is_err());
    }
}
