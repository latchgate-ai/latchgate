//! Tests for Config TOML deserialization, defaults, and path resolution.
//!
//! Validation tests live in `validate.rs`; env override tests live in `env.rs`.

use super::*;
use std::path::Path;

#[test]
fn default_sandbox_mode_is_strict() {
    let config = Config::default();
    assert_eq!(config.sandbox.mode, SandboxMode::Strict);
}

#[test]
fn default_strict_for_actions_is_true() {
    let config = Config::default();
    assert!(config.sandbox.strict_for_actions);
}

#[test]
fn default_redis_url() {
    assert_eq!(Config::default().storage.redis_url, None);
}

#[test]
fn default_opa_url() {
    assert_eq!(Config::default().policy.opa_url, None);
}

#[test]
fn default_lease_ttl_is_300_seconds() {
    assert_eq!(Config::default().policy.lease_ttl_seconds, 300);
}

#[test]
fn unresolved_paths_are_empty_by_default() {
    let config = Config::default();
    assert!(config.manifests_dir.is_empty());
    assert!(config.wasm_providers_dir.is_empty());
    assert!(config.storage.ledger_db_path.is_empty());
}

#[test]
fn config_uses_defaults_for_missing_fields() {
    let config: Config = toml::from_str("").unwrap();
    assert_eq!(config.logging.format, LogFormat::Auto);
    assert!(config.listener.listen_http_addr.is_none());
    assert!(!config.listener.unsafe_expose_http);
    assert_eq!(config.listener.public_base_url, "http://localhost:3000");
}

#[test]
fn dev_mode_defaults_to_false() {
    // SECURITY: dev mode must never be active without both the
    // `unsafe-dev` Cargo feature and the runtime env var.
    let config = Config::default();
    assert!(!config.dev_mode());
}

#[test]
fn posture_controls_dev_mode() {
    let config = Config {
        posture: SecurityPosture::all_insecure(),
        ..Config::default()
    };
    assert!(config.dev_mode());

    let config = Config {
        posture: SecurityPosture::default(),
        ..Config::default()
    };
    assert!(!config.dev_mode());
}

#[test]
fn config_parses_sandbox_mode_degraded_ok() {
    let toml_str = r#"
[sandbox]
mode = "degraded_ok"
strict_for_actions = false
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.sandbox.mode, SandboxMode::DegradedOk);
    assert!(!config.sandbox.strict_for_actions);
}

#[test]
fn config_parses_http_addr() {
    let toml_str = r#"
listen_http_addr = "127.0.0.1:8080"
unsafe_expose_http = true
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        config.listener.listen_http_addr,
        Some("127.0.0.1:8080".parse().unwrap())
    );
    assert!(config.listener.unsafe_expose_http);
}

#[test]
fn config_parses_uds_path() {
    let toml_str = r#"
listen_uds_path = "/tmp/mygate.sock"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.listener.listen_uds_path, "/tmp/mygate.sock");
}

#[test]
fn bind_addr_derived_from_http_addr() {
    let addr: std::net::SocketAddr = "127.0.0.1:4000".parse().unwrap();
    let config = Config {
        listener: ListenerConfig {
            listen_http_addr: Some(addr),
            unsafe_expose_http: true,
            ..ListenerConfig::default()
        },
        ..Config::default()
    };
    assert_eq!(
        config.listener.listen_http_addr.unwrap().ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert_eq!(config.listener.listen_http_addr.unwrap().port(), 4000);
}

#[test]
fn config_parses_manifests_dir() {
    let toml_str = r#"manifests_dir = "/opt/latchgate/manifests""#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.manifests_dir, "/opt/latchgate/manifests");
}

#[test]
fn config_parses_redis_opa_and_ttl() {
    let toml_str = r#"
redis_url = "redis://redis.internal:6380"
opa_url = "http://opa.internal:8182"
lease_ttl_seconds = 600
public_base_url = "https://gate.example.com"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        config.storage.redis_url,
        Some("redis://redis.internal:6380".to_string())
    );
    assert_eq!(
        config.policy.opa_url,
        Some("http://opa.internal:8182".to_string())
    );
    assert_eq!(config.policy.lease_ttl_seconds, 600);
    assert_eq!(config.listener.public_base_url, "https://gate.example.com");
}

/// TOML: operator_credentials parses correctly.
#[test]
fn config_parses_operator_credentials_toml() {
    let toml_str = r#"
[operator_credentials.alice]
api_key = "key-alice-secret"
dpop_jkt = "thumbprint-alice-abc"

[operator_credentials.bob]
api_key = "key-bob-secret"
dpop_jkt = "thumbprint-bob-xyz"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.operator_credentials.len(), 2);
    assert_eq!(
        config.operator_credentials["alice"].dpop_jkt.as_deref(),
        Some("thumbprint-alice-abc")
    );
    assert_eq!(config.operator_credentials["bob"].api_key, "key-bob-secret");
}

// -- PeercredPrincipal deserialization --

#[test]
fn peercred_principal_deserializes_with_owner() {
    let toml_str = r#"
[identity.peercred.principals]
1001 = { principal = "agent:deploy-bot", scopes = ["tools:call"], owner = "alice@company.com" }
1002 = { principal = "agent:email-assist", scopes = ["tools:call", "email:send"], owner = "bob@company.com" }
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    let p1001 = &config.identity.peercred.principals["1001"];
    assert_eq!(p1001.principal, "agent:deploy-bot");
    assert_eq!(
        p1001.owner.as_deref(),
        Some("alice@company.com"),
        "owner must deserialize from TOML"
    );
    let p1002 = &config.identity.peercred.principals["1002"];
    assert_eq!(p1002.owner.as_deref(), Some("bob@company.com"),);
}

#[test]
fn peercred_principal_deserializes_without_owner() {
    let toml_str = r#"
[identity.peercred.principals]
1001 = { principal = "agent:ci-runner", scopes = ["tools:call"] }
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    let p = &config.identity.peercred.principals["1001"];
    assert_eq!(p.principal, "agent:ci-runner");
    assert!(
        p.owner.is_none(),
        "owner must default to None when omitted from TOML — \
             this is the backward-compatibility guarantee"
    );
}

#[test]
fn peercred_principal_mixed_owner_and_no_owner() {
    let toml_str = r#"
[identity.peercred.principals]
1001 = { principal = "agent:with-owner", scopes = ["tools:call"], owner = "alice@company.com" }
1002 = { principal = "agent:no-owner", scopes = ["tools:call"] }
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        config.identity.peercred.principals["1001"].owner.as_deref(),
        Some("alice@company.com"),
    );
    assert!(
        config.identity.peercred.principals["1002"].owner.is_none(),
        "principals with and without owner must coexist in the same config"
    );
}

#[test]
fn from_file_resolves_empty_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("latchgate.toml");
    std::fs::write(&config_path, "redis_url = \"redis://127.0.0.1:6379\"\n").unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert!(
        !config.manifests_dir.is_empty(),
        "manifests_dir must be resolved, got empty"
    );
    assert!(
        !config.wasm_providers_dir.is_empty(),
        "wasm_providers_dir must be resolved, got empty"
    );
    assert!(
        !config.storage.ledger_db_path.is_empty(),
        "ledger_db_path must be resolved, got empty"
    );
}

#[test]
fn from_file_resolves_relative_to_config_parent() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("latchgate.toml");
    std::fs::write(&config_path, "").unwrap();

    let config = Config::from_file(&config_path).unwrap();

    let parent = tmp.path().to_string_lossy();
    assert!(
        config.manifests_dir.starts_with(parent.as_ref()),
        "manifests_dir should be under config parent: {}",
        config.manifests_dir,
    );
    assert!(
        config.storage.ledger_db_path.starts_with(parent.as_ref()),
        "ledger_db_path should be under config parent: {}",
        config.storage.ledger_db_path,
    );
}

#[test]
fn explicit_toml_paths_are_not_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("latchgate.toml");
    std::fs::write(
        &config_path,
        r#"
manifests_dir = "/custom/manifests"
wasm_providers_dir = "/custom/providers"
ledger_db_path = "/custom/audit.db"
"#,
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert_eq!(config.manifests_dir, "/custom/manifests");
    assert_eq!(config.wasm_providers_dir, "/custom/providers");
    assert_eq!(config.storage.ledger_db_path, "/custom/audit.db");
}

#[test]
fn source_is_explicit_for_from_file() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("latchgate.toml");
    std::fs::write(&config_path, "").unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert!(
        matches!(config.source, crate::ConfigSource::Explicit(_)),
        "source should be Explicit, got: {:?}",
        config.source,
    );
}

#[test]
fn source_is_defaults_for_default() {
    let config = Config::default();
    assert!(matches!(config.source, crate::ConfigSource::Defaults));
}

#[test]
fn manifest_dirs_contains_primary() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("latchgate.toml");
    std::fs::write(&config_path, "manifests_dir = \"/opt/manifests\"\n").unwrap();

    let config = Config::from_file(&config_path).unwrap();
    let dirs = config.manifest_dirs();

    assert!(
        dirs.iter().any(|d| d == Path::new("/opt/manifests")),
        "manifest_dirs must include the configured dir: {dirs:?}"
    );
    assert_eq!(
        dirs.last().map(|p| p.as_path()),
        Some(Path::new("/opt/manifests")),
        "configured dir must be last (highest priority)"
    );
}

#[test]
fn provider_dirs_contains_primary() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("latchgate.toml");
    std::fs::write(&config_path, "wasm_providers_dir = \"/opt/providers\"\n").unwrap();

    let config = Config::from_file(&config_path).unwrap();
    let dirs = config.provider_dirs();

    assert!(
        dirs.iter().any(|d| d == Path::new("/opt/providers")),
        "provider_dirs must include the configured dir: {dirs:?}"
    );
}

#[test]
fn toml_admin_tls_fields_parsed() {
    let toml_str = r#"
admin_tls_cert = "/certs/server.crt"
admin_tls_key = "/certs/server.key"
admin_tls_ca = "/certs/ca.crt"
listen_admin_http_addr = "0.0.0.0:9443"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        config.listener.admin_tls_cert.as_deref(),
        Some("/certs/server.crt"),
    );
    assert_eq!(
        config.listener.admin_tls_key.as_deref(),
        Some("/certs/server.key"),
    );
    assert_eq!(
        config.listener.admin_tls_ca.as_deref(),
        Some("/certs/ca.crt"),
    );
    assert!(config.listener.admin_tls_configured());
    assert_eq!(
        config.listener.listen_admin_http_addr.unwrap().to_string(),
        "0.0.0.0:9443",
    );
}

#[test]
fn toml_admin_tls_absent_defaults_to_none() {
    let config: Config = toml::from_str("").unwrap();
    assert!(config.listener.admin_tls_cert.is_none());
    assert!(config.listener.admin_tls_key.is_none());
    assert!(config.listener.admin_tls_ca.is_none());
    assert!(!config.listener.admin_tls_configured());
}

/// Managed-mode TOML with mTLS fields matches provisioner output.
#[test]
fn toml_tcp_mtls_mode_config() {
    let toml_str = r#"
listen_admin_http_addr = "0.0.0.0:9443"
admin_tls_cert = "/certs/server.crt"
admin_tls_key = "/certs/server.key"
admin_tls_ca = "/certs/ca.crt"
public_base_url = "https://latchgate"

[operator_credentials.platform]
api_key = "${LATCHGATE_OPERATOR_API_KEY}"
dpop_jkt = "test-thumbprint"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();

    assert!(config.listener.admin_tls_configured());
    assert!(!config.listener.unsafe_expose_http);
    assert_eq!(config.listener.public_base_url, "https://latchgate");
    assert!(config.operator_credentials.contains_key("platform"));
}

#[test]
fn posture_details_default_config_all_enforced() {
    let config = Config::default();
    let details = config.posture_details();

    for d in &details {
        assert!(
            d.enforced,
            "default config must enforce all protections, but '{}' is relaxed",
            d.name
        );
    }
}

#[test]
fn posture_details_identity_none_when_insecure() {
    let mut config = Config::default();
    config.posture.identity_insecure = true;
    let details = config.posture_details();

    let identity = details.iter().find(|d| d.name == "identity").unwrap();
    assert!(!identity.enforced);
    assert!(
        identity.status.contains("unauthenticated"),
        "identity status should say unauthenticated, got: {}",
        identity.status
    );
}

#[test]
fn posture_details_identity_peercred_shows_principal_count() {
    let toml_str = r#"
[identity]
provider = "peercred"

[identity.peercred.principals.1000]
principal = "alice"
scopes = ["tools:call"]

[identity.peercred.principals.1001]
principal = "bob"
scopes = ["tools:call"]
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    let details = config.posture_details();

    let identity = details.iter().find(|d| d.name == "identity").unwrap();
    assert!(identity.enforced);
    assert!(
        identity.status.contains("2 principals"),
        "expected '2 principals' in status, got: {}",
        identity.status
    );
}

#[test]
fn posture_details_signing_ephemeral_when_insecure() {
    let mut config = Config::default();
    config.posture.signing_insecure = true;
    let details = config.posture_details();

    let signing = details.iter().find(|d| d.name == "signing").unwrap();
    assert!(!signing.enforced);
    assert!(
        signing.status.contains("ephemeral"),
        "signing status should say ephemeral, got: {}",
        signing.status
    );
}

#[test]
fn posture_details_signing_persistent_with_keys() {
    let mut config = Config::default();
    config.signing.receipt_signing_key_path = Some("/keys/receipt.key".into());
    config.signing.grant_signing_key_path = Some("/keys/grant.key".into());
    config.signing.receipt_keys_jwks_path = Some("/keys/receipt.jwks".into());
    let details = config.posture_details();

    let signing = details.iter().find(|d| d.name == "signing").unwrap();
    assert!(signing.enforced);
    assert!(
        signing.status.contains("persistent") && signing.status.contains("JWKS"),
        "expected persistent + JWKS in status, got: {}",
        signing.status
    );
}

#[test]
fn posture_details_transport_uds_only_by_default() {
    let config = Config::default();
    let details = config.posture_details();

    let transport = details.iter().find(|d| d.name == "transport").unwrap();
    assert!(transport.enforced);
    assert_eq!(transport.status, "UDS only");
}

#[test]
fn posture_details_transport_http_not_enforced() {
    let mut config = Config::default();
    config.listener.unsafe_expose_http = true;
    config.listener.listen_http_addr = Some("127.0.0.1:3000".parse().unwrap());
    let details = config.posture_details();

    let transport = details.iter().find(|d| d.name == "transport").unwrap();
    assert!(!transport.enforced);
    assert!(
        transport.status.contains("HTTP") && transport.status.contains("127.0.0.1:3000"),
        "expected HTTP addr in status, got: {}",
        transport.status
    );
}

#[test]
fn posture_details_schema_warn_not_enforced() {
    let mut config = Config::default();
    config.posture.schema_insecure = true;
    config.response_schema_enforcement = ResponseSchemaEnforcement::Warn;
    let details = config.posture_details();

    let schema = details.iter().find(|d| d.name == "schema").unwrap();
    assert!(!schema.enforced);
    assert!(
        schema.status.contains("warn"),
        "expected 'warn' in status, got: {}",
        schema.status
    );
}
