//! Environment variable overrides for configuration.
//!
//! Precedence: env vars > TOML file > compiled defaults.
//! Invalid env values produce hard errors (fail-closed).

use std::net::SocketAddr;

use super::{
    Config, ConfigError, LogFormat, LogRotation, OperatorCredential, ResponseSchemaEnforcement,
};

/// Parse an env var value into any type that implements `FromStr`.
///
/// Returns `ConfigError::InvalidEnvVar` on parse failure. This is fail-closed:
/// an operator who sets an env var to an unparseable value gets a startup error,
/// not a silent fallback to default.
pub(crate) fn parse_env_value<T: std::str::FromStr>(
    name: &str,
    value: &str,
) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|e| ConfigError::InvalidEnvVar {
        name: name.to_string(),
        value: value.to_string(),
        reason: e.to_string(),
    })
}

/// Parse a boolean env var. Accepts `true`/`1` and `false`/`0` (case-insensitive).
///
/// SECURITY: rejects ambiguous values like `yes`, `on`, `enabled`. Boolean
/// security flags must be unambiguous.
pub(crate) fn parse_env_bool(name: &str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ConfigError::InvalidEnvVar {
            name: name.to_string(),
            value: value.to_string(),
            reason: "expected 'true', 'false', '1', or '0'".to_string(),
        }),
    }
}

/// Parse an optional string env var. Empty string maps to `None`,
/// non-empty maps to `Some(value)`.
///
/// This allows unsetting an Option field via env: `LATCHGATE_FIELD=""`.
pub(crate) fn parse_env_optional_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parse `LogFormat` from env var value.
pub(crate) fn parse_env_log_format(name: &str, value: &str) -> Result<LogFormat, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "auto" => Ok(LogFormat::Auto),
        "json" => Ok(LogFormat::Json),
        "pretty" => Ok(LogFormat::Pretty),
        _ => Err(ConfigError::InvalidEnvVar {
            name: name.to_string(),
            value: value.to_string(),
            reason: "expected 'auto', 'json', or 'pretty'".to_string(),
        }),
    }
}

/// Parse `ResponseSchemaEnforcement` from env var value.
pub(crate) fn parse_env_response_schema(
    name: &str,
    value: &str,
) -> Result<ResponseSchemaEnforcement, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "deny" => Ok(ResponseSchemaEnforcement::Deny),
        "warn" => Ok(ResponseSchemaEnforcement::Warn),
        _ => Err(ConfigError::InvalidEnvVar {
            name: name.to_string(),
            value: value.to_string(),
            reason: "expected 'deny' or 'warn'".to_string(),
        }),
    }
}

impl Config {
    pub(crate) fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        self.apply_env_overrides_from(|key| std::env::var(key).ok())
    }

    /// Testable core of env override logic. Accepts an env reader function
    /// so tests can inject values without touching process-global state.
    pub(crate) fn apply_env_overrides_from(
        &mut self,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<(), ConfigError> {
        // --- String fields ---

        if let Some(v) = get_env("LATCHGATE_LOG_LEVEL") {
            self.logging.level = v;
        }
        if let Some(v) = get_env("LATCHGATE_LOG_FORMAT") {
            self.logging.format = parse_env_log_format("LATCHGATE_LOG_FORMAT", &v)?;
        }
        if let Some(v) = get_env("LATCHGATE_LOG_FILE") {
            self.logging.file = Some(v);
        }
        if let Some(v) = get_env("LATCHGATE_LOG_ROTATION") {
            self.logging.rotation = match v.to_lowercase().as_str() {
                "daily" => LogRotation::Daily,
                "hourly" => LogRotation::Hourly,
                "never" => LogRotation::Never,
                _ => {
                    return Err(ConfigError::InvalidEnvVar {
                        name: "LATCHGATE_LOG_ROTATION".into(),
                        value: v,
                        reason: "must be daily, hourly, or never".into(),
                    });
                }
            };
        }
        if let Some(v) = get_env("LATCHGATE_LOG_MAX_FILES") {
            self.logging.max_files = parse_env_value("LATCHGATE_LOG_MAX_FILES", &v)?;
        }
        if let Some(v) = get_env("LATCHGATE_LISTEN_UDS_PATH") {
            self.listener.listen_uds_path = v;
        }
        if let Some(v) = get_env("LATCHGATE_LISTEN_ADMIN_UDS_PATH") {
            self.listener.listen_admin_uds_path = v;
        }
        if let Some(v) = get_env("LATCHGATE_LISTEN_HTTP_ADDR") {
            self.listener.listen_http_addr = Some(parse_env_value::<SocketAddr>(
                "LATCHGATE_LISTEN_HTTP_ADDR",
                &v,
            )?);
        }
        if let Some(v) = get_env("LATCHGATE_LISTEN_ADMIN_HTTP_ADDR") {
            self.listener.listen_admin_http_addr = Some(parse_env_value::<SocketAddr>(
                "LATCHGATE_LISTEN_ADMIN_HTTP_ADDR",
                &v,
            )?);
        }
        if let Some(v) = get_env("LATCHGATE_UNSAFE_EXPOSE_HTTP") {
            self.listener.unsafe_expose_http = parse_env_bool("LATCHGATE_UNSAFE_EXPOSE_HTTP", &v)?;
        }
        if let Some(v) = get_env("LATCHGATE_PUBLIC_BASE_URL") {
            self.listener.public_base_url = v;
        }

        // --- Admin TLS (mTLS for managed-mode TCP transport) ---

        if let Some(v) = get_env("LATCHGATE_ADMIN_TLS_CERT") {
            self.listener.admin_tls_cert = parse_env_optional_string(&v);
        }
        if let Some(v) = get_env("LATCHGATE_ADMIN_TLS_KEY") {
            self.listener.admin_tls_key = parse_env_optional_string(&v);
        }
        if let Some(v) = get_env("LATCHGATE_ADMIN_TLS_CA") {
            self.listener.admin_tls_ca = parse_env_optional_string(&v);
        }

        if let Some(v) = get_env("LATCHGATE_REDIS_URL") {
            self.storage.redis_url = Some(v);
        }

        if let Some(v) = get_env("LATCHGATE_OPA_URL") {
            self.policy.opa_url = Some(v);
        }

        // --- Numeric fields ---

        if let Some(v) = get_env("LATCHGATE_LEASE_TTL_SECONDS") {
            self.policy.lease_ttl_seconds = parse_env_value("LATCHGATE_LEASE_TTL_SECONDS", &v)?;
        }

        // --- Path / directory fields ---

        if let Some(v) = get_env("LATCHGATE_MANIFESTS_DIR") {
            self.manifests_dir = v;
        }
        if let Some(v) = get_env("LATCHGATE_WASM_PROVIDERS_DIR") {
            self.wasm_providers_dir = v;
        }
        if let Some(v) = get_env("LATCHGATE_LEDGER_DB_PATH") {
            self.storage.ledger_db_path = v;
        }
        if let Some(v) = get_env("LATCHGATE_LEDGER_JSONL_PATH") {
            self.storage.ledger_jsonl_path = parse_env_optional_string(&v);
        }

        // --- Signing material ---

        if let Some(v) = get_env("LATCHGATE_RECEIPT_SIGNING_KEY_PATH") {
            self.signing.receipt_signing_key_path = parse_env_optional_string(&v);
        }
        if let Some(v) = get_env("LATCHGATE_GRANT_SIGNING_KEY_PATH") {
            self.signing.grant_signing_key_path = parse_env_optional_string(&v);
        }
        if let Some(v) = get_env("LATCHGATE_RECEIPT_KEYS_JWKS_PATH") {
            self.signing.receipt_keys_jwks_path = parse_env_optional_string(&v);
        }

        // --- Enum fields ---

        if let Some(v) = get_env("LATCHGATE_RESPONSE_SCHEMA_ENFORCEMENT") {
            self.response_schema_enforcement =
                parse_env_response_schema("LATCHGATE_RESPONSE_SCHEMA_ENFORCEMENT", &v)?;
        }

        // --- SOPS ---

        if let Some(v) = get_env("LATCHGATE_SOPS_KEY_FILE") {
            self.secrets.sops_key_file = parse_env_optional_string(&v);
        }
        if let Some(v) = get_env("LATCHGATE_SOPS_SECRETS_FILE") {
            self.secrets.sops_secrets_file = parse_env_optional_string(&v);
        }

        // --- Host I/O clients ---
        //
        // LATCHGATE_HOST_IO_{NAME}_URL populates host_io.{name}.url
        // Empty value removes the backend (disables it).
        let host_io_backends = [
            ("LATCHGATE_HOST_IO_DATABASE_URL", "database"),
            ("LATCHGATE_HOST_IO_QUEUE_URL", "queue"),
            ("LATCHGATE_HOST_IO_STORAGE_URL", "storage"),
            ("LATCHGATE_HOST_IO_SMTP_URL", "smtp"),
        ];
        for (env_key, backend_name) in &host_io_backends {
            if let Some(v) = get_env(env_key) {
                if v.is_empty() {
                    self.host_io.remove(*backend_name);
                } else {
                    let mut table = toml::map::Map::new();
                    table.insert("url".into(), toml::Value::String(v));
                    self.host_io
                        .insert(backend_name.to_string(), toml::Value::Table(table));
                }
            }
        }

        // --- Operator credentials ---
        //
        // `LATCHGATE_OPERATOR_API_KEY` sets a single operator credential named
        // "platform" with the given API key. If `operator_credentials` already
        // contains a "platform" entry from TOML, the env var takes precedence.
        if let Some(v) = get_env("LATCHGATE_OPERATOR_API_KEY") {
            let dpop_jkt = get_env("LATCHGATE_OPERATOR_DPOP_JKT");
            self.operator_credentials.insert(
                "platform".to_string(),
                OperatorCredential {
                    api_key: v,
                    dpop_jkt,
                },
            );
        }

        // --- Per-session filesystem root prefixes ---
        //
        // Colon-separated list of absolute paths. Empty value disables
        // per-session roots entirely (fail-closed).
        if let Some(v) = get_env("LATCHGATE_FS_ROOT_ALLOWED_PREFIXES") {
            if v.is_empty() {
                self.fs_root_allowed_prefixes = Vec::new();
            } else {
                self.fs_root_allowed_prefixes = v
                    .split(':')
                    .filter(|s| !s.is_empty())
                    .map(std::path::PathBuf::from)
                    .collect();
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_env_bool, parse_env_optional_string};
    use crate::listener::ListenerConfig;
    use crate::{Config, ConfigError, LogFormat, ResponseSchemaEnforcement};
    use std::collections::HashMap;

    /// Build an env reader from a HashMap for isolated tests.
    fn env_from<'a>(map: &'a HashMap<&'a str, &'a str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| map.get(key).map(|v| v.to_string())
    }

    #[test]
    fn env_overrides_noop_when_empty() {
        let original = Config::default();
        let mut config = Config::default();
        let env: HashMap<&str, &str> = HashMap::new();
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.storage.redis_url, original.storage.redis_url);
        assert_eq!(config.policy.opa_url, original.policy.opa_url);
        assert_eq!(
            config.policy.lease_ttl_seconds,
            original.policy.lease_ttl_seconds
        );
    }

    #[test]
    fn env_overrides_string_fields() {
        let mut config = Config::default();
        let env = HashMap::from([
            ("LATCHGATE_REDIS_URL", "redis://redis.tenant-a:6379/0"),
            ("LATCHGATE_REDIS_KEY_PREFIX", "latchgate:acme:jti:"),
            ("LATCHGATE_OPA_URL", "http://opa.tenant-a:8181"),
            ("LATCHGATE_PUBLIC_BASE_URL", "https://gate.example.com"),
            ("LATCHGATE_LISTEN_UDS_PATH", "/run/latchgate/a.sock"),
            (
                "LATCHGATE_LISTEN_ADMIN_UDS_PATH",
                "/run/latchgate/a-admin.sock",
            ),
            ("LATCHGATE_MANIFESTS_DIR", "/var/latchgate/a/manifests"),
            ("LATCHGATE_WASM_PROVIDERS_DIR", "/opt/latchgate/providers"),
            ("LATCHGATE_LEDGER_DB_PATH", "/var/latchgate/a/audit.db"),
            ("LATCHGATE_LOG_LEVEL", "debug"),
            ("LATCHGATE_SOPS_BIN", "/usr/local/bin/sops"),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert_eq!(
            config.storage.redis_url,
            Some("redis://redis.tenant-a:6379/0".to_string())
        );
        assert_eq!(
            config.policy.opa_url,
            Some("http://opa.tenant-a:8181".to_string())
        );
        assert_eq!(config.listener.public_base_url, "https://gate.example.com");
        assert_eq!(config.listener.listen_uds_path, "/run/latchgate/a.sock");
        assert_eq!(
            config.listener.listen_admin_uds_path,
            "/run/latchgate/a-admin.sock"
        );
        assert_eq!(config.manifests_dir, "/var/latchgate/a/manifests");
        assert_eq!(config.wasm_providers_dir, "/opt/latchgate/providers");
        assert_eq!(config.storage.ledger_db_path, "/var/latchgate/a/audit.db");
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn env_overrides_numeric_fields() {
        let mut config = Config::default();
        let env = HashMap::from([
            ("LATCHGATE_LEASE_TTL_SECONDS", "2000"),
            ("LATCHGATE_LEASE_TTL_SECONDS", "600"),
            ("LATCHGATE_MAX_LEASE_TTL_SECONDS", "7200"),
            ("LATCHGATE_REPLAY_TTL_SECONDS", "360"),
            ("LATCHGATE_APPROVAL_TTL_SECONDS", "120"),
            ("LATCHGATE_MAX_CONCURRENT_EXECUTIONS", "8"),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert_eq!(config.policy.lease_ttl_seconds, 600);
    }

    #[test]
    fn env_overrides_bool_fields() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_UNSAFE_EXPOSE_HTTP", "true")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert!(config.listener.unsafe_expose_http);

        let mut config = Config {
            listener: ListenerConfig {
                unsafe_expose_http: true,
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        let env = HashMap::from([("LATCHGATE_UNSAFE_EXPOSE_HTTP", "false")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert!(!config.listener.unsafe_expose_http);

        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_UNSAFE_EXPOSE_HTTP", "1")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert!(config.listener.unsafe_expose_http);

        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_UNSAFE_EXPOSE_HTTP", "0")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert!(!config.listener.unsafe_expose_http);
    }

    #[test]
    fn env_overrides_optional_string_fields() {
        let mut config = Config::default();
        let env = HashMap::from([
            ("LATCHGATE_LEDGER_JSONL_PATH", "/var/log/latchgate.jsonl"),
            (
                "LATCHGATE_RECEIPT_SIGNING_KEY_PATH",
                "/etc/latchgate/receipt.key",
            ),
            (
                "LATCHGATE_GRANT_SIGNING_KEY_PATH",
                "/etc/latchgate/grant.key",
            ),
            (
                "LATCHGATE_RECEIPT_KEYS_JWKS_PATH",
                "/etc/latchgate/keys.jwks",
            ),
            ("LATCHGATE_SOPS_KEY_FILE", "/etc/latchgate/age.key"),
            (
                "LATCHGATE_SOPS_SECRETS_FILE",
                "/etc/latchgate/secrets.enc.yaml",
            ),
            ("LATCHGATE_HOST_IO_DATABASE_URL", "postgres://localhost/db"),
            ("LATCHGATE_HOST_IO_QUEUE_URL", "amqp://localhost"),
            ("LATCHGATE_HOST_IO_STORAGE_URL", "s3://bucket"),
            ("LATCHGATE_HOST_IO_SMTP_URL", "smtp://localhost:587"),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert_eq!(
            config.storage.ledger_jsonl_path.as_deref(),
            Some("/var/log/latchgate.jsonl")
        );
        assert_eq!(
            config.signing.receipt_signing_key_path.as_deref(),
            Some("/etc/latchgate/receipt.key")
        );
        assert_eq!(
            config.signing.grant_signing_key_path.as_deref(),
            Some("/etc/latchgate/grant.key")
        );
        assert_eq!(
            config.signing.receipt_keys_jwks_path.as_deref(),
            Some("/etc/latchgate/keys.jwks")
        );
        assert_eq!(
            config.secrets.sops_key_file.as_deref(),
            Some("/etc/latchgate/age.key")
        );
        assert_eq!(
            config.secrets.sops_secrets_file.as_deref(),
            Some("/etc/latchgate/secrets.enc.yaml")
        );
        // Host I/O backends populated via env vars.
        assert_eq!(
            config.host_io["database"].as_table().unwrap()["url"].as_str(),
            Some("postgres://localhost/db")
        );
        assert_eq!(
            config.host_io["queue"].as_table().unwrap()["url"].as_str(),
            Some("amqp://localhost")
        );
        assert_eq!(
            config.host_io["storage"].as_table().unwrap()["url"].as_str(),
            Some("s3://bucket")
        );
        assert_eq!(
            config.host_io["smtp"].as_table().unwrap()["url"].as_str(),
            Some("smtp://localhost:587")
        );
    }

    #[test]
    fn env_overrides_optional_string_empty_unsets() {
        let mut config = Config::default();
        // Pre-populate a host_io backend so we can verify removal.
        {
            let mut table = toml::map::Map::new();
            table.insert("url".into(), toml::Value::String("postgres://old".into()));
            config
                .host_io
                .insert("database".into(), toml::Value::Table(table));
        }
        config.storage.ledger_jsonl_path = Some("/old/path".into());

        let env = HashMap::from([
            ("LATCHGATE_HOST_IO_DATABASE_URL", ""),
            ("LATCHGATE_LEDGER_JSONL_PATH", ""),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert!(!config.host_io.contains_key("database"));
        assert!(config.storage.ledger_jsonl_path.is_none());
    }

    #[test]
    fn env_overrides_admin_tls_all_three() {
        let mut config = Config::default();
        let env = HashMap::from([
            ("LATCHGATE_ADMIN_TLS_CERT", "/certs/server.crt"),
            ("LATCHGATE_ADMIN_TLS_KEY", "/certs/server.key"),
            ("LATCHGATE_ADMIN_TLS_CA", "/certs/ca.crt"),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

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
    }

    #[test]
    fn env_overrides_admin_tls_empty_unsets() {
        let mut config = Config {
            listener: ListenerConfig {
                admin_tls_cert: Some("/old/cert.pem".into()),
                admin_tls_key: Some("/old/key.pem".into()),
                admin_tls_ca: Some("/old/ca.pem".into()),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };

        let env = HashMap::from([
            ("LATCHGATE_ADMIN_TLS_CERT", ""),
            ("LATCHGATE_ADMIN_TLS_KEY", ""),
            ("LATCHGATE_ADMIN_TLS_CA", ""),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert!(config.listener.admin_tls_cert.is_none());
        assert!(config.listener.admin_tls_key.is_none());
        assert!(config.listener.admin_tls_ca.is_none());
        assert!(!config.listener.admin_tls_configured());
    }

    #[test]
    fn env_overrides_admin_tls_over_toml() {
        let toml_str = r#"
admin_tls_cert = "/toml/server.crt"
admin_tls_key = "/toml/server.key"
admin_tls_ca = "/toml/ca.crt"
"#;
        let mut config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.listener.admin_tls_cert.as_deref(),
            Some("/toml/server.crt"),
        );

        let env = HashMap::from([
            ("LATCHGATE_ADMIN_TLS_CERT", "/env/server.crt"),
            ("LATCHGATE_ADMIN_TLS_KEY", "/env/server.key"),
            ("LATCHGATE_ADMIN_TLS_CA", "/env/ca.crt"),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert_eq!(
            config.listener.admin_tls_cert.as_deref(),
            Some("/env/server.crt"),
        );
        assert_eq!(
            config.listener.admin_tls_key.as_deref(),
            Some("/env/server.key"),
        );
        assert_eq!(config.listener.admin_tls_ca.as_deref(), Some("/env/ca.crt"),);
    }

    #[test]
    fn env_overrides_log_format() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LOG_FORMAT", "pretty")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.logging.format, LogFormat::Pretty);

        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LOG_FORMAT", "JSON")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.logging.format, LogFormat::Json);

        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LOG_FORMAT", "auto")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.logging.format, LogFormat::Auto);
    }

    #[test]
    fn env_overrides_response_schema_enforcement() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_RESPONSE_SCHEMA_ENFORCEMENT", "warn")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(
            config.response_schema_enforcement,
            ResponseSchemaEnforcement::Warn
        );

        let mut config = Config {
            response_schema_enforcement: ResponseSchemaEnforcement::Warn,
            ..Config::default()
        };
        let env = HashMap::from([("LATCHGATE_RESPONSE_SCHEMA_ENFORCEMENT", "deny")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(
            config.response_schema_enforcement,
            ResponseSchemaEnforcement::Deny
        );
    }

    #[test]
    fn env_overrides_listen_http_addr() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LISTEN_HTTP_ADDR", "0.0.0.0:8080")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(
            config.listener.listen_http_addr,
            Some("0.0.0.0:8080".parse().unwrap())
        );
    }

    #[test]
    fn env_overrides_error_on_invalid_u64() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LEASE_TTL_SECONDS", "not_a_number")]);
        let err = config.apply_env_overrides_from(env_from(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVar { .. }));
        let msg = err.to_string();
        assert!(msg.contains("LATCHGATE_LEASE_TTL_SECONDS"));
        assert!(msg.contains("not_a_number"));
    }

    #[test]
    fn env_overrides_error_on_invalid_bool() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_UNSAFE_EXPOSE_HTTP", "yes")]);
        let err = config.apply_env_overrides_from(env_from(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVar { .. }));
        let msg = err.to_string();
        assert!(msg.contains("LATCHGATE_UNSAFE_EXPOSE_HTTP"));
        assert!(msg.contains("yes"));
    }

    #[test]
    fn env_overrides_error_on_invalid_socket_addr() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LISTEN_HTTP_ADDR", "not:a:socket")]);
        let err = config.apply_env_overrides_from(env_from(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVar { .. }));
        let msg = err.to_string();
        assert!(msg.contains("LATCHGATE_LISTEN_HTTP_ADDR"));
    }

    #[test]
    fn env_overrides_error_on_invalid_log_format() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LOG_FORMAT", "yaml")]);
        let err = config.apply_env_overrides_from(env_from(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVar { .. }));
        let msg = err.to_string();
        assert!(msg.contains("yaml"));
    }

    #[test]
    fn env_overrides_error_on_invalid_response_schema() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_RESPONSE_SCHEMA_ENFORCEMENT", "allow")]);
        let err = config.apply_env_overrides_from(env_from(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVar { .. }));
        let msg = err.to_string();
        assert!(msg.contains("allow"));
    }

    #[test]
    fn env_overrides_error_on_negative_u64() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_LEASE_TTL_SECONDS", "-1")]);
        let err = config.apply_env_overrides_from(env_from(&env)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnvVar { .. }));
    }

    #[test]
    fn env_overrides_operator_api_key() {
        let mut config = Config::default();
        assert!(config.operator_credentials.is_empty());

        let env = HashMap::from([("LATCHGATE_OPERATOR_API_KEY", "secret-key-abc")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert_eq!(config.operator_credentials.len(), 1);
        let cred = config.operator_credentials.get("platform").unwrap();
        assert_eq!(cred.api_key, "secret-key-abc");
        assert!(cred.dpop_jkt.is_none());
    }

    #[test]
    fn env_overrides_operator_api_key_over_toml() {
        let toml_str = r#"
[operator_credentials.platform]
api_key = "from-toml"
"#;
        let mut config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.operator_credentials["platform"].api_key, "from-toml");

        let env = HashMap::from([("LATCHGATE_OPERATOR_API_KEY", "from-env")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.operator_credentials["platform"].api_key, "from-env");
    }

    #[test]
    fn env_overrides_operator_api_key_preserves_others() {
        let toml_str = r#"
[operator_credentials.alice]
api_key = "alice-key"
dpop_jkt = "alice-thumbprint"
"#;
        let mut config: Config = toml::from_str(toml_str).unwrap();

        let env = HashMap::from([("LATCHGATE_OPERATOR_API_KEY", "platform-key")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        // "platform" added
        assert_eq!(config.operator_credentials.len(), 2);
        assert_eq!(
            config.operator_credentials["platform"].api_key,
            "platform-key"
        );
        // "alice" untouched
        assert_eq!(config.operator_credentials["alice"].api_key, "alice-key");
        assert_eq!(
            config.operator_credentials["alice"].dpop_jkt.as_deref(),
            Some("alice-thumbprint")
        );
    }

    #[test]
    fn env_overrides_toml_value() {
        let toml_str = r#"redis_url = "redis://from-toml:6379""#;
        let mut config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.storage.redis_url,
            Some("redis://from-toml:6379".to_string())
        );

        let env = HashMap::from([("LATCHGATE_REDIS_URL", "redis://from-env:6379")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(
            config.storage.redis_url,
            Some("redis://from-env:6379".to_string())
        );
    }

    #[test]
    fn parse_env_bool_case_insensitive() {
        assert!(parse_env_bool("X", "TRUE").unwrap());
        assert!(parse_env_bool("X", "True").unwrap());
        assert!(!parse_env_bool("X", "FALSE").unwrap());
        assert!(!parse_env_bool("X", "False").unwrap());
    }

    #[test]
    fn parse_env_bool_rejects_ambiguous() {
        assert!(parse_env_bool("X", "yes").is_err());
        assert!(parse_env_bool("X", "on").is_err());
        assert!(parse_env_bool("X", "enabled").is_err());
        assert!(parse_env_bool("X", "").is_err());
    }

    #[test]
    fn parse_env_optional_string_empty_is_none() {
        assert!(parse_env_optional_string("").is_none());
    }

    #[test]
    fn parse_env_optional_string_nonempty_is_some() {
        assert_eq!(
            parse_env_optional_string("/path"),
            Some("/path".to_string())
        );
    }

    #[test]
    fn env_overrides_full_tenant_scenario() {
        let mut config = Config::default();
        let env = HashMap::from([
            (
                "LATCHGATE_LISTEN_UDS_PATH",
                "/run/latchgate/tenant-acme.sock",
            ),
            (
                "LATCHGATE_LISTEN_ADMIN_UDS_PATH",
                "/run/latchgate/tenant-acme-admin.sock",
            ),
            ("LATCHGATE_REDIS_URL", "redis://redis:6379/1"),
            ("LATCHGATE_REDIS_KEY_PREFIX", "latchgate:acme:jti:"),
            ("LATCHGATE_OPA_URL", "http://opa:8181"),
            ("LATCHGATE_LEASE_TTL_SECONDS", "300"),
            ("LATCHGATE_MAX_LEASE_TTL_SECONDS", "3600"),
            ("LATCHGATE_LEDGER_DB_PATH", "/var/latchgate/acme/audit.db"),
            ("LATCHGATE_MANIFESTS_DIR", "/var/latchgate/acme/manifests"),
            ("LATCHGATE_WASM_PROVIDERS_DIR", "/opt/latchgate/providers"),
            (
                "LATCHGATE_RECEIPT_SIGNING_KEY_PATH",
                "/var/latchgate/acme/receipt.key",
            ),
            (
                "LATCHGATE_GRANT_SIGNING_KEY_PATH",
                "/var/latchgate/acme/grant.key",
            ),
            (
                "LATCHGATE_RECEIPT_KEYS_JWKS_PATH",
                "/var/latchgate/acme/keys.jwks",
            ),
            ("LATCHGATE_PUBLIC_BASE_URL", "http://latchgate"),
            (
                "LATCHGATE_OPERATOR_API_KEY",
                "lgk_platform-operator-key-for-acme",
            ),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        assert_eq!(
            config.listener.listen_uds_path,
            "/run/latchgate/tenant-acme.sock"
        );
        assert_eq!(
            config.listener.listen_admin_uds_path,
            "/run/latchgate/tenant-acme-admin.sock"
        );
        assert_eq!(
            config.storage.redis_url,
            Some("redis://redis:6379/1".to_string())
        );
        assert_eq!(config.policy.opa_url, Some("http://opa:8181".to_string()));
        assert_eq!(config.policy.lease_ttl_seconds, 300);
        assert_eq!(
            config.storage.ledger_db_path,
            "/var/latchgate/acme/audit.db"
        );
        assert_eq!(config.manifests_dir, "/var/latchgate/acme/manifests");
        assert_eq!(config.wasm_providers_dir, "/opt/latchgate/providers");
        assert_eq!(
            config.signing.receipt_signing_key_path.as_deref(),
            Some("/var/latchgate/acme/receipt.key")
        );
        assert_eq!(
            config.signing.grant_signing_key_path.as_deref(),
            Some("/var/latchgate/acme/grant.key")
        );
        assert_eq!(
            config.signing.receipt_keys_jwks_path.as_deref(),
            Some("/var/latchgate/acme/keys.jwks")
        );
        assert_eq!(config.listener.public_base_url, "http://latchgate");
        assert_eq!(
            config.operator_credentials["platform"].api_key,
            "lgk_platform-operator-key-for-acme"
        );
    }

    #[test]
    fn env_overrides_full_tcp_mtls_tenant_scenario() {
        let mut config = Config::default();
        let env = HashMap::from([
            ("LATCHGATE_LISTEN_ADMIN_HTTP_ADDR", "0.0.0.0:9443"),
            ("LATCHGATE_ADMIN_TLS_CERT", "/certs/server.crt"),
            ("LATCHGATE_ADMIN_TLS_KEY", "/certs/server.key"),
            ("LATCHGATE_ADMIN_TLS_CA", "/certs/ca.crt"),
            ("LATCHGATE_REDIS_URL", "redis://redis:6379/1"),
            ("LATCHGATE_REDIS_KEY_PREFIX", "latchgate:acme:jti:"),
            ("LATCHGATE_OPA_URL", "http://opa:8181"),
            ("LATCHGATE_LEASE_TTL_SECONDS", "300"),
            ("LATCHGATE_LEDGER_DB_PATH", "/var/latchgate/acme/audit.db"),
            ("LATCHGATE_MANIFESTS_DIR", "/var/latchgate/acme/manifests"),
            ("LATCHGATE_WASM_PROVIDERS_DIR", "/opt/latchgate/providers"),
            (
                "LATCHGATE_RECEIPT_SIGNING_KEY_PATH",
                "/var/latchgate/acme/receipt.key",
            ),
            (
                "LATCHGATE_GRANT_SIGNING_KEY_PATH",
                "/var/latchgate/acme/grant.key",
            ),
            (
                "LATCHGATE_RECEIPT_KEYS_JWKS_PATH",
                "/var/latchgate/acme/keys.jwks",
            ),
            ("LATCHGATE_PUBLIC_BASE_URL", "https://latchgate"),
            (
                "LATCHGATE_OPERATOR_API_KEY",
                "lgk_platform-operator-key-for-acme",
            ),
        ]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();

        // Transport: TCP + mTLS, no unsafe_expose_http needed.
        assert_eq!(
            config.listener.listen_admin_http_addr.unwrap().to_string(),
            "0.0.0.0:9443",
        );
        assert!(!config.listener.unsafe_expose_http);
        assert!(config.listener.admin_tls_configured());
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
    }

    #[test]
    fn env_overrides_fs_root_allowed_prefixes() {
        let mut config = Config::default();
        let env = HashMap::from([(
            "LATCHGATE_FS_ROOT_ALLOWED_PREFIXES",
            "/home/user/projects:/srv/sandboxes",
        )]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.fs_root_allowed_prefixes.len(), 2);
        assert_eq!(
            config.fs_root_allowed_prefixes[0],
            std::path::Path::new("/home/user/projects")
        );
        assert_eq!(
            config.fs_root_allowed_prefixes[1],
            std::path::Path::new("/srv/sandboxes")
        );
    }

    #[test]
    fn env_empty_disables_fs_root_prefixes() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_FS_ROOT_ALLOWED_PREFIXES", "")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert!(
            config.fs_root_allowed_prefixes.is_empty(),
            "empty value must disable per-session roots"
        );
    }

    #[test]
    fn env_single_path_no_trailing_colon() {
        let mut config = Config::default();
        let env = HashMap::from([("LATCHGATE_FS_ROOT_ALLOWED_PREFIXES", "/home/user")]);
        config.apply_env_overrides_from(env_from(&env)).unwrap();
        assert_eq!(config.fs_root_allowed_prefixes.len(), 1);
    }
}
