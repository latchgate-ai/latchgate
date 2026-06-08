//! Re-exports and tests for doctor check functions.

#[cfg(test)]
mod tests {
    use crate::cmd::doctor::config_checks::*;
    use crate::cmd::doctor::dependency_checks::*;

    use crate::cmd::doctor::registry_checks::*;
    use crate::cmd::doctor::security_checks::*;

    use crate::cmd::doctor::Severity;
    use latchgate_config::{Config, OperatorCredential, SandboxMode, SecurityPosture};
    use std::collections::HashMap;

    /// Config with sensible defaults for testing. Override fields as needed.
    fn base_config() -> Config {
        Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        }
    }

    fn dev_config() -> Config {
        Config {
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        }
    }

    // -- check_config_file ----------------------------------------------------

    #[test]
    fn config_file_ok_when_base_url_set() {
        let cfg = base_config();
        let c = check_config_file(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    #[test]
    fn config_file_warns_when_base_url_empty() {
        let cfg = Config {
            listener: latchgate_config::ListenerConfig {
                public_base_url: String::new(),
                ..Default::default()
            },
            ..base_config()
        };
        let c = check_config_file(&cfg);
        assert_eq!(c.severity, Severity::Warn);
    }

    // -- check_operator_credentials -------------------------------------------

    #[test]
    fn operator_creds_error_when_empty_in_prod() {
        let cfg = Config {
            operator_credentials: HashMap::new(),
            ..base_config()
        };
        let c = check_operator_credentials(&cfg);
        assert_eq!(c.severity, Severity::Error);
    }

    #[test]
    fn operator_creds_warn_when_empty_in_dev() {
        let cfg = Config {
            operator_credentials: HashMap::new(),
            ..dev_config()
        };
        let c = check_operator_credentials(&cfg);
        assert_eq!(c.severity, Severity::Warn);
    }

    #[test]
    fn operator_creds_ok_with_dpop_binding() {
        let mut creds = HashMap::new();
        creds.insert(
            "ops".into(),
            OperatorCredential {
                api_key: "key-ops-abc".into(),
                dpop_jkt: Some("thumbprint-abc".into()),
            },
        );
        let cfg = Config {
            operator_credentials: creds,
            ..base_config()
        };
        let c = check_operator_credentials(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    #[test]
    fn operator_creds_error_missing_dpop_in_prod() {
        let mut creds = HashMap::new();
        creds.insert(
            "ops".into(),
            OperatorCredential {
                api_key: "key-ops-abc".into(),
                dpop_jkt: None,
            },
        );
        let cfg = Config {
            operator_credentials: creds,
            ..base_config()
        };
        let c = check_operator_credentials(&cfg);
        assert_eq!(c.severity, Severity::Error);
        assert!(c.message.contains("dpop_jkt"));
    }

    #[test]
    fn operator_creds_warn_missing_dpop_in_dev() {
        let mut creds = HashMap::new();
        creds.insert(
            "dev".into(),
            OperatorCredential {
                api_key: "key-dev-abc".into(),
                dpop_jkt: None,
            },
        );
        let cfg = Config {
            operator_credentials: creds,
            ..dev_config()
        };
        let c = check_operator_credentials(&cfg);
        assert_eq!(c.severity, Severity::Warn);
    }

    // -- check_signing_keys ---------------------------------------------------

    #[test]
    fn signing_keys_ok_when_both_set() {
        let cfg = Config {
            signing: latchgate_config::SigningConfig {
                receipt_signing_key_path: Some("/keys/receipt.key".into()),
                grant_signing_key_path: Some("/keys/grant.key".into()),
                ..Default::default()
            },
            ..base_config()
        };
        let c = check_signing_keys(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    #[test]
    fn signing_keys_error_when_missing_in_prod() {
        let cfg = Config {
            signing: latchgate_config::SigningConfig {
                receipt_signing_key_path: None,
                grant_signing_key_path: None,
                ..Default::default()
            },
            ..base_config()
        };
        let c = check_signing_keys(&cfg);
        assert_eq!(c.severity, Severity::Error);
        assert!(c.message.contains("receipt_signing_key_path"));
    }

    #[test]
    fn signing_keys_skip_in_dev_mode() {
        let cfg = Config {
            signing: latchgate_config::SigningConfig {
                receipt_signing_key_path: None,
                grant_signing_key_path: None,
                ..Default::default()
            },
            ..dev_config()
        };
        let c = check_signing_keys(&cfg);
        assert_eq!(c.severity, Severity::Skip);
        assert!(c.message.contains("skipped (dev)"));
    }

    // -- check_sops -----------------------------------------------------------

    #[test]
    fn sops_ok_when_not_configured() {
        let cfg = Config {
            secrets: latchgate_config::SecretsConfig::default(),
            ..base_config()
        };
        let c = check_sops(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    // -- check_providers_dir --------------------------------------------------

    #[test]
    fn providers_dir_error_strict_missing() {
        let cfg = Config {
            wasm_providers_dir: "/nonexistent/providers".into(),
            sandbox: latchgate_config::SandboxConfig {
                mode: SandboxMode::Strict,
                ..Default::default()
            },
            ..base_config()
        };
        let c = check_providers_dir(&cfg);
        assert_eq!(c.severity, Severity::Error);
    }

    #[test]
    fn providers_dir_warn_degraded_missing() {
        let cfg = Config {
            wasm_providers_dir: "/nonexistent/providers".into(),
            sandbox: latchgate_config::SandboxConfig {
                mode: SandboxMode::DegradedOk,
                ..Default::default()
            },
            ..base_config()
        };
        let c = check_providers_dir(&cfg);
        assert_eq!(c.severity, Severity::Warn);
    }

    #[test]
    fn providers_dir_ok_when_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            wasm_providers_dir: tmp.path().to_string_lossy().into(),
            ..base_config()
        };
        let c = check_providers_dir(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    // -- check_egress_proxy ---------------------------------------------------

    #[tokio::test]
    async fn egress_proxy_skip_when_unconfigured_in_dev() {
        let cfg = dev_config();
        let c = await_check_egress_proxy(&cfg).await;
        assert_eq!(c.severity, Severity::Skip);
    }

    #[tokio::test]
    async fn egress_proxy_warn_when_unconfigured_in_prod() {
        let cfg = base_config();
        let c = await_check_egress_proxy(&cfg).await;
        assert_eq!(c.severity, Severity::Warn);
        assert!(c.message.contains("defense-in-depth"));
    }

    // -- check_webhooks -------------------------------------------------------

    #[test]
    fn webhooks_ok_when_empty() {
        let cfg = Config {
            webhooks: vec![],
            ..base_config()
        };
        let checks = check_webhooks(&cfg);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].severity, Severity::Ok);
    }

    // -- check_secrets_coverage -----------------------------------------------

    #[test]
    fn secrets_coverage_ok_no_manifests() {
        let cfg = Config {
            manifests_dir: "/nonexistent/manifests".into(),
            ..base_config()
        };
        let c = check_secrets_coverage(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    // -- check_manifest_overrides ---------------------------------------------

    #[test]
    fn manifest_overrides_ok_when_no_user_dir() {
        let cfg = Config {
            manifests_dir: "/nonexistent/manifests".into(),
            ..base_config()
        };
        let c = check_manifest_overrides(&cfg);
        assert_eq!(c.severity, Severity::Ok);
        assert!(c.message.contains("no embedded"));
    }

    #[test]
    fn manifest_overrides_ok_when_user_dir_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            manifests_dir: tmp.path().to_string_lossy().into(),
            ..base_config()
        };
        let c = check_manifest_overrides(&cfg);
        assert_eq!(c.severity, Severity::Ok);
    }

    // -- Severity ordering ----------------------------------------------------

    #[test]
    fn severity_ordering() {
        assert!(Severity::Ok < Severity::Skip);
        assert!(Severity::Skip < Severity::Warn);
        assert!(Severity::Warn < Severity::Error);
    }
}
