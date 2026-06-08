//! Config validation methods.

use super::{Config, ConfigError, OperatorCredential};
use super::{IdentityProviderKind, ResponseSchemaEnforcement, WebhookMode};
use latchgate_core::EgressProfile;
use std::collections::HashMap;

/// Outcome of egress proxy coverage validation.
///
/// Distinguishes three states so the caller can decide how to proceed:
///
/// - `Covered` — proxy configured or no actions require one.
/// - `KernelOnly` — actions declared `proxy_allowlist` but no proxy is
///   configured. The kernel's per-call sink validation (Layer 1) still
///   enforces domain allowlists; only the network-boundary proxy (Layer 2)
///   is absent. Suitable for single-instance deployments.
///
/// The caller (kernel init) logs a structured warning for `KernelOnly`
/// rather than refusing to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressCoverageResult {
    /// All egress actions are covered by the proxy, or no actions require it.
    Covered,
    /// Actions use `proxy_allowlist` but no `egress_proxy_url` is configured.
    /// Kernel-level sink validation still enforces domain allowlists (Layer 1).
    KernelOnly {
        /// Action IDs that declared `proxy_allowlist` without a proxy.
        actions: Vec<String>,
    },
}

impl Config {
    pub fn validate_listen(&self) -> Result<(), ConfigError> {
        // SECURITY: explicit opt-in required before any TCP is exposed.
        // Prevents accidental HTTP exposure when operator forgot unsafe_expose_http.
        match (
            self.listener.listen_http_addr,
            self.listener.unsafe_expose_http,
        ) {
            (Some(addr), false) => Err(ConfigError::HttpAddrWithoutUnsafeFlag { addr }),
            _ => Ok(()),
        }?;

        // SECURITY: partial admin TLS configuration is a hard error. Setting
        // 1 or 2 of 3 fields is almost certainly a misconfiguration — fail
        // closed rather than silently falling back to plain HTTP.
        let tls_count = self.listener.admin_tls_field_count();
        if tls_count > 0 && tls_count < 3 {
            let present: Vec<&str> = [
                ("admin_tls_cert", &self.listener.admin_tls_cert),
                ("admin_tls_key", &self.listener.admin_tls_key),
                ("admin_tls_ca", &self.listener.admin_tls_ca),
            ]
            .iter()
            .filter(|(_, v)| v.is_some())
            .map(|(name, _)| *name)
            .collect();
            let missing: Vec<&str> = [
                ("admin_tls_cert", &self.listener.admin_tls_cert),
                ("admin_tls_key", &self.listener.admin_tls_key),
                ("admin_tls_ca", &self.listener.admin_tls_ca),
            ]
            .iter()
            .filter(|(_, v)| v.is_none())
            .map(|(name, _)| *name)
            .collect();
            return Err(ConfigError::AdminTlsIncomplete {
                present: present.iter().map(|s| s.to_string()).collect(),
                missing: missing.iter().map(|s| s.to_string()).collect(),
            });
        }

        // Admin TCP: allowed if mTLS is configured OR unsafe_expose_http is set.
        // SECURITY: mTLS provides mutual authentication — the admin listener
        // is safe to expose over TCP when both sides verify certificates.
        match (
            self.listener.listen_admin_http_addr,
            self.listener.unsafe_expose_http,
            self.listener.admin_tls_configured(),
        ) {
            (Some(addr), false, false) => Err(ConfigError::HttpAddrWithoutUnsafeFlag { addr }),
            _ => Ok(()),
        }
    }

    ///
    /// Validate operator authentication configuration for production safety.
    ///
    /// Production requires `operator_credentials` with `dpop_jkt` on every
    /// `--insecure-operator-auth`), validation is skipped.
    ///
    /// | relaxed? | `operator_credentials`              | Result |
    /// |----------|--------------------------------------|--------|
    /// | no       | non-empty, all have dpop_jkt         | Ok     |
    /// | no       | non-empty, some missing dpop_jkt     | Err    |
    /// | no       | empty                                | Err    |
    /// | yes      | any                                  | Ok     |
    pub fn validate_operator_auth(&self) -> Result<(), ConfigError> {
        if self.posture.operator_auth_insecure {
            return Ok(());
        }

        if self.operator_credentials.is_empty() {
            return Err(ConfigError::NoOperatorAuthConfigured);
        }

        // SECURITY: every credential MUST have dpop_jkt in production.
        for (operator_id, cred) in &self.operator_credentials {
            if cred.dpop_jkt.is_none() {
                return Err(ConfigError::OperatorCredentialMissingDpopJkt {
                    operator_id: operator_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Validate identity provider configuration for production safety.
    ///
    /// Production rules:
    /// - `IdentityProviderKind::None` is rejected (dev-only).
    /// - `peercred` with `allow_unmapped = true` is rejected.
    /// - `peercred` with an empty principal map is rejected (no caller
    ///   can authenticate, making the system non-functional).
    ///
    pub fn validate_identity_config(&self) -> Result<(), ConfigError> {
        if self.posture.identity_insecure {
            return Ok(());
        }

        match self.identity.provider {
            IdentityProviderKind::None => {
                return Err(ConfigError::NoneIdentityProviderInProduction);
            }
            IdentityProviderKind::Peercred => {
                if self.identity.peercred.allow_unmapped {
                    return Err(ConfigError::AllowUnmappedInProduction);
                }
                if self.identity.peercred.principals.is_empty() {
                    return Err(ConfigError::EmptyPeercredPrincipalMap);
                }
            }
        }

        Ok(())
    }

    /// Validate signing material configuration for production safety.
    ///
    /// Production requires persistent signing keys for receipts and grants,
    /// plus a JWKS path for historical key retention across rotations.
    /// Without these, receipts are unverifiable after restart, grants cannot
    /// be validated cross-process, and key rotation loses old verifying keys.
    ///
    pub fn validate_signing_material(&self) -> Result<(), ConfigError> {
        if self.posture.signing_insecure {
            return Ok(());
        }

        if self.signing.receipt_signing_key_path.is_none() {
            return Err(ConfigError::MissingReceiptSigningKeyPath);
        }
        if self.signing.grant_signing_key_path.is_none() {
            return Err(ConfigError::MissingGrantSigningKeyPath);
        }
        if self.signing.receipt_keys_jwks_path.is_none() {
            return Err(ConfigError::MissingReceiptKeysJwksPath);
        }

        Ok(())
    }

    /// Validate response schema enforcement for production safety.
    ///
    /// Production requires `deny` mode. `warn` allows responses that violate
    /// the declared output contract to reach the caller — weakening the
    /// Typed I/O guarantee that the product advertises.
    ///
    pub fn validate_response_schema_enforcement(&self) -> Result<(), ConfigError> {
        if self.posture.schema_insecure {
            return Ok(());
        }

        if self.response_schema_enforcement == ResponseSchemaEnforcement::Warn {
            return Err(ConfigError::WarnResponseSchemaInProduction);
        }

        Ok(())
    }

    /// Reject `file://` object storage URLs when storage validation is active.
    ///
    /// SECURITY: the `file://` backend gives WASM providers filesystem access
    /// through the `latchgate:io/storage` host import. In production, only
    /// cloud object stores (s3://, gs://, az://) are permitted.
    pub fn validate_storage_scheme(&self) -> Result<(), ConfigError> {
        if self.posture.storage_insecure {
            return Ok(());
        }
        if let Some(url_value) = self
            .host_io
            .get("storage")
            .and_then(|v| v.get("url"))
            .and_then(|v| v.as_str())
        {
            if url_value.starts_with("file://") || url_value.starts_with("file:") {
                return Err(ConfigError::FileStorageInProduction);
            }
        }
        Ok(())
    }

    /// Reject `webhook_mode = async` when webhook endpoints are configured
    /// and webhook validation is active.
    ///
    /// SECURITY: async delivery uses a bounded in-process channel that drops
    /// events when full. The transactional outbox guarantees no events are
    /// lost under load or crash.
    pub fn validate_webhook_mode(&self) -> Result<(), ConfigError> {
        if self.posture.webhooks_insecure {
            return Ok(());
        }
        if self.webhook_mode == WebhookMode::Async && !self.webhooks.is_empty() {
            return Err(ConfigError::AsyncWebhooksInProduction);
        }
        Ok(())
    }

    /// Central production security validation.
    ///
    /// Runs every sub-validator in order.  Each validator checks its own
    /// [`SecurityPosture`] flag and skips itself when that specific
    /// protection is explicitly relaxed.  Non-relaxed validators enforce
    /// even when other protections are disabled — there is no global
    /// bypass.
    ///
    /// Always called at startup; the per-protection granularity means
    /// partially-relaxed configurations still get validation on the
    /// protections that remain active.
    pub fn validate_production_security(&self) -> Result<(), ConfigError> {
        self.validate_listen()?;
        self.validate_operator_auth()?;
        self.validate_identity_config()?;
        self.validate_signing_material()?;
        self.validate_response_schema_enforcement()?;
        self.validate_storage_scheme()?;
        self.validate_webhook_mode()?;
        Ok(())
    }

    /// Canonicalize `fs_root_allowed_prefixes` entries in place.
    ///
    /// Resolves symlinks in each configured prefix so that prefix matching
    /// at lease time always compares canonical paths against canonical
    /// prefixes. Non-existent entries are dropped with a warning (they
    /// can never match anything).
    ///
    /// Called once at config load time, after env overrides are applied.
    pub fn canonicalize_fs_root_prefixes(&mut self) {
        let mut canonical = Vec::with_capacity(self.fs_root_allowed_prefixes.len());
        for prefix in &self.fs_root_allowed_prefixes {
            match prefix.canonicalize() {
                Ok(c) => {
                    if c != *prefix {
                        tracing::info!(
                            original = %prefix.display(),
                            canonical = %c.display(),
                            "fs_root_allowed_prefixes: entry canonicalized (symlink resolved)"
                        );
                    }
                    canonical.push(c);
                }
                Err(e) => {
                    tracing::warn!(
                        prefix = %prefix.display(),
                        error = %e,
                        "fs_root_allowed_prefixes: entry does not exist; ignoring"
                    );
                }
            }
        }
        self.fs_root_allowed_prefixes = canonical;
    }

    /// Verify that every action declaring `egress_profile = proxy_allowlist`
    /// has a configured egress proxy at the network layer.
    ///
    /// SECURITY: the kernel enforces the sink allowlist per-call; the proxy
    /// enforces it per-packet. Running with `proxy_allowlist` actions but no
    /// `egress_proxy_url` collapses defense-in-depth to a single layer.
    ///
    /// Returns [`EgressCoverageResult::KernelOnly`] when actions declare
    /// `proxy_allowlist` but no proxy is configured. The caller emits a
    /// structured startup warning — the gate proceeds with kernel-only
    /// enforcement (Layer 1: sink validation + SSRF protection + manifest
    /// domain allowlists).
    ///
    /// `actions_with_profiles` yields `(action_id, egress_profile)` pairs for
    /// every registered action. The caller wires this up after the registry
    /// is loaded; the method itself has no registry dependency.
    ///
    /// When `egress_insecure` is set, returns `Covered` unconditionally.
    pub fn validate_egress_proxy_coverage<'a, I>(
        &self,
        actions_with_profiles: I,
    ) -> EgressCoverageResult
    where
        I: IntoIterator<Item = (&'a str, EgressProfile)>,
    {
        if self.posture.egress_insecure {
            return EgressCoverageResult::Covered;
        }

        if self.egress.egress_proxy_url.is_some() {
            return EgressCoverageResult::Covered;
        }

        let using_proxy_allowlist: Vec<String> = actions_with_profiles
            .into_iter()
            .filter(|(_, p)| matches!(p, EgressProfile::ProxyAllowlist { .. }))
            .map(|(id, _)| id.to_string())
            .collect();

        if using_proxy_allowlist.is_empty() {
            EgressCoverageResult::Covered
        } else {
            EgressCoverageResult::KernelOnly {
                actions: using_proxy_allowlist,
            }
        }
    }

    /// Reject wildcard ACL entries that grant high or critical risk actions
    /// in production posture.
    ///
    /// SECURITY: the wildcard principal (`*`) matches every authenticated caller.
    /// Granting high/critical actions to `*` means any agent can trigger
    /// approval-gated operations — defeating least-privilege.
    ///
    /// `wildcard_actions_with_risk` yields `(action_id, risk_level)` pairs for
    /// every action in the wildcard ACL. The caller resolves these from the
    /// loaded data.json and registry.
    ///
    pub fn validate_wildcard_acl<'a, I>(
        &self,
        wildcard_actions_with_risk: I,
    ) -> Result<(), ConfigError>
    where
        I: IntoIterator<Item = (&'a str, latchgate_core::RiskLevel)>,
    {
        if self.posture.acl_insecure {
            return Ok(());
        }

        let high_risk_actions: Vec<String> = wildcard_actions_with_risk
            .into_iter()
            .filter(|(_, risk)| {
                matches!(
                    risk,
                    latchgate_core::RiskLevel::High | latchgate_core::RiskLevel::Critical
                )
            })
            .map(|(id, _)| id.to_string())
            .collect();

        if !high_risk_actions.is_empty() {
            return Err(ConfigError::WildcardAclHighRiskInProduction {
                actions: high_risk_actions,
            });
        }

        Ok(())
    }

    /// Narrow a domain allowlist to the intersection with the runtime override.
    ///
    /// If `egress_runtime_allowlist` is `None`, this is a no-op — the domain
    /// list passes through unchanged.
    ///
    /// Returns the number of domains removed. Callers should log when this is
    /// non-zero so operators can diagnose unexpected connectivity loss.
    ///
    /// SECURITY: this can only **remove** entries from `domains`, never add.
    /// A domain absent from the original set cannot appear after narrowing.
    pub fn narrow_egress_domains(&self, domains: &mut Vec<String>) -> usize {
        let runtime = match &self.egress.egress_runtime_allowlist {
            Some(rt) => rt,
            None => return 0,
        };

        let before = domains.len();
        domains.retain(|d| runtime.iter().any(|r| r == d));
        before - domains.len()
    }

    /// Return the effective set of operator credentials.
    ///
    /// Used at runtime to resolve operator identity from a presented token.
    pub fn effective_operator_credentials(&self) -> &HashMap<String, OperatorCredential> {
        &self.operator_credentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        IdentityConfig, IdentityProviderKind, PeercredConfig, PeercredPrincipal,
    };
    use crate::listener::ListenerConfig;
    use crate::signing::SigningConfig;
    use crate::{Config, ConfigError, EgressConfig, OperatorCredential, SecurityPosture};
    use latchgate_core::EgressProfile;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn named_credentials_with_dpop() -> HashMap<String, OperatorCredential> {
        let mut m = HashMap::new();
        m.insert(
            "alice".into(),
            OperatorCredential {
                api_key: "key-alice-abc123".into(),
                dpop_jkt: Some("test-thumbprint-abc".into()),
            },
        );
        m
    }

    fn named_credentials_without_dpop() -> HashMap<String, OperatorCredential> {
        let mut m = HashMap::new();
        m.insert(
            "alice".into(),
            OperatorCredential {
                api_key: "key-alice-abc123".into(),
                dpop_jkt: None,
            },
        );
        m
    }

    fn peercred_config_with_principal() -> IdentityConfig {
        IdentityConfig {
            provider: IdentityProviderKind::Peercred,
            peercred: PeercredConfig {
                principals: HashMap::from([(
                    "1001".to_string(),
                    PeercredPrincipal {
                        principal: "agent".to_string(),
                        scopes: vec!["tools:call".into()],
                        owner: None,
                    },
                )]),
                allow_unmapped: false,
            },
        }
    }

    /// Build a fully production-compliant Config.
    fn production_compliant_config() -> Config {
        Config {
            identity: peercred_config_with_principal(),
            operator_credentials: named_credentials_with_dpop(),
            signing: SigningConfig {
                receipt_signing_key_path: Some("/etc/latchgate/receipt.key".into()),
                grant_signing_key_path: Some("/etc/latchgate/grant.key".into()),
                receipt_keys_jwks_path: Some("/etc/latchgate/receipt-keys.jwks".into()),
            },
            response_schema_enforcement: ResponseSchemaEnforcement::Deny,
            posture: SecurityPosture::default(),
            ..Config::default()
        }
    }

    #[test]
    fn validate_listen_ok_when_http_addr_and_unsafe_flag() {
        let config = Config {
            listener: ListenerConfig {
                listen_http_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    3000,
                ))),
                unsafe_expose_http: true,
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate_listen().is_ok());
    }

    #[test]
    fn validate_listen_error_when_http_addr_without_unsafe_flag() {
        let config = Config {
            listener: ListenerConfig {
                listen_http_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    3000,
                ))),
                unsafe_expose_http: false,
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        let err = config.validate_listen().unwrap_err();
        assert!(matches!(err, ConfigError::HttpAddrWithoutUnsafeFlag { .. }));
    }

    /// Default Config must not expose a TCP listener.
    #[test]
    fn default_config_does_not_expose_tcp() {
        let config = Config::default();
        assert!(
            config.listener.listen_http_addr.is_none(),
            "default must not bind TCP"
        );
        assert!(
            !config.listener.unsafe_expose_http,
            "default must not set unsafe_expose_http"
        );
        assert!(
            config.listener.listen_admin_http_addr.is_none(),
            "default must not bind admin TCP"
        );
        assert!(config.validate_listen().is_ok());
    }

    /// Admin TCP with full mTLS config: no unsafe_expose_http required.
    #[test]
    fn validate_listen_ok_admin_tcp_with_mtls() {
        let config = Config {
            listener: ListenerConfig {
                listen_admin_http_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    9443,
                ))),
                admin_tls_cert: Some("/certs/server.crt".into()),
                admin_tls_key: Some("/certs/server.key".into()),
                admin_tls_ca: Some("/certs/ca.crt".into()),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        assert!(!config.listener.unsafe_expose_http);
        assert!(config.listener.admin_tls_configured());
        assert!(config.validate_listen().is_ok());
    }

    /// Admin TCP without mTLS and without unsafe flag: rejected.
    #[test]
    fn validate_listen_error_admin_tcp_without_mtls_or_unsafe() {
        let config = Config {
            listener: ListenerConfig {
                listen_admin_http_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    9443,
                ))),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        let err = config.validate_listen().unwrap_err();
        assert!(matches!(err, ConfigError::HttpAddrWithoutUnsafeFlag { .. }));
    }

    /// Admin TCP with unsafe flag (no TLS): accepted (legacy behavior).
    #[test]
    fn validate_listen_ok_admin_tcp_with_unsafe_flag() {
        let config = Config {
            listener: ListenerConfig {
                listen_admin_http_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    9080,
                ))),
                unsafe_expose_http: true,
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate_listen().is_ok());
    }

    /// Partial admin TLS config (only cert + key, missing CA): hard error.
    #[test]
    fn validate_listen_error_partial_admin_tls_missing_ca() {
        let config = Config {
            listener: ListenerConfig {
                admin_tls_cert: Some("/certs/server.crt".into()),
                admin_tls_key: Some("/certs/server.key".into()),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        let err = config.validate_listen().unwrap_err();
        match err {
            ConfigError::AdminTlsIncomplete { present, missing } => {
                assert_eq!(present.len(), 2);
                assert!(present.contains(&"admin_tls_cert".to_string()));
                assert!(present.contains(&"admin_tls_key".to_string()));
                assert_eq!(missing, vec!["admin_tls_ca".to_string()]);
            }
            other => panic!("expected AdminTlsIncomplete, got: {other:?}"),
        }
    }

    /// Partial admin TLS config (only cert, missing key + CA): hard error.
    #[test]
    fn validate_listen_error_partial_admin_tls_missing_key_and_ca() {
        let config = Config {
            listener: ListenerConfig {
                admin_tls_cert: Some("/certs/server.crt".into()),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        let err = config.validate_listen().unwrap_err();
        match err {
            ConfigError::AdminTlsIncomplete { present, missing } => {
                assert_eq!(present, vec!["admin_tls_cert".to_string()]);
                assert_eq!(missing.len(), 2);
                assert!(missing.contains(&"admin_tls_key".to_string()));
                assert!(missing.contains(&"admin_tls_ca".to_string()));
            }
            other => panic!("expected AdminTlsIncomplete, got: {other:?}"),
        }
    }

    /// Admin TLS without admin TCP addr: valid (no listener to protect,
    /// TLS fields are simply unused).
    #[test]
    fn validate_listen_ok_admin_tls_without_admin_addr() {
        let config = Config {
            listener: ListenerConfig {
                admin_tls_cert: Some("/certs/server.crt".into()),
                admin_tls_key: Some("/certs/server.key".into()),
                admin_tls_ca: Some("/certs/ca.crt".into()),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate_listen().is_ok());
    }

    /// Client TCP still requires unsafe_expose_http even when admin TLS
    /// is configured. Admin TLS only exempts the admin listener.
    #[test]
    fn validate_listen_error_client_tcp_not_exempted_by_admin_tls() {
        let config = Config {
            listener: ListenerConfig {
                listen_http_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    3000,
                ))),
                admin_tls_cert: Some("/certs/server.crt".into()),
                admin_tls_key: Some("/certs/server.key".into()),
                admin_tls_ca: Some("/certs/ca.crt".into()),
                ..ListenerConfig::default()
            },
            ..Config::default()
        };
        let err = config.validate_listen().unwrap_err();
        assert!(matches!(err, ConfigError::HttpAddrWithoutUnsafeFlag { .. }));
    }

    /// Default ListenerConfig has no TLS configured.
    #[test]
    fn default_listener_config_no_tls() {
        let listener = ListenerConfig::default();
        assert!(listener.admin_tls_cert.is_none());
        assert!(listener.admin_tls_key.is_none());
        assert!(listener.admin_tls_ca.is_none());
        assert!(!listener.admin_tls_configured());
        assert_eq!(listener.admin_tls_field_count(), 0);
    }

    /// Production with operator_credentials + dpop_jkt — fully compliant.
    #[test]
    fn validate_operator_auth_ok_with_credentials_and_dpop() {
        let config = Config {
            operator_credentials: named_credentials_with_dpop(),
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        assert!(config.validate_operator_auth().is_ok());
    }

    /// Production with operator_credentials missing dpop_jkt — hard error.
    #[test]
    fn validate_operator_auth_error_credentials_without_dpop_in_production() {
        let config = Config {
            operator_credentials: named_credentials_without_dpop(),
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_operator_auth().unwrap_err();
        assert!(
            matches!(err, ConfigError::OperatorCredentialMissingDpopJkt { .. }),
            "expected OperatorCredentialMissingDpopJkt, got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("alice"), "must name the offending credential");
        assert!(msg.contains("dpop_jkt"), "must explain what's missing");
    }

    /// Production with no credentials at all — hard error.
    #[test]
    fn validate_operator_auth_error_no_auth_in_production() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_operator_auth().unwrap_err();
        assert!(
            matches!(err, ConfigError::NoOperatorAuthConfigured),
            "expected NoOperatorAuthConfigured, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("operator_credentials"),
            "must name the solution"
        );
        assert!(
            msg.contains("LATCHGATE_UNSAFE_DEV"),
            "must mention dev bypass"
        );
    }

    /// Dev mode: no auth configured is accepted.
    #[test]
    fn validate_operator_auth_ok_no_auth_in_dev_mode() {
        let config = Config {
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_operator_auth().is_ok());
    }

    /// Dev mode: credentials without dpop_jkt accepted.
    #[test]
    fn validate_operator_auth_ok_credentials_without_dpop_in_dev_mode() {
        let config = Config {
            operator_credentials: named_credentials_without_dpop(),
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_operator_auth().is_ok());
    }

    /// effective_operator_credentials returns the configured credentials.
    #[test]
    fn effective_credentials_returns_configured() {
        let config = Config {
            operator_credentials: named_credentials_with_dpop(),
            ..Config::default()
        };
        let effective = config.effective_operator_credentials();
        assert!(effective.contains_key("alice"));
        assert_eq!(effective["alice"].api_key, "key-alice-abc123");
        assert!(effective["alice"].dpop_jkt.is_some());
    }

    /// Production with peercred + mapped principals — fully compliant.
    #[test]
    fn validate_identity_config_ok_peercred_with_principals() {
        let config = Config {
            identity: peercred_config_with_principal(),
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        assert!(config.validate_identity_config().is_ok());
    }

    /// Production with IdentityProviderKind::None — hard error.
    #[test]
    fn validate_identity_config_error_none_provider_in_production() {
        let config = Config {
            identity: IdentityConfig {
                provider: IdentityProviderKind::None,
                ..IdentityConfig::default()
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_identity_config().unwrap_err();
        assert!(
            matches!(err, ConfigError::NoneIdentityProviderInProduction),
            "expected NoneIdentityProviderInProduction, got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("peercred"), "must suggest a real provider");
        assert!(
            msg.contains("LATCHGATE_UNSAFE_DEV"),
            "must mention dev bypass"
        );
    }

    /// Production with peercred + allow_unmapped = true — hard error.
    #[test]
    fn validate_identity_config_error_allow_unmapped_in_production() {
        let config = Config {
            identity: IdentityConfig {
                provider: IdentityProviderKind::Peercred,
                peercred: PeercredConfig {
                    principals: HashMap::from([(
                        "1001".to_string(),
                        PeercredPrincipal {
                            principal: "agent".to_string(),
                            scopes: vec!["tools:call".into()],
                            owner: None,
                        },
                    )]),
                    allow_unmapped: true,
                },
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_identity_config().unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowUnmappedInProduction),
            "expected AllowUnmappedInProduction, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("allow_unmapped"),
            "must name the offending field"
        );
    }

    /// Production with peercred + empty principal map — hard error.
    #[test]
    fn validate_identity_config_error_empty_principal_map_in_production() {
        let config = Config {
            identity: IdentityConfig {
                provider: IdentityProviderKind::Peercred,
                peercred: PeercredConfig {
                    principals: HashMap::new(),
                    allow_unmapped: false,
                },
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_identity_config().unwrap_err();
        assert!(
            matches!(err, ConfigError::EmptyPeercredPrincipalMap),
            "expected EmptyPeercredPrincipalMap, got: {err}"
        );
    }

    /// Dev mode: None provider accepted.
    #[test]
    fn validate_identity_config_ok_none_in_dev_mode() {
        let config = Config {
            identity: IdentityConfig {
                provider: IdentityProviderKind::None,
                ..IdentityConfig::default()
            },
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_identity_config().is_ok());
    }

    /// Dev mode: allow_unmapped accepted.
    #[test]
    fn validate_identity_config_ok_allow_unmapped_in_dev_mode() {
        let config = Config {
            identity: IdentityConfig {
                provider: IdentityProviderKind::Peercred,
                peercred: PeercredConfig {
                    principals: HashMap::new(),
                    allow_unmapped: true,
                },
            },
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_identity_config().is_ok());
    }

    /// Production with all signing paths set — fully compliant.
    #[test]
    fn validate_signing_material_ok_with_all_paths() {
        let config = Config {
            signing: SigningConfig {
                receipt_signing_key_path: Some("/etc/latchgate/receipt.key".into()),
                grant_signing_key_path: Some("/etc/latchgate/grant.key".into()),
                receipt_keys_jwks_path: Some("/etc/latchgate/receipt-keys.jwks".into()),
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        assert!(config.validate_signing_material().is_ok());
    }

    /// Production with missing receipt signing key path — hard error.
    #[test]
    fn validate_signing_material_error_missing_receipt_signing_key() {
        let config = Config {
            signing: SigningConfig {
                receipt_signing_key_path: None,
                grant_signing_key_path: Some("/etc/latchgate/grant.key".into()),
                receipt_keys_jwks_path: Some("/etc/latchgate/receipt-keys.jwks".into()),
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_signing_material().unwrap_err();
        assert!(
            matches!(err, ConfigError::MissingReceiptSigningKeyPath),
            "expected MissingReceiptSigningKeyPath, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("receipt_signing_key_path"),
            "must name the field"
        );
        assert!(
            msg.contains("LATCHGATE_UNSAFE_DEV"),
            "must mention dev bypass"
        );
    }

    /// Production with missing grant signing key path — hard error.
    #[test]
    fn validate_signing_material_error_missing_grant_signing_key() {
        let config = Config {
            signing: SigningConfig {
                receipt_signing_key_path: Some("/etc/latchgate/receipt.key".into()),
                grant_signing_key_path: None,
                receipt_keys_jwks_path: Some("/etc/latchgate/receipt-keys.jwks".into()),
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_signing_material().unwrap_err();
        assert!(
            matches!(err, ConfigError::MissingGrantSigningKeyPath),
            "expected MissingGrantSigningKeyPath, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("grant_signing_key_path"),
            "must name the field"
        );
    }

    /// Production with missing receipt JWKS path — hard error.
    #[test]
    fn validate_signing_material_error_missing_receipt_jwks_path() {
        let config = Config {
            signing: SigningConfig {
                receipt_signing_key_path: Some("/etc/latchgate/receipt.key".into()),
                grant_signing_key_path: Some("/etc/latchgate/grant.key".into()),
                receipt_keys_jwks_path: None,
            },
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_signing_material().unwrap_err();
        assert!(
            matches!(err, ConfigError::MissingReceiptKeysJwksPath),
            "expected MissingReceiptKeysJwksPath, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("receipt_keys_jwks_path"),
            "must name the field"
        );
    }

    /// Dev mode: missing signing material accepted.
    #[test]
    fn validate_signing_material_ok_in_dev_mode() {
        let config = Config {
            signing: SigningConfig::default(),
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_signing_material().is_ok());
    }

    /// Production with deny enforcement — fully compliant.
    #[test]
    fn validate_response_schema_enforcement_ok_deny() {
        let config = Config {
            response_schema_enforcement: ResponseSchemaEnforcement::Deny,
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        assert!(config.validate_response_schema_enforcement().is_ok());
    }

    /// Production with warn enforcement — hard error.
    #[test]
    fn validate_response_schema_enforcement_error_warn_in_production() {
        let config = Config {
            response_schema_enforcement: ResponseSchemaEnforcement::Warn,
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let err = config.validate_response_schema_enforcement().unwrap_err();
        assert!(
            matches!(err, ConfigError::WarnResponseSchemaInProduction),
            "expected WarnResponseSchemaInProduction, got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("warn"), "must name the offending value");
        assert!(msg.contains("deny"), "must name the required value");
    }

    /// Dev mode: warn enforcement accepted.
    #[test]
    fn validate_response_schema_enforcement_ok_warn_in_dev_mode() {
        let config = Config {
            response_schema_enforcement: ResponseSchemaEnforcement::Warn,
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_response_schema_enforcement().is_ok());
    }

    /// Fully compliant production config passes all checks.
    #[test]
    fn validate_production_security_ok_with_full_config() {
        let config = production_compliant_config();
        assert!(config.validate_production_security().is_ok());
    }

    /// Production security catches identity provider = none.
    #[test]
    fn validate_production_security_catches_none_identity() {
        let mut config = production_compliant_config();
        config.identity.provider = IdentityProviderKind::None;
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(err, ConfigError::NoneIdentityProviderInProduction));
    }

    /// Production security catches missing receipt signing key.
    #[test]
    fn validate_production_security_catches_missing_receipt_key() {
        let mut config = production_compliant_config();
        config.signing.receipt_signing_key_path = None;
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(err, ConfigError::MissingReceiptSigningKeyPath));
    }

    /// Production security catches missing grant signing key.
    #[test]
    fn validate_production_security_catches_missing_grant_key() {
        let mut config = production_compliant_config();
        config.signing.grant_signing_key_path = None;
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(err, ConfigError::MissingGrantSigningKeyPath));
    }

    /// Production security catches missing JWKS path.
    #[test]
    fn validate_production_security_catches_missing_jwks() {
        let mut config = production_compliant_config();
        config.signing.receipt_keys_jwks_path = None;
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(err, ConfigError::MissingReceiptKeysJwksPath));
    }

    /// Production security catches warn response schema enforcement.
    #[test]
    fn validate_production_security_catches_warn_schema() {
        let mut config = production_compliant_config();
        config.response_schema_enforcement = ResponseSchemaEnforcement::Warn;
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(err, ConfigError::WarnResponseSchemaInProduction));
    }

    /// Production security catches missing operator credentials.
    #[test]
    fn validate_production_security_catches_no_operator_auth() {
        let mut config = production_compliant_config();
        config.operator_credentials = HashMap::new();
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(err, ConfigError::NoOperatorAuthConfigured));
    }

    /// Dev mode bypasses all production security checks.
    #[test]
    fn validate_production_security_ok_in_dev_mode() {
        let config = Config {
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_production_security().is_ok());
    }

    /// Production security catches file:// storage URL.
    #[test]
    fn validate_production_security_catches_file_storage() {
        let mut config = production_compliant_config();
        let mut storage = toml::value::Table::new();
        storage.insert("url".into(), toml::Value::String("file:///tmp/data".into()));
        config
            .host_io
            .insert("storage".into(), toml::Value::Table(storage));
        let err = config.validate_storage_scheme().unwrap_err();
        assert!(matches!(err, ConfigError::FileStorageInProduction));
    }

    /// Cloud storage URLs pass validation.
    #[test]
    fn validate_storage_scheme_accepts_s3() {
        let mut config = production_compliant_config();
        let mut storage = toml::value::Table::new();
        storage.insert("url".into(), toml::Value::String("s3://my-bucket".into()));
        config
            .host_io
            .insert("storage".into(), toml::Value::Table(storage));
        assert!(config.validate_storage_scheme().is_ok());
    }

    /// Production security catches async webhook mode with endpoints.
    #[test]
    fn validate_production_security_catches_async_webhooks() {
        let mut config = production_compliant_config();
        config.webhook_mode = WebhookMode::Async;
        config.webhooks = vec![toml::Value::String("placeholder".into())];
        let err = config.validate_webhook_mode().unwrap_err();
        assert!(matches!(err, ConfigError::AsyncWebhooksInProduction));
    }

    /// Async mode without any endpoints is fine (no events to lose).
    #[test]
    fn validate_webhook_mode_async_ok_without_endpoints() {
        let mut config = production_compliant_config();
        config.webhook_mode = WebhookMode::Async;
        config.webhooks = vec![];
        assert!(config.validate_webhook_mode().is_ok());
    }

    #[test]
    fn startup_fails_when_peercred_allow_unmapped_in_production() {
        let mut config = production_compliant_config();
        config.identity.peercred.allow_unmapped = true;
        assert!(config.validate_production_security().is_err());
    }

    #[test]
    fn startup_fails_when_operator_missing_dpop_jkt_in_production() {
        let mut config = production_compliant_config();
        config
            .operator_credentials
            .values_mut()
            .for_each(|c| c.dpop_jkt = None);
        let err = config.validate_production_security().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::OperatorCredentialMissingDpopJkt { .. }
        ));
    }

    #[test]
    fn dev_mode_allows_relaxed_security_config() {
        let config = Config {
            identity: IdentityConfig {
                provider: IdentityProviderKind::None,
                ..IdentityConfig::default()
            },
            signing: SigningConfig::default(),
            response_schema_enforcement: ResponseSchemaEnforcement::Warn,
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        assert!(config.validate_production_security().is_ok());
    }

    #[test]
    fn egress_proxy_coverage_ok_when_no_proxy_allowlist_actions() {
        let config = Config {
            posture: SecurityPosture::default(),
            egress: EgressConfig {
                egress_proxy_url: None,
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let actions = [("a", EgressProfile::None), ("b", EgressProfile::None)];
        assert_eq!(
            config.validate_egress_proxy_coverage(actions),
            EgressCoverageResult::Covered,
        );
    }

    #[test]
    fn egress_proxy_coverage_ok_when_proxy_url_configured() {
        let config = Config {
            posture: SecurityPosture::default(),
            egress: EgressConfig {
                egress_proxy_url: Some("http://127.0.0.1:3128".into()),
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let actions = [(
            "fetcher",
            EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["api.example.com".into()],
            },
        )];
        assert_eq!(
            config.validate_egress_proxy_coverage(actions),
            EgressCoverageResult::Covered,
        );
    }

    #[test]
    fn egress_proxy_coverage_kernel_only_when_proxy_allowlist_without_proxy() {
        let config = Config {
            posture: SecurityPosture::default(),
            egress: EgressConfig {
                egress_proxy_url: None,
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let actions = [
            ("no_net", EgressProfile::None),
            (
                "fetcher",
                EgressProfile::ProxyAllowlist {
                    allowed_domains: vec!["api.example.com".into()],
                },
            ),
            (
                "poster",
                EgressProfile::ProxyAllowlist {
                    allowed_domains: vec!["hooks.example.com".into()],
                },
            ),
        ];
        match config.validate_egress_proxy_coverage(actions) {
            EgressCoverageResult::KernelOnly { actions } => {
                assert_eq!(actions, vec!["fetcher".to_string(), "poster".to_string()]);
            }
            other => panic!("expected KernelOnly, got {other:?}"),
        }
    }

    #[test]
    fn egress_proxy_coverage_covered_in_dev_mode() {
        let config = Config {
            posture: SecurityPosture::all_insecure(),
            egress: EgressConfig {
                egress_proxy_url: None,
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let actions = [(
            "fetcher",
            EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["api.example.com".into()],
            },
        )];
        assert_eq!(
            config.validate_egress_proxy_coverage(actions),
            EgressCoverageResult::Covered,
            "egress_insecure must bypass egress proxy coverage check",
        );
    }

    #[test]
    fn narrow_noop_when_runtime_allowlist_is_none() {
        let config = Config {
            egress: EgressConfig {
                egress_runtime_allowlist: None,
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let mut domains = vec!["a.com".into(), "b.com".into()];
        let removed = config.narrow_egress_domains(&mut domains);
        assert_eq!(removed, 0);
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    #[test]
    fn narrow_removes_domains_not_in_runtime_allowlist() {
        let config = Config {
            egress: EgressConfig {
                egress_runtime_allowlist: Some(vec!["a.com".into()]),
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let mut domains = vec!["a.com".into(), "b.com".into(), "c.com".into()];
        let removed = config.narrow_egress_domains(&mut domains);
        assert_eq!(removed, 2);
        assert_eq!(domains, vec!["a.com"]);
    }

    #[test]
    fn narrow_cannot_add_domains() {
        let config = Config {
            egress: EgressConfig {
                egress_runtime_allowlist: Some(vec!["a.com".into(), "injected.com".into()]),
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let mut domains = vec!["a.com".into()];
        config.narrow_egress_domains(&mut domains);
        assert_eq!(domains, vec!["a.com"], "narrowing must never add domains");
    }

    #[test]
    fn narrow_empty_runtime_allowlist_removes_all() {
        let config = Config {
            egress: EgressConfig {
                egress_runtime_allowlist: Some(vec![]),
                ..EgressConfig::default()
            },
            ..Config::default()
        };
        let mut domains = vec!["a.com".into(), "b.com".into()];
        let removed = config.narrow_egress_domains(&mut domains);
        assert_eq!(removed, 2);
        assert!(domains.is_empty());
    }

    #[test]
    fn wildcard_acl_ok_when_only_low_risk() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let actions = [
            ("http_fetch", latchgate_core::RiskLevel::Low),
            ("github_read", latchgate_core::RiskLevel::Low),
        ];
        assert!(config.validate_wildcard_acl(actions).is_ok());
    }

    #[test]
    fn wildcard_acl_ok_with_medium_risk() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let actions = [
            ("http_fetch", latchgate_core::RiskLevel::Low),
            ("http_post", latchgate_core::RiskLevel::Medium),
        ];
        assert!(config.validate_wildcard_acl(actions).is_ok());
    }

    #[test]
    fn wildcard_acl_fails_with_high_risk() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let actions = [
            ("http_fetch", latchgate_core::RiskLevel::Low),
            ("fs_write", latchgate_core::RiskLevel::High),
        ];
        let err = config.validate_wildcard_acl(actions).unwrap_err();
        match err {
            ConfigError::WildcardAclHighRiskInProduction { actions } => {
                assert_eq!(actions, vec!["fs_write".to_string()]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn wildcard_acl_fails_with_critical_risk() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let actions = [
            ("http_fetch", latchgate_core::RiskLevel::Low),
            ("fs_delete", latchgate_core::RiskLevel::Critical),
        ];
        let err = config.validate_wildcard_acl(actions).unwrap_err();
        match err {
            ConfigError::WildcardAclHighRiskInProduction { actions } => {
                assert_eq!(actions, vec!["fs_delete".to_string()]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn wildcard_acl_reports_all_high_risk_actions() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let actions = [
            ("http_fetch", latchgate_core::RiskLevel::Low),
            ("fs_write", latchgate_core::RiskLevel::High),
            ("fs_delete", latchgate_core::RiskLevel::Critical),
        ];
        let err = config.validate_wildcard_acl(actions).unwrap_err();
        match err {
            ConfigError::WildcardAclHighRiskInProduction { actions } => {
                assert_eq!(actions.len(), 2);
                assert!(actions.contains(&"fs_write".to_string()));
                assert!(actions.contains(&"fs_delete".to_string()));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn wildcard_acl_ok_when_empty() {
        let config = Config {
            posture: SecurityPosture::default(),
            ..Config::default()
        };
        let actions: Vec<(&str, latchgate_core::RiskLevel)> = vec![];
        assert!(config.validate_wildcard_acl(actions).is_ok());
    }

    #[test]
    fn wildcard_acl_bypassed_in_dev_mode() {
        let config = Config {
            posture: SecurityPosture::all_insecure(),
            ..Config::default()
        };
        let actions = [("fs_delete", latchgate_core::RiskLevel::Critical)];
        assert!(
            config.validate_wildcard_acl(actions).is_ok(),
            "dev_mode must bypass wildcard ACL check"
        );
    }
}
