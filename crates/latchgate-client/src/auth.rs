//! Operator authentication credential and auto-discovery.
//!
//! [`OperatorAuth`] wraps a DPoP token + signing key for CLI => Gate requests.
//! [`auto_discover_operator_auth`] resolves credentials from `latchgate.toml`
//! and the `.latchgate/` PEM convention created by `latchgate init`.

use std::path::Path;

use latchgate_auth::DPoPSigningKey;
use latchgate_config::Config;

/// Sentinel token used by [`OperatorAuth::ephemeral`] so the TUI can
/// detect throwaway credentials that need upgrading.
const EPHEMERAL_TOKEN: &str = "ephemeral-first-launch";

/// Operator authentication credential used by the CLI.
///
/// DPoP proof-of-possession: every request generates a fresh proof with
/// unique `jti`, current `iat`, and request-bound `htm`/`htu`/`ath`.
/// The CLI must be provided a private key via `--operator-private-key`.
pub struct OperatorAuth {
    pub token: String,
    pub signing_key: DPoPSigningKey,
}

impl OperatorAuth {
    /// Build `OperatorAuth` from CLI arguments.
    ///
    /// Requires `private_key_path` — all operator credentials use DPoP.
    pub fn from_args(token: &str, private_key_path: Option<&Path>) -> Result<Self, String> {
        let path = private_key_path.ok_or_else(|| {
            "operator private key required for DPoP authentication.\n\
             Pass --operator-private-key <path> to provide the signing key."
                .to_string()
        })?;

        let pem = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read operator private key '{}': {e}", path.display()))?;

        // SECURITY: warn on loose file permissions (best-effort).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.mode() & 0o777;
                if mode & 0o077 != 0 {
                    eprintln!(
                        "  warning: operator private key '{}' has mode {:04o}; \
                         recommend 0600 for production",
                        path.display(),
                        mode,
                    );
                }
            }
        }

        let signing_key = DPoPSigningKey::from_pem(&pem)
            .map_err(|e| format!("invalid operator private key '{}': {e}", path.display()))?;

        Ok(OperatorAuth {
            token: token.to_string(),
            signing_key,
        })
    }

    /// Create an ephemeral operator auth for TUI first-launch mode.
    ///
    /// Generates a throwaway DPoP keypair. API calls will fail (no gate
    /// running), which the TUI reconnect logic handles gracefully.
    pub fn ephemeral() -> Self {
        let (signing_key, _) = latchgate_auth::dpop::generate_dpop_keypair()
            .expect("ephemeral DPoP keypair generation must not fail");
        Self {
            token: EPHEMERAL_TOKEN.into(),
            signing_key,
        }
    }

    /// Whether this auth was created by [`ephemeral()`](Self::ephemeral).
    ///
    /// The TUI uses this to detect when operator credentials need to be
    /// discovered (e.g. after the gate comes up externally while the TUI
    /// was started in first-launch mode).
    pub fn is_ephemeral(&self) -> bool {
        self.token == EPHEMERAL_TOKEN
    }
}

impl std::fmt::Debug for OperatorAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorAuth")
            .field("token", &"[redacted]")
            .field("signing_key", &"[redacted]")
            .finish()
    }
}

/// Auto-discover operator credentials from `latchgate.toml` and `.latchgate/`.
///
/// Resolution for a single configured credential:
///   1. Look for PEM at `.latchgate/<operator_name>.pem` (convention from `latchgate init`).
///   2. If found, construct `OperatorAuth::DPoP` automatically.
///   3. If not found, return an error with the expected path and actionable hint.
///
/// Multiple credentials require explicit `--operator-key` to disambiguate.
pub fn auto_discover_operator_auth(config: &Config) -> Result<OperatorAuth, String> {
    auto_discover_from_dir(config, Path::new("."))
}

/// Inner implementation with configurable base directory for testability.
///
/// `base_dir` is the project root — PEM is expected at `<base_dir>/.latchgate/<n>.pem`.
fn auto_discover_from_dir(config: &Config, base_dir: &Path) -> Result<OperatorAuth, String> {
    let creds = &config.operator_credentials;

    if creds.is_empty() {
        return Err("no operator credentials configured in latchgate.toml.\n\
             Add credentials or pass --operator-key explicitly."
            .into());
    }

    if creds.len() == 1 {
        let Some((id, cred)) = creds.iter().next() else {
            return Err("operator credentials map is unexpectedly empty".into());
        };

        // Convention: `latchgate init` writes the operator PEM to
        // .latchgate/operators/<operator_name>.pem relative to the project
        // root. Check the canonical path first, then fall back to the
        // legacy flat path (.latchgate/<name>.pem) for backward compat.
        let latchgate_dir = base_dir.join(".latchgate");
        let candidates = [
            latchgate_dir.join("operators").join(format!("{id}.pem")),
            latchgate_dir.join(format!("{id}.pem")),
        ];

        for pem_path in &candidates {
            if pem_path.exists() {
                return OperatorAuth::from_args(&cred.api_key, Some(pem_path)).map_err(|e| {
                    format!(
                        "found operator '{id}' with PEM at {}, but authentication failed: {e}",
                        pem_path.display()
                    )
                });
            }
        }

        return Err(format!(
            "found operator '{id}' in latchgate.toml but no PEM at {}.\n\
             Pass --operator-key and --operator-private-key explicitly,\n\
             or re-run: latchgate init",
            candidates[0].display()
        ));
    }

    let ids: Vec<_> = creds.keys().collect();
    Err(format!(
        "multiple operator credentials configured: {ids:?}\n\
         Pass --operator-key <KEY> to select one."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use latchgate_config::OperatorCredential;
    use p256::pkcs8::EncodePrivateKey;
    use std::collections::HashMap;

    fn config_with_creds(creds: HashMap<String, OperatorCredential>) -> Config {
        Config {
            operator_credentials: creds,
            ..Config::default()
        }
    }

    fn dpop_cred(key: &str, jkt: &str) -> OperatorCredential {
        OperatorCredential {
            api_key: key.to_string(),
            dpop_jkt: Some(jkt.to_string()),
        }
    }

    #[test]
    fn auto_discover_loads_pem_from_convention_path() {
        let tmp = tempfile::tempdir().unwrap();
        let latchgate_dir = tmp.path().join(".latchgate");
        std::fs::create_dir_all(&latchgate_dir).unwrap();

        let (signing_key, _pub_key) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let thumbprint = signing_key.thumbprint().unwrap();
        let pem = signing_key
            .as_inner()
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        std::fs::write(latchgate_dir.join("alice.pem"), pem.as_str().as_bytes()).unwrap();

        let mut creds = HashMap::new();
        creds.insert("alice".to_string(), dpop_cred("key-alice", &thumbprint));
        let config = config_with_creds(creds);

        let result = auto_discover_from_dir(&config, tmp.path());
        assert!(
            result.is_ok(),
            "auto-discover must succeed when PEM exists: {}",
            result.err().unwrap_or_default()
        );
    }

    #[test]
    fn auto_discover_errors_with_expected_path_when_pem_missing() {
        let tmp = tempfile::tempdir().unwrap();

        let mut creds = HashMap::new();
        creds.insert("alice".to_string(), dpop_cred("key-alice", "jkt-alice"));
        let config = config_with_creds(creds);

        let err = auto_discover_from_dir(&config, tmp.path()).unwrap_err();
        assert!(
            err.contains(".latchgate/operators/alice.pem"),
            "error must include expected PEM path: {err}"
        );
        assert!(
            err.contains("operator-private-key"),
            "error must include manual fallback hint: {err}"
        );
    }

    #[test]
    fn auto_discover_errors_on_corrupt_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let latchgate_dir = tmp.path().join(".latchgate");
        std::fs::create_dir_all(&latchgate_dir).unwrap();
        std::fs::write(latchgate_dir.join("dev.pem"), "not a real PEM").unwrap();

        let mut creds = HashMap::new();
        creds.insert("dev".to_string(), dpop_cred("dev-key", "jkt-dev"));
        let config = config_with_creds(creds);

        let err = auto_discover_from_dir(&config, tmp.path()).unwrap_err();
        assert!(
            err.contains("authentication failed"),
            "corrupt PEM must produce auth error, not panic: {err}"
        );
    }

    #[test]
    fn auto_discover_no_credentials_errors() {
        let config = config_with_creds(HashMap::new());
        let err = auto_discover_operator_auth(&config).unwrap_err();
        assert!(
            err.contains("no operator credentials"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn auto_discover_single_credential_without_pem_errors() {
        let mut creds = HashMap::new();
        creds.insert(
            "dev".to_string(),
            OperatorCredential {
                api_key: "dev-operator-key".into(),
                dpop_jkt: Some("jkt-dev".into()),
            },
        );
        let config = config_with_creds(creds);

        let err = auto_discover_operator_auth(&config).unwrap_err();
        assert!(
            err.contains("operator-private-key"),
            "must direct operator to provide private key: {err}"
        );
    }

    #[test]
    fn auto_discover_multiple_credentials_errors() {
        let mut creds = HashMap::new();
        creds.insert("alice".to_string(), dpop_cred("key-alice", "jkt-a"));
        creds.insert("bob".to_string(), dpop_cred("key-bob", "jkt-b"));
        let config = config_with_creds(creds);

        let err = auto_discover_operator_auth(&config).unwrap_err();
        assert!(
            err.contains("multiple operator credentials"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn auto_discover_multiple_credentials_errors_regardless_of_jkt() {
        let mut creds = HashMap::new();
        creds.insert("dev".to_string(), dpop_cred("dev-key", "jkt-dev"));
        creds.insert("prod".to_string(), dpop_cred("prod-key", "jkt-123"));
        let config = config_with_creds(creds);

        let err = auto_discover_operator_auth(&config).unwrap_err();
        assert!(err.contains("multiple"), "unexpected error: {err}");
    }
}
