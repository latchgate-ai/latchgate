//! Secret management: SOPS decrypt, JIT injection, and redaction.
//!
//! Secrets are decrypted from SOPS-encrypted files at execution time and
//! injected at the host I/O layer during WASM execution. Only secrets
//! declared in the action manifest are injected — undeclared keys in the SOPS
//! file are ignored (least privilege).
//!
//! # Caching
//!
//! SOPS decryption forks a subprocess per call. Under load this is a
//! bottleneck. The optional in-memory cache (keyed by file path + mtime +
//! inode) avoids redundant decryptions.
//!
//! # Security properties
//!
//! - Secrets are never logged, never included in audit events, never passed
//!   to OPA policy input.
//! - The `redact_value` helper replaces secret values with `***REDACTED***`
//!   for any path that needs to reference a secret's existence without its value.
//! - After execution, the `RunTask.env` map (which holds injected secrets)
//!   is dropped with the task — secrets do not persist in memory beyond the
//!   request lifecycle.
//! - Cached decrypted secrets are held in memory for at most `cache_ttl`.
//!   The cache is invalidated when the file's mtime or inode changes,
//!   ensuring rotated secrets are picked up even within the TTL window.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::process::Command;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use latchgate_core::SecretDecl;

// SecretsError

/// Errors from secret decryption and injection.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// SOPS binary not found on the host.
    #[error("sops binary not found (is sops installed?)")]
    SopsNotFound,

    /// SOPS decryption failed (bad key, corrupted file, etc.).
    ///
    /// SECURITY: Display shows only `code` (a safe summary). The `detail`
    /// field may contain the first 200 chars of SOPS stderr, which can
    /// include key hints or paths — it is available via Debug but must
    /// never flow into audit events, webhook payloads, or client responses.
    #[error("sops decryption failed: {code}")]
    DecryptFailed { code: String, detail: String },

    /// SOPS output could not be parsed as JSON.
    #[error("failed to parse sops output as JSON: {0}")]
    ParseError(String),

    /// The configured key file does not exist.
    #[error("key file not found: {0}")]
    KeyFileNotFound(PathBuf),

    /// A required secret is missing from the SOPS file.
    #[error("required secret '{name}' not found in sops file")]
    RequiredSecretMissing { name: String },

    /// SECURITY: a required secret was approved for this execution but the
    /// operator has no SOPS file configured, so it cannot be resolved. The
    /// action cannot run in a weaker posture than what was approved —
    /// fail-closed with the list of missing required secrets so operators can
    /// diagnose the misconfiguration.
    #[error("required secrets {names:?} cannot be resolved: sops_secrets_file not configured")]
    RequiredSecretsButNoSopsFile { names: Vec<String> },
}

// Decryption cache

/// Cache key: file identity (path + mtime + inode).
/// If any of these change, the cached entry is stale.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileCacheKey {
    path: PathBuf,
    mtime_nanos: u128,
    inode: u64,
}

/// Cached decryption result.
struct CacheEntry {
    secrets: HashMap<String, serde_json::Value>,
    cached_at: Instant,
}

/// Read file identity for cache keying. Returns None if stat fails.
fn file_cache_key(path: &Path) -> Option<FileCacheKey> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let mtime_nanos = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let inode = 0u64;

    Some(FileCacheKey {
        path: path.to_path_buf(),
        mtime_nanos,
        inode,
    })
}

// SecretsManager

/// Decrypts secrets from SOPS-encrypted files and filters them by manifest.
pub struct SecretsManager {
    sops_bin: String,
    key_file: Option<PathBuf>,
    cache_ttl: Duration,
    /// Sharded concurrent cache keyed by file identity (path + mtime + inode).
    ///
    /// `DashMap` uses per-shard locks internally, so concurrent WASM
    /// executions that all need secret injection contend only when they
    /// hash to the same shard — a ~1/N probability. The previous
    /// `Mutex<HashMap>` serialised every cache lookup behind a single
    /// exclusive lock.
    cache: DashMap<FileCacheKey, CacheEntry>,
}

impl SecretsManager {
    /// Create a new secrets manager.
    ///
    /// - `sops_bin`: path to the SOPS binary (usually `"sops"`).
    /// - `key_file`: optional path to an age key file. If set, exported as
    ///   `SOPS_AGE_KEY_FILE` when invoking SOPS.
    ///
    /// Cache is disabled by default (TTL = 0). Use `with_cache_ttl` to enable.
    pub fn new(sops_bin: &str, key_file: Option<PathBuf>) -> Self {
        Self {
            sops_bin: sops_bin.to_string(),
            key_file,
            cache_ttl: Duration::ZERO,
            cache: DashMap::new(),
        }
    }

    /// Enable decryption caching with the given TTL.
    ///
    /// Cache entries are keyed by file path + mtime + inode. A TTL of 0
    /// disables caching (every call forks `sops -d`).
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Decrypt a SOPS file and return only the secrets declared in the manifest.
    ///
    /// SECURITY: even if the SOPS file contains 20 keys, only the keys listed
    /// in `needed` are returned. This enforces least privilege — tools never
    /// receive secrets they didn't declare.
    ///
    /// The SOPS subprocess is driven via `tokio::process`, so this function
    /// does not block a tokio worker thread during fork/exec/wait.
    pub async fn decrypt_secrets(
        &self,
        sops_file: &Path,
        needed: &[SecretDecl],
    ) -> Result<HashMap<String, Zeroizing<String>>, SecretsError> {
        if needed.is_empty() {
            return Ok(HashMap::new());
        }

        // Validate key file exists if configured.
        if let Some(ref kf) = self.key_file {
            if !kf.exists() {
                return Err(SecretsError::KeyFileNotFound(kf.clone()));
            }
        }

        // Decrypt (or retrieve from cache).
        let all_secrets = self.decrypt_all(sops_file).await?;

        // SECURITY: filter to only declared keys.
        let needed_names: HashMap<&str, bool> =
            needed.iter().map(|s| (&*s.name, s.required)).collect();

        let mut result = HashMap::with_capacity(needed.len());

        for (name, required) in &needed_names {
            match all_secrets.get(*name) {
                Some(value) => {
                    // Convert JSON value to string. SOPS stores values as
                    // strings in the encrypted YAML, but after decryption
                    // they may be JSON strings or other types.
                    let string_value = match value {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    result.insert(name.to_string(), Zeroizing::new(string_value));
                }
                None if *required => {
                    return Err(SecretsError::RequiredSecretMissing {
                        name: name.to_string(),
                    });
                }
                None => {
                    debug!(
                        secret = %name,
                        "optional secret not found in sops file, skipping"
                    );
                }
            }
        }

        Ok(result)
    }

    /// Decrypt all secrets from a SOPS file, using the cache when available.
    ///
    /// Cache lookup and insert use `DashMap`'s per-shard locks. Concurrent
    /// WASM executions contend only when their cache keys hash to the same
    /// shard. The guard is never held across `.await`.
    async fn decrypt_all(
        &self,
        sops_file: &Path,
    ) -> Result<HashMap<String, serde_json::Value>, SecretsError> {
        // Try cache lookup if TTL > 0.
        if !self.cache_ttl.is_zero() {
            if let Some(key) = file_cache_key(sops_file) {
                if let Some(entry) = self.cache.get(&key) {
                    if entry.cached_at.elapsed() < self.cache_ttl {
                        debug!(path = %sops_file.display(), "sops cache hit");
                        return Ok(entry.secrets.clone());
                    }
                }
            }
        }

        // Cache miss or disabled — invoke SOPS asynchronously.
        let plaintext = self.run_sops_decrypt(sops_file).await?;
        let secrets: HashMap<String, serde_json::Value> = serde_json::from_str(&plaintext)
            .map_err(|e| SecretsError::ParseError(format!("invalid JSON from sops: {e}")))?;

        // Store in cache if TTL > 0.
        if !self.cache_ttl.is_zero() {
            if let Some(key) = file_cache_key(sops_file) {
                self.cache.insert(
                    key,
                    CacheEntry {
                        secrets: secrets.clone(),
                        cached_at: Instant::now(),
                    },
                );
            }
        }

        Ok(secrets)
    }

    /// Run `sops -d <file>` and return the plaintext output.
    ///
    /// Uses `tokio::process::Command` so the tokio runtime parks the task on
    /// the child's exit instead of holding a worker thread through the
    /// fork/exec/wait syscalls.
    async fn run_sops_decrypt(&self, sops_file: &Path) -> Result<String, SecretsError> {
        let mut cmd = Command::new(&self.sops_bin);
        cmd.args(["-d", &sops_file.to_string_lossy()]);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // If an age key file is configured, set the env var for SOPS.
        if let Some(ref kf) = self.key_file {
            cmd.env("SOPS_AGE_KEY_FILE", kf);
        }

        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretsError::SopsNotFound
            } else {
                SecretsError::DecryptFailed {
                    code: "sops_spawn_failed".into(),
                    detail: format!("failed to run sops: {e}"),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // SECURITY: log only that decryption failed, not the stderr content
            // (which might contain key hints). Include stderr in the error for
            // the operator but it won't reach audit/logs via normal paths.
            warn!("sops decryption failed for {:?}", sops_file);
            return Err(SecretsError::DecryptFailed {
                code: format!("sops_exit_{}", output.status.code().unwrap_or(-1)),
                detail: stderr.chars().take(200).collect::<String>(),
            });
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretsError::ParseError(format!("sops output is not valid UTF-8: {e}")))
    }

    /// Resolve approved secrets for a single execution.
    ///
    /// Intersects the policy-approved secret names with the manifest's
    /// declared secrets, then decrypts only that intersection. Optional
    /// secrets that cannot be resolved (no SOPS file configured) are
    /// silently skipped — the host I/O layer simply does not inject auth
    /// headers for those endpoints. Required secrets that cannot be
    /// resolved return [`SecretsError::RequiredSecretsButNoSopsFile`] so
    /// the kernel can fail-closed: executing in a weaker posture than what
    /// was approved is a security violation.
    ///
    /// SECURITY: the intersection is the least-privilege filter. Even if
    /// `approved_names` and the SOPS file both contain a secret the manifest
    /// did not declare, it will not be decrypted or returned.
    pub async fn resolve_approved(
        &self,
        approved_names: &[Arc<str>],
        manifest_secrets: &[SecretDecl],
        sops_secrets_file: Option<&str>,
    ) -> Result<HashMap<String, Zeroizing<String>>, SecretsError> {
        if approved_names.is_empty() {
            return Ok(HashMap::new());
        }

        let approved_set: std::collections::HashSet<&str> =
            approved_names.iter().map(|s| s.as_ref()).collect();
        let allowed_decls: Vec<SecretDecl> = manifest_secrets
            .iter()
            .filter(|s| approved_set.contains(&*s.name))
            .cloned()
            .collect();

        if allowed_decls.is_empty() {
            return Ok(HashMap::new());
        }

        let path = match sops_secrets_file {
            Some(p) => p,
            None => {
                let required_names: Vec<String> = allowed_decls
                    .iter()
                    .filter(|d| d.required)
                    .map(|d| d.name.to_string())
                    .collect();
                if !required_names.is_empty() {
                    return Err(SecretsError::RequiredSecretsButNoSopsFile {
                        names: required_names,
                    });
                }
                // All matched secrets are optional — safe to skip.
                tracing::info!(
                    optional_secrets = ?allowed_decls.iter().map(|d| &d.name).collect::<Vec<_>>(),
                    "sops_secrets_file not configured; skipping optional secrets"
                );
                return Ok(HashMap::new());
            }
        };

        self.decrypt_secrets(Path::new(path), &allowed_decls).await
    }
}

// Redaction

/// Redaction placeholder used in logs, audit events, and Debug output.
pub const REDACTED: &str = "***REDACTED***";

/// Replace a secret value with the redaction placeholder.
///
/// Use this whenever a secret's existence needs to be referenced without
/// exposing its value (e.g. in structured audit events).
#[cfg(test)]
fn redact_value(_value: &str) -> String {
    REDACTED.to_string()
}

/// Redact all values in a map, preserving keys.
///
/// Returns a new map suitable for logging or audit where keys are visible
/// but values are replaced with `***REDACTED***`.
#[cfg(test)]
fn redact_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    env.keys()
        .map(|k| (k.clone(), REDACTED.to_string()))
        .collect()
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // -- redact_value --

    #[test]
    fn test_redact_value() {
        assert_eq!(redact_value("my-secret-token"), "***REDACTED***");
    }

    #[test]
    fn test_redact_value_empty() {
        assert_eq!(redact_value(""), "***REDACTED***");
    }

    // -- redact_env --

    #[test]
    fn test_redact_env_preserves_keys() {
        let mut env = HashMap::new();
        env.insert("API_KEY".to_string(), "secret123".to_string());
        env.insert("DB_PASS".to_string(), "hunter2".to_string());

        let redacted = redact_env(&env);

        assert_eq!(redacted.len(), 2);
        assert_eq!(redacted["API_KEY"], "***REDACTED***");
        assert_eq!(redacted["DB_PASS"], "***REDACTED***");
    }

    #[test]
    fn test_redact_env_empty() {
        let env = HashMap::new();
        let redacted = redact_env(&env);
        assert!(redacted.is_empty());
    }

    // -- decrypt_secrets filtering --

    #[test]
    fn test_decrypt_returns_only_requested_keys() {
        // Simulate SOPS output with 5 keys, manifest declares 2.
        let sops_json = r#"{"A":"val_a","B":"val_b","C":"val_c","D":"val_d","E":"val_e"}"#;
        let all: HashMap<String, serde_json::Value> = serde_json::from_str(sops_json).unwrap();

        let needed = [
            SecretDecl {
                name: "A".into(),
                required: true,
            },
            SecretDecl {
                name: "C".into(),
                required: false,
            },
        ];

        // Manually run the filtering logic (same as decrypt_secrets inner loop).
        let needed_names: HashMap<&str, bool> =
            needed.iter().map(|s| (&*s.name, s.required)).collect();

        let mut result = HashMap::new();
        for name in needed_names.keys() {
            if let Some(serde_json::Value::String(s)) = all.get(*name) {
                result.insert(name.to_string(), s.clone());
            }
        }

        assert_eq!(result.len(), 2);
        assert_eq!(result["A"], "val_a");
        assert_eq!(result["C"], "val_c");
        assert!(!result.contains_key("B"));
        assert!(!result.contains_key("D"));
        assert!(!result.contains_key("E"));
    }

    #[test]
    fn test_decrypt_ignores_undeclared_keys() {
        let sops_json = r#"{"SECRET":"value","UNDECLARED":"other"}"#;
        let all: HashMap<String, serde_json::Value> = serde_json::from_str(sops_json).unwrap();

        let needed = vec![SecretDecl {
            name: "SECRET".into(),
            required: true,
        }];

        let mut result = HashMap::new();
        for decl in &needed {
            if let Some(serde_json::Value::String(s)) = all.get(&*decl.name) {
                result.insert(decl.name.to_string(), s.clone());
            }
        }

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("SECRET"));
        assert!(!result.contains_key("UNDECLARED"));
    }

    // -- RunTask Debug redaction --

    #[test]
    fn test_runtask_debug_redacts_secrets_and_sinks() {
        use crate::task::RunTask;

        let task = RunTask {
            module_digest: "sha256:aaa".into(),
            args_json: "{}".to_string(),
            allowed_imports: vec!["latchgate:io/http".into()],
            resource_limits: latchgate_core::ResourceLimits::default(),
            allowed_sinks: vec!["api.secret-service.com".into()],
            approved_secrets: vec!["SECRET_TOKEN".into()],
            decrypted_secrets: std::collections::HashMap::from([(
                "SECRET_TOKEN".into(),
                zeroize::Zeroizing::new("s3cr3t_v4lu3".into()),
            )]),
            trace_id: "test".into(),
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
        };

        let debug_str = format!("{task:?}");

        // Module digest and trace ID should be visible.
        assert!(debug_str.contains("sha256:aaa"));
        assert!(debug_str.contains("test"));
        // Sink URLs must NOT leak.
        assert!(
            !debug_str.contains("api.secret-service.com"),
            "SECURITY: sink URL leaked in Debug output"
        );
        // Secret names must NOT leak.
        assert!(
            !debug_str.contains("SECRET_TOKEN"),
            "SECURITY: secret name leaked in Debug output"
        );
        // Decrypted secret values must NOT leak.
        assert!(
            !debug_str.contains("s3cr3t_v4lu3"),
            "SECURITY: decrypted secret value leaked in Debug output"
        );
    }

    // -- SecretsManager construction --

    #[tokio::test]
    async fn test_secrets_manager_empty_needed() {
        let mgr = SecretsManager::new("sops", None);
        let result = mgr
            .decrypt_secrets(Path::new("/nonexistent"), &[])
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "empty needed list should return empty map"
        );
    }

    #[tokio::test]
    async fn test_missing_key_file_error() {
        let mgr = SecretsManager::new("sops", Some(PathBuf::from("/no/such/key.age")));
        let needed = vec![SecretDecl {
            name: "X".into(),
            required: true,
        }];
        let err = mgr
            .decrypt_secrets(Path::new("secrets.yaml"), &needed)
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::KeyFileNotFound(_)));
    }

    #[tokio::test]
    async fn test_sops_not_installed_error() {
        // Use a nonexistent binary name to trigger NotFound.
        let mgr = SecretsManager::new("/nonexistent/sops-binary-xyz", None);
        let needed = vec![SecretDecl {
            name: "X".into(),
            required: true,
        }];
        let err = mgr
            .decrypt_secrets(Path::new("secrets.yaml"), &needed)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SecretsError::SopsNotFound),
            "expected SopsNotFound, got: {err:?}"
        );
    }

    // -- Cache TTL builder --

    #[test]
    fn decrypt_failed_display_does_not_leak_stderr() {
        let err = SecretsError::DecryptFailed {
            code: "sops_exit_1".into(),
            detail: "age: error: no identity matched any of the recipients".into(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("sops_exit_1"),
            "Display must contain the safe code"
        );
        assert!(
            !display.contains("age:"),
            "SECURITY: stderr detail leaked into Display: {display}"
        );
        assert!(
            !display.contains("identity"),
            "SECURITY: stderr detail leaked into Display: {display}"
        );
    }

    #[test]
    fn test_cache_ttl_builder() {
        let mgr = SecretsManager::new("sops", None).with_cache_ttl(Duration::from_secs(30));
        assert_eq!(mgr.cache_ttl, Duration::from_secs(30));
    }

    #[test]
    fn test_default_cache_disabled() {
        let mgr = SecretsManager::new("sops", None);
        assert!(mgr.cache_ttl.is_zero());
    }

    // -- resolve_approved --

    #[tokio::test]
    async fn resolve_approved_empty_names_returns_empty() {
        let sm = SecretsManager::new("sops", None);
        let result = sm.resolve_approved(&[], &[], None).await;
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolve_approved_required_without_sops_file_errors() {
        let sm = SecretsManager::new("sops", None);
        let decls = vec![SecretDecl {
            name: "DB_PASSWORD".into(),
            required: true,
        }];
        let err = sm
            .resolve_approved(&["DB_PASSWORD".into()], &decls, None)
            .await
            .unwrap_err();
        match err {
            SecretsError::RequiredSecretsButNoSopsFile { names } => {
                assert_eq!(names, vec!["DB_PASSWORD".to_string()]);
            }
            other => panic!("expected RequiredSecretsButNoSopsFile, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_approved_optional_without_sops_file_returns_empty() {
        let sm = SecretsManager::new("sops", None);
        let decls = vec![SecretDecl {
            name: "GITHUB_TOKEN".into(),
            required: false,
        }];
        let result = sm
            .resolve_approved(&["GITHUB_TOKEN".into()], &decls, None)
            .await;
        assert!(
            result.is_ok(),
            "optional secrets without sops_secrets_file must be silently skipped"
        );
        assert!(
            result.unwrap().is_empty(),
            "skipped optional secrets must return empty map"
        );
    }

    #[tokio::test]
    async fn resolve_approved_mixed_required_and_optional_without_sops_file_errors() {
        let sm = SecretsManager::new("sops", None);
        let decls = vec![
            SecretDecl {
                name: "GITHUB_TOKEN".into(),
                required: false,
            },
            SecretDecl {
                name: "DB_PASSWORD".into(),
                required: true,
            },
        ];
        let err = sm
            .resolve_approved(&["GITHUB_TOKEN".into(), "DB_PASSWORD".into()], &decls, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SecretsError::RequiredSecretsButNoSopsFile { .. }),
            "required secret in approved set without sops_file must error even if other secrets are optional"
        );
    }

    #[tokio::test]
    async fn resolve_approved_no_matching_decls_returns_empty() {
        let sm = SecretsManager::new("sops", None);
        let decls = vec![SecretDecl {
            name: "OTHER_SECRET".into(),
            required: true,
        }];
        let result = sm
            .resolve_approved(&["NONEXISTENT".into()], &decls, Some("/dev/null"))
            .await;
        assert!(result.unwrap().is_empty());
    }

    // Async-runtime invariant: SOPS subprocess must not stall tokio
    //
    // Decryption forks and waits on the `sops` binary. If that wait is
    // driven through `std::process::Command::output` it parks the tokio
    // worker thread for the full duration of fork/exec/wait; under a
    // small worker pool this degrades latency of every concurrent
    // request. Driving it through `tokio::process::Command` yields at
    // each await point so other tasks keep making progress.
    //
    // The test pairs a deliberately slow `sops` (a shell script that
    // sleeps before emitting JSON) against a 10 ms ticker, both running
    // on a `current_thread` runtime. With a single worker thread the
    // runtime has nowhere to hide a blocking subprocess wait: either
    // the decrypt yields and the ticker fires, or it doesn't and the
    // ticker stalls.
    //
    // `#[cfg(unix)]` because the fixture is a shell script; on other
    // platforms this invariant is covered structurally by using
    // `tokio::process::Command` in the production path.

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn sops_decrypt_does_not_block_tokio_runtime() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU32, Ordering};

        const SOPS_SLEEP_SECS: f32 = 0.4;
        const TICK_INTERVAL: Duration = Duration::from_millis(10);
        // With SOPS_SLEEP_SECS = 0.4s and TICK_INTERVAL = 10ms the ideal
        // tick count is ~40. Require at least 20 to tolerate scheduler
        // noise while still catching a regression to a blocking wait,
        // which would yield zero ticks on a single-thread runtime.
        const MIN_TICKS: u32 = 20;

        // Fake SOPS binary: sleeps, then emits JSON on stdout. Ignores
        // its argv entirely — the real SOPS reads the file named by
        // `-d <path>`, but here we only care about the timing profile.
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("slow_sops.sh");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&script).unwrap();
            write!(
                f,
                "#!/bin/sh\nsleep {SOPS_SLEEP_SECS}\nprintf '{{\"TEST\":\"value\"}}'\n"
            )
            .unwrap();
            f.sync_all().unwrap();
            // File handle dropped here — OS releases write reference.
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // `sops_file` is passed through to the subprocess but our fake
        // ignores it; it just needs to exist so no earlier OS error
        // preempts the subprocess wait.
        let sops_file = dir.path().join("secrets.enc.yaml");
        std::fs::write(&sops_file, b"").unwrap();

        let mgr = SecretsManager::new(script.to_str().unwrap(), None);
        let decls = vec![SecretDecl {
            name: "TEST".into(),
            required: true,
        }];

        let ticks = AtomicU32::new(0);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();

        // Drive both futures on the single-thread runtime. The ticker
        // exits when the decrypt future signals completion, so we only
        // measure concurrency during the subprocess wait itself.
        let decrypt = async {
            let result = mgr.decrypt_secrets(&sops_file, &decls).await;
            let _ = done_tx.send(());
            result
        };
        let ticker = async {
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    _ = tokio::time::sleep(TICK_INTERVAL) => {
                        ticks.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        };

        let (result, ()) = tokio::join!(decrypt, ticker);
        let secrets = result.expect("fake sops should produce valid JSON");
        assert_eq!(secrets.get("TEST").map(|s| s.as_str()), Some("value"));

        let observed = ticks.load(Ordering::Relaxed);
        assert!(
            observed >= MIN_TICKS,
            "ticker fired only {observed} times during ~{SOPS_SLEEP_SECS}s decrypt \
             on a current_thread runtime — the subprocess wait is blocking the \
             worker (expected >= {MIN_TICKS} with a non-blocking `tokio::process::Command`)"
        );
    }
}
