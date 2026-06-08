//! Data structures for pipeline <-> WASM runtime communication.
//!
//! `RunTask` carries everything the WasmRuntime needs to instantiate and
//! execute a .wasm provider module.
//! `RunOutput` carries the result back to the pipeline for audit and response.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use latchgate_core::ResourceLimits;
use zeroize::Zeroizing;

pub struct RunTask {
    /// SHA-256 digest of the .wasm module to execute.
    pub module_digest: Arc<str>,

    /// JSON-serialised action arguments, passed to the WASM execute export.
    pub args_json: String,

    /// Host I/O imports this module is allowed to call.
    ///
    /// `Vec<Arc<str>>`: manifest-sourced and immutable per action version.
    /// Each clone is a refcount bump, not a heap allocation.
    pub allowed_imports: Vec<Arc<str>>,

    /// Resource limits for this execution (fuel, memory, timeout, I/O calls).
    pub resource_limits: ResourceLimits,

    /// Sinks approved by policy for this execution.
    ///
    /// `Arc<str>` elements: forwarded into `HostState`, audit events, and
    /// `RequestContext` — refcount-bump clones instead of heap allocations.
    pub allowed_sinks: Vec<Arc<str>>,

    /// Secret names approved for injection into host I/O calls.
    /// SECURITY: secrets are injected at host layer, never in WASM sandbox.
    pub approved_secrets: Vec<Arc<str>>,

    /// Decrypted secret key-value pairs for host-layer credential injection.
    /// SECURITY: these values NEVER enter the WASM sandbox. They are held
    /// in HostState and injected into outbound requests by host I/O handlers.
    /// Values are wrapped in `Zeroizing` to ensure plaintext is overwritten
    /// when the task is dropped — preventing recovery from process memory dumps.
    pub decrypted_secrets: HashMap<String, Zeroizing<String>>,

    /// Trace ID for correlation across logs, audit events, and metrics.
    pub trace_id: Arc<str>,

    /// Parsed database configuration from the action manifest.
    ///
    /// SECURITY: carried to the host I/O layer so database-specific handlers
    /// (e.g. mode enforcement, statement validation) can validate requests
    /// before any external I/O occurs. The WASM provider cannot influence
    /// this config. `None` for non-database actions.
    ///
    /// Parsed once at task construction (in the kernel) rather than on every
    /// execute call — the manifest JSON is static per action.
    pub database_config: Option<crate::database::DatabaseConfig>,

    /// Forward proxy URL for defense-in-depth egress control.
    /// Passed from Config through to HostState at execution time.
    pub egress_proxy_url: Option<Arc<str>>,

    /// Filesystem provider configuration. `None` for non-fs actions.
    /// Constructed by the kernel from the manifest's `FsConfig` and the
    /// operator-configured root fd.
    pub fs_config: Option<Arc<crate::fs_io::FsHostConfig>>,
}

impl std::fmt::Debug for RunTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunTask")
            .field("module_digest", &&*self.module_digest)
            .field("allowed_imports", &self.allowed_imports)
            .field("resource_limits", &self.resource_limits)
            .field("allowed_sinks_count", &self.allowed_sinks.len())
            .field("approved_secrets_count", &self.approved_secrets.len())
            .field("decrypted_secrets_count", &self.decrypted_secrets.len())
            .field("trace_id", &&*self.trace_id)
            .finish_non_exhaustive()
    }
}

/// Result of a WASM provider module execution.
#[derive(Debug, Clone)]
pub struct RunOutput {
    /// Parsed JSON from the WASM execute export result. Untrusted data.
    ///
    /// `Arc` because the value is cloned into `VerificationInput`,
    /// `ExecutionReceipt`, and `ExecutionResponse` — three consumers on
    /// the success path. `Arc::clone` is a refcount bump; without it
    /// each clone deep-copies the entire JSON tree (Strings, Maps, Vecs).
    pub stdout: Arc<serde_json::Value>,

    /// 0 = provider Ok, 1 = provider Err.
    pub exit_code: i64,

    /// Wall-clock duration of execution (including host I/O time).
    pub duration: Duration,

    /// Number of host I/O calls made during execution.
    pub io_calls_made: u32,

    /// Fuel consumed during execution (CPU metering).
    pub fuel_consumed: u64,

    /// Effects independently observed by the host during I/O execution.
    /// Passed to the verifier for cross-checking against provider output.
    pub host_observed: Vec<crate::host_io::HostObservedEffect>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_task(module_digest: &str, trace_id: &str) -> RunTask {
        RunTask {
            module_digest: Arc::from(module_digest),
            args_json: "{}".to_string(),
            allowed_imports: vec!["latchgate:io/http".into()],
            resource_limits: ResourceLimits::default(),
            allowed_sinks: vec!["api.github.com".into()],
            approved_secrets: vec!["GITHUB_TOKEN".into()],
            decrypted_secrets: HashMap::from([(
                "GITHUB_TOKEN".into(),
                Zeroizing::new("ghp_secret123".into()),
            )]),
            trace_id: Arc::from(trace_id),
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
        }
    }

    #[test]
    fn debug_redacts_secrets_and_sinks() {
        let task = test_task("sha256:abcd1234", "trace-001");
        let debug_output = format!("{task:?}");
        assert!(debug_output.contains("sha256:abcd1234"));
        assert!(debug_output.contains("trace-001"));
        assert!(
            !debug_output.contains("api.github.com"),
            "sink URL leaked in Debug output"
        );
        assert!(
            !debug_output.contains("GITHUB_TOKEN"),
            "secret name leaked in Debug output"
        );
        assert!(
            !debug_output.contains("ghp_secret123"),
            "decrypted secret value leaked in Debug output"
        );
        assert!(debug_output.contains("allowed_sinks_count"));
        assert!(debug_output.contains("approved_secrets_count"));
        assert!(debug_output.contains("decrypted_secrets_count"));
    }

    #[test]
    fn run_output_clone() {
        let output = RunOutput {
            stdout: Arc::new(serde_json::json!({"status": 200})),
            exit_code: 0,
            duration: Duration::from_millis(150),
            io_calls_made: 1,
            fuel_consumed: 50_000,
            host_observed: vec![],
        };
        let cloned = output.clone();
        assert_eq!(cloned.exit_code, 0);
        assert_eq!(cloned.io_calls_made, 1);
    }
}
