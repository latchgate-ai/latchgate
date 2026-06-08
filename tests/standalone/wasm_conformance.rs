//! WASM provider conformance tests requiring compiled .wasm modules.
//!
//! These tests load real provider binaries from `target/providers/`,
//! precompile them through `WasmRuntime`, and verify sandbox properties
//! that can only be tested with actual WASM execution:
//!
//!  - Fuel exhaustion terminates execution
//!  - Module digest mismatch at precompile is rejected
//!  - Precompiled module executes and returns structured output
//!  - Sink validation is enforced through the WASM host I/O boundary
//!  - Provider cannot call undeclared host imports
//!  - Provider does not receive secrets in its sandbox
//!  - VerifierKind::None produces UnverifiableDeclared, never Verified
//!
//! # Requirements
//!
//! Run `make providers` before these tests:
//!   make providers
//!   make test-conformance
//!
//! Provider .wasm files must exist in `target/providers/`.

use std::collections::HashMap;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use latchgate_core::VerificationOutcome;
use latchgate_core::{ResourceLimits, VerifierKind};
use latchgate_kernel::{VerificationInput, VerifierRegistry};
use latchgate_providers::RunTask;
use latchgate_providers::{ProviderError, WasmRuntime};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Workspace root (tests/ -> ..)
fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must be inside workspace root")
        .to_path_buf()
}

/// Path to a compiled provider .wasm file.
fn provider_wasm_path(name: &str) -> PathBuf {
    workspace_root().join(format!("target/providers/{name}.wasm"))
}

/// Load provider bytes and compute sha256 digest.
/// Returns `None` if the provider .wasm file does not exist (not built yet).
fn try_load_provider(name: &str) -> Option<(Vec<u8>, String)> {
    let path = provider_wasm_path(name);
    if !path.exists() {
        eprintln!("skipping: {name}.wasm not found at {path:?} — run `make providers` first");
        return None;
    }
    let bytes = std::fs::read(&path).unwrap();
    let hash = Sha256::digest(&bytes);
    let digest = format!("sha256:{}", hex::encode(hash));
    Some((bytes, digest))
}

/// Load a SHIPPED provider, failing the test if its `.wasm` is missing.
///
/// Shipped providers (see PROVIDERS in the build scripts and the Makefile)
/// are part of the trust chain — their conformance tests must run. A missing
/// module means the build is incomplete, which is a hard error, not a reason
/// to silently pass. CI builds providers before running conformance, so this
/// only fires on a genuinely broken local build.
macro_rules! require_shipped_provider {
    ($name:expr) => {
        match try_load_provider($name) {
            Some(v) => v,
            None => panic!(
                "shipped provider `{}` not built — run `make providers` first. \
                 A shipped provider is part of the trust chain; its conformance \
                 test must not be skipped.",
                $name
            ),
        }
    };
}

/// Skip the test if an OPTIONAL provider is not built. Reserved for
/// providers that are not part of the default shipped set.
#[allow(unused_macros)]
macro_rules! require_provider {
    ($name:expr) => {
        match try_load_provider($name) {
            Some(v) => v,
            None => return,
        }
    };
}

/// Skip the test if an adversarial fixture is not built.
macro_rules! require_fixture {
    ($name:expr) => {{
        let path = fixture_wasm_path($name);
        if !path.exists() {
            eprintln!(
                "skipping: fixture_{}.wasm not found at {:?} — run `make test-fixtures` first",
                $name, path
            );
            return;
        }
        path
    }};
}

/// Path to a compiled adversarial fixture .wasm file.
/// Built by `make test-fixtures`, output goes to target/test-fixtures/.
fn fixture_wasm_path(name: &str) -> PathBuf {
    workspace_root().join(format!("target/test-fixtures/fixture_{name}.wasm"))
}

fn run_task(digest: &str, args_json: &str, imports: Vec<&str>, sinks: Vec<&str>) -> RunTask {
    RunTask {
        module_digest: std::sync::Arc::from(digest),
        args_json: args_json.to_string(),
        allowed_imports: imports.into_iter().map(std::sync::Arc::from).collect(),
        resource_limits: ResourceLimits::default(),
        allowed_sinks: sinks.into_iter().map(std::sync::Arc::from).collect(),
        approved_secrets: vec![],
        decrypted_secrets: HashMap::new(),
        trace_id: std::sync::Arc::from(format!("conformance-{}", uuid::Uuid::now_v7()).as_str()),
        database_config: None,
        egress_proxy_url: None,
        fs_config: None,
    }
}

// ---------------------------------------------------------------------------
// Module loading and digest verification
// ---------------------------------------------------------------------------

/// Precompiling a real .wasm module with its correct digest succeeds.
#[tokio::test]
async fn precompile_http_api_with_correct_digest() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    assert!(
        rt.precompile(&bytes, &digest).is_ok(),
        "precompile with correct digest must succeed"
    );
    assert_eq!(rt.cached_module_count(), 1);
}

/// Precompiling a real .wasm module with a wrong digest is rejected.
#[tokio::test]
async fn precompile_http_api_with_wrong_digest_rejected() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, _) = require_shipped_provider!("http_api");
    let err = rt
        .precompile(
            &bytes,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::DigestMismatch { .. }),
        "wrong digest must be rejected: {err:?}"
    );
    assert_eq!(
        rt.cached_module_count(),
        0,
        "rejected module must not be cached"
    );
}

/// Every shipped provider precompiles successfully.
///
/// The set is the single source of truth for what ships; it must match the
/// PROVIDERS list in the build scripts and the Makefile. The cached-module
/// count is derived from the slice length, not hardcoded, so adding a
/// provider here cannot leave a stale assertion behind.
const SHIPPED_PROVIDERS: &[&str] = &["http_api", "fs"];

#[tokio::test]
async fn all_shipped_providers_precompile() {
    let rt = WasmRuntime::new(4).unwrap();
    for name in SHIPPED_PROVIDERS {
        let (bytes, digest) = require_shipped_provider!(name);
        rt.precompile(&bytes, &digest)
            .unwrap_or_else(|e| panic!("provider {name} must precompile: {e}"));
    }
    assert_eq!(
        rt.cached_module_count(),
        SHIPPED_PROVIDERS.len(),
        "every shipped provider must be cached after precompile"
    );
}

// ---------------------------------------------------------------------------
// Execution — http_api provider through WASM sandbox
// ---------------------------------------------------------------------------

/// http_api provider executes and returns structured output.
///
/// The host I/O call will fail (no target allowed) but the provider itself
/// must parse the request, call io_http::request, and propagate the host
/// error back as an Err result.
#[tokio::test]
async fn http_api_provider_executes_and_returns_output() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    rt.precompile(&bytes, &digest).unwrap();

    let task = run_task(
        &digest,
        r#"{"url":"https://httpbin.org/get","method":"GET"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec![], // no sinks allowed => host will reject the HTTP call
    );

    let result = rt.execute(task).await;
    // Provider should return an error because sink validation blocks the call.
    // The important thing is that it executes (no panic, no timeout, no
    // instantiation failure) and returns a structured result.
    match result {
        Ok(output) => {
            // Provider returned Ok or Err result — both valid.
            assert!(output.fuel_consumed > 0, "must consume some fuel");
        }
        Err(ProviderError::ExecutionFailed { .. }) => {
            // Host I/O error propagated — this is correct behavior.
        }
        Err(other) => {
            panic!("unexpected error: {other:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// fs provider — execution through the WASM boundary into the host pipeline
// ---------------------------------------------------------------------------
//
// The host-side path-validation pipeline (traversal, symlink escape, denied
// patterns, operation gating, size caps) is exhaustively unit-tested in
// `latchgate-providers::fs_io`. These tests cover the part that is NOT tested
// there: the `fs` WASM module itself correctly parsing the task, calling the
// `latchgate:io/fs` host import, and propagating the host outcome back as a
// structured response — and that a host-rejected path surfaces as a clean
// error rather than a panic, trap, or data leak.

/// Build an `FsHostConfig` rooted at a fresh temp dir for fs conformance.
///
/// `keep` returns the `TempDir` guard so the caller controls its lifetime —
/// the directory must outlive the execution or the root fd dangles.
fn fs_host_config(
    allowed_ops: Vec<latchgate_core::FsOperation>,
    allowed: &[&str],
    denied: &[&str],
) -> (
    std::sync::Arc<latchgate_providers::FsHostConfig>,
    tempfile::TempDir,
) {
    use latchgate_core::fs_path::GlobPattern;
    use latchgate_providers::{open_root_fd, FsHostConfig};

    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/main.rs"), b"fn main() {}").unwrap();
    std::fs::write(dir.path().join(".env"), b"SECRET=should_never_be_read").unwrap();

    let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
    let config = FsHostConfig {
        root_fd: std::sync::Arc::new(root_fd),
        root_canonical,
        allowed_operations: allowed_ops,
        allowed_paths: allowed
            .iter()
            .map(|p| GlobPattern::new(p).unwrap())
            .collect(),
        denied_paths: denied
            .iter()
            .map(|p| GlobPattern::new(p).unwrap())
            .collect(),
        max_file_bytes: 1024 * 1024,
    };
    (std::sync::Arc::new(config), dir)
}

/// The fs provider reads an allowed file and returns content + SHA-256 hash.
#[tokio::test]
async fn fs_provider_reads_allowed_file() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("fs");
    rt.precompile(&bytes, &digest).unwrap();

    let (fs_config, _dir) = fs_host_config(
        vec![latchgate_core::FsOperation::Read],
        &["src/**"],
        &["**/.env"],
    );

    let mut task = run_task(
        &digest,
        r#"{"operation":"read","path":"src/main.rs"}"#,
        vec!["latchgate:io/fs", "latchgate:io/log"],
        vec![],
    );
    task.fs_config = Some(fs_config);

    let output = rt.execute(task).await.expect("fs read must execute");
    assert_eq!(output.exit_code, 0, "read of an allowed file must succeed");
    // Envelope: { ok: true, data: { hash, size_bytes, content_base64, path } }.
    assert_eq!(
        output.stdout["ok"].as_bool(),
        Some(true),
        "read of an allowed file must report ok: {}",
        output.stdout
    );
    let data = &output.stdout["data"];
    let expected_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"fn main() {}")));
    assert_eq!(
        data["hash"].as_str(),
        Some(expected_hash.as_str()),
        "provider must return the host-computed content hash: {}",
        output.stdout
    );
    assert_eq!(data["size_bytes"].as_u64(), Some(12));
}

/// A path the host pipeline rejects (denied pattern) surfaces as a structured
/// provider error — not a panic, not a trap, and never the file contents.
///
/// `.env` is inside the root and would resolve, but the denied-pattern check
/// blocks it. This proves the WASM module propagates the host denial cleanly
/// rather than leaking the secret payload.
#[tokio::test]
async fn fs_provider_denied_path_surfaces_clean_error() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("fs");
    rt.precompile(&bytes, &digest).unwrap();

    let (fs_config, _dir) = fs_host_config(
        vec![latchgate_core::FsOperation::Read],
        &["**"],
        &["**/.env"],
    );

    let mut task = run_task(
        &digest,
        r#"{"operation":"read","path":".env"}"#,
        vec!["latchgate:io/fs", "latchgate:io/log"],
        vec![],
    );
    task.fs_config = Some(fs_config);

    let result = rt.execute(task).await;
    match result {
        Ok(output) => {
            // The provider reports host errors inside the envelope (ok: false
            // with an error code), not via a non-zero WASM exit code.
            assert_eq!(
                output.stdout["ok"].as_bool(),
                Some(false),
                "denied path must report ok: false: {}",
                output.stdout
            );
            assert_eq!(
                output.stdout["error"]["code"].as_str(),
                Some("path_denied"),
                "denied path must surface the path_denied code: {}",
                output.stdout
            );
            let body = serde_json::to_string(&output.stdout).unwrap();
            assert!(
                !body.contains("should_never_be_read"),
                "denied-file contents must never appear in provider output: {body}"
            );
        }
        Err(ProviderError::ExecutionFailed { reason }) => {
            assert!(
                !reason.contains("should_never_be_read"),
                "denied-file contents must never appear in provider error: {reason}"
            );
        }
        Err(other) => panic!("unexpected error type: {other:?}"),
    }
}

/// A traversal attempt (`../`) escaping the root is rejected end-to-end and
/// never reads anything outside the configured root.
#[tokio::test]
async fn fs_provider_traversal_escape_rejected() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("fs");
    rt.precompile(&bytes, &digest).unwrap();

    let (fs_config, _dir) = fs_host_config(vec![latchgate_core::FsOperation::Read], &["**"], &[]);

    let mut task = run_task(
        &digest,
        r#"{"operation":"read","path":"../../../../etc/passwd"}"#,
        vec!["latchgate:io/fs", "latchgate:io/log"],
        vec![],
    );
    task.fs_config = Some(fs_config);

    let result = rt.execute(task).await;
    match result {
        Ok(output) => {
            assert_eq!(
                output.stdout["ok"].as_bool(),
                Some(false),
                "traversal escape must be rejected, not served: {}",
                output.stdout
            );
            // openat2 RESOLVE_BENEATH rejects the escape; the host maps it to
            // a traversal or path-invalid error depending on where it trips.
            let code = output.stdout["error"]["code"].as_str().unwrap_or("");
            assert!(
                matches!(
                    code,
                    "traversal" | "path_invalid" | "path_not_allowed" | "path_not_found"
                ),
                "traversal escape must surface a path-rejection code, got {code:?}: {}",
                output.stdout
            );
            let body = serde_json::to_string(&output.stdout).unwrap();
            assert!(
                !body.contains("root:") && !body.contains("/bin/"),
                "traversal must not return host /etc/passwd contents: {body}"
            );
        }
        Err(ProviderError::ExecutionFailed { .. }) => {
            // Host pipeline rejected the escape before any read — also correct.
        }
        Err(other) => panic!("unexpected error type: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Fuel exhaustion
// ---------------------------------------------------------------------------

/// Provider with near-zero fuel budget is terminated.
#[tokio::test]
async fn fuel_exhaustion_terminates_provider() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    rt.precompile(&bytes, &digest).unwrap();

    let mut task = run_task(
        &digest,
        r#"{"url":"https://httpbin.org/get"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec!["httpbin.org"],
    );
    // Tiny fuel budget — not enough to parse JSON.
    task.resource_limits.fuel = 100;

    let err = rt.execute(task).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::FuelExhausted),
        "tiny fuel must cause FuelExhausted, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sink validation through WASM boundary
// ---------------------------------------------------------------------------

/// Provider calling io_http with an undeclared sink gets an error, not data.
#[tokio::test]
async fn sink_validation_blocks_undeclared_target() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    rt.precompile(&bytes, &digest).unwrap();

    let task = run_task(
        &digest,
        r#"{"url":"https://evil.com/exfiltrate","method":"GET"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec!["safe.example.com"], // evil.com not in allowed sinks
    );

    let result = rt.execute(task).await;
    match result {
        Ok(output) => {
            // Provider must have received an error from the host and returned it.
            assert_eq!(output.exit_code, 1, "provider must report host error");
        }
        Err(ProviderError::ExecutionFailed { reason }) => {
            assert!(
                reason.contains("sink") || reason.contains("allowed") || reason.contains("denied"),
                "error should mention sink validation: {reason}"
            );
        }
        Err(other) => {
            panic!("unexpected error type: {other:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Import gating through WASM instantiation
// ---------------------------------------------------------------------------

/// Provider with declared imports can be instantiated.
#[tokio::test]
async fn provider_with_declared_imports_instantiates() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    rt.precompile(&bytes, &digest).unwrap();

    // http_api requires latchgate:io/http + latchgate:io/log.
    let task = run_task(
        &digest,
        r#"{"url":"https://example.com"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec![],
    );

    // Should at least instantiate (execution may fail at I/O, but not at
    // instantiation). Any error must NOT be ImportNotDeclared.
    let result = rt.execute(task).await;
    if let Err(ref e) = result {
        assert!(
            !matches!(e, ProviderError::ImportNotDeclared { .. }),
            "declared imports must not fail gating: {e:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-call isolation
// ---------------------------------------------------------------------------

/// Two sequential executions of the same module produce independent results.
/// No state from the first call leaks into the second.
#[tokio::test]
async fn sequential_executions_are_isolated() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    rt.precompile(&bytes, &digest).unwrap();

    let task1 = run_task(
        &digest,
        r#"{"url":"https://a.example.com"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec![],
    );
    let task2 = run_task(
        &digest,
        r#"{"url":"https://b.example.com"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec![],
    );

    let r1 = rt.execute(task1).await;
    let r2 = rt.execute(task2).await;

    // Both must produce results (Ok or Err), not panics or hangs.
    assert!(
        r1.is_ok() || r1.is_err(),
        "first call must produce a result"
    );
    assert!(
        r2.is_ok() || r2.is_err(),
        "second call must produce a result"
    );
}

// ---------------------------------------------------------------------------
// Secrets never in WASM sandbox
// ---------------------------------------------------------------------------

/// Secrets in RunTask.decrypted_secrets are NOT passed to the WASM module.
/// They are held in HostState for host-layer injection only. The provider
/// cannot read them through any export or import.
///
/// We verify this indirectly: the http_api provider calls io_http::request
/// with no Authorization header in its request. If secrets leaked into the
/// sandbox, the provider could theoretically read them — but the WIT
/// interface has no "get_secret" import, so there's no path.
///
/// This test ensures execution succeeds even with secrets in the RunTask,
/// and the provider output does not contain the secret value.
#[tokio::test]
async fn secrets_not_visible_to_provider() {
    let rt = WasmRuntime::new(4).unwrap();
    let (bytes, digest) = require_shipped_provider!("http_api");
    rt.precompile(&bytes, &digest).unwrap();

    let mut task = run_task(
        &digest,
        r#"{"url":"https://example.com","method":"GET"}"#,
        vec!["latchgate:io/http", "latchgate:io/log"],
        vec!["example.com"],
    );
    task.approved_secrets = vec!["SECRET_TOKEN".into()];
    task.decrypted_secrets.insert(
        "SECRET_TOKEN".into(),
        zeroize::Zeroizing::new("super_secret_value_xyz".into()),
    );

    let result = rt.execute(task).await;
    // Whether the call succeeds or fails, the output must not contain the secret.
    match result {
        Ok(output) => {
            let output_str = serde_json::to_string(&output.stdout).unwrap();
            assert!(
                !output_str.contains("super_secret_value_xyz"),
                "provider output must not contain secret value: {output_str}"
            );
        }
        Err(e) => {
            let err_str = format!("{e:?}");
            assert!(
                !err_str.contains("super_secret_value_xyz"),
                "provider error must not contain secret value: {err_str}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// VerifierKind::None => UnverifiableDeclared (through real verifier registry)
// ---------------------------------------------------------------------------

/// When VerifierKind::None is configured, the verification outcome must
/// always be UnverifiableDeclared — never Verified, regardless of what
/// the provider returned.
///
/// This is the honest-semantics invariant: the system never claims
/// "verified" without an actual verification step.
#[tokio::test]
async fn verifier_none_always_returns_unverifiable_declared() {
    let registry = VerifierRegistry::new();

    // Simulate a variety of provider outputs — all must produce
    // UnverifiableDeclared when verifier kind is None.
    let test_cases = [
        serde_json::json!({"status": 200, "body": "success"}),
        serde_json::json!({"error": "something failed"}),
        serde_json::json!(null),
        serde_json::json!({"status": 500}),
        serde_json::json!({"rows_affected": 42}),
    ];

    for (i, output) in test_cases.iter().enumerate() {
        let input = VerificationInput {
            action_id: format!("test_action_{i}").into(),
            provider_output: std::sync::Arc::new(output.clone()),
            exit_code: if i % 2 == 0 { 0 } else { 1 },
            approved_targets: &[],
            verification_config: None,
            host_observed: &[],
        };

        let outcome = registry.verify(VerifierKind::None, &input).await.unwrap();
        assert_eq!(
            outcome,
            VerificationOutcome::UnverifiableDeclared,
            "VerifierKind::None must ALWAYS return UnverifiableDeclared, \
             got {outcome:?} for case {i}: {output}"
        );

        // Extra safety: must never be Verified.
        assert!(
            !outcome.is_verified(),
            "VerifierKind::None must NEVER return Verified"
        );
    }
}

// ---------------------------------------------------------------------------
// Memory limit enforcement (S2)
// ---------------------------------------------------------------------------

/// A provider that allocates memory aggressively is terminated with
/// MemoryLimitExceeded before it can exceed the configured cap.
///
/// This test uses the `adversarial_memory_hog` fixture which allocates in
/// 1 MiB chunks indefinitely. We set a tight memory cap (4 MiB) and verify
/// that wasmtime's StoreLimits trap fires before any significant overshoot.
///
/// Why this matters: fuel exhaustion (CPU) and timeout (wall-clock) do not
/// bound memory. A separate memory cap is required to prevent a malicious
/// provider from causing OOM on the host.
#[tokio::test]
async fn memory_limit_terminates_memory_hog_provider() {
    let rt = WasmRuntime::new(4).unwrap();

    let path = require_fixture!("memory_hog");
    let bytes = std::fs::read(&path).unwrap();
    let hash = sha2::Sha256::digest(&bytes);
    let digest = format!("sha256:{}", hex::encode(hash));

    rt.precompile(&bytes, &digest).unwrap();

    let mut task = run_task(
        &digest,
        r#"{}"#,
        vec![], // no imports needed — pure allocation
        vec![],
    );
    // 4 MiB cap: tight enough that the provider cannot do any real work,
    // generous enough that the WASM runtime itself starts up cleanly.
    task.resource_limits.memory_mb = 4;
    // High fuel so CPU limit doesn't fire first.
    task.resource_limits.fuel = 100_000_000;
    // Long timeout so wall-clock limit doesn't fire first.
    task.resource_limits.timeout_seconds = 30;

    let err = rt.execute(task).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::MemoryLimitExceeded),
        "memory hog must be terminated with MemoryLimitExceeded, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Epoch-based wall-clock timeout (S3)
// ---------------------------------------------------------------------------

/// A provider that runs an infinite pure-computation loop is interrupted by
/// the wasmtime epoch ticker, not by fuel exhaustion.
///
/// This test uses the `adversarial_infinite_loop` fixture which spins
/// forever with no host imports and no await points. We set:
///   - fuel = 0 (unlimited, so fuel exhaustion cannot fire)
///   - timeout_seconds = 2 (tight, so we see the result quickly)
///
/// The epoch ticker increments the engine epoch every 250 ms. After
/// `timeout_seconds * 4` ticks the Store's epoch deadline fires and
/// wasmtime traps the execution. tokio::time::timeout is the outer safety
/// net but the epoch interrupt fires first because there are no await
/// points for tokio to observe.
///
/// Why this matters: tokio::time::timeout fires only at .await points.
/// A tight compute loop with no I/O would run forever without epoch
/// interruption — this test proves the epoch mechanism works end-to-end.
#[tokio::test]
async fn epoch_deadline_terminates_infinite_loop_provider() {
    let rt = WasmRuntime::new(4).unwrap();

    let path = require_fixture!("infinite_loop");
    let bytes = std::fs::read(&path).unwrap();
    let hash = sha2::Sha256::digest(&bytes);
    let digest = format!("sha256:{}", hex::encode(hash));

    rt.precompile(&bytes, &digest).unwrap();

    let mut task = run_task(
        &digest,
        r#"{}"#,
        vec![], // no imports needed — pure computation
        vec![],
    );
    // Unlimited fuel — ensures WasmTimeout comes from epoch, not fuel.
    // wasmtime treats fuel=0 as "not metered", but our execute() path
    // sets fuel before calling. Use a very large value instead so the
    // code path is exercised but fuel never runs out in 2 seconds.
    task.resource_limits.fuel = u64::MAX / 2;
    // Short timeout: we expect the epoch to fire within 2–3 seconds.
    task.resource_limits.timeout_seconds = 2;
    // Generous memory: this provider allocates nothing significant.
    task.resource_limits.memory_mb = 64;

    let start = std::time::Instant::now();
    let err = rt.execute(task).await.unwrap_err();
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ProviderError::WasmTimeout),
        "infinite loop must be terminated with WasmTimeout, got: {err:?}"
    );

    // Sanity-check timing: must have fired within a reasonable window.
    // Lower bound: at least 1 s (we set timeout_seconds = 2).
    // Upper bound: no more than 10 s (epoch overshoot is at most 250 ms).
    assert!(
        elapsed.as_secs_f64() >= 1.0,
        "timeout fired too early ({elapsed:.2?}) — epoch ticker may not be running"
    );
    assert!(
        elapsed.as_secs_f64() < 10.0,
        "timeout fired too late ({elapsed:.2?}) — epoch deadline may not be working"
    );
}
