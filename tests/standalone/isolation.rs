//! WASM provider isolation and host I/O boundary tests.
//!
//! These tests verify sandbox properties that must hold regardless of
//! which provider module is loaded:
//!
//!  - Unknown module digests fail closed (ModuleNotFound, not silent allow).
//!  - Digest mismatch at precompile is rejected before WASM compilation.
//!  - Multiple execute() calls are stateless — no shared mutable state.
//!  - Host I/O rejects undeclared sinks (fail-closed egress).
//!  - Host I/O enforces per-execution call budgets.
//!  - Infrastructure init rejects invalid URLs and double-init.
//!
//! No compiled .wasm modules or external infrastructure required.

use std::collections::HashMap;

use latchgate_providers::WasmRuntime;
use latchgate_providers::{HostState, HostStateConfig};

// ---------------------------------------------------------------------------
// Fail-closed: unknown or invalid modules
// ---------------------------------------------------------------------------

/// Executing a task for a module that was never precompiled returns
/// ModuleNotFound — not a silent allow or a panic.
#[tokio::test]
async fn execute_unknown_digest_fails_closed() {
    let rt = WasmRuntime::new(4).unwrap();
    let task = latchgate_providers::RunTask {
        module_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        args_json: "{}".into(),
        allowed_imports: vec![],
        resource_limits: latchgate_core::ResourceLimits::default(),
        allowed_sinks: vec![],
        approved_secrets: vec![],
        decrypted_secrets: HashMap::new(),
        trace_id: "isolation-test".into(),
        database_config: None,
        egress_proxy_url: None,
        fs_config: None,
    };
    let err = rt.execute(task).await.unwrap_err();
    assert!(
        matches!(
            err,
            latchgate_providers::ProviderError::ModuleNotFound { .. }
        ),
        "unknown digest must return ModuleNotFound, got: {err:?}"
    );
}

/// Digest mismatch is caught before wasmtime compilation — the runtime
/// never attempts to compile bytes whose hash doesn't match the declared
/// digest.
#[tokio::test]
async fn precompile_wrong_digest_is_rejected_before_compile() {
    let rt = WasmRuntime::new(4).unwrap();
    let garbage = b"not a valid wasm module at all";
    let err = rt.precompile(garbage, "sha256:baad").unwrap_err();
    assert!(
        matches!(
            err,
            latchgate_providers::ProviderError::DigestMismatch { .. }
        ),
        "digest mismatch must be caught before WASM compilation: {err:?}"
    );
    assert_eq!(
        rt.cached_module_count(),
        0,
        "nothing must be cached after a rejected precompile"
    );
}

// ---------------------------------------------------------------------------
// Per-call isolation
// ---------------------------------------------------------------------------

/// Multiple execute() calls with the same missing digest each return
/// independent errors. No shared mutable state leaks between calls.
#[tokio::test]
async fn execute_is_stateless_across_calls() {
    let rt = WasmRuntime::new(4).unwrap();

    let task = |trace_id: &str| latchgate_providers::RunTask {
        module_digest: "sha256:cafe".into(),
        args_json: "{}".into(),
        allowed_imports: vec![],
        resource_limits: latchgate_core::ResourceLimits::default(),
        allowed_sinks: vec![],
        approved_secrets: vec![],
        decrypted_secrets: HashMap::new(),
        trace_id: trace_id.into(),
        database_config: None,
        egress_proxy_url: None,
        fs_config: None,
    };

    let e1 = rt.execute(task("call-1")).await.unwrap_err();
    let e2 = rt.execute(task("call-2")).await.unwrap_err();

    assert!(matches!(
        e1,
        latchgate_providers::ProviderError::ModuleNotFound { .. }
    ));
    assert!(matches!(
        e2,
        latchgate_providers::ProviderError::ModuleNotFound { .. }
    ));
}

// ---------------------------------------------------------------------------
// Host I/O boundary: sink validation and budgets
// ---------------------------------------------------------------------------

/// Host I/O rejects requests to sinks not in the action's allowed list.
/// This is the core egress enforcement — a provider cannot exfiltrate
/// data to an arbitrary endpoint.
#[test]
fn host_io_rejects_undeclared_sinks() {
    let state = HostState::new(HostStateConfig {
        allowed_sinks: vec!["api.allowed.com".into()],
        approved_secrets: vec![],
        decrypted_secrets: HashMap::new(),
        trace_id: "test".into(),
        max_io_calls: 10,
        max_host_response_bytes: 10 * 1024 * 1024,
        allowed_imports: vec!["latchgate:io/http".into()],
        database_config: None,
        egress_proxy_url: None,
        fs_config: None,
        max_log_calls: None,
        max_log_message_bytes: None,
    });

    assert!(
        state
            .validate_sink("https://api.allowed.com/endpoint")
            .is_ok(),
        "declared sink must be accepted"
    );
    assert!(
        state.validate_sink("https://evil.com/steal").is_err(),
        "undeclared sink must be rejected"
    );
    assert!(
        state.validate_sink("https://internal.corp/admin").is_err(),
        "undeclared internal sink must be rejected"
    );
}

/// I/O call budget prevents a provider from making unlimited outbound
/// requests. After the budget is exhausted, every subsequent call fails.
#[test]
fn host_io_enforces_call_budget() {
    let state = HostState::new(HostStateConfig {
        allowed_sinks: vec!["api.example.com".into()],
        approved_secrets: vec![],
        decrypted_secrets: HashMap::new(),
        trace_id: "test".into(),
        max_io_calls: 2,
        max_host_response_bytes: 10 * 1024 * 1024,
        allowed_imports: vec!["latchgate:io/http".into()],
        database_config: None,
        egress_proxy_url: None,
        fs_config: None,
        max_log_calls: None,
        max_log_message_bytes: None,
    });

    assert!(state.consume_io_call().is_ok(), "call 1 within budget");
    assert!(state.consume_io_call().is_ok(), "call 2 within budget");
    assert!(
        state.consume_io_call().is_err(),
        "call 3 must fail — budget exhausted"
    );
    assert_eq!(state.io_calls_count(), 2);
}

// ---------------------------------------------------------------------------
// Infrastructure init: fail-fast, no silent fallback
// ---------------------------------------------------------------------------

/// init_storage() with a completely invalid URL must fail, not panic or
/// silently succeed with a broken client.
#[tokio::test]
async fn init_storage_rejects_invalid_url() {
    let rt = WasmRuntime::new(4).unwrap();
    assert!(
        rt.init_storage("not-a-url-at-all").is_err(),
        "init_storage must reject invalid URL"
    );
}

/// init_smtp() with a syntactically invalid URL must fail.
#[tokio::test]
async fn init_smtp_rejects_invalid_url() {
    let rt = WasmRuntime::new(4).unwrap();
    assert!(
        rt.init_smtp(":::invalid:::").is_err(),
        "init_smtp must reject invalid URL"
    );
}

/// init_smtp() with a URL missing a host component must fail.
#[tokio::test]
async fn init_smtp_rejects_url_without_host() {
    let rt = WasmRuntime::new(4).unwrap();
    assert!(
        rt.init_smtp("smtp:///no-host").is_err(),
        "init_smtp must reject URL without host"
    );
}

/// Double-init must be rejected — silently overwriting a live client
/// would be a state corruption bug.
#[tokio::test]
async fn init_storage_double_call_is_rejected() {
    let rt = WasmRuntime::new(4).unwrap();
    let _ = rt.init_storage("file:///tmp/latchgate-test-store");
    assert!(
        rt.init_storage("file:///tmp/other").is_err(),
        "second init_storage call must be rejected (already initialised)"
    );
}

#[tokio::test]
async fn init_smtp_double_call_is_rejected() {
    let rt = WasmRuntime::new(4).unwrap();
    let _ = rt.init_smtp("smtp://user:pass@localhost:587");
    assert!(
        rt.init_smtp("smtp://user:pass@other-host:587").is_err(),
        "second init_smtp call must be rejected (already initialised)"
    );
}
