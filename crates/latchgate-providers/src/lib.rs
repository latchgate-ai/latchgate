//! Action execution providers for LatchGate.
//!
//! The kernel dispatches to [`WasmRuntime`] which loads and executes .wasm
//! provider modules in sandboxed instances with host-mediated I/O.

pub(crate) mod backends;
pub(crate) mod database;
#[allow(unsafe_code)]
pub(crate) mod fs_io;
pub(crate) mod host_io;
mod policy_context;
pub mod secrets;
pub(crate) mod task;
pub(crate) mod wasm;

// ── Re-exports: only the types downstream crates actually consume ───────────

pub use backends::init_backends;
pub use database::{
    classify_sql, count_sql_params, extract_tables, DatabaseConfig, DatabaseMode, OperationClass,
};
pub use fs_io::{open_root_fd, FsHostConfig};
pub use host_io::{HostState, HostStateConfig};
pub use policy_context::build_policy_context;
pub use secrets::{SecretsError, SecretsManager};
pub use task::{RunOutput, RunTask};
pub use wasm::{LoadMode, WasmRuntime};

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("WASM module not found: {digest}")]
    ModuleNotFound { digest: String },

    #[error("WASM module digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("WASM fuel exhausted")]
    FuelExhausted,

    #[error("WASM memory limit exceeded")]
    MemoryLimitExceeded,

    #[error("WASM execution timed out")]
    WasmTimeout,

    #[error("I/O budget exceeded (max_io_calls)")]
    IoBudgetExceeded,

    #[error("WASM import not declared in manifest: {import}")]
    ImportNotDeclared { import: String },

    #[error("WASM execution failed: {reason}")]
    ExecutionFailed { reason: String },

    #[error("path traversal rejected: {path} escapes {root}")]
    PathTraversal { path: String, root: String },
}
