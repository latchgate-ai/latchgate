//! WASM provider runtime — wasmtime component model integration.
//!
//! Manages the lifecycle of .wasm provider modules: precompilation,
//! digest verification, caching, and per-call sandboxed execution.
//!
//! # Security properties
//!
//! - Module digest verified at precompile time (SHA-256).
//! - Every execution gets a fresh `Store` + `Instance` (no shared state).
//! - Only manifest-declared imports are linked (capability-based).
//! - Resource limits enforced: fuel (CPU), memory, wall-clock timeout, I/O budget.
//! - Credentials never enter the sandbox; injected at host I/O layer.
//!
//! Pipeline hands a `RunTask` to `execute()`; the WASM sandbox calls
//! back into `HostState` for validated I/O.

pub(crate) mod amqp_pool;
mod host_database;
mod host_fs;
mod host_http;
mod host_log;
mod host_queue;
mod host_smtp;
mod host_storage;
mod runtime;

pub use runtime::{LoadMode, WasmRuntime};

use std::sync::Arc;

use lettre::{AsyncSmtpTransport, Tokio1Executor};
use wasmtime::{StoreLimits, StoreLimitsBuilder};

use crate::host_io::HostState;

// WIT bindings (generated from providers/wit/ at compile time)

// Generate host-side bindings from WIT definitions.
// This produces:
//   - Record types for each WIT record (HttpRequest, HttpResponse, etc.)
//   - Host traits for each import interface (io_http::Host, etc.)
//   - Provider struct for instantiating and calling the execute export
wasmtime::component::bindgen!({
    world: "provider",
    path: "../../providers/wit",
    imports: { default: async },
    exports: { default: async },
});

// WasmHostState — per-execution sandbox state

/// Per-execution state held in the wasmtime `Store`.
///
/// Wraps our `HostState` (sink validation, I/O budget) with wasmtime-
/// required fields (resource limiter, WASI context).
pub(crate) struct WasmHostState {
    /// Host I/O state: sink validation, I/O budget, secret gating.
    pub(crate) host_io: HostState,
    /// External I/O backend connections (database, queue, storage, email).
    pub(crate) resources: HostResources,
    /// wasmtime store limits (memory cap).
    limits: StoreLimits,
    /// WASI context (required for wasm32-wasip2 components).
    wasi_ctx: wasmtime_wasi::WasiCtx,
    /// WASI resource table.
    resource_table: wasmtime::component::ResourceTable,
}

/// Optional host I/O backend connections, grouped to keep
/// `WasmHostState::new` from growing a parameter per backend.
///
/// Every field is `Option` — `None` when the corresponding URL is not
/// configured. All inner types are internally `Arc`-backed; cloning
/// per-execution is O(1).
pub(crate) struct HostResources {
    /// PostgreSQL connection pool.
    pub(crate) db_pool: Option<sqlx::PgPool>,
    /// AMQP connection pool.
    pub(crate) amqp_pool: Option<amqp_pool::Pool>,
    /// Object storage client.
    pub(crate) object_store: Option<Arc<dyn object_store::ObjectStore + Send + Sync>>,
    /// Pre-built SMTP transport.
    pub(crate) smtp_transport: Option<Arc<AsyncSmtpTransport<Tokio1Executor>>>,
    /// Pre-built HTTP client for egress proxy mode.
    ///
    /// Built once at startup via `WasmRuntime::init_http_proxy()` and
    /// shared across all executions. The proxy URL is server-wide config,
    /// so a single client (with its connection pool + TLS session cache)
    /// serves every WASM HTTP call in proxy mode. `reqwest::Client` is
    /// internally `Arc`-backed — clone is O(1).
    ///
    /// `None` when no egress proxy is configured (direct mode uses
    /// per-request clients with DNS pinning instead).
    pub(crate) http_proxy_client: Option<reqwest::Client>,
}

impl HostResources {
    /// All backends absent — used in tests and when no host I/O is configured.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            db_pool: None,
            amqp_pool: None,
            object_store: None,
            smtp_transport: None,
            http_proxy_client: None,
        }
    }
}

impl WasmHostState {
    pub(crate) fn new(host_io: HostState, resources: HostResources, memory_mb: u32) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_mb as usize * 1024 * 1024)
            .instances(1)
            .tables(10)
            .memories(1)
            .build();

        // SECURITY: minimal WASI context — no filesystem, no env, no args.
        // Provider modules run in a stripped-down sandbox.
        let wasi_ctx = wasmtime_wasi::WasiCtxBuilder::new().build();

        Self {
            host_io,
            resources,
            limits,
            wasi_ctx,
            resource_table: wasmtime::component::ResourceTable::new(),
        }
    }
}

// wasmtime-wasi requires WasiView to be implemented.
impl wasmtime_wasi::WasiView for WasmHostState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

// HasData bridges wasmtime's generic linker to our concrete host state.
// Required by `Provider::add_to_linker` to resolve the `D` type parameter.
pub(crate) struct WasmHostAccess;

impl wasmtime::component::HasData for WasmHostAccess {
    type Data<'a> = &'a mut WasmHostState;
}

// wasmtime requires the store data to provide a limiter.
impl wasmtime::ResourceLimiter for WasmHostState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }
}

// Helpers shared across host implementations

/// Strip HTML tags to produce a basic plain-text representation.
///
/// Used to generate the text/plain alternative in multipart/alternative
/// emails. Not a full HTML parser — handles the common case of element
/// tags and collapses runs of whitespace. Good enough for email fallback;
/// not intended for security-sensitive sanitization.
pub(crate) fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                // Block-level tags get a space so words don't merge.
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    // Collapse whitespace runs and trim.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_html_tags_basic() {
        assert_eq!(strip_html_tags("<p>Hello</p>"), "Hello");
    }

    #[test]
    fn strip_html_tags_collapses_whitespace() {
        assert_eq!(
            strip_html_tags("<div>  Hello  </div>  <p>  World  </p>"),
            "Hello World"
        );
    }

    #[test]
    fn strip_html_tags_separates_block_content() {
        // Words from adjacent tags must not merge: "<b>a</b><b>b</b>" => "a b"
        assert_eq!(strip_html_tags("<b>one</b><b>two</b>"), "one two");
    }
}
