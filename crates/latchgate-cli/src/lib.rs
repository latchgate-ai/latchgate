//! LatchGate CLI — `latchgate` binary.

pub mod client;
pub mod cmd;
pub mod config;
pub mod output;

// Re-export compile-time embedded assets from the shared crate.
// Internal CLI modules reference these as `crate::embedded_manifests` etc.
pub use latchgate_embed::embedded_manifests;
pub use latchgate_embed::embedded_policies;
pub use latchgate_embed::embedded_presets;
pub use latchgate_embed::embedded_providers;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub use client::OperatorAuth;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum AuditOutputFormat {
    Table,
    Json,
    Jsonl,
    Csv,
}

/// Version string for branded headers (e.g. `v0.1.0 (a1b2c3d4 2025-06-01)`).
pub const VERSION: &str = concat!(
    "v",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("GIT_SHA"),
    " ",
    env!("BUILD_DATE"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "latchgate",
    about = "LatchGate — execution security kernel for AI agents",
    long_about = None,
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (", env!("GIT_SHA"), " ", env!("BUILD_DATE"), ")"
    ),
    propagate_version = true,
    disable_help_subcommand = true,
    help_template = "{before-help}{usage-heading} {usage}\n\n{all-args}{after-help}",
)]
pub struct Cli {
    /// Path to the configuration file.
    ///
    /// Discovery order: `--config` / `$LATCHGATE_CONFIG` => `.latchgate/latchgate.toml`
    /// => `$XDG_CONFIG_HOME/latchgate/latchgate.toml` => built-in defaults.
    #[arg(long, env = "LATCHGATE_CONFIG", global = true, value_name = "PATH")]
    pub config: Option<String>,

    /// Emit structured JSON instead of human-readable output.
    ///
    /// Useful for scripting, CI pipelines, and monitoring. Exit codes are
    /// unchanged: 0 = success / gate healthy, non-zero = error / degraded.
    #[arg(long, global = true)]
    pub json: bool,

    /// Operator API key for authenticated commands (approvals, revoke, audit).
    ///
    /// Required for commands that mutate approval state or access operator
    /// endpoints. Corresponds to a named key in `[operator_credentials]` or
    /// the `api_key` from `[operator_credentials]` in latchgate.toml.
    #[arg(
        long,
        env = "LATCHGATE_OPERATOR_KEY",
        global = true,
        value_name = "KEY",
        hide_env_values = true
    )]
    pub operator_key: Option<String>,

    /// Path to the operator's DPoP private key (PEM-encoded P-256 / ES256).
    ///
    /// When provided, the CLI uses DPoP proof-of-possession for operator
    /// authentication: `Authorization: DPoP <token>` + `DPoP: <proof>`.
    /// Required in production (dev_mode=false) where all operator credentials
    /// have `dpop_jkt` configured.
    ///
    #[arg(
        long,
        env = "LATCHGATE_OPERATOR_PRIVATE_KEY",
        global = true,
        value_name = "PATH",
        hide_env_values = true
    )]
    pub operator_private_key: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

// Re-export subcommand enums from their owning modules so `latchgate-bin`
// (and any future consumer) can reference them as `latchgate_cli::XCommand`.
pub use cmd::approvals::ApprovalsCommand;
pub use cmd::domains::DomainsCommand;
pub use cmd::operator::OperatorCommand;
pub use cmd::policy::PolicyCommand;
pub use cmd::secrets::SecretsCommand;
pub use config::ConfigCommand;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start LatchGate.
    ///
    /// Default: embedded mode — SQLite state, embedded regorus policy engine,
    /// in-memory replay cache. Zero external dependencies.
    ///
    /// With `--infra`: managed Docker mode — Redis + OPA + Squid + Prometheus
    /// in containers. Full defense-in-depth egress proxy.
    ///
    Up {
        /// Remove `.latchgate/` and re-run the setup wizard before starting.
        #[arg(long)]
        reset: bool,

        /// Start Redis + OPA + Squid + Prometheus in Docker containers.
        ///
        /// Provides HA replay protection (Redis), external policy evaluation
        /// (OPA), defense-in-depth egress proxy (Squid), and metrics
        /// collection (Prometheus). Requires Docker.
        #[arg(long)]
        infra: bool,

        /// Use an external Redis instance for state (replay cache, budgets,
        /// approvals). Enables HA replay protection without full `--infra`.
        #[arg(long, value_name = "URL", conflicts_with = "infra")]
        with_redis: Option<String>,

        /// Use an external OPA instance for policy evaluation instead of the
        /// embedded regorus engine.
        #[arg(long, value_name = "URL", conflicts_with = "infra")]
        with_opa: Option<String>,

        /// Disable caller identity validation (allow provider = none).
        ///
        /// INSECURE: without identity, the gate cannot distinguish callers.
        /// Use only for local development with no network exposure.
        #[arg(long)]
        insecure_identity: bool,

        /// Disable persistent signing key validation (ephemeral keys only).
        ///
        /// INSECURE: receipts and grants are unverifiable after restart.
        #[arg(long)]
        insecure_signing: bool,

        /// Allow response_schema_enforcement = warn (non-strict schemas).
        ///
        /// Weakens the Typed I/O guarantee: responses that violate their
        /// declared schema are logged but still returned to the caller.
        #[arg(long)]
        schema_warn: bool,

        /// Expose HTTP listeners on the given address (e.g. 127.0.0.1:3000).
        ///
        /// INSECURE: adds an HTTP transport alongside UDS. Must never be
        /// reachable from an untrusted network.
        #[arg(long, value_name = "ADDR")]
        expose_http: Option<std::net::SocketAddr>,

        /// Disable operator DPoP proof-of-possession validation.
        #[arg(long, hide = true)]
        insecure_operator_auth: bool,

        /// Allow file:// storage backend.
        #[arg(long, hide = true)]
        insecure_storage: bool,

        /// Allow async webhook delivery mode.
        #[arg(long, hide = true)]
        insecure_webhooks: bool,

        /// Skip egress proxy coverage validation.
        #[arg(long, hide = true)]
        insecure_egress: bool,

        /// Skip wildcard ACL risk validation.
        #[arg(long, hide = true)]
        insecure_acl: bool,
    },

    /// Stop Docker containers started by `latchgate up --infra`.
    ///
    /// For cleanup when `up --infra` was interrupted without graceful
    /// shutdown (kill -9, terminal closed). Normally Ctrl+C in `up`
    /// handles teardown automatically.
    Down {
        /// Also delete the data directory (audit.db, receipts, cache).
        ///
        /// Destructive — the audit trail cannot be recovered. Prompts for
        /// interactive confirmation unless `--yes` is given.
        #[arg(long)]
        prune: bool,

        /// Skip the confirmation prompt for `--prune`.
        #[arg(long, short)]
        yes: bool,
    },

    /// Start the gate server from a config file.
    ///
    /// Loads config, initialises all subsystems, and binds listeners.
    /// Security posture is read from the config file's `[posture]` section.
    /// For managed setups use `latchgate up`; this command is for custom
    /// deployments and platform provisioners.
    Serve,

    /// Launch an agent inside a Linux namespace sandbox.
    ///
    /// The agent runs in isolated user/network/mount/PID/UTS/IPC/cgroup
    /// namespaces with only two paths to the outside world: the gate UDS
    /// (for protected actions) and an HTTPS proxy (for LLM API traffic to
    /// allowed hosts).
    ///
    /// Everything else — host filesystem, network, credentials, other
    /// processes — is absent from the namespace.
    ///
    /// Requires Linux ≥ 5.8 with unprivileged user namespaces.
    ///
    /// # Examples
    ///
    /// ```text
    /// latchgate sandbox -- claude-code
    /// latchgate sandbox --workspace ./my-project -- claude-code
    /// latchgate sandbox --allow-host api.deepseek.com -- my-agent
    /// ```
    Sandbox {
        /// Host directory mounted as /workspace (read-write) inside the sandbox.
        ///
        /// Default: current working directory.
        #[arg(long, value_name = "PATH")]
        workspace: Option<std::path::PathBuf>,

        /// Use a built-in agent profile (claude-code, codex, cursor).
        ///
        /// A profile provides pre-configured allow_hosts and pass_env for the
        /// named agent. CLI flags merge additively on top of the profile.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,

        /// Add a hostname to the proxy allowlist (repeatable).
        ///
        /// The agent can only reach these hosts via HTTPS (port 443).
        /// Additive with hosts from config file.
        #[arg(long = "allow-host", value_name = "HOST")]
        allow_hosts: Vec<String>,

        /// Additional read-only bind mount from host (repeatable).
        #[arg(long = "ro-mount", value_name = "PATH")]
        ro_mounts: Vec<std::path::PathBuf>,

        /// Pass an environment variable into the sandbox (repeatable).
        ///
        /// Only explicitly listed variables are passed. No blanket inheritance.
        #[arg(long = "pass-env", value_name = "VAR")]
        pass_env: Vec<String>,

        /// Path to the LatchGate gate UDS.
        #[arg(long, value_name = "PATH")]
        gate_socket: Option<std::path::PathBuf>,

        /// Load sandbox config from a standalone TOML file.
        ///
        /// Overrides `[sandbox.agent]` from latchgate.toml. CLI flags
        /// still take precedence over this file.
        #[arg(long = "sandbox-config", value_name = "PATH")]
        sandbox_config: Option<std::path::PathBuf>,

        /// Command and arguments to run inside the sandbox.
        ///
        /// Everything after `--` is the agent command line. Optional when
        /// `--profile` is given: the profile's agent binary is the default.
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Internal: sandbox-init shim executed by bubblewrap inside the sandbox.
    ///
    /// Reads a sealed memfd config, applies rlimits + Landlock + seccomp,
    /// then execs the agent command. Not intended for direct user invocation.
    #[command(hide = true)]
    SandboxInit {
        /// File descriptor number of the sealed memfd containing the shim config.
        #[arg(long = "config-fd", value_name = "FD")]
        config_fd: i32,
    },

    /// Run pre-flight checks before starting the gate.
    ///
    /// Verifies config, Redis, OPA, provider modules, manifests, secrets,
    /// and host WASM capabilities. Exits 0 if all required checks pass,
    /// non-zero if any ERROR-level check fails.
    Doctor,

    /// Show whether the gate is running and what it is serving.
    ///
    /// Connects to the gate via the configured UDS socket (or HTTP in dev
    /// mode) and prints its health status and the list of registered actions.
    Status,

    /// Launch the interactive operator terminal.
    ///
    /// Connects to a running gate and provides a real-time dashboard,
    /// approval workflow, and management screens. Requires operator
    /// authentication.
    ///
    /// Not compatible with `--json`.
    Tui,

    /// Manage configuration — set values, validate.
    ///
    /// `config set KEY VALUE` edits latchgate.toml in place, preserving
    /// comments and formatting. Type is inferred from the existing field;
    /// new fields default to string. The modified config is validated
    /// before writing — invalid values never reach disk.
    ///
    /// `config validate` runs all production security checks and reports
    /// pass/fail per check.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Manage OPA policy ACLs — grant and revoke actions per principal.
    ///
    /// Operates on `policies/data.json` without manual JSON editing.
    /// Action IDs are validated against manifests. `allowed_sinks` are
    /// auto-derived from `declared_side_effects` — never set manually.
    ///
    /// Does not require the gate to be running — reads and writes local files.
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Manage SOPS-encrypted secrets — init, set, get, list, remove.
    ///
    /// Wraps `age-keygen` and `sops` so the operator never leaves the CLI.
    /// All decrypted material is held in temporary files with 0600 permissions
    /// and never emitted to logs.
    #[command(subcommand)]
    Secrets(SecretsCommand),

    /// Scaffold a working LatchGate project in the current directory.
    ///
    /// Without `--preset`, launches the interactive TUI in setup mode:
    /// preset selection, init execution, principal/operator configuration,
    /// and gate lifecycle — all from one screen.
    ///
    /// With `--preset`, runs non-interactively (CI/Docker pipelines).
    ///
    #[command(hide = true)]
    Init {
        /// Preset name or path to a custom preset TOML file.
        ///
        /// Built-in presets: `quickstart`, `agent`, `coding`,
        /// `read-only`, `ops`, `devops`, `data`, `team`, `lockdown`,
        /// `blank`, `permissive`.
        ///
        /// When omitted, launches the interactive TUI in setup mode.
        #[arg(long)]
        preset: Option<String>,

        /// Install location: `project` (.latchgate/) or `user` (~/.config/latchgate/).
        ///
        /// Project-local isolates state per directory. User-global shares one
        /// config across the machine. Default: project.
        #[arg(long, value_parser = ["project", "user"])]
        location: Option<String>,

        /// List available presets with descriptions.
        #[arg(long)]
        list_presets: bool,

        /// Dump a built-in preset as TOML for customization.
        #[arg(long, value_name = "NAME")]
        export_preset: Option<String>,

        /// Also extract example manifests (with httpbin.org domains) into
        /// a `_examples/` subdirectory alongside production manifests.
        #[arg(long)]
        include_examples: bool,

        /// Overwrite `latchgate.toml` if it already exists.
        #[arg(long)]
        force: bool,

        /// Configure for local development (peercred identity with current
        /// UID). Allows `latchgate up` without the unsafe-dev escape hatch.
        ///
        /// NOT FOR PRODUCTION — accepts any local process as a valid caller.
        #[arg(long)]
        dev: bool,
    },

    /// List registered actions.
    ///
    ///
    /// Queries the running gate for the current action registry. Use
    /// `--action` to show full manifest details for one action.
    Actions {
        /// Show full manifest details for a specific action.
        #[arg(value_name = "ACTION_ID")]
        action: Option<String>,
    },

    /// Query the audit trail.
    ///
    /// Returns the most recent audit events from the ledger, with optional
    /// filters. The ledger records every allow, deny, and error decision.
    ///
    /// Requires operator authentication.
    Audit {
        #[arg(long, value_enum)]
        format: Option<AuditOutputFormat>,

        /// Maximum number of events to return.
        #[arg(long, short, default_value = "20", value_name = "N")]
        limit: usize,

        /// Filter by action ID.
        #[arg(long, value_name = "ACTION_ID")]
        action: Option<String>,

        /// Filter by principal (agent identifier).
        #[arg(long, value_name = "PRINCIPAL")]
        principal: Option<String>,

        /// Filter by decision (allow, deny, error, pending_approval).
        #[arg(long, value_name = "DECISION")]
        decision: Option<String>,

        /// Return events after this timestamp (ISO 8601, e.g. 2025-01-01T00:00:00Z).
        #[arg(long, value_name = "TIMESTAMP")]
        after: Option<String>,

        /// Return events before this timestamp (ISO 8601).
        #[arg(long, value_name = "TIMESTAMP")]
        before: Option<String>,

        /// Filter by trace ID (exact match).
        #[arg(long, value_name = "TRACE_ID")]
        trace_id: Option<String>,

        /// Filter by session ID (exact match).
        #[arg(long, value_name = "SESSION_ID")]
        session_id: Option<String>,

        /// Filter by event type (e.g. action_call, lease_issued, admin_revoke_all).
        #[arg(long, value_name = "EVENT_TYPE")]
        event_type: Option<String>,
    },

    /// Verify the integrity of the ledger's tamper-evident hash-chain.
    ///
    /// Walks every event in insertion order and checks that each prev_hash
    /// matches the SHA-256 of the preceding event's JSON. Exits 0 if intact,
    /// 2 if broken.
    ///
    /// Requires operator authentication.
    Verify,

    /// Advance the revocation epoch — immediately invalidates all outstanding grants.
    ///
    /// This is the emergency kill-switch. Use it if credentials may be
    /// compromised or an agent is behaving unexpectedly. All in-flight
    /// ExecutionGrants issued before this call will be rejected on the next
    /// enforcement check. New grants carry the new epoch and remain valid.
    ///
    /// Prompts for confirmation unless --yes is given.
    /// Requires --operator-key or LATCHGATE_OPERATOR_KEY.
    Revoke {
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },

    /// Manage pending approvals — list, review, approve, or deny.
    ///
    /// The reference operator interface for human-in-the-loop approval.
    /// All commands require --operator-key or LATCHGATE_OPERATOR_KEY.
    #[command(subcommand)]
    Approvals(ApprovalsCommand),

    /// Operator key management.
    ///
    /// Generate DPoP keypairs for operator authentication.
    #[command(subcommand)]
    Operator(OperatorCommand),

    /// Manage learned egress domains — list, add, remove.
    ///
    /// Learned domains augment the static manifest allowlist. When an operator
    /// approves a new domain, it can be remembered so future requests to that
    /// domain auto-allow without re-approval. Reads/writes the SQLite ledger
    /// directly — does not require the gate to be running.
    #[command(subcommand)]
    Domains(DomainsCommand),

    /// Generate shell completion scripts.
    ///
    /// Outputs a completion script for the specified shell to stdout.
    /// Redirect to the appropriate completions directory for your shell.
    ///
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}
