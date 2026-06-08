//! Interactive operator terminal for LatchGate.
//!
//! Connects to a running gate and provides a real-time dashboard, approval
//! workflow, and management screens. Requires operator authentication.

mod actions;
mod activity;
mod allowlists;
mod approvals;
mod config;
mod config_logic;
mod dashboard;
mod domains;
mod formatting;
mod input;
mod learned_list;
mod paths;
mod screen;
mod theme;
mod widgets;
pub mod wizard;

mod app;

pub use app::run;

// Diagnostic types — display-oriented results for the config screen

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Ok,
    Skip,
    Warn,
    Error,
}

/// Single diagnostic check result displayed in the config screen.
#[derive(Debug)]
pub struct DiagnosticCheck {
    pub section: String,
    pub name: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
}

/// Result of a webhook test delivery (display-oriented).
#[derive(Debug)]
pub struct WebhookTestResult {
    pub endpoint_name: String,
    pub ok: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

/// Async diagnostic runner injected by the CLI at launch.
///
/// The CLI provides the concrete implementation, keeping the TUI free of
/// direct dependencies on doctor internals.
pub trait DoctorRunner: Send + Sync {
    /// Run all diagnostic checks against the given configuration.
    fn run(
        &self,
        config: latchgate_config::Config,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<DiagnosticCheck>> + Send>>;
}

// Init wizard types — created by the wizard, consumed by CLI init command

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallLocation {
    /// `.latchgate/` under the current directory.
    Project,
    /// `$XDG_CONFIG_HOME/latchgate/` with data in `$XDG_DATA_HOME/latchgate/`.
    User,
}

impl InstallLocation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::User => "user",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityChoice {
    /// `peercred` — UID-based identity.  Recommended for local dev.
    /// The wizard auto-maps the current UID to a development principal.
    Peercred,
    /// No identity provider.  **INSECURE**: the gate cannot distinguish
    /// callers.  Requires `--insecure-identity` at runtime.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningChoice {
    /// Generate persistent Ed25519 keys for receipts and grants.
    /// Recommended — receipts and grants are verifiable across restarts.
    Persistent,
    /// Skip key generation.  **INSECURE**: ephemeral keys only, receipts
    /// unverifiable after restart.  Requires `--insecure-signing` at runtime.
    Ephemeral,
}

/// All decisions resolved before the init command touches the filesystem.
pub struct InitPlan {
    pub preset: latchgate_embed::embedded_presets::Preset,
    pub location: InstallLocation,
    pub identity: IdentityChoice,
    pub signing: SigningChoice,
    pub include_examples: bool,
    pub force: bool,
}

// SetupOps — local file operations injected by the CLI

/// Trait for local configuration operations (TOML editing, keygen, SOPS).
///
/// Write methods return the updated `Config` after persisting the change,
/// so the TUI can refresh its view without re-reading the file.
///
/// The CLI provides the concrete implementation; the TUI never touches
/// local files directly.
pub trait SetupOps: Send + Sync {
    /// Set a TOML config field.
    fn set_config(&self, key: &str, value: &str) -> Result<latchgate_config::Config, String>;

    /// Add a peercred principal mapping.
    fn add_principal(
        &self,
        uid: u32,
        name: &str,
        scopes: &str,
        owner: Option<&str>,
    ) -> Result<latchgate_config::Config, String>;

    /// Remove a peercred principal mapping.
    fn remove_principal(&self, uid: u32) -> Result<latchgate_config::Config, String>;

    /// Add an operator credential (generates API key + DPoP keypair).
    /// Returns `(updated_config, api_key, private_key_path)`.
    fn add_operator(
        &self,
        name: &str,
    ) -> Result<(latchgate_config::Config, String, String), String>;

    /// Remove an operator credential.
    fn remove_operator(&self, name: &str) -> Result<latchgate_config::Config, String>;

    /// Add a webhook endpoint with an auto-generated HMAC secret.
    ///
    /// Returns `(updated_config, generated_secret)`.
    fn add_webhook(
        &self,
        name: &str,
        url: &str,
        events: &str,
        format: &str,
    ) -> Result<(latchgate_config::Config, String), String>;

    /// Remove a webhook endpoint.
    fn remove_webhook(&self, name: &str) -> Result<latchgate_config::Config, String>;

    /// Send a test event to a webhook endpoint and report the result.
    ///
    /// Returns a pinned future because delivery requires async HTTP.
    fn test_webhook(
        &self,
        name: &str,
        config: &latchgate_config::Config,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WebhookTestResult> + Send>>;

    /// Execute an init plan (scaffold project, extract manifests, generate config).
    fn execute_init(&self, plan: &InitPlan) -> Result<latchgate_config::Config, String>;

    /// Initialize SOPS encryption (age keypair + encrypted secrets file).
    fn secrets_init(&self, force: bool) -> Result<latchgate_config::Config, String>;

    /// Set a secret value (encrypt and store).
    fn secrets_set(&self, key: &str, value: &str) -> Result<(), String>;

    /// List secret keys with set/unset status.
    fn secrets_list(&self) -> Result<Vec<SecretEntry>, String>;

    /// Remove a secret from the encrypted store.
    fn secrets_remove(&self, key: &str) -> Result<(), String>;

    // -- Manifest editing (used by Actions screen) ---------------------------

    /// List editable manifests from the configured manifests directory.
    ///
    /// Returns one [`ManifestInfo`] per `.yaml`/`.yml` file that parses
    /// successfully. Files that fail to parse are silently skipped (the
    /// operator can fix them with `latchgate doctor`).
    fn list_manifests(&self) -> Result<Vec<ManifestInfo>, String>;

    /// Read a manifest from disk by action_id.
    ///
    /// Scans the manifests directory for a file whose `action_id` field
    /// matches. Returns the parsed `ActionSpec` or an error if not found
    /// or unparseable.
    fn read_manifest(&self, action_id: &str) -> Result<latchgate_registry::ActionSpec, String>;

    /// Validate and atomically write a manifest to disk.
    ///
    /// If a file for this `action_id` already exists, it is overwritten.
    /// Otherwise a new file `{action_id}.yaml` is created in the
    /// manifests directory.
    ///
    /// The write is atomic (tmp => fsync => rename) and includes a
    /// round-trip validation check. Returns the path of the written file.
    fn write_manifest(
        &self,
        spec: &latchgate_registry::ActionSpec,
    ) -> Result<std::path::PathBuf, String>;

    /// Export a custom preset TOML file.
    ///
    /// Writes a preset file containing the given action IDs, wildcard
    /// grant level, name, and description. The file is written to the
    /// presets directory (or project root if no presets dir exists).
    /// Returns the path of the written file.
    fn export_preset(
        &self,
        name: &str,
        description: &str,
        action_ids: &[String],
        wildcard_grant: &str,
    ) -> Result<std::path::PathBuf, String>;

    /// List all discoverable presets: built-in, user-global, and project-local.
    ///
    /// Presets that fail to parse are silently skipped.
    fn list_presets(&self) -> Vec<PresetListEntry>;

    // -- Diagnostics ----------------------------------------------------------

    /// Check whether `config.manifests_dir` agrees with what resource
    /// discovery resolves from the current working directory.
    ///
    /// Returns `Some(warning)` on mismatch, `None` when consistent or when
    /// discovery is unavailable (e.g. running outside a project tree).
    fn check_manifests_dir_consistency(&self) -> Option<String>;
}

pub struct SecretEntry {
    pub key: String,
    pub is_set: bool,
    /// Actions that declare this secret in their manifest.
    pub required_by: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetSource {
    /// Compiled into the binary from `definitions/presets/`.
    Builtin,
    /// `~/.config/latchgate/presets/` (user-global).
    User,
    /// `.latchgate/presets/` (project-local).
    Project,
}

impl PresetSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Builtin => "built-in",
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

/// A preset discovered by [`SetupOps::list_presets`].
pub struct PresetListEntry {
    pub preset: latchgate_embed::embedded_presets::Preset,
    pub source: PresetSource,
}

// ManifestInfo — summary for the TUI actions list

/// Metadata for a manifest file on disk, used by the TUI actions editor.
///
/// Returned by [`SetupOps::list_manifests`] to populate the editable
/// actions list without loading full `ActionSpec` structs.
pub struct ManifestInfo {
    pub action_id: String,
    pub version: String,
    pub risk_level: String,
    pub provider_module_digest: String,
    pub file_path: std::path::PathBuf,
}

// GateOps — gate lifecycle operations injected by the CLI

/// Boxed future returned by [`GateOps::start`].
pub type StartFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<(latchgate_config::Config, latchgate_client::OperatorAuth), String>,
            > + Send
            + 'a,
    >,
>;

/// Boxed future returned by [`GateOps::reload`].
pub type ReloadFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<ReloadResult, String>> + Send + 'a>>;

pub struct ReloadResult {
    pub actions: usize,
    pub policy_version: String,
}

/// Gate lifecycle controls injected by the CLI.
///
/// When the gate was started via `latchgate up`, the TUI can stop it
/// directly. When the gate is externally managed (`serve`, systemd,
/// Docker Compose, etc.), the TUI shows a flash message instead.
///
/// The CLI provides the concrete implementation; the TUI checks
/// `can_stop()` before offering the Shift+S shortcut.
pub trait GateOps: Send + Sync {
    /// Short label for the title bar: `"up"`, `"serve"`, or `"ext"`.
    fn mode_label(&self) -> &str;

    /// Whether the TUI can stop the gate (true only for `up` sessions).
    fn can_stop(&self) -> bool;

    /// Stop the gate. Tears down Docker containers started by `up`.
    fn stop(&self) -> Result<(), String>;

    /// Whether the TUI can start the gate (true when no session is active).
    fn can_start(&self) -> bool;

    /// Start the gate: launch Docker deps, spawn the gate server, wait for
    /// healthy. Returns the generated config and operator auth on success.
    ///
    /// The caller must restore the terminal before calling this — the
    /// implementation prints Docker startup progress to stdout/stderr.
    fn start(&self) -> StartFuture<'_>;

    /// Whether the gate supports hot-reload (true for `up` sessions where
    /// the gate exposes the admin socket).
    fn can_reload(&self) -> bool;

    /// Hot-reload manifests and policy data without restarting the gate.
    ///
    /// Calls `POST /v1/admin/reload` on the running gate using the
    /// operator auth held by the TUI session.
    fn reload(&self) -> ReloadFuture<'_>;
}
