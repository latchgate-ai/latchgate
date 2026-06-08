//! `latchgate up` — one-command gate bootstrap.
//!
//! Default (no flags): embedded mode — SQLite state, in-process regorus
//! policy engine, in-memory bounded replay cache. Zero external dependencies.
//!
//! `--infra`: managed Docker mode — Redis + OPA + Squid + Prometheus in
//! containers. Full defense-in-depth egress proxy. Requires Docker.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command as ShellCommand;
use std::time::Duration;

use latchgate_config::Config;

use crate::output::Printer;

use super::init::execute::execute_plan;

const PROJECT_NAME: &str = "latchgate";

const STATE_DIR_NAME: &str = "latchgate-up";

pub(crate) const COMPOSE_FILENAME: &str = "docker-compose.yml";

pub(crate) const CONFIG_FILENAME: &str = "latchgate-up.toml";

const PROMETHEUS_CONFIG_FILENAME: &str = "prometheus.yml";

const SQUID_CONFIG_FILENAME: &str = "squid.conf";

const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

const HEALTH_INTERVAL: Duration = Duration::from_secs(2);

/// Infrastructure mode selected by CLI flags.
#[derive(Debug, Clone)]
pub enum InfraMode {
    /// Embedded: SQLite + regorus + in-memory replay. Zero external deps.
    Embedded,
    /// Docker: Redis + OPA + Squid + Prometheus in managed containers.
    Docker,
    /// Selective external backends without the full Docker stack.
    Selective {
        redis_url: Option<String>,
        opa_url: Option<String>,
    },
}

/// Orchestrate startup and build a [`Config`].
///
/// Dispatches to the embedded or Docker path based on `mode`.
/// The caller passes the returned Config to `server::serve()`.
///
/// When `pinned` is `Some`, resource discovery is skipped and the provided
/// paths are used directly.  This is the restart path: the TUI reads paths
/// from the previous config so the gate reloads from the same directories
/// the Actions editor wrote to.
pub async fn run(
    pr: &Printer,
    reset: bool,
    mode: &InfraMode,
    posture: &latchgate_config::SecurityPosture,
    expose_http: Option<std::net::SocketAddr>,
    pinned: Option<&PinnedPaths>,
) -> Result<Config, String> {
    pr.blank();
    pr.info(&format!("LatchGate {}", crate::VERSION));
    pr.blank();

    match mode {
        InfraMode::Docker => run_docker(pr, reset, posture, expose_http).await,
        InfraMode::Embedded => {
            run_embedded(pr, reset, posture, expose_http, None, None, pinned).await
        }
        InfraMode::Selective { redis_url, opa_url } => {
            run_embedded(
                pr,
                reset,
                posture,
                expose_http,
                redis_url.as_deref(),
                opa_url.as_deref(),
                pinned,
            )
            .await
        }
    }
}

/// Start in embedded mode: SQLite state, in-process policy, no containers.
///
/// Optionally accepts external Redis and/or OPA URLs for the selective
/// (`--with-redis` / `--with-opa`) mode.
async fn run_embedded(
    pr: &Printer,
    reset: bool,
    posture: &latchgate_config::SecurityPosture,
    expose_http: Option<std::net::SocketAddr>,
    redis_url: Option<&str>,
    opa_url: Option<&str>,
    pinned: Option<&PinnedPaths>,
) -> Result<Config, String> {
    pr.step(1, 3, "Discovering resources...");
    let resources = if let Some(p) = pinned {
        // Restart path: use the exact directories the previous session used.
        // policies_dir is not needed in embedded mode (regorus is compiled in),
        // so derive a placeholder from the manifests parent.
        let policies_dir = PathBuf::from(&p.manifests_dir)
            .parent()
            .map(|d| d.join("policies"))
            .unwrap_or_default();
        Resources {
            manifests_dir: p.manifests_dir.clone(),
            providers_dir: p.providers_dir.clone(),
            policies_dir,
        }
    } else {
        discover_resources(pr, reset)
            .map_err(|_| "resource discovery failed — run `latchgate init` first")?
    };

    pr.step(2, 3, "Preparing state...");
    let state =
        prepare_state_dir(pr).map_err(|_| "failed to prepare state directory".to_string())?;
    let data = prepare_data_dir(pr).map_err(|_| "failed to prepare data directory".to_string())?;

    pr.step(3, 3, "Generating config...");
    let mut config = generate_embedded_config(
        &UpDirs {
            state: &state,
            data: &data,
        },
        &resources,
        expose_http,
        posture,
        redis_url,
        opa_url,
        pr,
    )
    .map_err(|_| "config generation failed".to_string())?;

    config.posture = posture.clone();

    print_posture_banner(pr, &config);

    // Preflight checks.
    pr.blank();
    pr.info("Running pre-flight checks...");
    let errors = crate::cmd::doctor::run_preflight(&config).await;
    if !errors.is_empty() {
        pr.blank();
        for err in &errors {
            pr.error(&format!("{}: {}", err.name, err.message));
        }
        pr.blank();
        pr.hint("Run `latchgate doctor` for full diagnostics.");
        pr.blank();

        let mut msg = String::from("pre-flight checks failed:");
        for err in &errors {
            msg.push_str(&format!("\n  {}: {}", err.name, err.message));
        }
        return Err(msg);
    }
    pr.success("Pre-flight passed");

    Ok(config)
}

/// Start with managed Docker dependencies (Redis + OPA + Squid + Prometheus).
///
async fn run_docker(
    pr: &Printer,
    reset: bool,
    posture: &latchgate_config::SecurityPosture,
    expose_http: Option<std::net::SocketAddr>,
) -> Result<Config, String> {
    pr.step(1, 5, "Checking Docker...");
    let docker_version =
        check_docker(pr).map_err(|_| "Docker check failed — is Docker installed and running?")?;
    pr.success(&format!("Docker detected ({docker_version})"));

    pr.step(2, 5, "Discovering resources...");
    let resources = discover_resources(pr, reset)
        .map_err(|_| "resource discovery failed — run `latchgate init` first")?;

    pr.step(3, 5, "Preparing dev stack...");
    let state =
        prepare_state_dir(pr).map_err(|_| "failed to prepare state directory".to_string())?;
    let data = prepare_data_dir(pr).map_err(|_| "failed to prepare data directory".to_string())?;
    write_prometheus_config(&state, pr)
        .map_err(|_| "failed to write Prometheus config".to_string())?;
    write_squid_config(&state, &resources.manifests_dir, pr)
        .map_err(|_| "failed to write Squid config".to_string())?;
    write_compose_file(&state, &resources.policies_dir, pr)
        .map_err(|_| "failed to write Docker Compose file".to_string())?;

    pr.step(4, 5, "Starting containers...");
    compose_up(&state, pr).map_err(|_| "Docker Compose up failed — check Docker logs")?;

    pr.step(5, 5, "Waiting for health checks...");
    wait_for_redis(pr)
        .await
        .map_err(|_| "Redis health check timed out")?;
    wait_for_opa(pr)
        .await
        .map_err(|_| "OPA health check timed out")?;
    wait_for_squid(pr)
        .await
        .map_err(|_| "Squid proxy health check timed out")?;
    wait_for_prometheus(pr)
        .await
        .map_err(|_| "Prometheus health check timed out")?;

    let mut config = generate_config(
        &UpDirs {
            state: &state,
            data: &data,
        },
        &resources,
        expose_http,
        posture,
        pr,
    )
    .map_err(|_| "config generation failed".to_string())?;

    // Set the security posture from explicit CLI flags.  No blanket bypass —
    // only the protections the operator explicitly relaxed are skipped.
    config.posture = posture.clone();

    // ── Posture banner ───────────────────────────────────────────────
    print_posture_banner(pr, &config);

    // Preflight: verify startup-critical subsystems before handing off to serve.
    pr.blank();
    pr.info("Running pre-flight checks...");
    let errors = crate::cmd::doctor::run_preflight(&config).await;
    if !errors.is_empty() {
        pr.blank();
        for err in &errors {
            pr.error(&format!("{}: {}", err.name, err.message));
        }
        pr.blank();
        pr.hint("Run `latchgate doctor` for full diagnostics.");
        pr.blank();

        let mut msg = String::from("pre-flight checks failed:");
        for err in &errors {
            msg.push_str(&format!("\n  {}: {}", err.name, err.message));
        }
        return Err(msg);
    }
    pr.success("Pre-flight passed");

    Ok(config)
}

/// Print the security posture banner.
///
/// Every `latchgate up` invocation displays this table so the operator
/// always knows exactly which protections are active and which are relaxed.
fn print_posture_banner(pr: &Printer, config: &latchgate_config::Config) {
    pr.blank();
    let any_relaxed = config.posture.any_relaxed();
    if any_relaxed {
        pr.warn("⚠  Security posture: DEVELOPMENT — NOT SECURE — DO NOT EXPOSE");
    } else {
        pr.success("Security posture: PRODUCTION ✓");
    }

    for d in config.posture_details() {
        if d.enforced {
            pr.success(&format!("    {:<12}{:<32}✓", d.name, d.status));
        } else {
            pr.warn(&format!("    {:<12}{:<32}⚠  {}", d.name, d.status, d.flag));
        }
    }

    if any_relaxed {
        pr.blank();
        pr.warn(
            "These relaxations disable production protections. This \
             configuration is for local development only.",
        );
    }

    // Surface the gate log path so users can find it.
    let log_path = state_dir().join("logs").join("gate.log");
    pr.info(&format!("Gate log: {}", log_path.display()));

    pr.blank();
}

/// Tear down Docker containers started by [`run`] in `--infra` mode.
///
/// Called after `serve()` returns (signal received) or by `latchgate down`.
/// Idempotent — safe to call even if no session is active or if embedded
/// mode was used (no compose file → no-op).
pub fn cleanup(pr: &Printer) {
    let state = state_dir();
    let compose_file = state.join(COMPOSE_FILENAME);

    if !compose_file.exists() {
        return;
    }

    pr.blank();
    pr.hint("Stopping Redis + OPA + Squid + Prometheus...");

    let compose_path = compose_file.to_string_lossy();
    let result = ShellCommand::new("docker")
        .args([
            "compose",
            "-p",
            PROJECT_NAME,
            "-f",
            &compose_path,
            "down",
            "-v",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) if status.success() => {
            let _ = std::fs::remove_dir_all(&state);
            pr.success("Cleaned up.");
        }
        Ok(status) => {
            pr.warn(&format!(
                "docker compose down exited with code {}. Run manually:",
                status.code().unwrap_or(-1),
            ));
            pr.hint_cmd(&format!(
                "docker compose -p {PROJECT_NAME} -f {compose_path} down -v"
            ));
        }
        Err(e) => {
            pr.warn(&format!("failed to run docker compose down: {e}"));
        }
    }
}

/// Return the deterministic state directory used by `up` and `down`.
///
/// Resolves via [`latchgate_core::paths::resolve_runtime_dir`] to avoid
/// world-writable `/tmp`. On Linux with systemd this lands under
/// `$XDG_RUNTIME_DIR/latchgate/up/` (mode 0700, owned by the user).
/// Falls back to `/tmp/latchgate-<uid>/up/` on macOS or when XDG is unset.
pub fn state_dir() -> PathBuf {
    latchgate_core::paths::resolve_runtime_dir()
        .unwrap_or_else(|_| std::env::temp_dir().join("latchgate"))
        .join(STATE_DIR_NAME)
}

/// Config file path for the active `up` session, if one exists.
///
/// Returns `Some(path)` when a previous `latchgate up` wrote its ephemeral
/// config to the runtime state directory. The caller can load this with
/// `Config::from_file` and use the corresponding `operator.pem` in the
/// same directory for authentication.
pub fn active_session_config() -> Option<PathBuf> {
    let path = state_dir().join(CONFIG_FILENAME);
    path.exists().then_some(path)
}

/// Operator PEM path for the active `up` session, if one exists.
pub fn active_session_pem() -> Option<PathBuf> {
    let path = state_dir().join("operator.pem");
    path.exists().then_some(path)
}

/// Check whether a LatchGate project exists in the current directory.
///
/// Returns `true` if `.latchgate/latchgate.toml` exists — the single
/// source of truth for project setup. Does not check repo-root or
/// binary-relative layouts; those are resource paths, not project state.
pub fn has_project() -> bool {
    std::env::current_dir()
        .map(|cwd| cwd.join(".latchgate/latchgate.toml").is_file())
        .unwrap_or(false)
}

/// Filesystem paths to LatchGate resources required by the gate.
pub(crate) struct Resources {
    pub(crate) policies_dir: PathBuf,
    pub(crate) manifests_dir: PathBuf,
    pub(crate) providers_dir: PathBuf,
}

/// Pinned resource paths for restart — bypasses discovery.
///
/// When the TUI restarts the gate, it passes the resource paths from the
/// previous config so discovery cannot silently resolve to a different
/// directory tree.  This prevents the "new action vanishes" bug where
/// the Actions editor writes to `config.manifests_dir` but a restart
/// re-discovers from `definitions/manifests`.
pub struct PinnedPaths {
    pub manifests_dir: PathBuf,
    pub providers_dir: PathBuf,
}

/// Verify Docker and the Compose plugin are available. Returns the version string.
fn check_docker(pr: &Printer) -> Result<String, i32> {
    // Docker daemon reachable?
    let daemon = ShellCommand::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match daemon {
        Ok(s) if s.success() => {}
        Ok(_) => {
            pr.error("Docker daemon is not running.");
            pr.hint("Start Docker and try again.");
            return Err(1);
        }
        Err(_) => {
            pr.error("docker is not installed or not in PATH.");
            pr.hint("Install: https://docs.docker.com/get-docker/");
            return Err(1);
        }
    }

    // Compose plugin?
    let compose = ShellCommand::new("docker")
        .args(["compose", "version", "--short"])
        .output();

    match compose {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Ok(version)
        }
        _ => {
            pr.error("docker compose plugin is not installed.");
            pr.hint("Install: https://docs.docker.com/compose/install/");
            Err(1)
        }
    }
}

/// Locate manifests, providers, and OPA policies on the filesystem.
///
/// `.latchgate/` is the single source of truth for project setup:
///   - Present and valid => discover resources (repo root, binary, or init output).
///   - Present but corrupt => error.
///   - Absent => launch the interactive setup wizard.
///
/// With `reset`, an existing `.latchgate/` is removed first, forcing
/// the wizard to run again.
fn discover_resources(pr: &Printer, reset: bool) -> Result<Resources, i32> {
    let cwd = std::env::current_dir().map_err(|e| {
        pr.error(&format!("cannot determine working directory: {e}"));
        1
    })?;

    let lg_dir = cwd.join(".latchgate");

    // --reset: tear down and re-run the wizard.
    if reset && lg_dir.exists() {
        pr.info("Resetting project \u{2014} removing .latchgate/\u{2026}");
        std::fs::remove_dir_all(&lg_dir).map_err(|e| {
            pr.error(&format!("cannot remove .latchgate/: {e}"));
            1
        })?;
    }

    // Setup check: .latchgate/ is the single indicator of project state.
    if !lg_dir.exists() {
        run_first_time_setup(&cwd, pr)?;
    } else if !lg_dir.join("latchgate.toml").is_file() {
        // Directory exists but no config — corrupt or interrupted init.
        pr.error(".latchgate/ exists but is incomplete or corrupt.");
        pr.blank();
        pr.hint("Remove it and re-run, or reinitialize:");
        pr.hint_cmd("latchgate up --reset");
        pr.hint_cmd("latchgate init --force");
        pr.blank();
        return Err(1);
    }

    // Project is set up. Discover actual resource paths.
    if let Some(resources) = try_discover_resources_in(&cwd) {
        // Informational: repo-root checkout without compiled providers.
        if cwd.join("definitions/manifests").is_dir()
            && (!resources.providers_dir.is_dir() || dir_is_empty(&resources.providers_dir))
        {
            pr.info("target/providers/ is missing \u{2014} embedded providers will be used");
        }
        return Ok(resources);
    }

    pr.error("Project is set up but resources could not be located.");
    pr.blank();
    pr.hint("Try resetting:");
    pr.hint_cmd("latchgate up --reset");
    pr.blank();
    Err(1)
}

/// Try to locate resources relative to `base_dir` without side effects.
///
/// Returns `None` if no valid layout is found. Does not print or modify
/// the filesystem.
///
/// Three layouts, tried in order:
///   - **Repo root** — detected by `definitions/policies/opa/` + `definitions/manifests/`.
///   - **Installed binary** — resources at `../share/latchgate/` relative to
///     the binary (tarball / brew layout).
///   - **Init output** — `.latchgate/policies/latchgate.rego` +
///     `.latchgate/manifests/`, generated by `latchgate init`.
pub(crate) fn try_discover_resources_in(base_dir: &Path) -> Option<Resources> {
    // 1. Repo root?
    let cwd_policies = base_dir.join("definitions/policies/opa");
    let cwd_manifests = base_dir.join("definitions/manifests");
    let cwd_providers = base_dir.join("target/providers");

    if cwd_policies.is_dir() && cwd_manifests.is_dir() {
        return Some(Resources {
            policies_dir: cwd_policies,
            manifests_dir: cwd_manifests,
            providers_dir: cwd_providers,
        });
    }

    // 2. Binary-relative (tarball / brew install)?
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let share_base = bin_dir.join("../share/latchgate");
            if let Ok(share) = share_base.canonicalize() {
                let policies = share.join("policies/opa");
                let manifests = share.join("manifests");
                let providers = share.join("providers");

                if policies.is_dir() && manifests.is_dir() {
                    return Some(Resources {
                        policies_dir: policies,
                        manifests_dir: manifests,
                        providers_dir: providers,
                    });
                }
            }
        }
    }

    // 3. Init output (.latchgate/ from `latchgate init`)?
    let lg_dir = base_dir.join(".latchgate");
    let init_policies = lg_dir.join("policies");
    let init_manifests = lg_dir.join("manifests");
    if init_policies.join("latchgate.rego").is_file() && init_manifests.is_dir() {
        let init_providers = lg_dir.join("providers");
        return Some(Resources {
            policies_dir: init_policies,
            manifests_dir: init_manifests,
            providers_dir: init_providers,
        });
    }

    None
}

/// Launch the interactive setup wizard and execute the resulting plan.
///
/// Called by [`discover_resources`] when no existing project is found.
/// The wizard presents a TUI for selecting install location and security
/// preset, then scaffolds the project and displays operator credentials.
///
/// The wizard uses `force: false` (never overwrites an existing project)
/// and `dev: false` (production security posture).
fn run_first_time_setup(cwd: &Path, pr: &Printer) -> Result<(), i32> {
    pr.blank();
    pr.info("No project found \u{2014} launching setup wizard\u{2026}");
    pr.blank();

    // The wizard takes over the terminal (alternate screen, raw mode) and
    // restores it before returning. The `up` output resumes seamlessly.
    let plan = latchgate_tui::wizard::run_wizard(false, false).map_err(|e| {
        if e == "setup cancelled" {
            pr.info("Setup cancelled.");
        } else {
            pr.error(&format!("setup wizard failed: {e}"));
        }
        1
    })?;

    pr.blank();
    pr.info(&format!(
        "Initializing with {} preset\u{2026}",
        plan.preset.name,
    ));

    let result = execute_plan(&plan).map_err(|msg| {
        pr.error(&format!("init failed: {msg}"));
        1
    })?;

    // Validate the generated config before proceeding.
    if let Err(e) = Config::from_file(&result.config_path) {
        pr.error(&format!("generated config failed validation: {e}"));
        return Err(1);
    }

    // Display operator credentials — api_key is shown once, never logged.
    let rel = |p: &Path| -> String { p.strip_prefix(cwd).unwrap_or(p).display().to_string() };

    pr.blank();
    pr.section("Operator credentials");
    pr.blank();
    pr.field("operator:", &result.operator_name);
    pr.field("api_key: ", &result.api_key);
    pr.field("dpop_jkt:", &pr.cyan(&result.dpop_jkt));
    pr.field("pem:     ", &rel(&result.pem_path));
    pr.blank();
    pr.warn("api_key shown once \u{2014} save it now");
    pr.blank();

    Ok(())
}

fn dir_is_empty(path: &Path) -> bool {
    path.read_dir()
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true)
}

fn prepare_state_dir(pr: &Printer) -> Result<PathBuf, i32> {
    let state = state_dir();
    std::fs::create_dir_all(&state).map_err(|e| {
        pr.error(&format!(
            "cannot create state directory {}: {e}",
            state.display()
        ));
        1
    })?;

    // Restrict the state directory to the owning user. The directory holds
    // generated configs, compose files, and socket paths — another user
    // with write access could swap a compose file or inject a socket.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&state, perms).map_err(|e| {
            pr.error(&format!(
                "cannot set permissions on {}: {e}",
                state.display()
            ));
            1
        })?;
    }

    Ok(state)
}

/// Prepare the durable, project-local data directory (`.latchgate/data/`).
///
/// Unlike the runtime state dir — which is UID-keyed, machine-global, and
/// reused across every project and every run — durable state belongs to the
/// project. The audit ledger (history + learned domains/paths) and the
/// receipt/grant signing keys (which sign audit-referenced material and must
/// outlive a single session) live here, so that `.latchgate/` is the single
/// authoritative home for a project's state: removing it fully resets the
/// project, and separate projects never share data.
///
/// Callers run `discover_resources` first, which guarantees `.latchgate/`
/// exists at the cwd, so `ProjectDirs::from_cwd()` resolves correctly here.
fn prepare_data_dir(pr: &Printer) -> Result<PathBuf, i32> {
    let data = latchgate_core::paths::ProjectDirs::from_cwd()
        .map_err(|e| {
            pr.error(&format!("cannot resolve project data directory: {e}"));
            1
        })?
        .data_dir();

    std::fs::create_dir_all(&data).map_err(|e| {
        pr.error(&format!(
            "cannot create data directory {}: {e}",
            data.display()
        ));
        1
    })?;

    // Restrict to the owning user: the directory holds the audit ledger and
    // private signing keys.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&data, perms).map_err(|e| {
            pr.error(&format!(
                "cannot set permissions on {}: {e}",
                data.display()
            ));
            1
        })?;
    }

    Ok(data)
}
///
/// The gate runs in-process — it is **not** a Docker service. Only the
/// dependencies that require persistence or isolation run in containers.
/// Prometheus scrapes the gate's `/metrics` endpoint via `host.docker.internal`.
fn write_compose_file(state_dir: &Path, policies_dir: &Path, pr: &Printer) -> Result<(), i32> {
    let compose_path = state_dir.join(COMPOSE_FILENAME);

    // Policies path must be absolute for the Docker volume mount.
    let policies_abs = policies_dir.canonicalize().map_err(|e| {
        pr.error(&format!(
            "cannot resolve policies directory {}: {e}",
            policies_dir.display()
        ));
        1
    })?;

    // Prometheus config path — written by write_prometheus_config() before this.
    let prom_config = state_dir.join(PROMETHEUS_CONFIG_FILENAME);
    let prom_config_abs = prom_config.canonicalize().map_err(|e| {
        pr.error(&format!(
            "cannot resolve prometheus config {}: {e}",
            prom_config.display()
        ));
        1
    })?;

    // Squid config path — written by write_squid_config() before this.
    let squid_conf = state_dir.join(SQUID_CONFIG_FILENAME);
    let squid_conf_abs = squid_conf.canonicalize().map_err(|e| {
        pr.error(&format!(
            "cannot resolve squid config {}: {e}",
            squid_conf.display()
        ));
        1
    })?;
    let squid_egress_dir = state_dir.join("egress");
    let squid_egress_abs = squid_egress_dir.canonicalize().map_err(|e| {
        pr.error(&format!(
            "cannot resolve squid egress dir {}: {e}",
            squid_egress_dir.display()
        ));
        1
    })?;

    let yaml = format!(
        r#"# Auto-generated by `latchgate up`. Do not edit.
# Tear down: latchgate down
services:
  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
    command: >
      redis-server
      --save ""
      --appendonly no
      --maxmemory 64mb
      --maxmemory-policy allkeys-lru
      --requirepass "changeme"
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "changeme", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  opa:
    image: openpolicyagent/opa:0.70.0
    ports:
      - "127.0.0.1:8181:8181"
    command:
      - "run"
      - "--server"
      - "--addr=0.0.0.0:8181"
      - "/policies"
    volumes:
      - {policies}:/policies:ro
    healthcheck:
      test: ["CMD", "/opa", "version"]
      interval: 5s
      timeout: 3s
      retries: 5

  squid:
    build:
      dockerfile_inline: |
        FROM alpine:3.20
        RUN apk add --no-cache squid && rm -rf /var/cache/apk/*
        RUN mkdir -p /run/squid /var/run/latchgate/egress && chown squid:squid /run/squid /var/run/latchgate/egress
        USER squid
        ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
    read_only: true
    ports:
      - "127.0.0.1:3128:3128"
    volumes:
      - {squid_conf}:/etc/squid/squid.conf:ro
      - {squid_egress}:/var/run/latchgate/egress
    tmpfs:
      - /tmp:nosuid,size=16M
      - /run/squid:nosuid,size=4M
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 3128"]
      interval: 5s
      timeout: 3s
      retries: 5
      start_period: 5s

  prometheus:
    image: prom/prometheus:v2.54.1
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - {prom_config}:/etc/prometheus/prometheus.yml:ro
    extra_hosts:
      - "host.docker.internal:host-gateway"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=7d"
      - "--storage.tsdb.retention.size=256MB"
      - "--web.enable-lifecycle"
      - "--log.level=warn"
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:9090/-/healthy"]
      interval: 10s
      timeout: 3s
      retries: 5
"#,
        policies = policies_abs.display(),
        squid_conf = squid_conf_abs.display(),
        squid_egress = squid_egress_abs.display(),
        prom_config = prom_config_abs.display(),
    );

    let mut file = std::fs::File::create(&compose_path).map_err(|e| {
        pr.error(&format!("cannot write compose file: {e}"));
        1
    })?;
    file.write_all(yaml.as_bytes()).map_err(|e| {
        pr.error(&format!("cannot write compose file: {e}"));
        1
    })?;

    Ok(())
}

/// Write Prometheus scrape configuration to the state dir.
///
/// Scrapes the gate's `/metrics` endpoint on the host. The gate listens
/// on `127.0.0.1:3000` in dev mode — Prometheus reaches it via
/// `host.docker.internal` (Docker's host-to-container bridge).
///
/// Scrape interval is 15s — standard for infrastructure monitoring.
/// `honor_labels: true` preserves metric labels set by the gate.
fn write_prometheus_config(state_dir: &Path, pr: &Printer) -> Result<(), i32> {
    let config_path = state_dir.join(PROMETHEUS_CONFIG_FILENAME);

    let yaml = r#"# Auto-generated by `latchgate up`. Do not edit.
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "latchgate"
    honor_labels: true
    metrics_path: "/metrics"
    static_configs:
      - targets: ["host.docker.internal:3000"]
        labels:
          instance: "dev"
"#;

    std::fs::write(&config_path, yaml).map_err(|e| {
        pr.error(&format!(
            "cannot write prometheus config to {}: {e}",
            config_path.display()
        ));
        1
    })?;

    Ok(())
}

/// Write Squid proxy configuration and deny-all seed to the state dir.
///
/// The allowlist starts empty (deny-all). The gate's startup sync
/// populates it from manifests + learned domains after the server
/// starts, then signals Squid to reload via `egress_reload_command`.
///
/// SECURITY: defense-in-depth. The kernel's `validate_sink()` and the
/// proxy's ACL enforce the same domain set independently.
fn write_squid_config(state_dir: &Path, _manifests_dir: &Path, pr: &Printer) -> Result<(), i32> {
    let conf_path = state_dir.join(SQUID_CONFIG_FILENAME);

    // Egress directory: gate writes the live allowlist here, Squid reads it.
    // Both the gate process (host) and the Squid container mount this path.
    let egress_dir = state_dir.join("egress");
    std::fs::create_dir_all(&egress_dir).map_err(|e| {
        pr.error(&format!(
            "cannot create egress directory {}: {e}",
            egress_dir.display()
        ));
        1
    })?;

    let conf = r#"# Auto-generated by `latchgate up`. Do not edit.
http_port 3128
acl allowed_domains dstdomain "/var/run/latchgate/egress/allowlist.txt"
acl to_private dst 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
acl to_cgnat dst 100.64.0.0/10
acl to_metadata dst 169.254.169.254
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny to_localhost
http_access deny to_private
http_access deny to_cgnat
http_access deny to_metadata
http_access allow allowed_domains
http_access deny all
forwarded_for delete
cache deny all
access_log stdio:/dev/stdout
cache_log /dev/stderr
pid_filename /tmp/squid.pid
"#;

    std::fs::write(&conf_path, conf).map_err(|e| {
        pr.error(&format!(
            "cannot write squid config to {}: {e}",
            conf_path.display()
        ));
        1
    })?;

    // Deny-all seed — gate startup sync populates the real allowlist.
    let seed = "# Deny-all seed. Gate writes live allowlist at startup.\n";
    let allowlist_path = egress_dir.join("allowlist.txt");
    std::fs::write(&allowlist_path, seed).map_err(|e| {
        pr.error(&format!(
            "cannot write squid allowlist seed to {}: {e}",
            allowlist_path.display()
        ));
        1
    })?;

    pr.success("Squid config written (deny-all seed — gate populates at startup)");

    Ok(())
}

fn compose_up(state_dir: &Path, pr: &Printer) -> Result<(), i32> {
    let compose_path = state_dir.join(COMPOSE_FILENAME);
    let compose_str = compose_path.to_string_lossy();

    pr.info("Starting Redis + OPA + Squid + Prometheus...");

    let result = ShellCommand::new("docker")
        .args([
            "compose",
            "-p",
            PROJECT_NAME,
            "-f",
            &compose_str,
            "up",
            "-d",
            "--wait",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();

    match result {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            pr.error("docker compose up failed.");
            pr.blank();

            // Detect common failure: port already in use.
            if stderr.contains("address already in use")
                || stderr.contains("port is already allocated")
            {
                pr.hint("Port 6379, 8181, or 9090 is already in use.");
                pr.hint("Stop the conflicting service or run `latchgate down` first.");
            } else {
                pr.hint(&stderr);
                pr.hint(&format!(
                    "Logs: docker compose -p {PROJECT_NAME} -f {compose_str} logs"
                ));
            }
            pr.blank();
            Err(1)
        }
        Err(e) => {
            pr.error(&format!("failed to run docker compose: {e}"));
            Err(1)
        }
    }
}

/// Wait for Redis to accept TCP connections on 127.0.0.1:6379.
async fn wait_for_redis(pr: &Printer) -> Result<(), i32> {
    const REDIS_ADDR: &str = "127.0.0.1:6379";
    let addr: SocketAddr = REDIS_ADDR
        .parse()
        .expect("REDIS_ADDR is a valid socket address literal");
    let deadline = tokio::time::Instant::now() + HEALTH_TIMEOUT;

    loop {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
            pr.success("Redis healthy (127.0.0.1:6379)");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            pr.error("Redis did not become healthy within 60s.");
            pr.hint_cmd(&format!("docker compose -p {PROJECT_NAME} logs redis"));
            return Err(1);
        }
        tokio::time::sleep(HEALTH_INTERVAL).await;
    }
}

/// Wait for OPA to respond to HTTP health checks on 127.0.0.1:8181.
async fn wait_for_opa(pr: &Printer) -> Result<(), i32> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| {
            pr.error(&format!("failed to create HTTP client: {e}"));
            1
        })?;

    let deadline = tokio::time::Instant::now() + HEALTH_TIMEOUT;

    loop {
        match client.get("http://127.0.0.1:8181/health").send().await {
            Ok(resp) if resp.status().is_success() => {
                pr.success("OPA healthy (127.0.0.1:8181)");
                return Ok(());
            }
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            pr.error("OPA did not become healthy within 60s.");
            pr.hint_cmd(&format!("docker compose -p {PROJECT_NAME} logs opa"));
            return Err(1);
        }
        tokio::time::sleep(HEALTH_INTERVAL).await;
    }
}

/// Wait for Squid proxy to accept TCP connections on 127.0.0.1:3128.
async fn wait_for_squid(pr: &Printer) -> Result<(), i32> {
    const SQUID_ADDR: &str = "127.0.0.1:3128";
    let addr: SocketAddr = SQUID_ADDR
        .parse()
        .expect("SQUID_ADDR is a valid socket address literal");
    let deadline = tokio::time::Instant::now() + HEALTH_TIMEOUT;

    loop {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
            pr.success("Squid healthy (127.0.0.1:3128)");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            pr.error("Squid did not become healthy within 60s.");
            pr.hint_cmd(&format!("docker compose -p {PROJECT_NAME} logs squid"));
            return Err(1);
        }
        tokio::time::sleep(HEALTH_INTERVAL).await;
    }
}

/// Wait for Prometheus to respond to health checks on 127.0.0.1:9090.
///
/// Note: Prometheus starts before the gate, so the scrape target is not
/// yet available. That's fine — Prometheus will start scraping once the
/// gate is up. We only verify Prometheus itself is healthy here.
async fn wait_for_prometheus(pr: &Printer) -> Result<(), i32> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| {
            pr.error(&format!("failed to create HTTP client: {e}"));
            1
        })?;

    let deadline = tokio::time::Instant::now() + HEALTH_TIMEOUT;

    loop {
        match client.get("http://127.0.0.1:9090/-/healthy").send().await {
            Ok(resp) if resp.status().is_success() => {
                pr.success("Prometheus healthy (127.0.0.1:9090)");
                return Ok(());
            }
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            pr.error("Prometheus did not become healthy within 60s.");
            pr.hint_cmd(&format!("docker compose -p {PROJECT_NAME} logs prometheus"));
            return Err(1);
        }
        tokio::time::sleep(HEALTH_INTERVAL).await;
    }
}

/// Generate a config for embedded mode and write it to the state dir.
///
/// Produces a config with:
/// - No `redis_url` (SQLite state + bounded in-memory replay)
/// - No `opa_url` (embedded regorus)
/// - No `egress_proxy_url` (kernel-only enforcement)
///
/// Optionally accepts overrides for Redis and/or OPA URLs when using
/// `--with-redis` / `--with-opa`.
/// Filesystem roots used when generating an `up` config: ephemeral runtime
/// state vs. durable, project-local data. Bundled so generators take one
/// argument instead of two parallel paths.
struct UpDirs<'a> {
    /// UID-keyed runtime dir — sockets, logs, generated config, infra files.
    state: &'a Path,
    /// `.latchgate/data/` — audit ledger and durable signing keys.
    data: &'a Path,
}

fn generate_embedded_config(
    dirs: &UpDirs,
    resources: &Resources,
    expose_http: Option<std::net::SocketAddr>,
    posture: &latchgate_config::SecurityPosture,
    redis_url: Option<&str>,
    opa_url: Option<&str>,
    pr: &Printer,
) -> Result<Config, i32> {
    let state_dir = dirs.state;
    let data_dir = dirs.data;
    let config_path = state_dir.join(CONFIG_FILENAME);
    let ledger_path = data_dir.join("audit.db");

    // Reuse the project's operator credential so the gate accepts the same
    // key the CLI, TUI, and MCP operator adapter discover from the project
    // config — no second, divergent credential is ever minted.
    let operator = resolve_project_operator().map_err(|e| {
        pr.error(&e);
        1
    })?;

    let uds_path = super::paths::default_uds_path();
    let admin_uds_path = super::paths::default_admin_uds_path();
    let uds_display = uds_path.display();
    let admin_uds_display = admin_uds_path.display();

    let identity_section = read_project_identity_section().unwrap_or_else(|| {
        "# --- Identity ---\n\
         [identity]\n\
         provider = \"none\"\n"
            .to_string()
    });
    let secrets_section = read_project_secrets_section().unwrap_or_default();
    let webhooks_section = read_project_webhooks_section().unwrap_or_default();

    let transport_section = if let Some(addr) = expose_http {
        format!(
            r#"# --- Transport (HTTP exposed: {addr}) ---
listen_uds_path = "{uds_display}"
listen_admin_uds_path = "{admin_uds_display}"
listen_http_addr = "{addr}"
listen_admin_http_addr = "127.0.0.1:3001"
unsafe_expose_http = true
public_base_url = "http://{addr}""#
        )
    } else {
        format!(
            r#"# --- Transport (UDS only) ---
listen_uds_path = "{uds_display}"
listen_admin_uds_path = "{admin_uds_display}""#
        )
    };

    // Backend sections — only emit when explicitly requested.
    let redis_section = match redis_url {
        Some(url) => format!("redis_url = \"{url}\""),
        None => "# redis_url not set — using SQLite state + in-memory replay".to_string(),
    };
    let opa_section = match opa_url {
        Some(url) => format!("opa_url = \"{url}\""),
        None => "# opa_url not set — using embedded regorus".to_string(),
    };

    let toml_content = format!(
        r#"# Auto-generated by `latchgate up`. Do not edit.

{transport_section}

# --- Registry ---
manifests_dir = {manifests}
wasm_providers_dir = {providers}

# --- Audit ---
ledger_db_path = {ledger}

# --- Signing (durable — persisted under .latchgate/data) ---
receipt_signing_key_path = {receipt_key}
grant_signing_key_path = {grant_key}
receipt_keys_jwks_path = {receipt_jwks}

# --- Response schema enforcement ---
response_schema_enforcement = "deny"

# --- Backends ---
{redis_section}
{opa_section}
# egress_proxy_url not set — kernel-only enforcement (Layer 1)

# --- Logging ---
log_level = "info"
log_format = "auto"
log_file = {log_file}

# --- Table sections below (bare top-level keys must appear above) ---

[sandbox]
mode = "degraded_ok"

# --- Operator credentials (reused from project config) ---
[operator_credentials.{operator_name}]
api_key = "{api_key}"
dpop_jkt = "{dpop_jkt}"

{identity_section}
{secrets_section}
{webhooks_section}
{posture_section}"#,
        manifests = toml_quote(&resources.manifests_dir),
        providers = toml_quote(&resources.providers_dir),
        ledger = toml_quote_path(&ledger_path),
        receipt_key = toml_quote_path(&data_dir.join("receipt-signing.key")),
        grant_key = toml_quote_path(&data_dir.join("grant-signing.key")),
        receipt_jwks = toml_quote_path(&data_dir.join("receipt-keys.jwks")),
        log_file = toml_quote_path(&state_dir.join("logs").join("gate.log")),
        operator_name = operator.name,
        api_key = operator.api_key,
        dpop_jkt = operator.dpop_jkt,
        posture_section = format_posture_section(posture),
    );

    std::fs::write(&config_path, &toml_content).map_err(|e| {
        pr.error(&format!(
            "cannot write config to {}: {e}",
            config_path.display()
        ));
        1
    })?;

    // Mirror the project's operator PEM into the session dir so clients that
    // resolve the active session (TUI, MCP operator adapter) find the key
    // alongside the session config. The api_key/dpop_jkt above and this PEM
    // are the same credential the gate authenticates against.
    let pem_path = copy_operator_pem(&operator.pem_path, state_dir, pr)?;

    pr.blank();
    println!("  Operator credentials:");
    println!("    operator:  {}", operator.name);
    println!("    api_key:   {}", operator.api_key);
    println!("    dpop_jkt:  {}", operator.dpop_jkt);
    println!("    pem:       {}", pem_path.display());
    pr.blank();

    let config = Config::from_file(&config_path).map_err(|e| {
        pr.error(&format!("generated config is invalid: {e}"));
        1
    })?;

    Ok(config)
}

/// Generate a config TOML, write it to the state dir, and load it.
///
/// The config points `redis_url` and `opa_url` at the Docker containers,
/// `manifests_dir` and `wasm_providers_dir` at the discovered resources.
///
/// When `expose_http` is `Some`, HTTP listeners are added at the given
/// address alongside UDS.  When `None`, only UDS listeners are configured.
fn generate_config(
    dirs: &UpDirs,
    resources: &Resources,
    expose_http: Option<std::net::SocketAddr>,
    posture: &latchgate_config::SecurityPosture,
    pr: &Printer,
) -> Result<Config, i32> {
    let state_dir = dirs.state;
    let data_dir = dirs.data;
    let config_path = state_dir.join(CONFIG_FILENAME);
    let ledger_path = data_dir.join("audit.db");

    // Reuse the project's operator credential so the gate accepts the same
    // key the CLI, TUI, and MCP operator adapter discover from the project
    // config. Operator endpoints are DPoP-only, so the credential's dpop_jkt
    // and its on-disk PEM are carried through together (fail-closed).
    let operator = resolve_project_operator().map_err(|e| {
        pr.error(&e);
        1
    })?;

    let uds_path = super::paths::default_uds_path();
    let admin_uds_path = super::paths::default_admin_uds_path();
    let uds_display = uds_path.display();
    let admin_uds_display = admin_uds_path.display();

    // Inherit identity config from the project config (written by `init`)
    // instead of hardcoding provider = "none" which requires the unsafe-dev gate.
    let identity_section = read_project_identity_section().unwrap_or_else(|| {
        "# --- Identity ---\n\
         [identity]\n\
         provider = \"none\"\n"
            .to_string()
    });

    // Inherit secrets config so the TUI can manage encrypted secrets without
    // the user having to re-init after every `up` session.
    let secrets_section = read_project_secrets_section().unwrap_or_default();
    let webhooks_section = read_project_webhooks_section().unwrap_or_default();

    // Transport section: UDS is always present.  HTTP listeners are added
    // only when --expose-http is given.
    let transport_section = if let Some(addr) = expose_http {
        format!(
            r#"# --- Transport (HTTP exposed: {addr}) ---
listen_uds_path = "{uds_display}"
listen_admin_uds_path = "{admin_uds_display}"
listen_http_addr = "{addr}"
listen_admin_http_addr = "127.0.0.1:3001"
unsafe_expose_http = true
public_base_url = "http://{addr}""#
        )
    } else {
        format!(
            r#"# --- Transport (UDS only) ---
listen_uds_path = "{uds_display}"
listen_admin_uds_path = "{admin_uds_display}""#
        )
    };

    let toml_content = format!(
        r#"# Auto-generated by `latchgate up`. Do not edit.

{transport_section}

# --- Registry ---
manifests_dir = {manifests}
wasm_providers_dir = {providers}

# --- Audit ---
ledger_db_path = {ledger}

# --- Signing (durable — persisted under .latchgate/data) ---
receipt_signing_key_path = {receipt_key}
grant_signing_key_path = {grant_key}
receipt_keys_jwks_path = {receipt_jwks}

# --- Response schema enforcement ---
response_schema_enforcement = "deny"

# --- Dependencies ---
redis_url = "redis://:changeme@127.0.0.1:6379"
opa_url = "http://127.0.0.1:8181"
egress_proxy_url = "http://127.0.0.1:3128"

# --- Egress live sync ---
egress_live_allowlist_path = {egress_path}
egress_reload_command = "docker compose -p latchgate exec -T squid squid -k reconfigure"

# --- Logging ---
log_level = "info"
log_format = "auto"
log_file = {log_file}

# --- Table sections below (bare top-level keys must appear above) ---

[sandbox]
mode = "degraded_ok"

# --- Operator credentials (reused from project config) ---
[operator_credentials.{operator_name}]
api_key = "{api_key}"
dpop_jkt = "{dpop_jkt}"

{identity_section}
{secrets_section}
{webhooks_section}
{posture_section}"#,
        manifests = toml_quote(&resources.manifests_dir),
        providers = toml_quote(&resources.providers_dir),
        ledger = toml_quote_path(&ledger_path),
        receipt_key = toml_quote_path(&data_dir.join("receipt-signing.key")),
        grant_key = toml_quote_path(&data_dir.join("grant-signing.key")),
        receipt_jwks = toml_quote_path(&data_dir.join("receipt-keys.jwks")),
        egress_path = toml_quote_path(&state_dir.join("egress").join("allowlist.txt")),
        log_file = toml_quote_path(&state_dir.join("logs").join("gate.log")),
        operator_name = operator.name,
        api_key = operator.api_key,
        dpop_jkt = operator.dpop_jkt,
        posture_section = format_posture_section(posture),
    );

    std::fs::write(&config_path, &toml_content).map_err(|e| {
        pr.error(&format!(
            "cannot write config to {}: {e}",
            config_path.display()
        ));
        1
    })?;

    // Mirror the project's operator PEM into the session dir (see the embedded
    // writer for rationale) — same credential the gate authenticates against.
    let pem_path = copy_operator_pem(&operator.pem_path, state_dir, pr)?;

    // Display operator credentials — api_key is shown once, never logged.
    pr.blank();
    println!("  Operator credentials:");
    println!("    operator:  {}", operator.name);
    println!("    api_key:   {}", operator.api_key);
    println!("    dpop_jkt:  {}", operator.dpop_jkt);
    println!("    pem:       {}", pem_path.display());
    pr.blank();

    let config = Config::from_file(&config_path).map_err(|e| {
        pr.error(&format!("generated config is invalid: {e}"));
        1
    })?;

    Ok(config)
}

/// Quote a path as a TOML string value (with double quotes, backslash-escaped).
fn toml_quote(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

/// Quote a path as a TOML string value.
fn toml_quote_path(path: &Path) -> String {
    toml_quote(path)
}

/// Render the `[posture]` TOML section.
///
/// Only emits fields that are `true` so production configs (all-secure)
/// get no posture section at all — the `#[serde(default)]` on the struct
/// handles the absence as all-`false`.
fn format_posture_section(posture: &latchgate_config::SecurityPosture) -> String {
    if !posture.any_relaxed() {
        return String::new();
    }
    let mut s = String::from("# --- Security posture (relaxed protections) ---\n[posture]\n");
    let field = |s: &mut String, name: &str, val: bool| {
        if val {
            s.push_str(name);
            s.push_str(" = true\n");
        }
    };
    field(&mut s, "identity_insecure", posture.identity_insecure);
    field(&mut s, "signing_insecure", posture.signing_insecure);
    field(
        &mut s,
        "operator_auth_insecure",
        posture.operator_auth_insecure,
    );
    field(&mut s, "schema_insecure", posture.schema_insecure);
    field(&mut s, "storage_insecure", posture.storage_insecure);
    field(&mut s, "webhooks_insecure", posture.webhooks_insecure);
    field(&mut s, "egress_insecure", posture.egress_insecure);
    field(&mut s, "acl_insecure", posture.acl_insecure);
    s
}

/// Read the `[identity]` section from the project config if present.
///
/// When `.latchgate/latchgate.toml` has a non-default identity provider
/// (e.g. peercred configured by `init --dev`), reconstruct the TOML
/// sections so `up` carries them into its ephemeral config instead of
/// hardcoding `provider = "none"` which requires the unsafe-dev gate.
fn read_project_identity_section() -> Option<String> {
    let project_config = std::env::current_dir()
        .ok()?
        .join(".latchgate/latchgate.toml");

    let config = Config::from_file(&project_config).ok()?;

    match config.identity.provider {
        latchgate_config::IdentityProviderKind::Peercred => {
            let mut out = String::from("# --- Identity (inherited from project config) ---\n");
            out.push_str("[identity]\nprovider = \"peercred\"\n\n");
            out.push_str("[identity.peercred]\n");
            out.push_str(&format!(
                "allow_unmapped = {}\n",
                config.identity.peercred.allow_unmapped
            ));

            for (uid, p) in &config.identity.peercred.principals {
                out.push_str(&format!(
                    "\n[identity.peercred.principals.{uid}]\n\
                     principal = {:?}\nscopes = {:?}\n",
                    p.principal, p.scopes
                ));
            }
            out.push('\n');
            Some(out)
        }
        _ => None,
    }
}

/// Read the `[secrets]` section from the project config if present.
///
/// When `.latchgate/latchgate.toml` has SOPS paths configured (set by
/// `secrets_init`), carry them into the ephemeral `up` config so the
/// TUI can manage encrypted secrets without re-initialization.
fn read_project_secrets_section() -> Option<String> {
    let project_config = std::env::current_dir()
        .ok()?
        .join(".latchgate/latchgate.toml");

    let config = Config::from_file(&project_config).ok()?;

    let secrets_file = config.secrets.sops_secrets_file.as_deref()?;
    let key_file = config.secrets.sops_key_file.as_deref()?;

    // Only emit the section if both files still exist on disk.
    // Stale paths in the project config should not propagate.
    if !std::path::Path::new(secrets_file).exists() || !std::path::Path::new(key_file).exists() {
        return None;
    }

    let mut out = String::from("# --- Secrets (inherited from project config) ---\n");
    out.push_str("[secrets]\n");
    out.push_str(&format!("sops_secrets_file = {secrets_file:?}\n"));
    out.push_str(&format!("sops_key_file = {key_file:?}\n\n"));
    Some(out)
}

/// Read `[[webhooks]]` sections from the project config if present.
///
/// Webhook endpoints configured via TUI or manual TOML edits must be
/// carried into the ephemeral `up` session config — without this, the
/// webhook dispatcher starts with zero endpoints and silently drops
/// all events.
fn read_project_webhooks_section() -> Option<String> {
    let project_config = std::env::current_dir()
        .ok()?
        .join(".latchgate/latchgate.toml");

    let raw = std::fs::read_to_string(&project_config).ok()?;

    // Extract the raw TOML text for [[webhooks]] sections. Re-serializing
    // from Config.webhooks (Vec<toml::Value>) would lose formatting and
    // comments. Instead, find the first `[[webhooks]]` header and take
    // everything from there to the next non-webhook top-level section.
    let doc: toml_edit::DocumentMut = raw.parse().ok()?;
    let arr = doc.get("webhooks")?.as_array_of_tables()?;
    if arr.is_empty() {
        return None;
    }

    // Re-emit from the parsed document to get clean, canonical TOML.
    let mut out = String::from("# --- Webhooks (inherited from project config) ---\n");
    for table in arr.iter() {
        out.push_str("\n[[webhooks]]\n");
        out.push_str(&table.to_string());
    }
    out.push('\n');
    Some(out)
}

/// Operator credential resolved from the project config, reused verbatim by
/// `latchgate up` so the running gate and every operator client authenticate
/// against a single source of truth.
struct ProjectOperator {
    /// Operator name (the `[operator_credentials.<name>]` table key).
    name: String,
    /// Bearer token presented on operator requests.
    api_key: String,
    /// JWK SHA-256 thumbprint binding the api_key to the DPoP private key.
    dpop_jkt: String,
    /// On-disk DPoP private key (PEM) matching `dpop_jkt`.
    pem_path: PathBuf,
}

/// Resolve the project's operator credential and its DPoP private key.
///
/// `latchgate init` writes exactly one `[operator_credentials.<name>]` entry
/// with a `dpop_jkt` and the matching PEM at
/// `.latchgate/operators/<name>.pem`. `up` reuses this credential rather than
/// minting a throwaway one, so the gate it launches accepts the same key the
/// CLI, TUI, and MCP operator adapter discover from the project config.
///
/// Returns `Err` with an actionable message when the credential is missing,
/// lacks a `dpop_jkt` (operator endpoints are DPoP-only — a bare api_key is
/// rejected fail-closed), has more than one entry (ambiguous), or has no PEM
/// on disk.
fn resolve_project_operator() -> Result<ProjectOperator, String> {
    let project = latchgate_core::paths::ProjectDirs::from_cwd()
        .map_err(|e| format!("cannot resolve project directory: {e}"))?;
    let config_path = project.config_file();

    let config = Config::from_file(&config_path).map_err(|e| {
        format!(
            "cannot read project config '{}': {e}",
            config_path.display()
        )
    })?;

    let creds = &config.operator_credentials;
    let (name, cred) = match creds.len() {
        0 => {
            return Err(format!(
                "no operator credentials in '{}' — run `latchgate init`",
                config_path.display()
            ))
        }
        1 => creds
            .iter()
            .next()
            .expect("len checked == 1 immediately above"),
        _ => {
            let ids: Vec<&str> = creds.keys().map(String::as_str).collect();
            return Err(format!(
                "multiple operator credentials configured ({ids:?}); \
                 `latchgate up` requires exactly one"
            ));
        }
    };

    let dpop_jkt = cred.dpop_jkt.clone().ok_or_else(|| {
        format!(
            "operator '{name}' has no dpop_jkt; operator endpoints are \
             DPoP-only — re-run `latchgate init`"
        )
    })?;

    // Convention: `.latchgate/operators/<name>.pem` (canonical), with the
    // legacy flat `.latchgate/<name>.pem` accepted for projects created by
    // older layouts.
    let install_dir = project.install_dir();
    let candidates = [
        project.operators_dir().join(format!("{name}.pem")),
        install_dir.join(format!("{name}.pem")),
    ];
    let pem_path = candidates
        .iter()
        .find(|p| p.is_file())
        .cloned()
        .ok_or_else(|| {
            format!(
                "operator '{name}' has no private key at {} — re-run `latchgate init`",
                candidates[0].display()
            )
        })?;

    Ok(ProjectOperator {
        name: name.clone(),
        api_key: cred.api_key.clone(),
        dpop_jkt,
        pem_path,
    })
}

/// Copy the project operator PEM into the session state directory at
/// `operator.pem`, preserving 0600 permissions, and return the destination
/// path. The session copy lets clients that resolve the active `up` session
/// locate the key alongside the session config without reaching back into the
/// project tree.
fn copy_operator_pem(src: &Path, state_dir: &Path, pr: &Printer) -> Result<PathBuf, i32> {
    let pem = std::fs::read_to_string(src).map_err(|e| {
        pr.error(&format!(
            "cannot read operator private key '{}': {e}",
            src.display()
        ));
        1
    })?;

    let dest = state_dir.join("operator.pem");
    super::secure_file::write_private_file(&dest, &pem).map_err(|e| {
        pr.error(&format!(
            "cannot write operator PEM to {}: {e}",
            dest.display()
        ));
        1
    })?;

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- try_discover_resources_in ---------------------------------------------

    #[test]
    fn discover_repo_root_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        std::fs::create_dir_all(base.join("definitions/policies/opa")).unwrap();
        std::fs::create_dir_all(base.join("definitions/manifests")).unwrap();
        std::fs::create_dir_all(base.join("target/providers")).unwrap();

        let res = try_discover_resources_in(base).expect("repo root layout must be found");
        assert_eq!(res.policies_dir, base.join("definitions/policies/opa"));
        assert_eq!(res.manifests_dir, base.join("definitions/manifests"));
    }

    #[test]
    fn discover_init_output_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        std::fs::create_dir_all(base.join(".latchgate/policies")).unwrap();
        std::fs::write(
            base.join(".latchgate/policies/latchgate.rego"),
            "package latchgate",
        )
        .unwrap();
        std::fs::create_dir_all(base.join(".latchgate/manifests")).unwrap();

        let res = try_discover_resources_in(base).expect("init output layout must be found");
        assert_eq!(res.policies_dir, base.join(".latchgate/policies"));
        assert_eq!(res.manifests_dir, base.join(".latchgate/manifests"));
    }

    #[test]
    fn discover_empty_dir_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            try_discover_resources_in(tmp.path()).is_none(),
            "empty dir must return None",
        );
    }

    #[test]
    fn discover_repo_root_preferred_over_init() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        std::fs::create_dir_all(base.join("definitions/policies/opa")).unwrap();
        std::fs::create_dir_all(base.join("definitions/manifests")).unwrap();
        std::fs::create_dir_all(base.join(".latchgate/policies")).unwrap();
        std::fs::write(
            base.join(".latchgate/policies/latchgate.rego"),
            "package latchgate",
        )
        .unwrap();
        std::fs::create_dir_all(base.join(".latchgate/manifests")).unwrap();

        let res = try_discover_resources_in(base).unwrap();
        assert!(
            res.policies_dir.ends_with("definitions/policies/opa"),
            "repo root layout must take priority, got: {}",
            res.policies_dir.display()
        );
    }

    // -- dir_is_empty ---------------------------------------------------------

    #[test]
    fn dir_is_empty_on_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(dir_is_empty(tmp.path()));
    }

    #[test]
    fn dir_is_empty_on_nonempty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file.txt"), "x").unwrap();
        assert!(!dir_is_empty(tmp.path()));
    }

    #[test]
    fn dir_is_empty_on_nonexistent() {
        assert!(dir_is_empty(Path::new("/nonexistent/path/abc")));
    }
}
