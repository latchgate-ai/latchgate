//! `latchgate tui` — delegates to the `latchgate-tui` crate.

use std::sync::Arc;
use std::time::Duration;

use latchgate_client::{GateClient, OperatorAuth};
use latchgate_config::Config;

use crate::cmd::doctor;
use crate::output::Printer;

/// Concrete [`DoctorRunner`](latchgate_tui::DoctorRunner) backed by the
/// CLI's doctor module.
struct CliDoctorRunner;

impl latchgate_tui::DoctorRunner for CliDoctorRunner {
    fn run(
        &self,
        config: Config,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<latchgate_tui::DiagnosticCheck>> + Send>,
    > {
        Box::pin(async move {
            let checks = doctor::collect_all_checks(&config).await;
            checks
                .into_iter()
                .map(|(section, c)| latchgate_tui::DiagnosticCheck {
                    section,
                    name: c.name.to_string(),
                    severity: match c.severity {
                        doctor::Severity::Ok => latchgate_tui::DiagnosticSeverity::Ok,
                        doctor::Severity::Skip => latchgate_tui::DiagnosticSeverity::Skip,
                        doctor::Severity::Warn => latchgate_tui::DiagnosticSeverity::Warn,
                        doctor::Severity::Error => latchgate_tui::DiagnosticSeverity::Error,
                    },
                    message: c.message,
                })
                .collect()
        })
    }
}

fn make_doctor_runner() -> Arc<dyn latchgate_tui::DoctorRunner> {
    Arc::new(CliDoctorRunner)
}

const PID_FILENAME: &str = "gate.pid";

const HEALTH_TIMEOUT_SECS: u64 = 60;

const LOG_TAIL_LINES: usize = 10;

/// Gate lifecycle implementation.
///
/// Detects whether a `latchgate up` session is active by checking for
/// the compose file in the state directory. When active, `stop()` tears
/// down the Docker containers and terminates the gate server process.
///
/// `start()` runs gate bootstrap via `up::run()`, spawns the
/// gate binary as a background child process (`latchgate serve`), and
/// waits for the healthz endpoint to respond.
struct CliGateOps;

impl CliGateOps {
    /// Path to the compose file that indicates an active `up` session.
    fn compose_file() -> std::path::PathBuf {
        crate::cmd::up::state_dir().join(crate::cmd::up::COMPOSE_FILENAME)
    }

    /// Path to the PID file for the background gate server.
    fn pid_file() -> std::path::PathBuf {
        crate::cmd::up::state_dir().join(PID_FILENAME)
    }

    /// Path to the generated config file in the state directory.
    fn config_file() -> std::path::PathBuf {
        crate::cmd::up::state_dir().join(crate::cmd::up::CONFIG_FILENAME)
    }

    /// Terminate the gate server process tracked by the PID file.
    ///
    /// Sends SIGTERM via the `kill` binary (no `unsafe` needed), waits
    /// briefly for clean shutdown, then removes the PID file.
    fn terminate_server() {
        let pid_path = Self::pid_file();
        let Ok(pid_str) = std::fs::read_to_string(&pid_path) else {
            return;
        };
        let pid = pid_str.trim();
        if pid.is_empty() {
            let _ = std::fs::remove_file(&pid_path);
            return;
        }

        // Send SIGTERM via the kill binary — avoids unsafe libc calls.
        let _ = std::process::Command::new("kill")
            .args(["-TERM", pid])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // Brief wait for clean shutdown before Docker teardown.
        std::thread::sleep(Duration::from_secs(2));
        let _ = std::fs::remove_file(&pid_path);
    }

    /// Read the last [`LOG_TAIL_LINES`] lines from a log file.
    ///
    /// Returns an empty string on any I/O error — callers must not depend
    /// on log availability for correctness.
    fn tail_log(path: &std::path::Path) -> String {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return String::new();
        };
        let lines: Vec<&str> = contents.lines().collect();
        let start = lines.len().saturating_sub(LOG_TAIL_LINES);
        lines[start..].join("\n")
    }
}

impl latchgate_tui::GateOps for CliGateOps {
    fn mode_label(&self) -> &str {
        if Self::compose_file().exists() {
            "up"
        } else {
            "ext"
        }
    }

    fn can_stop(&self) -> bool {
        Self::compose_file().exists()
    }

    fn stop(&self) -> Result<(), String> {
        // Terminate the gate server process (if started by us).
        Self::terminate_server();

        // Tear down Docker containers (silent printer — TUI owns terminal).
        let pr = Printer::new(true);
        crate::cmd::up::cleanup(&pr);
        Ok(())
    }

    fn can_start(&self) -> bool {
        // Can start only if no up session is already active.
        !Self::compose_file().exists()
    }

    fn start(&self) -> latchgate_tui::StartFuture<'_> {
        Box::pin(async {
            // ── Phase 0: recover posture + paths from previous session ──
            //
            // SECURITY: a restart must never silently lower the security
            // posture.  Read the posture from the previous config; fall back
            // to the secure default (all protections enforced), never to
            // all_insecure().
            //
            // Pinning resource paths prevents discovery from resolving to a
            // different directory tree on restart, which would silently drop
            // actions the editor just wrote.
            let config_path = Self::config_file();
            let (posture, pinned) = if config_path.is_file() {
                match latchgate_config::Config::from_file(&config_path) {
                    Ok(prev) => {
                        let paths = crate::cmd::up::PinnedPaths {
                            manifests_dir: std::path::PathBuf::from(&prev.manifests_dir),
                            providers_dir: std::path::PathBuf::from(&prev.wasm_providers_dir),
                        };
                        (prev.posture, Some(paths))
                    }
                    Err(_) => {
                        // Config is corrupt — use secure defaults, let discovery run.
                        (latchgate_config::SecurityPosture::default(), None)
                    }
                }
            } else {
                // First start — no previous session to inherit from.
                (latchgate_config::SecurityPosture::default(), None)
            };

            // ── Phase 1: bootstrap gate ──────────────────────────────
            //
            // Printer uses non-JSON mode so step progress is visible
            // (the TUI has restored the terminal before calling us).
            let pr = Printer::new(false);
            let config = crate::cmd::up::run(
                &pr,
                false,
                &crate::cmd::up::InfraMode::Embedded,
                &posture,
                None,
                pinned.as_ref(),
            )
            .await
            .map_err(|msg| format!("up: {msg}"))?;

            // ── Phase 2: Spawn gate server ────────────────────────────
            //
            // The binary crate is the only one that links latchgate-api,
            // so we spawn the current executable with `serve --config`.
            let exe =
                std::env::current_exe().map_err(|e| format!("cannot resolve binary path: {e}"))?;
            let config_path = Self::config_file();
            let state = crate::cmd::up::state_dir();

            // Route server stderr to a log file for post-mortem debugging.
            let log_path = state.join("gate-serve.log");
            let log_file = std::fs::File::create(&log_path)
                .map_err(|e| format!("cannot create log at {}: {e}", log_path.display()))?;

            let mut cmd = std::process::Command::new(&exe);
            cmd.args(["serve", "--config"])
                .arg(&config_path)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::from(log_file));

            // Security posture is recorded in the generated config file's
            // [posture] section, so the child `serve` process inherits it
            // without any env var propagation.

            let child = cmd.spawn().map_err(|e| format!("cannot start gate: {e}"))?;

            // Track PID for stop().
            let pid_path = Self::pid_file();
            std::fs::write(&pid_path, child.id().to_string())
                .map_err(|e| format!("cannot write PID to {}: {e}", pid_path.display()))?;

            pr.blank();
            pr.info("Waiting for gate to become healthy…");

            // ── Phase 3: Wait for healthy ─────────────────────────────
            let client = GateClient::from_config(&config)
                .map_err(|e| format!("failed to initialize client: {e}"))?;
            let mut healthy = false;
            for _ in 0..HEALTH_TIMEOUT_SECS {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if client.healthz().await.unwrap_or(false) {
                    healthy = true;
                    break;
                }
            }

            if !healthy {
                // Surface the server log tail so the user sees the actual
                // failure reason (e.g. config validation errors) instead
                // of only a generic timeout message.
                let tail = Self::tail_log(&log_path);

                // Clean up the failed attempt.
                Self::terminate_server();
                let silent = Printer::new(true);
                crate::cmd::up::cleanup(&silent);

                let mut msg = format!("gate did not become healthy within {HEALTH_TIMEOUT_SECS}s");
                if !tail.is_empty() {
                    msg.push_str("\n\ngate-serve.log (last lines):\n");
                    msg.push_str(&tail);
                } else {
                    msg.push_str(&format!(" — check {} for details", log_path.display()));
                }
                return Err(msg);
            }

            // ── Phase 4: Discover operator auth ───────────────────────
            //
            // The `up` flow generates operator credentials and writes the
            // PEM to state_dir/operator.pem. Build OperatorAuth from the
            // config's single credential entry + the PEM path.
            let pem_path = state.join("operator.pem");
            let api_key = config
                .operator_credentials
                .values()
                .next()
                .map(|c| c.api_key.clone())
                .ok_or("generated config has no operator credentials")?;

            let auth = OperatorAuth::from_args(&api_key, Some(&pem_path)).map_err(|e| {
                format!(
                    "operator auth setup failed (PEM at {}): {e}",
                    pem_path.display()
                )
            })?;

            pr.success("Gate is healthy — returning to TUI");
            pr.blank();

            Ok((config, auth))
        })
    }

    fn can_reload(&self) -> bool {
        // Reload is available whenever an up session is active (the gate
        // is running and we have the admin socket).
        Self::compose_file().exists()
    }

    fn reload(&self) -> latchgate_tui::ReloadFuture<'_> {
        Box::pin(async {
            // Read config to get the admin socket path / base URL.
            let config_path = Self::config_file();
            let config = latchgate_config::Config::from_file(&config_path)
                .map_err(|e| format!("cannot read config: {e}"))?;

            let client = latchgate_client::GateClient::from_config(&config)
                .map_err(|e| format!("client init: {e}"))?;

            let auth = latchgate_client::auto_discover_operator_auth(&config)
                .map_err(|e| format!("operator auth: {e}"))?;

            let resp = client
                .admin_reload(&auth)
                .await
                .map_err(|e| format!("reload failed: {e}"))?;

            let actions = resp["actions"].as_u64().unwrap_or(0) as usize;
            let policy_version = resp["policy_version"].as_str().unwrap_or("").to_string();

            Ok(latchgate_tui::ReloadResult {
                actions,
                policy_version,
            })
        })
    }
}

pub async fn run(
    config: &Config,
    auth: Option<OperatorAuth>,
    json_mode: bool,
    first_launch: bool,
) -> i32 {
    let setup = Arc::new(crate::cmd::setup_ops::CliSetupOps::new(config));
    let gate_ops: Option<Arc<dyn latchgate_tui::GateOps>> = Some(Arc::new(CliGateOps));
    latchgate_tui::run(
        config,
        auth,
        json_mode,
        make_doctor_runner(),
        setup,
        gate_ops,
        first_launch,
    )
    .await
}
