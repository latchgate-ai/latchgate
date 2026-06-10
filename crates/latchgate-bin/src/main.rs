//! LatchGate server + CLI binary.
//!
//! All commands are dispatched here. `up`, `down`, `sandbox`, and `init`
//! manage their own lifecycle (Docker orchestration, config generation,
//! TUI setup). All other commands load config from file or defaults before
//! executing.

use std::path::Path;

use clap::Parser;

use latchgate_api as api;
use latchgate_cli::{self as cli, Command};
use latchgate_config::Config;

fn load_config(config_flag: Option<&str>) -> Config {
    match config_flag {
        Some(path) => Config::from_file(Path::new(path)).unwrap_or_else(|e| {
            eprintln!("error: failed to load config from '{path}': {e}");
            std::process::exit(1);
        }),
        None => Config::load().unwrap_or_else(|e| {
            eprintln!("error: failed to load configuration: {e}");
            eprintln!();
            eprintln!("  Run 'latchgate init' to generate .latchgate/latchgate.toml,");
            eprintln!("  or use 'latchgate up' for a one-command dev setup.");
            std::process::exit(1);
        }),
    }
}

fn try_load_config(config_flag: Option<&str>) -> Option<Config> {
    match config_flag {
        Some(path) => Config::from_file(Path::new(path)).ok(),
        None => Config::load().ok(),
    }
}

/// Resolve operator authentication from CLI flags or auto-discovery.
///
/// Resolution order (highest to lowest priority):
///   1. `--operator-key` CLI flag / `LATCHGATE_OPERATOR_KEY` env var
///   2. Auto-discovery from `latchgate.toml` (single credential with PEM)
///
/// When `--operator-private-key` is also provided, uses DPoP
/// proof-of-possession. Without a private key, the CLI cannot authenticate
/// to a production gate.
fn resolve_operator_auth(
    args: &cli::Cli,
    config: &Config,
    pr: &cli::output::Printer,
) -> Result<cli::OperatorAuth, i32> {
    let explicit_key = args.operator_key.as_deref().filter(|k| !k.is_empty());
    let private_key_path = args.operator_private_key.as_deref();

    let emit_error = |msg: &str| {
        if args.json {
            cli::output::print_json(&serde_json::json!({
                "ok": false,
                "error": msg,
            }));
        } else {
            pr.blank();
            pr.error(msg);
            pr.blank();
        }
    };

    match (explicit_key, private_key_path) {
        // Explicit key (flag or env) — use it, optionally with DPoP.
        (Some(key), pk) => cli::OperatorAuth::from_args(key, pk).map_err(|e| {
            emit_error(&e);
            1
        }),

        // Private key without operator key — ambiguous, refuse.
        (None, Some(_)) => {
            emit_error(
                "--operator-private-key requires --operator-key.\n  \
                 The private key alone is not enough to identify which operator credential to use.",
            );
            Err(1)
        }

        // Neither provided — auto-discover from config.
        (None, None) => cli::client::auto_discover_operator_auth(config).map_err(|e| {
            emit_error(&e);
            1
        }),
    }
}

/// `latchgate up` — start deps + gate.
async fn cmd_up(
    pr: &cli::output::Printer,
    reset: bool,
    mode: cli::cmd::up::InfraMode,
    posture: latchgate_config::SecurityPosture,
    expose_http: Option<std::net::SocketAddr>,
) {
    pr.banner(cli::VERSION);
    match cli::cmd::up::run(pr, reset, &mode, &posture, expose_http, None).await {
        Ok(config) => {
            let _log_guard = api::server::init_logging(&config);
            api::server::serve(config).await;
            cli::cmd::up::cleanup(pr);
        }
        Err(msg) => {
            pr.error(&msg);
            std::process::exit(1);
        }
    }
}

/// `latchgate down` — stop containers started by `up --infra`.
fn cmd_down(pr: &cli::output::Printer, config_flag: Option<&str>, prune: bool, yes: bool) -> ! {
    let data_dir = if prune {
        try_load_config(config_flag).map(|c| {
            Path::new(&c.storage.ledger_db_path)
                .parent()
                .unwrap_or(Path::new("."))
                .to_path_buf()
        })
    } else {
        None
    };
    let code = cli::cmd::down::run(pr, prune, yes, data_dir.as_deref());
    std::process::exit(code);
}

/// `latchgate sandbox` — launch agent in Linux namespace.
async fn cmd_sandbox(
    pr: &cli::output::Printer,
    config_flag: Option<&str>,
    sandbox_args: cli::cmd::sandbox::SandboxArgs,
) -> ! {
    // Sandbox manages its own lifecycle. Config is optional — the
    // sandbox can run from CLI flags alone or a standalone TOML.
    let mut sa = sandbox_args;
    sa.config = try_load_config(config_flag);
    let code = cli::cmd::sandbox::run(sa, pr).await;
    std::process::exit(code);
}

/// `latchgate sandbox-init` — internal shim executed by bwrap inside the sandbox.
#[cfg(target_os = "linux")]
fn cmd_sandbox_init(pr: &cli::output::Printer, config_fd: i32) -> ! {
    match latchgate_sandbox::run_sandbox_init(config_fd) {
        Ok(()) => unreachable!("exec_command does not return on success"),
        Err(e) => {
            pr.error(&format!("sandbox-init failed: {e}"));
            std::process::exit(127);
        }
    }
}

/// Build `SandboxArgs` from the parsed CLI command.
fn build_sandbox_args(args: &cli::Cli) -> cli::cmd::sandbox::SandboxArgs {
    let Command::Sandbox {
        workspace,
        profile,
        allow_hosts,
        ro_mounts,
        pass_env,
        gate_socket,
        sandbox_config,
        command,
    } = &args.command
    else {
        unreachable!()
    };
    cli::cmd::sandbox::SandboxArgs {
        config: None, // filled by cmd_sandbox
        sandbox_config: sandbox_config.clone(),
        profile: profile.clone(),
        workspace: workspace.clone(),
        allow_hosts: allow_hosts.clone(),
        ro_mounts: ro_mounts.clone(),
        pass_env: pass_env.clone(),
        gate_socket: gate_socket.clone(),
        command: command.clone(),
    }
}

/// `latchgate init` — scaffold a project.
async fn cmd_init(args: &cli::Cli, pr: &cli::output::Printer) -> ! {
    api::server::init_logging_quiet();

    if let Command::Init {
        preset,
        location,
        list_presets,
        export_preset,
        include_examples,
        force,
        dev,
    } = &args.command
    {
        let has_explicit_action = preset.is_some() || *list_presets || export_preset.is_some();

        if has_explicit_action {
            let code = cli::cmd::init::run(&cli::cmd::init::InitArgs {
                preset: preset.as_deref(),
                location: location.as_deref(),
                list_presets: *list_presets,
                export_preset: export_preset.as_deref(),
                include_examples: *include_examples,
                force: *force,
                dev: *dev,
                pr,
                json_mode: args.json,
            });
            std::process::exit(code);
        }

        // Interactive: launch the full TUI in first-launch/setup mode.
        let config = Config::default();
        let code = cli::cmd::tui::run(&config, None, args.json, true).await;
        std::process::exit(code);
    }
    unreachable!();
}

/// `latchgate tui` — interactive operator terminal.
async fn cmd_tui(args: &cli::Cli) -> ! {
    api::server::init_logging_quiet();

    // Config resolution priority:
    //   1. Explicit --config path
    //   2. Active `up` session (ephemeral config in runtime dir)
    //   3. Normal discovery (project / user-global / defaults)
    let (config, first_launch, up_session) = match &args.config {
        Some(path) => match Config::from_file(Path::new(path)) {
            Ok(c) => (c, false, false),
            Err(e) => {
                eprintln!("error: failed to load config from '{path}': {e}");
                std::process::exit(1);
            }
        },
        None => {
            if let Some(up_config) = cli::cmd::up::active_session_config() {
                match Config::from_file(&up_config) {
                    Ok(c) => (c, false, true),
                    Err(_) => match Config::load() {
                        Ok(c) => (c, false, false),
                        Err(_) => (Config::default(), true, false),
                    },
                }
            } else {
                match Config::load() {
                    Ok(c) => (c, false, false),
                    Err(_) => (Config::default(), true, false),
                }
            }
        }
    };

    let auth = if first_launch {
        // No credentials yet — generate ephemeral keypair to satisfy
        // the type. API calls will fail (no gate running), which the
        // TUI reconnect logic handles gracefully.
        None
    } else {
        let explicit_key = args.operator_key.as_deref().filter(|k| !k.is_empty());
        let pk_path = args.operator_private_key.as_deref();
        match (explicit_key, pk_path) {
            (Some(key), pk) => Some(cli::OperatorAuth::from_args(key, pk).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            })),
            (None, Some(_)) => {
                eprintln!("error: --operator-private-key requires --operator-key");
                std::process::exit(1);
            }
            (None, None) if up_session => {
                // Active `up` session: use the ephemeral PEM from the
                // state directory paired with the config's credentials.
                let pem = cli::cmd::up::active_session_pem().unwrap_or_else(|| {
                    eprintln!("error: up session config exists but operator.pem is missing");
                    std::process::exit(1);
                });
                let cred = config
                    .operator_credentials
                    .values()
                    .next()
                    .unwrap_or_else(|| {
                        eprintln!("error: up session config has no operator credentials");
                        std::process::exit(1);
                    });
                Some(
                    cli::OperatorAuth::from_args(&cred.api_key, Some(&pem)).unwrap_or_else(|e| {
                        eprintln!("error: up-session operator auth failed: {e}");
                        std::process::exit(1);
                    }),
                )
            }
            (None, None) => Some(
                cli::client::auto_discover_operator_auth(&config).unwrap_or_else(|e| {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }),
            ),
        }
    };

    let code = cli::cmd::tui::run(&config, auth, args.json, first_launch).await;
    std::process::exit(code);
}

fn main() {
    let args = cli::Cli::parse();

    // Sandbox-init is a synchronous, single-threaded shim that forks
    // internally (loopback_forward::spawn). It MUST run outside the tokio
    // runtime: fork() copies tokio's thread-local "inside runtime" guard,
    // causing the forwarder child's block_on() to panic. Dispatching here
    // — before any runtime exists — gives the child clean thread-local
    // state after fork.
    #[cfg(target_os = "linux")]
    if let Command::SandboxInit { config_fd } = &args.command {
        let pr = cli::output::Printer::new(args.json);
        cmd_sandbox_init(&pr, *config_fd);
    }
    #[cfg(not(target_os = "linux"))]
    if let Command::SandboxInit { .. } = &args.command {
        let pr = cli::output::Printer::new(args.json);
        pr.error("sandbox-init is only available on Linux");
        std::process::exit(1);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async_main(args));
}

async fn async_main(args: cli::Cli) {
    let pr = cli::output::Printer::new(args.json);

    // ── Commands that manage their own lifecycle ────────────────────────

    match &args.command {
        Command::Up {
            reset,
            infra,
            with_redis,
            with_opa,
            insecure_identity,
            insecure_signing,
            schema_warn,
            expose_http,
            insecure_operator_auth,
            insecure_storage,
            insecure_webhooks,
            insecure_egress,
            insecure_acl,
        } => {
            let posture = latchgate_config::SecurityPosture {
                identity_insecure: *insecure_identity,
                signing_insecure: *insecure_signing,
                operator_auth_insecure: *insecure_operator_auth,
                schema_insecure: *schema_warn,
                storage_insecure: *insecure_storage,
                webhooks_insecure: *insecure_webhooks,
                egress_insecure: *insecure_egress,
                acl_insecure: *insecure_acl,
            };
            let mode = if *infra {
                cli::cmd::up::InfraMode::Docker
            } else if with_redis.is_some() || with_opa.is_some() {
                cli::cmd::up::InfraMode::Selective {
                    redis_url: with_redis.clone(),
                    opa_url: with_opa.clone(),
                }
            } else {
                cli::cmd::up::InfraMode::Embedded
            };
            cmd_up(&pr, *reset, mode, posture, *expose_http).await;
            return;
        }
        Command::Down { prune, yes } => cmd_down(&pr, args.config.as_deref(), *prune, *yes),
        Command::Sandbox { .. } => {
            cmd_sandbox(&pr, args.config.as_deref(), build_sandbox_args(&args)).await;
        }
        // SandboxInit is dispatched before the tokio runtime in main().
        Command::SandboxInit { .. } => unreachable!("handled before runtime"),
        Command::Completions { shell } => {
            std::process::exit(cli::cmd::completions::run(*shell, &pr));
        }
        Command::Init { .. } => cmd_init(&args, &pr).await,
        Command::Tui => cmd_tui(&args).await,
        _ => {}
    }

    // ── All other commands: load config, dispatch ──────────────────────

    let config = load_config(args.config.as_deref());

    // `serve` manages its own logging (full tracing, file output, rotation).
    if matches!(&args.command, Command::Serve) {
        let _log_guard = api::server::init_logging(&config);
        api::server::serve(config).await;
        return;
    }

    api::server::init_logging_quiet();
    let exit_code = dispatch_command(&args, &config, &pr).await;
    std::process::exit(exit_code);
}

/// Dispatch commands that depend on a loaded [`Config`].
async fn dispatch_command(args: &cli::Cli, config: &Config, pr: &cli::output::Printer) -> i32 {
    match &args.command {
        // Already handled in main — unreachable.
        Command::Up { .. }
        | Command::Down { .. }
        | Command::Sandbox { .. }
        | Command::SandboxInit { .. }
        | Command::Completions { .. }
        | Command::Tui
        | Command::Init { .. }
        | Command::Serve => unreachable!(),

        // ── No auth required ──────────────────────────────────────────
        Command::Doctor => cli::cmd::doctor::run(config, pr).await,
        Command::Status => cli::cmd::status::run(config, pr).await,

        Command::Actions { action } => cli::cmd::actions::run(config, action.as_deref(), pr).await,

        Command::Operator(sub) => match sub {
            cli::OperatorCommand::Keygen { output } => {
                cli::cmd::operator::run_keygen(output, pr, args.json)
            }
        },

        Command::Config(sub) => dispatch_config(args, config, sub, pr).await,

        Command::Policy(sub) => cli::cmd::policy::run(&config.manifests_dir, sub, pr, args.json),

        Command::Secrets(sub) => cli::cmd::secrets::run(config, sub, pr, args.json),

        Command::Domains(sub) => cli::cmd::domains::run(config, sub, pr),

        // ── Auth required ─────────────────────────────────────────────
        Command::Audit {
            format,
            limit,
            action,
            principal,
            decision,
            after,
            before,
            trace_id,
            session_id,
            event_type,
        } => {
            let params = cli::client::AuditParams {
                limit: Some(*limit),
                action_id: action.clone(),
                principal: principal.clone(),
                decision: decision.clone(),
                after: after.clone(),
                before: before.clone(),
                trace_id: trace_id.clone(),
                session_id: session_id.clone(),
                event_type: event_type.clone(),
            };
            match resolve_operator_auth(args, config, pr) {
                Ok(auth) => cli::cmd::audit::run(config, &auth, params, pr, format).await,
                Err(code) => code,
            }
        }

        Command::Verify => match resolve_operator_auth(args, config, pr) {
            Ok(auth) => cli::cmd::verify::run(config, &auth, pr).await,
            Err(code) => code,
        },

        Command::Revoke { yes } => match resolve_operator_auth(args, config, pr) {
            Ok(auth) => cli::cmd::revoke::run(config, &auth, *yes, pr).await,
            Err(code) => code,
        },

        Command::Approvals(sub) => match resolve_operator_auth(args, config, pr) {
            Ok(auth) => cli::cmd::approvals::run(config, &auth, sub, pr).await,
            Err(code) => code,
        },
    }
}

/// Dispatch `latchgate config <subcommand>`.
async fn dispatch_config(
    args: &cli::Cli,
    config: &Config,
    sub: &cli::ConfigCommand,
    pr: &cli::output::Printer,
) -> i32 {
    let json = args.json;
    let config_path = args.config.as_deref();

    match sub {
        cli::ConfigCommand::Path => cli::config::run_path(config, pr, json),
        cli::ConfigCommand::Resources => cli::config::run_resources(config, pr, json),
        cli::ConfigCommand::Get { key } => {
            cli::config::run_get(config_path, key.as_deref(), pr, json)
        }
        cli::ConfigCommand::Set { key, value } => {
            cli::config::run_set(config_path, key, value, pr, json)
        }
        cli::ConfigCommand::Unset { key } => cli::config::run_unset(config_path, key, pr, json),
        cli::ConfigCommand::Validate => cli::config::run_validate(config, pr, json),
        cli::ConfigCommand::AddOperator {
            name,
            api_key,
            key_dir,
        } => {
            cli::config::run_add_operator(config_path, name, api_key.as_deref(), key_dir, pr, json)
        }
        cli::ConfigCommand::RemoveOperator { name } => {
            cli::config::run_remove_operator(config_path, name, pr, json)
        }
        cli::ConfigCommand::AddPrincipal {
            uid,
            name,
            scopes,
            owner,
            force,
        } => cli::config::run_add_principal(
            &cli::config::AddPrincipalArgs {
                config_path,
                uid: *uid,
                name,
                scopes_csv: scopes,
                owner: owner.as_deref(),
                force: *force,
            },
            pr,
            json,
        ),
        cli::ConfigCommand::RemovePrincipal { uid } => {
            cli::config::run_remove_principal(config_path, *uid, pr, json)
        }
        cli::ConfigCommand::ListPrincipals => cli::config::run_list_principals(config, pr, json),
        cli::ConfigCommand::AddWebhook {
            name,
            url,
            secret,
            events,
            headers,
            timeout,
            format,
        } => cli::config::run_add_webhook(
            &cli::config::AddWebhookArgs {
                config_path,
                name,
                url,
                secret: secret.as_deref(),
                events_csv: events,
                headers_csv: headers.as_deref(),
                timeout: *timeout,
                format,
            },
            pr,
            json,
        ),
        cli::ConfigCommand::RemoveWebhook { name } => {
            cli::config::run_remove_webhook(config_path, name, pr, json)
        }
        cli::ConfigCommand::ListWebhooks => cli::config::run_list_webhooks(config, pr, json),
        cli::ConfigCommand::TestWebhook { name } => {
            cli::config::run_test_webhook(config, name.as_deref(), pr, json).await
        }
    }
}
