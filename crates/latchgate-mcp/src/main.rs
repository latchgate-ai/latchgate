//! `latchgate-mcp` — LatchGate MCP adapter.
//!
//! ```sh
//! latchgate-mcp serve --gate-url http://localhost:3000
//! latchgate-mcp serve --gate-socket /run/user/1000/latchgate/gate.sock --public-base-url http://localhost:3000
//! latchgate-mcp operator \
//!     --admin-socket /run/user/1000/latchgate/gate-admin.sock \
//!     --operator-key .latchgate/operators/dev.pem \
//!     --operator-token dev-operator-key \
//!     --operator-id dev \
//!     --public-base-url http://localhost:3000
//! latchgate-mcp install --ide cursor                        # auto-detects transport
//! latchgate-mcp install --ide cursor --gate-url http://localhost:3000
//! latchgate-mcp install --ide claude --dry-run
//! ```

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use latchgate_mcp::{
    admin_client::AdminClient,
    config::{Cli, Command, OperatorArgs, ServeArgs},
    gate_client::GateClient,
    install,
    server::McpServer,
};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve(args) => run_agent(args).await,
        Command::Operator(args) => run_operator(args).await,
        Command::Install(args) => {
            if let Err(e) = install::run(&args) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Run the agent MCP stdio server. Holds no operator credential and never
/// advertises approval tools; held actions are resolved by polling for an
/// out-of-band operator approval.
async fn run_agent(args: ServeArgs) {
    init_logging(&args.log_level);

    if args.use_uds() && args.effective_public_base_url().is_none() {
        eprintln!(
            "error: --public-base-url (or LATCHGATE_PUBLIC_URL) is required when using \
             Unix socket transport.\n\
             It must match the 'public_base_url' setting in latchgate.toml.\n\
             Example: --public-base-url http://localhost:3000"
        );
        std::process::exit(1);
    }

    let session_id = args.effective_session_id();
    let agent_id = args.agent_id.clone();

    let client = if args.use_uds() {
        #[cfg(unix)]
        {
            let public_base_url = args
                .effective_public_base_url()
                .expect("public_base_url validated above");
            GateClient::new_uds(
                args.gate_socket.clone(),
                args.effective_base_url(),
                public_base_url,
                agent_id.clone(),
                session_id,
            )
            .unwrap_or_else(|e| {
                eprintln!("error: failed to create gate client: {e}");
                std::process::exit(1);
            })
        }
        #[cfg(not(unix))]
        {
            eprintln!(
                "error: Unix domain socket transport is not supported on this platform.\n\
                 Use --gate-url to specify an HTTP endpoint instead."
            );
            std::process::exit(1);
        }
    } else {
        let base_url = args
            .gate_url
            .clone()
            .expect("gate_url is Some when use_uds() is false");
        GateClient::new_http(base_url, agent_id.clone(), session_id).unwrap_or_else(|e| {
            eprintln!("error: failed to create gate client: {e}");
            std::process::exit(1);
        })
    };

    McpServer::agent(client, args.agent_id).run().await;
}

/// Run the operator MCP stdio server (approval session).
///
/// Loads and verifies the operator credential before serving. An invalid
/// credential aborts the process with a clear message rather than surfacing
/// a runtime 401 on the first approval. Must run as a separate adapter
/// instance from the agent `serve` session.
async fn run_operator(args: OperatorArgs) {
    init_logging(&args.log_level);

    #[cfg(not(unix))]
    {
        let _ = &args;
        eprintln!("error: the operator session requires Unix domain socket support.");
        std::process::exit(1);
    }

    #[cfg(unix)]
    {
        let signing_key = AdminClient::load_signing_key(&args.operator_key).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });

        // The operator session connects to the admin socket. The agent gate
        // client shares the same transport endpoint for tool listing and
        // action context; both authenticate independently.
        let transport = latchgate_client::Transport::uds(
            args.admin_socket.to_string_lossy().into_owned(),
            args.public_base_url.clone(),
        );

        let admin = AdminClient::new(
            transport,
            signing_key,
            args.operator_token.clone(),
            args.operator_id.clone(),
        );

        // Fail fast: verify the credential against the admin API before
        // advertising any approval tool.
        if let Err(e) = admin.verify_credential().await {
            eprintln!(
                "error: operator credential verification failed against {}: {e}\n\
                 Check --operator-key, --operator-token, and --operator-id against the \
                 gate's operator_credentials configuration.",
                args.admin_socket.display()
            );
            std::process::exit(1);
        }

        info!(
            operator_id = %args.operator_id,
            admin_socket = %args.admin_socket.display(),
            allowlist_enabled = args.enable_allowlist_tool,
            "operator credential verified — approval tools enabled"
        );

        // The operator session reaches the gate over the same admin socket for
        // tool listing; action execution is not performed on this session.
        let session_id = uuid::Uuid::now_v7().to_string();
        let client = GateClient::new_uds(
            args.admin_socket.clone(),
            "http://localhost".to_string(),
            args.public_base_url.clone(),
            args.agent_id.clone(),
            session_id,
        )
        .unwrap_or_else(|e| {
            eprintln!("error: failed to create gate client: {e}");
            std::process::exit(1);
        });

        McpServer::operator(client, admin, args.agent_id, args.enable_allowlist_tool)
            .run()
            .await;
    }
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
