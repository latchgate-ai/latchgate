//! `latchgate approvals` — operator approval workflow.
//!
//! Reference operator interface for the human-in-the-loop approval model.
//! All commands are thin wrappers around the Approval API — no approval
//! logic runs locally. The CLI authenticates, fetches, renders, and submits.
//!
//! For an interactive real-time interface, see `latchgate tui`.

use serde_json::json;

use latchgate_config::Config;

use crate::client::{GateClient, OperatorAuth};
use crate::cmd::text::truncate;
use crate::output::{print_json, Printer};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ApprovalsCommand {
    /// List pending approvals.
    ///
    /// Shows a summary table of approvals awaiting operator review.
    /// Use --all to include completed (approved/denied/failed) approvals.
    List {
        /// Show all approvals, not just pending.
        #[arg(long)]
        all: bool,

        /// Maximum number of results.
        #[arg(long, short, default_value = "50", value_name = "N")]
        limit: usize,
    },

    /// Show full detail of a pending approval for review.
    ///
    /// Displays the immutable execution plan: what action, what targets,
    /// what secrets (names only), what budget, when it expires.
    Show {
        /// Approval ID to inspect.
        #[arg(value_name = "APPROVAL_ID")]
        id: String,
    },

    /// Approve a pending action and trigger execution.
    ///
    /// The approved plan is executed through the hardened kernel path.
    /// Produces a signed receipt and audit evidence.
    /// Prompts for confirmation unless --yes is given.
    Approve {
        /// Approval ID to approve.
        #[arg(value_name = "APPROVAL_ID")]
        id: String,

        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,

        /// Learn a domain for future use by this action.
        ///
        /// After successful execution, the specified domain is added to the
        /// action's learned domains. Future requests to this domain will be
        /// allowed without re-approval. Per-action isolation applies.
        #[arg(long, value_name = "DOMAIN")]
        learn_domain: Option<String>,
    },

    /// Deny a pending action without execution.
    ///
    /// The approval is atomically marked as denied. No side effect occurs.
    Deny {
        /// Approval ID to deny.
        #[arg(value_name = "APPROVAL_ID")]
        id: String,

        /// Reason for denial (recorded in audit trail).
        #[arg(long, short, value_name = "REASON")]
        reason: Option<String>,
    },
}

/// Run an approvals subcommand. Returns exit code.
pub async fn run(
    config: &Config,
    auth: &OperatorAuth,
    command: &ApprovalsCommand,
    pr: &Printer,
) -> i32 {
    match command {
        ApprovalsCommand::List { all, limit } => run_list(config, auth, *all, *limit, pr).await,
        ApprovalsCommand::Show { id } => run_show(config, auth, id, pr).await,
        ApprovalsCommand::Approve {
            id,
            yes,
            learn_domain,
        } => run_approve(config, auth, id, *yes, learn_domain.as_deref(), pr).await,
        ApprovalsCommand::Deny { id, reason } => {
            run_deny(config, auth, id, reason.as_deref(), pr).await
        }
    }
}

async fn run_list(
    config: &Config,
    auth: &OperatorAuth,
    all: bool,
    limit: usize,
    pr: &Printer,
) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };
    let status_filter = if all { None } else { Some("pending") };

    let approvals = match client
        .list_approvals(auth, status_filter, Some(limit))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Cannot list approvals: {e}"));
                pr.blank();
            }
            return 1;
        }
    };

    if pr.json {
        print_json(&json!({ "approvals": approvals }));
        return 0;
    }

    pr.blank();

    if approvals.is_empty() {
        pr.info(if all {
            "No approvals found."
        } else {
            "No pending approvals."
        });
        pr.blank();
        return 0;
    }

    // Column widths.
    let id_w = approvals
        .iter()
        .filter_map(|a| a["approval_id"].as_str())
        .map(|s| s.len().min(12))
        .max()
        .unwrap_or(12)
        .max(8);
    let act_w = approvals
        .iter()
        .filter_map(|a| a["action_id"].as_str())
        .map(|s| s.len())
        .max()
        .unwrap_or(9)
        .max(6);

    // Header.
    println!(
        "  {id:<id_w$}  {state:<9}  {risk:<8}  {action:<act_w$}  {principal}",
        id = pr.dim("approval"),
        state = pr.dim("status"),
        risk = pr.dim("risk"),
        action = pr.dim("action"),
        principal = pr.dim("requested_by"),
    );
    println!(
        "  {}  {}  {}  {}  {}",
        pr.dim(&"─".repeat(id_w)),
        pr.dim(&"─".repeat(9)),
        pr.dim(&"─".repeat(8)),
        pr.dim(&"─".repeat(act_w)),
        pr.dim(&"─".repeat(20)),
    );

    for a in &approvals {
        let id = a["approval_id"].as_str().unwrap_or("?");
        let id_short = &id[..id.len().min(id_w)];
        let state = a["status"].as_str().unwrap_or("?");
        let risk = a["risk_level"].as_str().unwrap_or("?");
        let action = a["action_id"].as_str().unwrap_or("-");
        let principal = a["principal"].as_str().unwrap_or("-");

        let state_col = match state {
            "pending" => pr.yellow(state),
            "claimed" => pr.yellow("claimed"),
            "approved" => pr.green(state),
            "denied" => pr.red(state),
            "failed" => pr.red(state),
            other => pr.dim(other),
        };

        let risk_col = match risk {
            "high" | "critical" => pr.red(risk),
            "medium" => pr.yellow(risk),
            _ => pr.green(risk),
        };

        println!(
            "  {id:<id_w$}  {state:<9}  {risk:<8}  {action:<act_w$}  {principal}",
            id = pr.dim(id_short),
            state = state_col,
            risk = risk_col,
            action = action,
            principal = pr.dim(&truncate(principal, 20)),
        );
    }

    println!(
        "\n  {} approval(s){}",
        approvals.len(),
        if approvals.len() >= limit {
            format!(
                "  ·  {}",
                pr.dim(&format!("showing latest {limit}; use --limit for more"))
            )
        } else {
            String::new()
        },
    );
    pr.blank();
    0
}

async fn run_show(config: &Config, auth: &OperatorAuth, id: &str, pr: &Printer) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    let detail = match client.get_approval(auth, id).await {
        Ok(d) => d,
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Cannot fetch approval: {e}"));
                pr.blank();
            }
            return 1;
        }
    };

    if pr.json {
        print_json(&detail);
        return 0;
    }

    pr.blank();

    let state = detail["status"].as_str().unwrap_or("?");
    let state_display = match state {
        "pending" => pr.yellow("PENDING"),
        "claimed" => pr.yellow("CLAIMED"),
        "approved" => pr.green("APPROVED"),
        "denied" => pr.red("DENIED"),
        "failed" => pr.red("FAILED"),
        other => other.to_string(),
    };

    pr.section(&format!("Approval {}", &id[..id.len().min(12)]));
    pr.blank();

    pr.table(&[
        ("status", &state_display),
        ("action", detail["action_id"].as_str().unwrap_or("-")),
        ("version", detail["action_version"].as_str().unwrap_or("-")),
        ("risk_level", detail["risk_level"].as_str().unwrap_or("-")),
        ("requested_by", detail["principal"].as_str().unwrap_or("-")),
        ("session", detail["session_id"].as_str().unwrap_or("-")),
    ]);

    pr.blank();

    // Targets / secrets / egress.
    if let Some(targets) = detail["approved_targets"].as_array() {
        let t: Vec<&str> = targets.iter().filter_map(|v| v.as_str()).collect();
        pr.table(&[("targets", &t.join(", "))]);
    }
    if let Some(secrets) = detail["approved_secrets"].as_array() {
        let s: Vec<&str> = secrets.iter().filter_map(|v| v.as_str()).collect();
        if s.is_empty() {
            pr.table(&[("secrets", "(none)")]);
        } else {
            pr.table(&[("secrets", &s.join(", "))]);
        }
    }
    if let Some(egress) = detail.get("approved_egress") {
        let e_str = if egress.is_string() {
            egress.as_str().unwrap_or("?").to_string()
        } else {
            serde_json::to_string(egress).unwrap_or_else(|_| "?".into())
        };
        pr.table(&[("egress", &e_str)]);
    }

    // Database-specific review (when present).
    if let Some(db) = detail.get("database_review") {
        pr.blank();
        pr.section("Database");
        pr.blank();

        let mut db_rows: Vec<(&str, String)> = Vec::new();
        if let Some(v) = db["database_mode"].as_str() {
            db_rows.push(("db_mode", v.to_string()));
        }
        if let Some(v) = db["statement_mode"].as_str() {
            db_rows.push(("stmt_mode", v.to_string()));
        }
        if let Some(v) = db["statement_id"].as_str() {
            db_rows.push(("statement_id", v.to_string()));
        }
        if let Some(v) = db["operation_class"].as_str() {
            let display = match v {
                "update" | "delete" => pr.yellow(v),
                "ddl" | "grant_revoke" | "unknown" | "multi_statement" => pr.red(v),
                _ => v.to_string(),
            };
            db_rows.push(("operation", display));
        }
        if let Some(tables) = db["tables"].as_array() {
            let t: Vec<&str> = tables.iter().filter_map(|v| v.as_str()).collect();
            if !t.is_empty() {
                db_rows.push(("tables", t.join(", ")));
            }
        }
        if let Some(params) = db["params_preview"].as_array() {
            let p: Vec<&str> = params.iter().filter_map(|v| v.as_str()).collect();
            if !p.is_empty() {
                db_rows.push(("params", p.join(", ")));
            }
        }
        if let Some(v) = db["query_shape"].as_str() {
            db_rows.push(("query", truncate(v, 60)));
        }

        let refs: Vec<(&str, &str)> = db_rows.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pr.table(&refs);
    }

    pr.blank();

    // Budget.
    if let Some(budget) = detail.get("budget_snapshot") {
        let calls = budget["calls_remaining"]
            .as_i64()
            .map(|c| {
                if c == i64::MAX {
                    "unlimited".to_string()
                } else {
                    c.to_string()
                }
            })
            .unwrap_or_else(|| "-".into());
        pr.table(&[("budget_calls", &calls)]);
    }

    // Timing / integrity.
    if detail.get("expires_at").is_some() || detail.get("plan_hash").is_some() {
        pr.blank();
        let mut rows: Vec<(&str, String)> = Vec::new();
        if let Some(v) = detail["expires_at"].as_str() {
            rows.push(("expires_at", v.to_string()));
        }
        if let Some(v) = detail["verifier_kind"].as_str() {
            rows.push(("verifier", v.to_string()));
        }
        if let Some(v) = detail["provider_module_digest"].as_str() {
            rows.push(("provider", truncate(v, 48)));
        }
        if let Some(v) = detail["plan_hash"].as_str() {
            rows.push(("plan_hash", truncate(v, 48)));
        }
        if let Some(v) = detail["request_hash"].as_str() {
            rows.push(("request_hash", truncate(v, 48)));
        }
        let refs: Vec<(&str, &str)> = rows.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pr.table(&refs);
    }

    // Lifecycle.
    if let Some(claimed_by) = detail["claimed_by"].as_str() {
        pr.blank();
        pr.table(&[("claimed_by", claimed_by)]);
    }
    if let Some(completed_at) = detail["completed_at"].as_str() {
        pr.table(&[("completed_at", completed_at)]);
    }

    pr.blank();
    0
}

async fn run_approve(
    config: &Config,
    auth: &OperatorAuth,
    id: &str,
    yes: bool,
    learn_domain: Option<&str>,
    pr: &Printer,
) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    // Fetch the detail so the operator can see what they're approving.
    let detail = match client.get_approval(auth, id).await {
        Ok(d) => d,
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Cannot fetch approval: {e}"));
                pr.blank();
            }
            return 1;
        }
    };

    // Resolve learn_domain: explicit flag takes precedence, otherwise
    // detect from unresolved_domains in the approval detail and prompt.
    let effective_learn_domain: Option<String> = if learn_domain.is_some() {
        learn_domain.map(|s| s.to_string())
    } else if !yes && !pr.json {
        // Auto-detect: if the pending approval was triggered by an unknown
        // domain, offer to learn it. This makes the common case (agent hits
        // new URL => operator approves => domain remembered) a single flow.
        detail
            .get("unresolved_domains")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };

    // Confirmation gate.
    if !yes && !pr.json {
        pr.blank();
        eprintln!(
            "  {}  About to approve: {} ({})",
            pr.warn_sym(),
            pr.bold(detail["action_id"].as_str().unwrap_or("?")),
            detail["risk_level"].as_str().unwrap_or("?"),
        );
        if let Some(targets) = detail["approved_targets"].as_array() {
            let t: Vec<&str> = targets.iter().filter_map(|v| v.as_str()).collect();
            eprintln!("     targets: {}", t.join(", "));
        }
        // Unresolved domains: show prominently so the operator knows why
        // this approval was triggered.
        if let Some(domains) = detail.get("unresolved_domains").and_then(|v| v.as_array()) {
            let ds: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();
            if !ds.is_empty() {
                eprintln!(
                    "     {} unknown domain: {}",
                    pr.warn_sym(),
                    pr.bold(&ds.join(", "))
                );
            }
        }
        // Database summary for informed approval.
        if let Some(db) = detail.get("database_review") {
            let mode = db["statement_mode"].as_str().unwrap_or("?");
            let op = db["operation_class"].as_str().unwrap_or("?");
            let tables: Vec<&str> = db["tables"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            eprintln!("     database: {} {} on [{}]", mode, op, tables.join(", "));
            if let Some(sid) = db["statement_id"].as_str() {
                eprintln!("     statement: {sid}");
            }
            if let Some(q) = db["query_shape"].as_str() {
                eprintln!("     query: {}", truncate(q, 60));
            }
        }
        eprintln!(
            "     requested by: {}",
            detail["principal"].as_str().unwrap_or("?")
        );
        if let Some(ref domain) = effective_learn_domain {
            eprintln!("     {}", pr.bold(&format!("learn domain: {domain}")));
        }
        pr.blank();
        eprint!(
            "  Type {} to confirm, anything else to cancel: ",
            pr.bold("yes")
        );

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() || line.trim() != "yes" {
            pr.blank();
            pr.info("Approval cancelled.");
            pr.blank();
            return 0;
        }

        // If we auto-detected a domain, ask whether to remember it.
        // The operator already confirmed the approve — this is the learning
        // decision only. Explicit --learn-domain skips this (already decided).
        if learn_domain.is_none() {
            if let Some(ref domain) = effective_learn_domain {
                let action_id = detail["action_id"].as_str().unwrap_or("?");
                pr.blank();
                eprint!(
                    "  Remember '{}' for future {} calls? [y/n] ",
                    pr.bold(domain),
                    pr.bold(action_id),
                );
                let mut ans = String::new();
                let learn = std::io::stdin().read_line(&mut ans).is_ok()
                    && ans.trim().eq_ignore_ascii_case("y");
                if !learn {
                    // Approve without learning — one-time only.
                    // Shadow effective_learn_domain to None.
                    return submit_approve(&client, auth, id, None, pr).await;
                }
            }
        }
    }

    // Submit.
    submit_approve(&client, auth, id, effective_learn_domain.as_deref(), pr).await
}

async fn submit_approve(
    client: &GateClient,
    auth: &OperatorAuth,
    id: &str,
    learn_domain: Option<&str>,
    pr: &Printer,
) -> i32 {
    match client.approve_approval(auth, id, learn_domain, None).await {
        Ok(result) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "approval_id": id,
                    "result": result,
                }));
                return 0;
            }

            pr.blank();
            pr.success("Approval executed.");
            pr.blank();

            let mut rows = vec![("approval_id", id.to_string())];
            if let Some(v) = result["approved_by"].as_str() {
                rows.push(("approved_by", v.to_string()));
            }
            if let Some(v) = result["receipt_id"].as_str() {
                rows.push(("receipt_id", v.to_string()));
            }
            if let Some(v) = result["trace_id"].as_str() {
                rows.push(("trace_id", v.to_string()));
            }
            if let Some(v) = result["grant_id"].as_str() {
                rows.push(("grant_id", v.to_string()));
            }
            let outcome = result["verification"]["outcome"].as_str().unwrap_or("-");
            rows.push(("verification", outcome.to_string()));
            if let Some(v) = result["learned_domain"].as_str() {
                rows.push(("learned_domain", v.to_string()));
            }
            let refs: Vec<(&str, &str)> = rows.iter().map(|(k, v)| (*k, v.as_str())).collect();
            pr.table(&refs);
            pr.blank();
            0
        }
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "approval_id": id, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Approve failed: {e}"));
                pr.blank();
            }
            1
        }
    }
}

async fn run_deny(
    config: &Config,
    auth: &OperatorAuth,
    id: &str,
    reason: Option<&str>,
    pr: &Printer,
) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    match client.deny_approval(auth, id, reason).await {
        Ok(result) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "approval_id": id,
                    "result": result,
                }));
                return 0;
            }

            pr.blank();
            pr.success("Approval denied.");
            pr.blank();

            let mut rows = vec![("approval_id", id.to_string())];
            if let Some(v) = result["denied_by"].as_str() {
                rows.push(("denied_by", v.to_string()));
            }
            if let Some(v) = result["deny_reason"].as_str() {
                rows.push(("reason", v.to_string()));
            }
            let refs: Vec<(&str, &str)> = rows.iter().map(|(k, v)| (*k, v.as_str())).collect();
            pr.table(&refs);
            pr.blank();
            0
        }
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "approval_id": id, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Deny failed: {e}"));
                pr.blank();
            }
            1
        }
    }
}
