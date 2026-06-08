//! Learned domain management — kernel facade.
//!
//! Wraps `LedgerStore` domain operations with `spawn_blocking` so the API
//! layer never imports `latchgate-ledger` directly.

use std::sync::Arc;

use crate::AppState;
use latchgate_ledger::EntrySource;

/// A learned domain entry returned from the ledger.
pub use latchgate_ledger::LearnedDomain;

/// Re-export `EntrySource` so the API layer doesn't need `latchgate-ledger`.
pub use latchgate_ledger::EntrySource as DomainAddSource;

/// List learned domains, optionally filtered by action_id.
pub async fn list(
    state: &AppState,
    action_filter: Option<&str>,
) -> Result<Vec<LearnedDomain>, String> {
    let ledger = Arc::clone(&state.ledger);
    let filter = action_filter.map(String::from);
    tokio::task::spawn_blocking(move || ledger.list_learned_domains(filter.as_deref()))
        .await
        .map_err(|e| format!("list_domains task panicked: {e}"))?
        .map_err(|e| format!("list_domains ledger error: {e}"))
}

/// Add a learned domain for an action. Returns `true` if newly inserted.
pub async fn add(
    state: &AppState,
    action_id: &str,
    domain: &str,
    operator_id: &str,
    source: EntrySource,
    approval_id: Option<&str>,
) -> Result<bool, String> {
    let ledger = Arc::clone(&state.ledger);
    let aid = action_id.to_string();
    let dom = domain.to_string();
    let op = operator_id.to_string();
    let appr = approval_id.map(String::from);
    tokio::task::spawn_blocking(move || {
        ledger.add_learned_domain(&aid, &dom, &op, source, appr.as_deref(), false)
    })
    .await
    .map_err(|e| format!("add_domain task panicked: {e}"))?
    .map_err(|e| format!("add_domain ledger error: {e}"))
}

/// Remove a learned domain. Returns `true` if a row was deleted.
pub async fn remove(state: &AppState, action_id: &str, domain: &str) -> Result<bool, String> {
    let ledger = Arc::clone(&state.ledger);
    let aid = action_id.to_string();
    let dom = domain.to_string();
    tokio::task::spawn_blocking(move || ledger.remove_learned_domain(&aid, &dom))
        .await
        .map_err(|e| format!("remove_domain task panicked: {e}"))?
        .map_err(|e| format!("remove_domain ledger error: {e}"))
}

/// Clear all learned domains for an action. Returns count deleted.
pub async fn clear_for_action(state: &AppState, action_id: &str) -> Result<usize, String> {
    let ledger = Arc::clone(&state.ledger);
    let aid = action_id.to_string();
    tokio::task::spawn_blocking(move || ledger.clear_learned_domains_for_action(&aid))
        .await
        .map_err(|e| format!("clear_domains task panicked: {e}"))?
        .map_err(|e| format!("clear_domains ledger error: {e}"))
}
