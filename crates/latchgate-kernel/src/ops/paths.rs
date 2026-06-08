//! Learned path management — kernel facade.

use std::sync::Arc;

use crate::AppState;
use latchgate_ledger::EntrySource;

pub use latchgate_ledger::EntrySource as PathAddSource;
pub use latchgate_ledger::LearnedPath;

pub async fn list(
    state: &AppState,
    action_filter: Option<&str>,
) -> Result<Vec<LearnedPath>, String> {
    let ledger = Arc::clone(&state.ledger);
    let filter = action_filter.map(String::from);
    tokio::task::spawn_blocking(move || ledger.list_learned_paths(filter.as_deref()))
        .await
        .map_err(|e| format!("list_paths task panicked: {e}"))?
        .map_err(|e| format!("list_paths ledger error: {e}"))
}

pub async fn add(
    state: &AppState,
    action_id: &str,
    path_glob: &str,
    operator_id: &str,
    source: EntrySource,
    approval_id: Option<&str>,
) -> Result<bool, String> {
    let ledger = Arc::clone(&state.ledger);
    let aid = action_id.to_string();
    let pg = path_glob.to_string();
    let op = operator_id.to_string();
    let appr = approval_id.map(String::from);
    tokio::task::spawn_blocking(move || {
        ledger.add_learned_path(&aid, &pg, &op, source, appr.as_deref())
    })
    .await
    .map_err(|e| format!("add_path task panicked: {e}"))?
    .map_err(|e| format!("add_path ledger error: {e}"))
}

pub async fn remove(state: &AppState, action_id: &str, path_glob: &str) -> Result<bool, String> {
    let ledger = Arc::clone(&state.ledger);
    let aid = action_id.to_string();
    let pg = path_glob.to_string();
    tokio::task::spawn_blocking(move || ledger.remove_learned_path(&aid, &pg))
        .await
        .map_err(|e| format!("remove_path task panicked: {e}"))?
        .map_err(|e| format!("remove_path ledger error: {e}"))
}

pub async fn clear_for_action(state: &AppState, action_id: &str) -> Result<usize, String> {
    let ledger = Arc::clone(&state.ledger);
    let aid = action_id.to_string();
    tokio::task::spawn_blocking(move || ledger.clear_learned_paths_for_action(&aid))
        .await
        .map_err(|e| format!("clear_paths task panicked: {e}"))?
        .map_err(|e| format!("clear_paths ledger error: {e}"))
}

/// Validate a path glob. Delegates to [`latchgate_ledger::validate_path_glob`].
pub fn validate_path_glob(path_glob: &str) -> Result<(), String> {
    latchgate_ledger::validate_path_glob(path_glob).map_err(|e| e.to_string())
}
