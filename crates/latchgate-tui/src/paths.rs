//! Learned Paths — Allowlists sub-tab.
//!
//! Thin entity definition over [`LearnedListScreen`]. All shared state,
//! rendering, key handling, and tick logic live in [`super::learned_list`].
//!
//! Data sources:
//! - `GateClient::list_actions()` — action ID list for the action selector.
//! - `GateClient::list_paths(auth, action_filter)` — paths per action.
//! - `GateClient::add_path(auth, action_id, path_glob)` — add entry.
//! - `GateClient::remove_path(auth, action_id, path_glob)` — remove entry.
//! - `GateClient::clear_paths(auth, action_id)` — remove all for action.

use serde_json::Value;

use latchgate_client::{ClientError, GateClient, OperatorAuth};

use super::learned_list::{LearnedEntity, LearnedListScreen};

// PathEntity

/// Marker type carrying path-specific display config and CRUD bindings.
pub(crate) struct PathEntity;

impl LearnedEntity for PathEntity {
    const TAB_LABEL: &'static str = "Paths";
    const ENTITY_NOUN: &'static str = "path";
    const ENTITY_NOUN_PLURAL: &'static str = "paths";
    const PRIMARY_HEADER: &'static str = " Path glob";
    const PRIMARY_MIN_WIDTH: u16 = 24;
    const JSON_FIELD: &'static str = "path_glob";
    const ADD_PROMPT: &'static str = " Add path glob (Enter to submit, Esc to cancel) ";
    const ADD_MAX_LEN: usize = 512;
    const EMPTY_MESSAGE: &'static str = "No learned paths for this action.";
    const STATUS_HINT: &'static str =
        "[a]dd  [x]remove  [c]lear  [/]jump  [←=>]action  [↑↓]navigate  [q]uit";

    const HELP_KEYS: &'static [(&'static str, &'static str)] = &[
        ("←/h", "Previous action"),
        ("=>/l", "Next action"),
        ("/", "Filter actions by name (↑↓ select, Enter go)"),
        ("↑/k", "Move cursor up"),
        ("↓/j", "Move cursor down"),
        ("a", "Add path glob"),
        ("x", "Remove selected path"),
        ("c", "Clear all paths for action"),
    ];

    fn list<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_filter: Option<&'a str>,
    ) -> impl std::future::Future<Output = Result<Vec<Value>, ClientError>> + Send + 'a {
        client.list_paths(auth, action_filter)
    }

    fn add<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
        value: &'a str,
    ) -> impl std::future::Future<Output = Result<Value, ClientError>> + Send + 'a {
        client.add_path(auth, action_id, value)
    }

    fn remove<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
        value: &'a str,
    ) -> impl std::future::Future<Output = Result<Value, ClientError>> + Send + 'a {
        client.remove_path(auth, action_id, value)
    }

    fn clear<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
    ) -> impl std::future::Future<Output = Result<Value, ClientError>> + Send + 'a {
        client.clear_paths(auth, action_id)
    }
}

// Public alias — preserves the API consumed by app.rs

pub(crate) type PathsScreen = LearnedListScreen<PathEntity>;
