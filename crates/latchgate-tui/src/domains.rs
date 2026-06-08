//! Learned Domains — Allowlists sub-tab.
//!
//! Thin entity definition over [`LearnedListScreen`]. All shared state,
//! rendering, key handling, and tick logic live in [`super::learned_list`].
//!
//! Data sources:
//! - `GateClient::list_actions()` — action ID list for the action selector.
//! - `GateClient::list_domains(auth, action_filter)` — domains per action.
//! - `GateClient::add_domain(auth, action_id, domain)` — add entry.
//! - `GateClient::remove_domain(auth, action_id, domain)` — remove entry.
//! - `GateClient::clear_domains(auth, action_id)` — remove all for action.

use serde_json::Value;

use latchgate_client::{ClientError, GateClient, OperatorAuth};

use super::learned_list::{LearnedEntity, LearnedListScreen};

// DomainEntity

/// Marker type carrying domain-specific display config and CRUD bindings.
pub(crate) struct DomainEntity;

impl LearnedEntity for DomainEntity {
    const TAB_LABEL: &'static str = "Domains";
    const ENTITY_NOUN: &'static str = "domain";
    const ENTITY_NOUN_PLURAL: &'static str = "domains";
    const PRIMARY_HEADER: &'static str = " Domain";
    const PRIMARY_MIN_WIDTH: u16 = 20;
    const JSON_FIELD: &'static str = "domain";
    const ADD_PROMPT: &'static str = " Add domain (Enter to submit, Esc to cancel) ";
    const ADD_MAX_LEN: usize = 253;
    const EMPTY_MESSAGE: &'static str = "No learned domains for this action.";
    const STATUS_HINT: &'static str =
        "[a]dd  [x]remove  [c]lear  [/]jump  [←=>]action  [↑↓]navigate  [q]uit";

    const HELP_KEYS: &'static [(&'static str, &'static str)] = &[
        ("←/h", "Previous action"),
        ("=>/l", "Next action"),
        ("/", "Filter actions by name (↑↓ select, Enter go)"),
        ("↑/k", "Move cursor up"),
        ("↓/j", "Move cursor down"),
        ("a", "Add domain"),
        ("x", "Remove selected domain"),
        ("c", "Clear all domains for action"),
    ];

    fn list<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_filter: Option<&'a str>,
    ) -> impl std::future::Future<Output = Result<Vec<Value>, ClientError>> + Send + 'a {
        client.list_domains(auth, action_filter)
    }

    fn add<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
        value: &'a str,
    ) -> impl std::future::Future<Output = Result<Value, ClientError>> + Send + 'a {
        client.add_domain(auth, action_id, value)
    }

    fn remove<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
        value: &'a str,
    ) -> impl std::future::Future<Output = Result<Value, ClientError>> + Send + 'a {
        client.remove_domain(auth, action_id, value)
    }

    fn clear<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
    ) -> impl std::future::Future<Output = Result<Value, ClientError>> + Send + 'a {
        client.clear_domains(auth, action_id)
    }
}

// Public alias — preserves the API consumed by app.rs

pub(crate) type DomainsScreen = LearnedListScreen<DomainEntity>;
