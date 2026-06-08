//! Generic learned-list screen for per-action CRUD entities.
//!
//! Domains and Paths share an identical state machine: fetch action IDs, let
//! the operator cycle through actions with `←`/`=>`, display the entity list,
//! and provide add / remove / clear mutations. The only differences are the
//! entity noun, JSON field name, table header, input constraints, and which
//! [`GateClient`] methods to call.
//!
//! This module captures the shared logic in [`LearnedListScreen<E>`], driven
//! by the [`LearnedEntity`] trait that supplies the per-entity configuration
//! and CRUD bindings.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row};
use ratatui::Frame;
use serde_json::Value;

use latchgate_client::{ClientError, GateClient, OperatorAuth};

use super::formatting::truncate;
use super::input::{FlashMessage, InputAction, TextInput};
use super::screen::{ScreenAction, TuiScreen};
use super::theme::Theme;
use super::widgets::{EmptyState, ScrollableTable};

// LearnedEntity — per-entity configuration + CRUD bindings

/// Entity-specific display configuration and client method bindings.
///
/// Implementors are zero-sized marker types (e.g. `DomainEntity`, `PathEntity`)
/// whose only job is to carry associated constants and forward CRUD calls to
/// the matching [`GateClient`] methods.
pub(crate) trait LearnedEntity: Send + 'static {
    /// Tab label in the chrome nav bar (e.g. `"Domains"`).
    const TAB_LABEL: &'static str;

    /// Singular noun for flash messages (e.g. `"domain"`).
    const ENTITY_NOUN: &'static str;

    /// Plural noun for titles and empty states (e.g. `"domains"`).
    const ENTITY_NOUN_PLURAL: &'static str;

    /// Table column header for the primary field (e.g. `" Domain"`).
    const PRIMARY_HEADER: &'static str;

    /// Minimum width for the primary column in the table.
    const PRIMARY_MIN_WIDTH: u16;

    /// JSON field name to extract the primary value from API responses.
    const JSON_FIELD: &'static str;

    /// Prompt shown in the add-entry input bar.
    const ADD_PROMPT: &'static str;

    /// Maximum character length for the add-entry input.
    const ADD_MAX_LEN: usize;

    /// Message shown when the list is empty.
    const EMPTY_MESSAGE: &'static str;

    /// Status bar key hints.
    const STATUS_HINT: &'static str;

    /// Help overlay key descriptions.
    const HELP_KEYS: &'static [(&'static str, &'static str)];

    /// List entities for an action (or all actions if filter is `None`).
    fn list<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_filter: Option<&'a str>,
    ) -> impl Future<Output = Result<Vec<Value>, ClientError>> + Send + 'a;

    /// Add an entity for an action.
    fn add<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
        value: &'a str,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send + 'a;

    /// Remove an entity from an action.
    fn remove<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
        value: &'a str,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send + 'a;

    /// Clear all entities for an action.
    fn clear<'a>(
        client: &'a GateClient,
        auth: &'a OperatorAuth,
        action_id: &'a str,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send + 'a;
}

// Pending mutations

enum Mutation {
    Add(String),
    Remove(String),
    Clear,
}

/// Maximum number of match rows shown in the live jump-filter list.
const MAX_JUMP_ROWS: usize = 8;

// LearnedListScreen

/// Generic CRUD screen for per-action learned entities.
///
/// Type parameter `E` carries the entity-specific configuration; the screen
/// struct holds all shared state. Construct with [`new`](Self::new) and
/// register as any other [`TuiScreen`].
pub(crate) struct LearnedListScreen<E: LearnedEntity> {
    action_ids: Vec<String>,
    active_action_idx: usize,
    items: Vec<Value>,
    selected: usize,
    add_input: Option<TextInput>,
    /// Active "jump to action" filter input (opened with `/`).
    jump_input: Option<TextInput>,
    /// Indices into `action_ids` matching the current jump query, in order.
    /// Recomputed each time the query changes. Empty query ⇒ all actions.
    jump_matches: Vec<usize>,
    /// Selected row within `jump_matches` while the jump filter is open.
    jump_selected: usize,
    /// Last jump query the match list was computed for — lets the live filter
    /// detect buffer changes without re-scanning on every keystroke.
    jump_query: String,
    confirm_clear: bool,
    confirm_remove: bool,
    pending: Option<Mutation>,
    error: Option<String>,
    actions_fetched: bool,
    _entity: PhantomData<E>,
}

impl<E: LearnedEntity> LearnedListScreen<E> {
    pub fn new() -> Self {
        Self {
            action_ids: Vec::new(),
            active_action_idx: 0,
            items: Vec::new(),
            selected: 0,
            add_input: None,
            jump_input: None,
            jump_matches: Vec::new(),
            jump_selected: 0,
            jump_query: String::new(),
            confirm_clear: false,
            confirm_remove: false,
            pending: None,
            error: None,
            actions_fetched: false,
            _entity: PhantomData,
        }
    }

    fn active_action_id(&self) -> Option<&str> {
        self.action_ids
            .get(self.active_action_idx)
            .map(String::as_str)
    }

    fn selected_value(&self) -> Option<&str> {
        self.items
            .get(self.selected)
            .and_then(|v| v[E::JSON_FIELD].as_str())
    }

    fn switch_action(&mut self, delta: isize) {
        if self.action_ids.is_empty() {
            return;
        }
        let len = self.action_ids.len() as isize;
        let new = (self.active_action_idx as isize + delta).rem_euclid(len) as usize;
        self.active_action_idx = new;
        self.items.clear();
        self.selected = 0;
    }

    /// Recompute `jump_matches` for `query` (case-insensitive substring).
    /// An empty query matches all actions. Resets `jump_selected` to the top
    /// and records the query so the live filter can detect changes cheaply.
    fn recompute_jump_matches(&mut self, query: &str) {
        let needle = query.trim().to_ascii_lowercase();
        self.jump_matches = self
            .action_ids
            .iter()
            .enumerate()
            .filter(|(_, id)| needle.is_empty() || id.to_ascii_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect();
        self.jump_selected = 0;
        self.jump_query = query.to_string();
    }

    /// Switch the active action to `idx` (an index into `action_ids`),
    /// reloading the entity list on the next tick. No-op if already active.
    fn select_action(&mut self, idx: usize) {
        if idx < self.action_ids.len() && idx != self.active_action_idx {
            self.active_action_idx = idx;
            self.items.clear();
            self.selected = 0;
        }
    }

    /// Clamp `self.selected` to the current item list bounds.
    fn clamp_selection(&mut self) {
        if self.items.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.items.len() {
            self.selected = self.items.len() - 1;
        }
    }

    /// Render the live jump-filter match list: a bordered, scrollable window
    /// of matching action ids with the current selection highlighted.
    fn render_jump_matches(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_active);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        if self.jump_matches.is_empty() {
            frame.render_widget(
                Paragraph::new(Span::styled("(no matching actions)", theme.dim)),
                inner,
            );
            return;
        }

        // Scroll the visible window to keep the selection in view.
        let capacity = (inner.height as usize).min(MAX_JUMP_ROWS);
        let start = self
            .jump_selected
            .saturating_sub(capacity.saturating_sub(1))
            .min(self.jump_matches.len().saturating_sub(capacity));

        let lines: Vec<Line<'_>> = self
            .jump_matches
            .iter()
            .enumerate()
            .skip(start)
            .take(capacity)
            .map(|(row, &idx)| {
                let id = self.action_ids[idx].as_str();
                let selected = row == self.jump_selected;
                let marker = if selected { "▸ " } else { "  " };
                let style = if selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };
                Line::from(Span::styled(format!("{marker}{id}"), style))
            })
            .collect();

        frame.render_widget(Paragraph::new(lines), inner);
    }
}

// TuiScreen

impl<E: LearnedEntity> TuiScreen for LearnedListScreen<E> {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let action_label = self.active_action_id().unwrap_or("(none)");
        // Show the action position so the operator knows how many remain
        // (e.g. "web_read (12/87)") rather than cycling blind.
        let title = if self.action_ids.is_empty() {
            format!(" Learned {} — {} ", E::TAB_LABEL, action_label)
        } else {
            format!(
                " Learned {} — {} ◀ ▶ ({}/{})  [{} entr{}] ",
                E::TAB_LABEL,
                action_label,
                self.active_action_idx + 1,
                self.action_ids.len(),
                self.items.len(),
                if self.items.len() == 1 { "y" } else { "ies" },
            )
        };

        // Reserve a bottom strip for the add input or confirmation prompts.
        // The jump filter needs extra height for its live match list.
        let (table_area, bottom_area) = if self.jump_input.is_some() {
            // Input box (3) + up to MAX_JUMP_ROWS match rows inside a border.
            let visible = self.jump_matches.len().min(MAX_JUMP_ROWS) as u16;
            let strip = 3 + visible + 2; // input + rows + list border
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(strip)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else if self.add_input.is_some() || self.confirm_clear || self.confirm_remove {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(title);

        let inner = block.inner(table_area);
        frame.render_widget(block, table_area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        // Error takes priority over table content.
        if let Some(ref err) = self.error {
            frame.render_widget(
                Paragraph::new(Span::styled(err.as_str(), theme.status_error)),
                inner,
            );
        } else {
            let header = Row::new(vec![E::PRIMARY_HEADER, "Source", "Added by", "Added at"])
                .style(theme.header);

            let widths = [
                Constraint::Min(E::PRIMARY_MIN_WIDTH),
                Constraint::Length(10),
                Constraint::Length(14),
                Constraint::Length(20),
            ];

            let rows: Vec<Row<'_>> = self
                .items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let primary = item[E::JSON_FIELD].as_str().unwrap_or("-");
                    let source = item["source"].as_str().unwrap_or("-");
                    let added_by = item["added_by"].as_str().unwrap_or("-");
                    let added_at = item["added_at"]
                        .as_str()
                        .and_then(|s| s.get(..19))
                        .unwrap_or("-");

                    let base = if i == self.selected {
                        theme.selected.add_modifier(Modifier::BOLD)
                    } else {
                        ratatui::style::Style::default()
                    };

                    let marker = if i == self.selected { "▸" } else { " " };

                    Row::new(vec![
                        Line::from(Span::styled(format!("{marker} {primary}"), base)),
                        Line::from(Span::styled(source, base.patch(theme.dim))),
                        Line::from(Span::styled(truncate(added_by, 14), base.patch(theme.dim))),
                        Line::from(Span::styled(added_at, base.patch(theme.dim))),
                    ])
                })
                .collect();

            // When the action has no entries, hint how to add one and — if
            // there are other actions — how to jump to a different one.
            let empty_hint = if self.action_ids.len() > 1 {
                "[a] to add   [/] to find another action"
            } else {
                "[a] to add"
            };

            frame.render_widget(
                ScrollableTable::new(rows, widths)
                    .header(header)
                    .selected(self.selected)
                    .empty(EmptyState::new(E::EMPTY_MESSAGE, theme).hint(empty_hint)),
                inner,
            );
        }

        // Bottom panel: add input, jump filter + match list, or prompts.
        if let Some(ba) = bottom_area {
            if let Some(ref input) = self.add_input {
                input.render(ba, frame, theme);
            } else if let Some(ref input) = self.jump_input {
                // Input box on top, live match list below.
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(0)])
                    .split(ba);
                input.render(chunks[0], frame, theme);
                self.render_jump_matches(chunks[1], frame, theme);
            } else if self.confirm_remove {
                let value = self.selected_value().unwrap_or("?");
                let msg = format!(" Remove {} '{}'? [y/n] ", E::ENTITY_NOUN, value,);
                frame.render_widget(
                    Paragraph::new(Span::styled(msg, theme.status_warn)).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(theme.status_warn),
                    ),
                    ba,
                );
            } else if self.confirm_clear {
                let msg = format!(
                    " Clear all learned {} for {}? [y/n] ",
                    E::ENTITY_NOUN_PLURAL,
                    self.active_action_id().unwrap_or("?"),
                );
                frame.render_widget(
                    Paragraph::new(Span::styled(msg, theme.status_warn)).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(theme.status_warn),
                    ),
                    ba,
                );
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, _theme: &Theme) -> ScreenAction {
        // Remove confirmation mode.
        if self.confirm_remove {
            return match key.code {
                KeyCode::Char('y') => {
                    self.confirm_remove = false;
                    let value = match self.selected_value() {
                        Some(v) => v.to_string(),
                        None => return ScreenAction::EndInput,
                    };
                    self.pending = Some(Mutation::Remove(value));
                    ScreenAction::AsyncAction
                }
                _ => {
                    self.confirm_remove = false;
                    ScreenAction::EndInput
                }
            };
        }

        // Clear confirmation mode.
        if self.confirm_clear {
            return match key.code {
                KeyCode::Char('y') => {
                    self.confirm_clear = false;
                    self.pending = Some(Mutation::Clear);
                    ScreenAction::AsyncAction
                }
                _ => {
                    self.confirm_clear = false;
                    ScreenAction::EndInput
                }
            };
        }

        // Add input mode.
        if let Some(ref mut input) = self.add_input {
            return match input.handle_key(key) {
                InputAction::Submit(value) => {
                    let value = value.trim().to_string();
                    self.add_input = None;
                    if value.is_empty() {
                        ScreenAction::EndInput
                    } else {
                        self.pending = Some(Mutation::Add(value));
                        ScreenAction::AsyncAction
                    }
                }
                InputAction::Cancel => {
                    self.add_input = None;
                    ScreenAction::EndInput
                }
                InputAction::Continue => ScreenAction::Noop,
            };
        }

        // Jump-to-action filter mode: live, incremental match list.
        if self.jump_input.is_some() {
            // Up/Down move the selection within the current match list,
            // independent of the text cursor.
            match key.code {
                KeyCode::Up => {
                    self.jump_selected = self.jump_selected.saturating_sub(1);
                    return ScreenAction::Noop;
                }
                KeyCode::Down => {
                    if self.jump_selected + 1 < self.jump_matches.len() {
                        self.jump_selected += 1;
                    }
                    return ScreenAction::Noop;
                }
                _ => {}
            }

            // Feed the key to the input, then drop the borrow before touching
            // the rest of `self`.
            let input = self.jump_input.as_mut().expect("checked is_some above");
            let outcome = input.handle_key(key);
            let query = input.value().to_string();

            return match outcome {
                InputAction::Submit(_) => {
                    let target = self.jump_matches.get(self.jump_selected).copied();
                    if let Some(idx) = target {
                        self.select_action(idx);
                    }
                    self.jump_input = None;
                    ScreenAction::EndInput
                }
                InputAction::Cancel => {
                    self.jump_input = None;
                    ScreenAction::EndInput
                }
                InputAction::Continue => {
                    // Recompute the match list only when the query changed.
                    if query != self.jump_query {
                        self.recompute_jump_matches(&query);
                    }
                    ScreenAction::Noop
                }
            };
        }

        // Normal mode.
        match key.code {
            // Action selector.
            KeyCode::Left | KeyCode::Char('h') => {
                self.switch_action(-1);
                ScreenAction::Noop
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.switch_action(1);
                ScreenAction::Noop
            }

            // Jump to an action by substring (avoids cycling through dozens).
            KeyCode::Char('/') if !self.action_ids.is_empty() => {
                self.jump_input = Some(TextInput::new(
                    " Jump to action (type to filter, ↑↓ select, Enter go, Esc cancel) ",
                    64,
                ));
                // Seed the match list with all actions for an empty query.
                self.recompute_jump_matches("");
                ScreenAction::BeginInput
            }

            // Item navigation.
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.items.is_empty() && self.selected > 0 {
                    self.selected -= 1;
                }
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.items.len() {
                    self.selected += 1;
                }
                ScreenAction::Noop
            }

            // Add entry.
            KeyCode::Char('a') if self.active_action_id().is_some() => {
                self.add_input = Some(TextInput::new(E::ADD_PROMPT, E::ADD_MAX_LEN));
                ScreenAction::BeginInput
            }

            // Remove selected entry (with confirmation).
            KeyCode::Char('x') if self.selected_value().is_some() => {
                self.confirm_remove = true;
                ScreenAction::BeginInput
            }

            // Clear all entries for the active action.
            KeyCode::Char('c') if self.active_action_id().is_some() && !self.items.is_empty() => {
                self.confirm_clear = true;
                ScreenAction::BeginInput
            }

            _ => ScreenAction::Noop,
        }
    }

    fn handle_action<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> Pin<Box<dyn Future<Output = Option<FlashMessage>> + Send + 'a>> {
        Box::pin(async move {
            let mutation = self.pending.take()?;
            let action_id = self.active_action_id()?.to_string();

            match mutation {
                Mutation::Add(value) => match E::add(client, auth, &action_id, &value).await {
                    Ok(_) => Some(FlashMessage::success(format!(
                        "✓ Added {}: {value}",
                        E::ENTITY_NOUN,
                    ))),
                    Err(e) => Some(FlashMessage::error(format!("Add failed: {e}"))),
                },
                Mutation::Remove(value) => {
                    match E::remove(client, auth, &action_id, &value).await {
                        Ok(_) => Some(FlashMessage::success(format!(
                            "✓ Removed {}: {value}",
                            E::ENTITY_NOUN,
                        ))),
                        Err(e) => Some(FlashMessage::error(format!("Remove failed: {e}"))),
                    }
                }
                Mutation::Clear => match E::clear(client, auth, &action_id).await {
                    Ok(_) => Some(FlashMessage::success(format!(
                        "✓ Cleared all {} for {action_id}",
                        E::ENTITY_NOUN_PLURAL,
                    ))),
                    Err(e) => Some(FlashMessage::error(format!("Clear failed: {e}"))),
                },
            }
        })
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // Fetch the action ID list once.
            if !self.actions_fetched {
                match client.list_actions().await {
                    Ok(actions) => {
                        self.action_ids = actions
                            .iter()
                            .filter_map(|a| a["action_id"].as_str().map(str::to_string))
                            .collect();
                        self.actions_fetched = true;
                        if self.active_action_idx >= self.action_ids.len() {
                            self.active_action_idx = 0;
                        }
                    }
                    Err(e) => {
                        self.error = Some(format!("Actions: {e}"));
                        return;
                    }
                }
            }

            // Fetch entities for the active action.
            let filter = self.active_action_id().map(str::to_string);
            match E::list(client, auth, filter.as_deref()).await {
                Ok(list) => {
                    self.items = list;
                    self.error = None;
                    self.clamp_selection();
                }
                Err(ClientError::NotReachable(msg)) => {
                    self.error = Some(format!("Gate unreachable: {msg}"));
                }
                Err(ClientError::Http { status: 404, .. }) => {
                    // Action or entity not found — treat as empty.
                    self.items.clear();
                    self.error = None;
                    self.clamp_selection();
                }
                Err(ClientError::Http { status: 401, .. })
                | Err(ClientError::Http { status: 403, .. }) => {
                    self.error = Some(
                        "Not authorized — operator credentials required. \
                         Run `latchgate init` or pass --operator-key."
                            .into(),
                    );
                }
                Err(e) => {
                    self.error = Some(format!("Error: {e}"));
                }
            }
        })
    }

    fn tab_label(&self) -> &'static str {
        E::TAB_LABEL
    }

    fn is_modal(&self) -> bool {
        self.add_input.is_some()
            || self.jump_input.is_some()
            || self.confirm_remove
            || self.confirm_clear
    }

    fn status_hint(&self) -> &str {
        E::STATUS_HINT
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        E::HELP_KEYS
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal entity for exercising the shared screen logic. CRUD methods are
    /// never invoked by these tests (they target the pure filter/selection
    /// helpers), so they are left unimplemented.
    struct TestEntity;

    impl LearnedEntity for TestEntity {
        const TAB_LABEL: &'static str = "Test";
        const ENTITY_NOUN: &'static str = "entry";
        const ENTITY_NOUN_PLURAL: &'static str = "entries";
        const PRIMARY_HEADER: &'static str = " Value";
        const PRIMARY_MIN_WIDTH: u16 = 10;
        const JSON_FIELD: &'static str = "value";
        const ADD_PROMPT: &'static str = " Add ";
        const ADD_MAX_LEN: usize = 64;
        const EMPTY_MESSAGE: &'static str = "No entries";
        const STATUS_HINT: &'static str = "";
        const HELP_KEYS: &'static [(&'static str, &'static str)] = &[];

        async fn list<'a>(
            _c: &'a GateClient,
            _a: &'a OperatorAuth,
            _f: Option<&'a str>,
        ) -> Result<Vec<Value>, ClientError> {
            unreachable!("not exercised in tests")
        }
        async fn add<'a>(
            _c: &'a GateClient,
            _a: &'a OperatorAuth,
            _id: &'a str,
            _v: &'a str,
        ) -> Result<Value, ClientError> {
            unreachable!("not exercised in tests")
        }
        async fn remove<'a>(
            _c: &'a GateClient,
            _a: &'a OperatorAuth,
            _id: &'a str,
            _v: &'a str,
        ) -> Result<Value, ClientError> {
            unreachable!("not exercised in tests")
        }
        async fn clear<'a>(
            _c: &'a GateClient,
            _a: &'a OperatorAuth,
            _id: &'a str,
        ) -> Result<Value, ClientError> {
            unreachable!("not exercised in tests")
        }
    }

    fn screen_with_actions(ids: &[&str]) -> LearnedListScreen<TestEntity> {
        let mut s = LearnedListScreen::<TestEntity>::new();
        s.action_ids = ids.iter().map(|s| s.to_string()).collect();
        s.actions_fetched = true;
        s
    }

    #[test]
    fn empty_query_matches_all_actions() {
        let mut s = screen_with_actions(&["web_read", "slack_post", "fs_write"]);
        s.recompute_jump_matches("");
        assert_eq!(s.jump_matches, vec![0, 1, 2]);
        assert_eq!(s.jump_selected, 0);
    }

    #[test]
    fn filter_is_case_insensitive_substring() {
        let mut s = screen_with_actions(&["web_read", "WEB_write", "fs_read"]);
        s.recompute_jump_matches("web");
        assert_eq!(s.jump_matches, vec![0, 1]);

        s.recompute_jump_matches("READ");
        assert_eq!(s.jump_matches, vec![0, 2]);
    }

    #[test]
    fn filter_resets_selection_to_top() {
        let mut s = screen_with_actions(&["a", "b", "c"]);
        s.jump_selected = 2;
        s.recompute_jump_matches("");
        assert_eq!(s.jump_selected, 0, "recompute must reset selection");
    }

    #[test]
    fn no_match_yields_empty_list() {
        let mut s = screen_with_actions(&["web_read", "fs_write"]);
        s.recompute_jump_matches("zzz");
        assert!(s.jump_matches.is_empty());
    }

    #[test]
    fn select_action_switches_and_resets_items() {
        let mut s = screen_with_actions(&["a", "b", "c"]);
        s.selected = 3;
        s.items = vec![serde_json::json!({"value": "x"})];

        s.select_action(2);
        assert_eq!(s.active_action_idx, 2);
        assert_eq!(s.selected, 0, "switching action resets the item cursor");
        assert!(s.items.is_empty(), "items cleared to reload on next tick");
    }

    #[test]
    fn select_action_is_noop_for_current_or_out_of_range() {
        let mut s = screen_with_actions(&["a", "b"]);
        s.items = vec![serde_json::json!({"value": "x"})];

        // Re-selecting the active action does not clear items.
        s.select_action(0);
        assert_eq!(s.active_action_idx, 0);
        assert_eq!(s.items.len(), 1);

        // Out-of-range index is ignored.
        s.select_action(99);
        assert_eq!(s.active_action_idx, 0);
    }
}
