//! Screen 4 — Audit.
//!
//! Scrollable audit log with server-side filters (decision, action, principal)
//! and client-side text search. Incrementally fetches new events each tick by
//! tracking the newest timestamp, capped at 500 events to bound memory.
//!
//! Data source: `GateClient::audit_events(params)`.

use chrono::Utc;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Wrap};
use ratatui::Frame;
use serde_json::Value;

use latchgate_client::{AuditParams, ClientError, GateClient, OperatorAuth};

use super::formatting::{decision_indicator, timestamp_age_style, truncate};
use super::input::{InputAction, TextInput};
use super::screen::{ScreenAction, TuiScreen};
use super::theme::Theme;
use super::widgets::{self, EmptyState, ScrollableTable};

/// Maximum events held in memory.
const MAX_EVENTS: usize = 500;

/// Events fetched per tick.
const FETCH_LIMIT: usize = 100;

/// Overlap window (milliseconds) subtracted from the newest-known timestamp
/// when re-fetching the head. The ledger's `after` cursor is exclusive and
/// timestamps are millisecond-granular, so two events written in the same
/// millisecond could straddle the cursor and be missed. Re-querying a small
/// window behind the cursor and de-duplicating by event identity closes that
/// gap without unbounded re-fetching.
const HEAD_OVERLAP_MS: i64 = 1_000;

/// Fixed height of the event detail pane (including border).
const DETAIL_HEIGHT: u16 = 14;

// Event identity

/// Stable identity of an audit event for de-duplication across overlapping
/// fetches. The ledger is append-only and a single `trace_id` can emit
/// several events (e.g. `pending_approval` then `allow`), so identity is the
/// triple of trace, event type, and timestamp.
#[derive(PartialEq, Eq, Hash)]
struct EventKey<'a> {
    trace_id: &'a str,
    event_type: &'a str,
    timestamp: &'a str,
}

impl<'a> EventKey<'a> {
    fn of(ev: &'a Value) -> Self {
        Self {
            trace_id: ev["trace_id"].as_str().unwrap_or(""),
            event_type: ev["event_type"].as_str().unwrap_or(""),
            timestamp: ev["timestamp"].as_str().unwrap_or(""),
        }
    }

    fn to_owned(&self) -> OwnedEventKey {
        OwnedEventKey {
            trace_id: self.trace_id.to_owned(),
            event_type: self.event_type.to_owned(),
            timestamp: self.timestamp.to_owned(),
        }
    }
}

/// Owned form of [`EventKey`] for use in `HashSet`s and captured selection
/// anchors that must outlive the borrowed event.
#[derive(PartialEq, Eq, Hash, Clone)]
struct OwnedEventKey {
    trace_id: String,
    event_type: String,
    timestamp: String,
}

// Filter types

/// Server-side filter applied to audit queries.
#[derive(Clone)]
enum ActivityFilter {
    All,
    Decision(String),
    Action(String),
    Principal(String),
    EventType(String),
}

impl ActivityFilter {
    fn label(&self) -> &str {
        match self {
            Self::All => "all",
            Self::Decision(_) => "decision",
            Self::Action(_) => "action",
            Self::Principal(_) => "principal",
            Self::EventType(_) => "event_type",
        }
    }

    fn value(&self) -> Option<&str> {
        match self {
            Self::All => None,
            Self::Decision(v) | Self::Action(v) | Self::Principal(v) | Self::EventType(v) => {
                Some(v)
            }
        }
    }

    /// Apply this filter to [`AuditParams`].
    fn apply(&self, params: &mut AuditParams) {
        match self {
            Self::All => {}
            Self::Decision(v) => params.decision = Some(v.clone()),
            Self::Action(v) => params.action_id = Some(v.clone()),
            Self::Principal(v) => params.principal = Some(v.clone()),
            Self::EventType(v) => params.event_type = Some(v.clone()),
        }
    }
}

/// Which filter kind is being edited.
#[derive(Clone, Copy)]
enum FilterKind {
    Decision,
    Action,
    Principal,
    EventType,
}

impl FilterKind {
    fn label(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Action => "action",
            Self::Principal => "principal",
            Self::EventType => "event_type",
        }
    }
}

// InputMode

/// What the screen is currently capturing keyboard input for.
enum InputMode {
    /// Typing a filter value.
    Filter(FilterKind, TextInput),
    /// Typing a search term.
    Search(TextInput),
}

// ActivityScreen

pub(crate) struct ActivityScreen {
    events: Vec<Value>,
    newest_timestamp: Option<String>,
    oldest_timestamp: Option<String>,
    selected: usize,
    filter: ActivityFilter,
    input_mode: Option<InputMode>,
    search_term: Option<String>,
    error: Option<String>,
    /// Set by `o` key — triggers backward fetch in `handle_action`.
    load_older: bool,
    /// When true, a detail pane shows the selected event's full fields.
    show_detail: bool,
    /// Vertical scroll offset within the detail pane.
    detail_scroll: usize,
}

impl ActivityScreen {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            newest_timestamp: None,
            oldest_timestamp: None,
            selected: 0,
            filter: ActivityFilter::All,
            input_mode: None,
            search_term: None,
            error: None,
            load_older: false,
            show_detail: false,
            detail_scroll: 0,
        }
    }

    /// Reset state when the filter changes. Clears events so the next tick
    /// does a fresh fetch with the new filter applied.
    fn reset_for_filter_change(&mut self) {
        self.events.clear();
        self.newest_timestamp = None;
        self.oldest_timestamp = None;
        self.selected = 0;
    }

    /// Compute the exclusive `after` cursor for the head re-fetch.
    ///
    /// Subtracts [`HEAD_OVERLAP_MS`] from the newest-known timestamp so that
    /// events sharing a millisecond with the cursor are not skipped by the
    /// ledger's strict `timestamp > ?` comparison. Returns `None` (full head
    /// fetch) when no events are held yet or the timestamp cannot be parsed.
    fn head_after_cursor(&self) -> Option<String> {
        let newest = self.newest_timestamp.as_deref()?;
        let parsed = chrono::DateTime::parse_from_rfc3339(newest).ok()?;
        let shifted = parsed - chrono::Duration::milliseconds(HEAD_OVERLAP_MS);
        Some(
            shifted
                .with_timezone(&Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
    }

    /// Merge a freshly fetched head window (newest-first) into the held event
    /// list, de-duplicating by [`EventKey`] and preserving newest-first order.
    ///
    /// New events are prepended; events already present (from the overlap
    /// window) are dropped from the incoming batch. The currently selected
    /// event is re-anchored by identity so the cursor stays on the same row
    /// when newer events shift indices.
    fn merge_head(&mut self, fetched: Vec<Value>) {
        if fetched.is_empty() {
            return;
        }

        // Identity of the selected row, captured before indices shift.
        let anchor: Option<OwnedEventKey> = self
            .visible_events()
            .get(self.selected)
            .map(|ev| EventKey::of(ev).to_owned());

        if self.events.is_empty() {
            self.events = fetched;
        } else {
            let existing: std::collections::HashSet<OwnedEventKey> = self
                .events
                .iter()
                .map(|ev| EventKey::of(ev).to_owned())
                .collect();

            let mut fresh: Vec<Value> = fetched
                .into_iter()
                .filter(|ev| !existing.contains(&EventKey::of(ev).to_owned()))
                .collect();

            if fresh.is_empty() {
                return;
            }

            fresh.append(&mut self.events);
            self.events = fresh;
        }

        self.events.truncate(MAX_EVENTS);

        // Refresh cursors from the merged list.
        if let Some(ts) = self.events.first().and_then(|e| e["timestamp"].as_str()) {
            self.newest_timestamp = Some(ts.to_owned());
        }
        if let Some(ts) = self.events.last().and_then(|e| e["timestamp"].as_str()) {
            self.oldest_timestamp = Some(ts.to_owned());
        }

        // Re-anchor the selection to the same event identity, falling back to
        // clamping when the row was truncated away or filtered out.
        if let Some(key) = anchor {
            let visible = self.visible_events();
            let found = visible
                .iter()
                .position(|ev| EventKey::of(ev).to_owned() == key);
            self.selected =
                found.unwrap_or_else(|| self.selected.min(visible.len().saturating_sub(1)));
        }
    }

    /// Events visible after client-side search filtering and approval
    /// consolidation.
    ///
    /// When an approval is resolved, the ledger holds both the original
    /// `pending_approval` event and the terminal `allow`/`deny` event. Both
    /// share the same `approval_id`. This method hides superseded pending
    /// events so each approval lifecycle appears as a single row.
    fn visible_events(&self) -> Vec<&Value> {
        let filtered: Vec<&Value> = match &self.search_term {
            Some(t) if !t.is_empty() => {
                let term = t.to_lowercase();
                self.events
                    .iter()
                    .filter(|ev| {
                        let haystack = [
                            ev["timestamp"].as_str().unwrap_or(""),
                            ev["decision"].as_str().unwrap_or(""),
                            ev["action_id"].as_str().unwrap_or(""),
                            ev["principal"].as_str().unwrap_or(""),
                            ev["trace_id"].as_str().unwrap_or(""),
                        ];
                        haystack.iter().any(|s| s.to_lowercase().contains(&term))
                    })
                    .collect()
            }
            _ => self.events.iter().collect(),
        };

        // Consolidate: collect approval_ids that have a terminal decision.
        let resolved: std::collections::HashSet<&str> = filtered
            .iter()
            .filter(|ev| ev["decision"].as_str().unwrap_or("") != "pending_approval")
            .filter_map(|ev| ev["approval_id"].as_str())
            .collect();

        if resolved.is_empty() {
            return filtered;
        }

        // Hide pending_approval events whose approval_id has been resolved.
        filtered
            .into_iter()
            .filter(|ev| {
                if ev["decision"].as_str() == Some("pending_approval") {
                    if let Some(aid) = ev["approval_id"].as_str() {
                        return !resolved.contains(aid);
                    }
                }
                true
            })
            .collect()
    }

    // -- Rendering -----------------------------------------------------------

    fn title_line(&self) -> String {
        let mut title = " Activity".to_string();
        match &self.filter {
            ActivityFilter::All => title.push_str(" (all)"),
            f => {
                title.push_str(&format!(" ({}={}) ", f.label(), f.value().unwrap_or("?")));
            }
        }
        if let Some(ref term) = self.search_term {
            if !term.is_empty() {
                title.push_str(&format!(" search:\"{term}\""));
            }
        }
        title.push(' ');
        title
    }

    /// Render the event detail pane showing all fields of the selected event.
    fn render_detail(
        &self,
        area: Rect,
        frame: &mut Frame,
        theme: &Theme,
        selected_event: Option<&Value>,
    ) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border)
            .title(" Event Detail — [Esc] close ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let Some(ev) = selected_event else {
            frame.render_widget(
                Paragraph::new(Span::styled("No event selected.", theme.dim)),
                inner,
            );
            return;
        };

        let kw = 14;
        let max_val = inner.width.saturating_sub(kw as u16 + 2) as usize;
        let mut lines: Vec<Line<'_>> = Vec::with_capacity(24);

        // Primary fields in a fixed, readable order.
        let ordered_keys: &[(&str, &str)] = &[
            ("timestamp", "  Timestamp  "),
            ("event_type", "  Event      "),
            ("decision", "  Decision   "),
            ("action_id", "  Action     "),
            ("principal", "  Principal  "),
            ("risk_level", "  Risk       "),
            ("trace_id", "  Trace      "),
            ("duration_ms", "  Duration   "),
        ];

        for &(key, label) in ordered_keys {
            let val = match &ev[key] {
                Value::Null => continue,
                Value::String(s) => s.clone(),
                Value::Number(n) => {
                    if key == "duration_ms" {
                        format!("{n} ms")
                    } else {
                        n.to_string()
                    }
                }
                other => other.to_string(),
            };

            let value_span = if key == "decision" {
                let (dot, style) = decision_indicator(&val, theme);
                Span::styled(format!("{dot} {val}"), style)
            } else if key == "risk_level" {
                widgets::risk_badge(&val, theme)
            } else {
                Span::raw(truncate(&val, max_val))
            };

            lines.push(widgets::key_value_line(label, value_span, kw, theme));
        }

        // Error / reason / details — the fields operators actually need to
        // diagnose failures. Rendered with error styling for visibility.
        for key in &["error", "reason", "error_code", "details"] {
            let val = match &ev[*key] {
                Value::Null => continue,
                Value::String(s) => s.clone(),
                Value::Object(_) | Value::Array(_) => {
                    serde_json::to_string_pretty(&ev[*key]).unwrap_or_default()
                }
                other => other.to_string(),
            };
            if val.is_empty() {
                continue;
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!("  {:<width$}", key, width = kw - 2),
                theme.status_error,
            )));
            // Wrap long error text across multiple lines, splitting on
            // character boundaries (not bytes) so multi-byte glyphs are
            // never broken.
            let chars: Vec<char> = val.chars().collect();
            for chunk in chars.chunks(max_val) {
                let text: String = chunk.iter().collect();
                lines.push(Line::from(Span::styled(
                    format!("  {text}"),
                    theme.status_error,
                )));
            }
        }

        // Remaining fields not covered above (future-proof against new fields).
        let known: &[&str] = &[
            "timestamp",
            "event_type",
            "decision",
            "action_id",
            "principal",
            "risk_level",
            "trace_id",
            "duration_ms",
            "error",
            "reason",
            "error_code",
            "details",
        ];
        if let Value::Object(map) = ev {
            let extras: Vec<_> = map
                .iter()
                .filter(|(k, v)| !known.contains(&k.as_str()) && !v.is_null())
                .collect();
            if !extras.is_empty() {
                lines.push(Line::default());
                for (k, v) in extras {
                    let display = match v {
                        Value::String(s) => truncate(s, max_val),
                        _ => truncate(&humanize_extra(k, v), max_val),
                    };
                    // Guarantee at least two spaces between key and value even
                    // when the key is wider than the alignment column — `{:<w}`
                    // adds no padding once the string already exceeds `w`.
                    let pad = (kw).saturating_sub(k.chars().count() + 2).max(2);
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {k}{}", " ".repeat(pad)), theme.dim),
                        Span::raw(display),
                    ]));
                }
            }
        }

        // Apply scroll offset, clamped to actual content.
        let max_scroll = lines.len().saturating_sub(inner.height as usize);
        let scroll = self.detail_scroll.min(max_scroll);
        let visible_lines: Vec<Line<'_>> = lines.into_iter().skip(scroll).collect();

        frame.render_widget(
            Paragraph::new(Text::from(visible_lines)).wrap(Wrap { trim: false }),
            inner,
        );
    }
}

// TuiScreen

impl TuiScreen for ActivityScreen {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        // Build vertical layout based on active overlays.
        let mut constraints: Vec<Constraint> = Vec::with_capacity(3);
        constraints.push(Constraint::Min(6)); // table (always)
        if self.show_detail {
            constraints.push(Constraint::Length(DETAIL_HEIGHT)); // detail pane
        }
        if self.input_mode.is_some() {
            constraints.push(Constraint::Length(3)); // input widget
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);

        let table_area = chunks[0];
        let mut slot = 1;
        let detail_area = if self.show_detail {
            let a = chunks[slot];
            slot += 1;
            Some(a)
        } else {
            None
        };
        let input_area = if self.input_mode.is_some() {
            Some(chunks[slot])
        } else {
            None
        };

        // -- Table --
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(self.title_line());

        let inner = block.inner(table_area);
        frame.render_widget(block, table_area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        // Compute the filtered event list once for both the table and
        // detail pane, avoiding redundant per-event to_lowercase scans.
        let visible = self.visible_events();

        // Error display.
        if let Some(ref err) = self.error {
            frame.render_widget(
                Paragraph::new(Span::styled(err.as_str(), theme.status_error)),
                inner,
            );
        } else {
            let header = Row::new(vec![
                " Time",
                "Decision",
                "Action",
                "Principal",
                "Risk",
                "Trace",
            ])
            .style(theme.header);
            let widths = [
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(18),
                Constraint::Length(20),
                Constraint::Length(6),
                Constraint::Min(8),
            ];

            let now = Utc::now();

            let rows: Vec<Row<'_>> = visible
                .iter()
                .enumerate()
                .map(|(i, ev)| {
                    let ts_raw = ev["timestamp"].as_str().unwrap_or("");
                    let ts = ts_raw.get(11..19).unwrap_or("-");
                    let decision = ev["decision"].as_str().unwrap_or("-");
                    let action = ev["action_id"].as_str().unwrap_or("-");
                    let principal = ev["principal"].as_str().unwrap_or("-");
                    let risk = ev["risk_level"].as_str().unwrap_or("");
                    let trace = ev["trace_id"].as_str().unwrap_or("-");

                    let (dot, decision_style) = decision_indicator(decision, theme);
                    let ts_style = timestamp_age_style(ts_raw, &now, theme);

                    let base = if i == self.selected {
                        theme.selected
                    } else {
                        Style::default()
                    };

                    Row::new(vec![
                        Line::from(Span::styled(format!(" {ts}"), base.patch(ts_style))),
                        Line::from(Span::styled(
                            format!("{dot} {decision}"),
                            base.patch(decision_style),
                        )),
                        Line::from(Span::styled(truncate(action, 18), base)),
                        Line::from(Span::styled(truncate(principal, 20), base.patch(theme.dim))),
                        Line::from(if risk.is_empty() {
                            Span::styled("–", theme.dim)
                        } else {
                            widgets::risk_badge(risk, theme)
                        }),
                        Line::from(Span::styled(truncate(trace, 10), base.patch(theme.dim))),
                    ])
                })
                .collect();

            frame.render_widget(
                ScrollableTable::new(rows, widths)
                    .header(header)
                    .selected(self.selected)
                    .empty(EmptyState::new("No events.", theme).hint("[f]ilter  [/]search")),
                inner,
            );
        }

        // -- Detail pane --
        if let Some(da) = detail_area {
            let sel = visible.get(self.selected).copied();
            self.render_detail(da, frame, theme, sel);
        }

        // -- Input overlay --
        if let Some(ref mode) = self.input_mode {
            if let Some(ia) = input_area {
                match mode {
                    InputMode::Filter(_, ref input) | InputMode::Search(ref input) => {
                        input.render(ia, frame, theme);
                    }
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, _theme: &Theme) -> ScreenAction {
        // Route to active input.
        if let Some(ref mut mode) = self.input_mode {
            match mode {
                InputMode::Filter(kind, ref mut input) => {
                    let kind = *kind;
                    return match input.handle_key(key) {
                        InputAction::Submit(value) => {
                            let new_filter = if value.is_empty() {
                                ActivityFilter::All
                            } else {
                                match kind {
                                    FilterKind::Decision => ActivityFilter::Decision(value),
                                    FilterKind::Action => ActivityFilter::Action(value),
                                    FilterKind::Principal => ActivityFilter::Principal(value),
                                    FilterKind::EventType => ActivityFilter::EventType(value),
                                }
                            };
                            self.filter = new_filter;
                            self.input_mode = None;
                            self.reset_for_filter_change();
                            ScreenAction::EndInput
                        }
                        InputAction::Cancel => {
                            self.input_mode = None;
                            ScreenAction::EndInput
                        }
                        InputAction::Continue => ScreenAction::Noop,
                    };
                }
                InputMode::Search(ref mut input) => {
                    return match input.handle_key(key) {
                        InputAction::Submit(value) => {
                            self.search_term = if value.is_empty() { None } else { Some(value) };
                            self.selected = 0;
                            self.input_mode = None;
                            ScreenAction::EndInput
                        }
                        InputAction::Cancel => {
                            self.input_mode = None;
                            ScreenAction::EndInput
                        }
                        InputAction::Continue => ScreenAction::Noop,
                    };
                }
            }
        }

        let visible_len = self.visible_events().len();

        match key.code {
            // Navigation — reset detail scroll when selection changes.
            KeyCode::Up | KeyCode::Char('k') => {
                if visible_len > 0 && self.selected > 0 {
                    self.selected -= 1;
                    self.detail_scroll = 0;
                }
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if visible_len > 0 {
                    let next = (self.selected + 1).min(visible_len.saturating_sub(1));
                    if next != self.selected {
                        self.selected = next;
                        self.detail_scroll = 0;
                    }
                }
                ScreenAction::Noop
            }
            KeyCode::Home => {
                if visible_len > 0 {
                    self.selected = 0;
                    self.detail_scroll = 0;
                }
                ScreenAction::Noop
            }
            KeyCode::End => {
                if visible_len > 0 {
                    self.selected = visible_len.saturating_sub(1);
                    self.detail_scroll = 0;
                }
                ScreenAction::Noop
            }

            // Toggle event detail pane.
            KeyCode::Enter => {
                if visible_len > 0 {
                    self.show_detail = !self.show_detail;
                    self.detail_scroll = 0;
                }
                ScreenAction::Noop
            }
            // Close detail pane (or no-op — global keys handle quit).
            KeyCode::Esc => {
                if self.show_detail {
                    self.show_detail = false;
                    self.detail_scroll = 0;
                }
                ScreenAction::Noop
            }

            // Scroll detail pane content.  The render clamps the effective
            // offset to actual line count, so visual correctness is always
            // maintained.  The cap here prevents unbounded growth that would
            // require many '-' presses to scroll back.
            KeyCode::Char('+') | KeyCode::Char('=') if self.show_detail => {
                if self.detail_scroll < 200 {
                    self.detail_scroll += 1;
                }
                ScreenAction::Noop
            }
            KeyCode::Char('-') if self.show_detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
                ScreenAction::Noop
            }

            // Filter cycling: f opens the next filter kind input.
            KeyCode::Char('f') => {
                let next_kind = match &self.filter {
                    ActivityFilter::All => FilterKind::Decision,
                    ActivityFilter::Decision(_) => FilterKind::Action,
                    ActivityFilter::Action(_) => FilterKind::Principal,
                    ActivityFilter::Principal(_) => FilterKind::EventType,
                    ActivityFilter::EventType(_) => {
                        // Cycle back to All.
                        self.filter = ActivityFilter::All;
                        self.reset_for_filter_change();
                        return ScreenAction::Noop;
                    }
                };
                let label = format!(
                    " Filter by {} (Enter to apply, Esc to cancel) ",
                    next_kind.label()
                );
                self.input_mode = Some(InputMode::Filter(next_kind, TextInput::new(&label, 128)));
                ScreenAction::BeginInput
            }

            // Search.
            KeyCode::Char('/') => {
                self.input_mode = Some(InputMode::Search(TextInput::new(
                    " Search (Enter to apply, Esc to cancel) ",
                    128,
                )));
                ScreenAction::BeginInput
            }

            // Refresh: clear and refetch.
            KeyCode::Char('r') => {
                self.reset_for_filter_change();
                ScreenAction::Noop
            }

            // Load older events (backward pagination).
            KeyCode::Char('o') => {
                if self.oldest_timestamp.is_some() {
                    self.load_older = true;
                    ScreenAction::AsyncAction
                } else {
                    ScreenAction::Noop
                }
            }

            _ => ScreenAction::Noop,
        }
    }

    fn handle_action<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<super::input::FlashMessage>> + Send + 'a>,
    > {
        Box::pin(async move {
            if !self.load_older {
                return None;
            }
            self.load_older = false;

            let oldest = self.oldest_timestamp.as_ref()?;

            // Widen the exclusive `before` cursor by the overlap window so
            // same-millisecond siblings at the tail are not skipped; the merge
            // below de-duplicates the overlap.
            let before = chrono::DateTime::parse_from_rfc3339(oldest)
                .ok()
                .map(|dt| {
                    (dt + chrono::Duration::milliseconds(HEAD_OVERLAP_MS))
                        .with_timezone(&Utc)
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                })
                .unwrap_or_else(|| oldest.clone());

            let mut params = AuditParams {
                limit: Some(FETCH_LIMIT),
                before: Some(before),
                ..Default::default()
            };
            self.filter.apply(&mut params);

            match client.audit_events(auth, &params).await {
                Ok(older_events) => {
                    let existing: std::collections::HashSet<OwnedEventKey> = self
                        .events
                        .iter()
                        .map(|ev| EventKey::of(ev).to_owned())
                        .collect();

                    let fresh: Vec<Value> = older_events
                        .into_iter()
                        .filter(|ev| !existing.contains(&EventKey::of(ev).to_owned()))
                        .collect();

                    if fresh.is_empty() {
                        return Some(super::input::FlashMessage::info("No older events."));
                    }

                    self.events.extend(fresh);
                    self.events.truncate(MAX_EVENTS);

                    if let Some(ts) = self.events.last().and_then(|e| e["timestamp"].as_str()) {
                        self.oldest_timestamp = Some(ts.to_owned());
                    }
                    None
                }
                Err(e) => Some(super::input::FlashMessage::error(format!(
                    "Load older: {e}"
                ))),
            }
        })
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let mut params = AuditParams {
                limit: Some(FETCH_LIMIT),
                ..Default::default()
            };
            self.filter.apply(&mut params);

            // Re-fetch the head with a small overlap window behind the newest
            // known event. Because the ledger's `after` cursor is exclusive and
            // millisecond-granular, this prevents same-millisecond siblings
            // from being skipped; duplicates are removed in `merge_head`.
            params.after = self.head_after_cursor();

            match client.audit_events(auth, &params).await {
                Ok(fetched) => {
                    self.error = None;
                    self.merge_head(fetched);
                }
                Err(ClientError::NotReachable(msg)) => {
                    self.error = Some(format!("Gate unreachable: {msg}"));
                }
                Err(ClientError::Http { status: 404, .. }) => {
                    // No audit events yet — treat as empty.
                    self.error = None;
                }
                Err(e) => {
                    self.error = Some(format!("Error: {e}"));
                }
            }
        })
    }

    fn tab_label(&self) -> &'static str {
        "Audit"
    }

    fn is_modal(&self) -> bool {
        self.input_mode.is_some()
    }

    fn status_hint(&self) -> &str {
        if self.show_detail {
            "[↑↓/jk]scroll  [Enter]close detail  [+/-]scroll detail  [f]ilter  [/]search  [q]uit"
        } else {
            "[↑↓/jk]scroll  [Enter]detail  [f]ilter  [/]search  [o]lder  [r]efresh  [q]uit"
        }
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("Enter", "Toggle event detail pane"),
            ("Esc", "Close detail pane"),
            ("+/-", "Scroll detail content"),
            ("f", "Cycle filter (decision/action/principal/event_type)"),
            ("/", "Text search across visible fields"),
            ("o", "Load older events (backward pagination)"),
            ("r", "Clear and refetch"),
            ("↑/k", "Scroll up"),
            ("↓/j", "Scroll down"),
            ("Home", "Jump to newest"),
            ("End", "Jump to oldest"),
        ]
    }
}

// Extra-field display helpers

/// Render an "extra" audit field for display, rewriting known sentinels into
/// human-readable form. The budget `i64::MAX` sentinel means "no budget /
/// unlimited" — showing the raw 19-digit number is confusing and looks like a
/// bug. All other fields fall through to their compact JSON form.
fn humanize_extra(key: &str, value: &Value) -> String {
    if key == "budgets_after" || key == "budgets_before" {
        if let Some(calls) = value.get("calls_remaining").and_then(Value::as_i64) {
            if calls == i64::MAX {
                return "{calls_remaining: unlimited}".to_string();
            }
            return format!("{{calls_remaining: {calls}}}");
        }
    }
    value.to_string()
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(trace: &str, etype: &str, ts: &str) -> Value {
        json!({ "trace_id": trace, "event_type": etype, "timestamp": ts })
    }

    fn ids(events: &[Value]) -> Vec<(String, String)> {
        events
            .iter()
            .map(|e| {
                (
                    e["event_type"].as_str().unwrap().to_owned(),
                    e["timestamp"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn merge_head_into_empty_takes_all() {
        let mut s = ActivityScreen::new();
        s.merge_head(vec![
            event("t2", "allow", "2026-01-01T00:00:02.000Z"),
            event("t1", "allow", "2026-01-01T00:00:01.000Z"),
        ]);
        assert_eq!(s.events.len(), 2);
        assert_eq!(
            s.newest_timestamp.as_deref(),
            Some("2026-01-01T00:00:02.000Z")
        );
    }

    #[test]
    fn merge_head_dedups_overlap_window() {
        let mut s = ActivityScreen::new();
        s.merge_head(vec![event("t1", "allow", "2026-01-01T00:00:01.000Z")]);

        // Re-fetch overlaps the same event plus a genuinely new one.
        s.merge_head(vec![
            event("t2", "allow", "2026-01-01T00:00:02.000Z"),
            event("t1", "allow", "2026-01-01T00:00:01.000Z"),
        ]);

        assert_eq!(s.events.len(), 2, "duplicate must be dropped");
        assert_eq!(
            ids(&s.events),
            vec![
                ("allow".into(), "2026-01-01T00:00:02.000Z".into()),
                ("allow".into(), "2026-01-01T00:00:01.000Z".into()),
            ]
        );
    }

    #[test]
    fn merge_head_keeps_same_millisecond_siblings() {
        let mut s = ActivityScreen::new();
        // Two distinct events written in the same millisecond.
        s.merge_head(vec![
            event("t1", "allow", "2026-01-01T00:00:01.000Z"),
            event("t1", "pending_approval", "2026-01-01T00:00:01.000Z"),
        ]);
        assert_eq!(s.events.len(), 2, "siblings must both survive");
    }

    #[test]
    fn merge_head_reanchors_selection_on_insert_above() {
        let mut s = ActivityScreen::new();
        s.merge_head(vec![
            event("t2", "allow", "2026-01-01T00:00:02.000Z"),
            event("t1", "allow", "2026-01-01T00:00:01.000Z"),
        ]);
        // Operator selects the older event (index 1).
        s.selected = 1;

        // A newer event arrives, shifting indices down by one.
        s.merge_head(vec![event("t3", "allow", "2026-01-01T00:00:03.000Z")]);

        // Selection must still point at t1, now at index 2.
        let sel = &s.visible_events()[s.selected];
        assert_eq!(sel["trace_id"].as_str(), Some("t1"));
    }

    #[test]
    fn merge_head_clamps_when_selected_truncated_away() {
        let mut s = ActivityScreen::new();
        s.merge_head(vec![event("t1", "allow", "2026-01-01T00:00:01.000Z")]);
        s.selected = 0;
        // Empty re-fetch: nothing changes, selection stays valid.
        s.merge_head(vec![]);
        assert_eq!(s.selected, 0);
    }

    #[test]
    fn head_after_cursor_subtracts_overlap() {
        let mut s = ActivityScreen::new();
        assert_eq!(s.head_after_cursor(), None, "no events => full head fetch");

        s.newest_timestamp = Some("2026-01-01T00:00:05.000Z".into());
        let cursor = s.head_after_cursor().unwrap();
        // 1000ms overlap => 4.000Z.
        assert_eq!(cursor, "2026-01-01T00:00:04.000Z");
    }

    #[test]
    fn head_after_cursor_none_on_unparseable() {
        let mut s = ActivityScreen::new();
        s.newest_timestamp = Some("not-a-timestamp".into());
        assert_eq!(s.head_after_cursor(), None);
    }

    #[test]
    fn humanize_extra_marks_unlimited_budget() {
        let v = json!({ "calls_remaining": i64::MAX });
        let out = humanize_extra("budgets_after", &v);
        assert!(out.contains("unlimited"), "got: {out}");
        assert!(!out.contains("9223372036854775807"), "got: {out}");
    }

    #[test]
    fn humanize_extra_keeps_finite_budget() {
        let v = json!({ "calls_remaining": 42 });
        let out = humanize_extra("budgets_after", &v);
        assert!(out.contains("42"), "got: {out}");
    }
}
