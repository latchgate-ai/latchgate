//! Screen 2 — Approvals.
//!
//! The critical operator workflow: list/detail split with approvals on one
//! side and full request context on the other. Supports approve (with
//! confirmation), learn+approve, and deny (with inline reason input).
//!
//! The list is filterable by status (`f` key cycles All => Pending => Approved
//! => Denied => All). Default is All with pending items sorted first, so the
//! operator can see recently-resolved items without switching screens.
//!
//! Responsive: side-by-side at ≥ 140 cols, stacked when narrow.

use chrono::Utc;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Row, Wrap};
use ratatui::Frame;
use serde_json::Value;

use latchgate_client::{ClientError, GateClient, OperatorAuth};

use super::formatting::{join_str_array, truncate};
use super::input::{FlashMessage, InputAction, TextInput};
use super::screen::{ScreenAction, TuiScreen};
use super::theme::Theme;
use super::widgets::{self, Spinner};

/// Terminal width at which list and detail sit side-by-side.
const WIDE_THRESHOLD: u16 = 140;

/// Timestamp age thresholds for color fade.
const AGE_DIM_SECS: i64 = 5 * 60;
const AGE_FAINT_SECS: i64 = 30 * 60;

// Status filter

/// Server-side status filter applied to approval queries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusFilter {
    All,
    Pending,
    Approved,
    Denied,
}

impl StatusFilter {
    /// API parameter value. `None` fetches all statuses.
    fn api_param(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Pending => Some("pending"),
            Self::Approved => Some("approved"),
            Self::Denied => Some("denied"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Denied => "Denied",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::All => Self::Pending,
            Self::Pending => Self::Approved,
            Self::Approved => Self::Denied,
            Self::Denied => Self::All,
        }
    }
}

// Internal types

/// Queued mutation set by `handle_key`, executed by `handle_action`.
///
/// Every field is captured when the operator *initiates* the action (opens an
/// input or presses `[y]`), never at execution time. This closes the TOCTOU
/// window where a concurrent tick could re-anchor the selection or overwrite
/// `self.detail` between the operator's confirmation and the async execution.
enum PendingAction {
    Approve {
        approval_id: String,
    },
    ApproveAndLearn {
        approval_id: String,
        learn_domain: Option<String>,
        learn_path: Option<String>,
    },
    Deny {
        approval_id: String,
        reason: String,
    },
}

/// Action awaiting operator confirmation before execution.
///
/// Carries the `approval_id` captured at initiation time so that the
/// subsequent `[y]` press can build a [`PendingAction`] without re-reading
/// `selected_id()` (which may have shifted due to a concurrent tick).
enum ConfirmAction {
    Approve {
        approval_id: String,
    },
    LearnApprove {
        approval_id: String,
        learn_domain: Option<String>,
        learn_path: Option<String>,
    },
}

/// Deny-reason input paired with the approval it targets.
///
/// The `approval_id` is captured when `[d]` is pressed, not when the
/// operator submits the reason.
struct DenyInput {
    approval_id: String,
    input: TextInput,
}

// ApprovalsScreen

pub(crate) struct ApprovalsScreen {
    approvals: Vec<Value>,
    selected: usize,
    detail: Option<Value>,
    deny_input: Option<DenyInput>,
    confirm_action: Option<ConfirmAction>,
    pending_action: Option<PendingAction>,
    error: Option<String>,
    status_filter: StatusFilter,
    /// Monotonic counter for Spinner animation.
    tick_count: usize,
}

impl ApprovalsScreen {
    pub fn new() -> Self {
        Self {
            approvals: Vec::new(),
            selected: 0,
            detail: None,
            deny_input: None,
            confirm_action: None,
            pending_action: None,
            error: None,
            status_filter: StatusFilter::All,
            tick_count: 0,
        }
    }

    /// Approval ID of the currently selected item (if any).
    fn selected_id(&self) -> Option<&str> {
        self.approvals
            .get(self.selected)
            .and_then(|a| a["approval_id"].as_str())
    }

    /// Status of the currently selected item (`"pending"`, `"approved"`, etc.).
    fn selected_status(&self) -> Option<&str> {
        self.approvals
            .get(self.selected)
            .and_then(|a| a["status"].as_str())
    }

    /// Whether the selected item is actionable (pending).
    fn selected_is_pending(&self) -> bool {
        self.selected_status() == Some("pending")
    }

    /// Whether the loaded detail has unresolved domains or paths.
    fn has_unresolved(&self) -> bool {
        let Some(d) = &self.detail else { return false };
        let domains = d
            .get("unresolved_domains")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        let paths = d
            .get("unresolved_paths")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        domains || paths
    }

    /// First unresolved domain from the loaded detail.
    fn first_unresolved_domain(&self) -> Option<&str> {
        self.detail
            .as_ref()?
            .get("unresolved_domains")?
            .as_array()?
            .first()?
            .as_str()
    }

    /// First unresolved path from the loaded detail.
    fn first_unresolved_path(&self) -> Option<&str> {
        self.detail
            .as_ref()?
            .get("unresolved_paths")?
            .as_array()?
            .first()?
            .as_str()
    }

    // -- Rendering ----------------------------------------------------------

    fn render_list(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let pending_count = self
            .approvals
            .iter()
            .filter(|a| a["status"].as_str() == Some("pending"))
            .count();
        let title = match self.status_filter {
            StatusFilter::All if pending_count > 0 => {
                format!(
                    " Approvals ({}, {} pending)  [f]ilter ",
                    self.approvals.len(),
                    pending_count,
                )
            }
            _ => format!(
                " {} ({})  [f]ilter ",
                self.status_filter.label(),
                self.approvals.len(),
            ),
        };
        let Some(inner) = widgets::begin_active_panel(frame, area, title, theme) else {
            return;
        };

        let header = Row::new(vec!["  Action", "Principal", "Status", "Risk", "Remaining"])
            .style(theme.header);
        let widths = [
            Constraint::Min(14),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(10),
        ];

        let now = Utc::now();

        let rows: Vec<Row<'_>> = self
            .approvals
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let action = a["action_id"].as_str().unwrap_or("-");
                let principal = a["principal"].as_str().unwrap_or("-");
                let risk = a["risk_level"].as_str().unwrap_or("?");
                let expires = a["expires_at"].as_str().unwrap_or("");
                let status = a["status"].as_str().unwrap_or("?");

                let base = if i == self.selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                let marker = if i == self.selected { "▸ " } else { "  " };

                let remaining = format_remaining(expires);
                let time_style = expiry_age_style(expires, &now, theme);

                let status_style = match status {
                    "pending" => theme.status_warn,
                    "approved" => theme.status_ok,
                    "denied" => theme.status_error,
                    _ => theme.dim,
                };

                Row::new(vec![
                    Line::from(Span::styled(
                        format!("{marker}{}", truncate(action, 12)),
                        base,
                    )),
                    Line::from(Span::styled(truncate(principal, 14), base.patch(theme.dim))),
                    Line::from(Span::styled(status, base.patch(status_style))),
                    Line::from(widgets::risk_badge(risk, theme)),
                    Line::from(Span::styled(remaining, time_style)),
                ])
            })
            .collect();

        let empty_msg = match self.status_filter {
            StatusFilter::All => "No approvals.",
            StatusFilter::Pending => "No pending approvals.",
            StatusFilter::Approved => "No approved approvals.",
            StatusFilter::Denied => "No denied approvals.",
        };

        frame.render_widget(
            widgets::ScrollableTable::new(rows, widths)
                .header(header)
                .selected(self.selected)
                .empty(
                    widgets::EmptyState::new(empty_msg, theme).hint("[f]ilter  [Enter] dashboard"),
                ),
            inner,
        );
    }

    fn render_detail(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let Some(inner) = widgets::begin_detail_panel(frame, area, " Detail ", theme) else {
            return;
        };

        // Reserve space for deny input when active.
        let (detail_area, input_area) = if self.deny_input.is_some() {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(inner);
            (chunks[0], Some(chunks[1]))
        } else {
            (inner, None)
        };

        let Some(detail) = &self.detail else {
            let msg = if self.approvals.is_empty() {
                "No pending approvals."
            } else {
                "Loading…"
            };
            frame.render_widget(Paragraph::new(msg).style(theme.dim), detail_area);
            if self.detail.is_none() && !self.approvals.is_empty() {
                let offset = msg.chars().count() as u16 + 1;
                if detail_area.width > offset {
                    let spinner_area = Rect::new(detail_area.x + offset, detail_area.y, 1, 1);
                    frame.render_widget(Spinner::new(self.tick_count, theme), spinner_area);
                }
            }
            return;
        };

        let kw = 11; // label column width
        let mut lines: Vec<Line<'_>> = Vec::with_capacity(20);

        // -- Core fields ----------------------------------------------------

        let id_raw = detail["approval_id"].as_str().unwrap_or("-");
        lines.push(widgets::key_value_line(
            "Approval: ",
            Span::raw(truncate(id_raw, 36)),
            kw,
            theme,
        ));
        lines.push(widgets::key_value_line(
            "Action:   ",
            Span::raw(detail["action_id"].as_str().unwrap_or("-")),
            kw,
            theme,
        ));
        lines.push(widgets::key_value_line(
            "Principal:",
            Span::raw(detail["principal"].as_str().unwrap_or("-")),
            kw,
            theme,
        ));

        // Risk (badge).
        let risk = detail["risk_level"].as_str().unwrap_or("?");
        lines.push(widgets::key_value_line(
            "Risk:     ",
            widgets::risk_badge(risk, theme),
            kw,
            theme,
        ));

        // Trust status.
        if let Some(trust) = detail["trust_status"].as_str() {
            let (dot, trust_style) = match trust {
                "digest_ok" | "verified" => ("●", theme.status_ok),
                "unverified" => ("○", theme.status_warn),
                _ => ("○", theme.dim),
            };
            lines.push(widgets::key_value_line(
                "Trust:    ",
                Span::styled(format!("{dot} {trust}"), trust_style),
                kw,
                theme,
            ));
        }

        // Targets.
        if let Some(targets) = detail["approved_targets"].as_array() {
            let t = join_str_array(targets);
            lines.push(widgets::key_value_line(
                "Targets:  ",
                Span::raw(if t.is_empty() { "(none)".into() } else { t }),
                kw,
                theme,
            ));
        }

        // Secrets (names only).
        if let Some(secrets) = detail["approved_secrets"].as_array() {
            let s = join_str_array(secrets);
            lines.push(widgets::key_value_line(
                "Secrets:  ",
                Span::raw(if s.is_empty() { "(none)".into() } else { s }),
                kw,
                theme,
            ));
        }

        // Egress.
        if let Some(egress) = detail.get("approved_egress") {
            let display = match egress.as_str() {
                Some(s) => s.to_string(),
                None => serde_json::to_string(egress).unwrap_or_else(|_| "?".into()),
            };
            lines.push(widgets::key_value_line(
                "Egress:   ",
                Span::raw(display),
                kw,
                theme,
            ));
        }

        // Expires.
        if let Some(expires) = detail["expires_at"].as_str() {
            lines.push(widgets::key_value_line(
                "Expires:  ",
                Span::raw(format_remaining(expires)),
                kw,
                theme,
            ));
        }

        // -- Database review (when present) ---------------------------------

        if let Some(db) = detail.get("database_review") {
            lines.push(Line::default());
            if let Some(mode) = db["statement_mode"].as_str() {
                lines.push(widgets::key_value_line(
                    "DB mode:  ",
                    Span::raw(mode),
                    kw,
                    theme,
                ));
            }
            if let Some(op) = db["operation_class"].as_str() {
                let op_style = match op {
                    "ddl" | "grant_revoke" | "unknown" | "multi_statement" => theme.status_error,
                    "update" | "delete" => theme.status_warn,
                    _ => Style::default(),
                };
                lines.push(widgets::key_value_line(
                    "DB op:    ",
                    Span::styled(op, op_style),
                    kw,
                    theme,
                ));
            }
            if let Some(q) = db["query_shape"].as_str() {
                lines.push(widgets::key_value_line(
                    "Query:    ",
                    Span::raw(truncate(q, 50)),
                    kw,
                    theme,
                ));
            }
        }

        // -- Unresolved warnings --------------------------------------------

        if let Some(domains) = detail.get("unresolved_domains").and_then(Value::as_array) {
            for d in domains.iter().filter_map(Value::as_str) {
                lines.push(Line::from(Span::styled(
                    format!("  ⚠ Unresolved domain: {d}"),
                    theme.status_warn,
                )));
            }
        }
        if let Some(paths) = detail.get("unresolved_paths").and_then(Value::as_array) {
            for p in paths.iter().filter_map(Value::as_str) {
                lines.push(Line::from(Span::styled(
                    format!("  ⚠ Unresolved path: {p}"),
                    theme.status_warn,
                )));
            }
        }

        // -- Screen-local error ---------------------------------------------

        if let Some(ref err) = self.error {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(err.as_str(), theme.status_error)));
        }

        frame.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            detail_area,
        );

        // Deny input overlay.
        if let Some(ref deny) = self.deny_input {
            if let Some(ia) = input_area {
                deny.input.render(ia, frame, theme);
            }
        }
    }
}

// TuiScreen implementation

impl TuiScreen for ApprovalsScreen {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let wide = area.width >= WIDE_THRESHOLD;

        if wide {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(35), Constraint::Min(0)])
                .split(area);

            self.render_list(chunks[0], frame, theme);
            self.render_detail(chunks[1], frame, theme);
        } else {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(self.approvals.len().min(8) as u16 + 3),
                    Constraint::Min(8),
                ])
                .split(area);

            self.render_list(chunks[0], frame, theme);
            self.render_detail(chunks[1], frame, theme);
        }

        // Confirmation dialog renders on top of everything.
        if self.confirm_action.is_some() {
            let question = match &self.confirm_action {
                Some(ConfirmAction::Approve { .. }) => "Approve this request?",
                Some(ConfirmAction::LearnApprove { .. }) => "Learn + approve this request?",
                None => unreachable!(),
            };
            widgets::render_confirm_dialog(area, frame, theme, question);
        }
    }

    fn handle_key(&mut self, key: KeyEvent, _theme: &Theme) -> ScreenAction {
        // Route to deny input if active.
        if let Some(ref mut deny) = self.deny_input {
            return match deny.input.handle_key(key) {
                InputAction::Submit(reason) => {
                    let approval_id = deny.approval_id.clone();
                    self.deny_input = None;
                    self.pending_action = Some(PendingAction::Deny {
                        approval_id,
                        reason,
                    });
                    ScreenAction::AsyncAction
                }
                InputAction::Cancel => {
                    self.deny_input = None;
                    ScreenAction::EndInput
                }
                InputAction::Continue => ScreenAction::Noop,
            };
        }

        // Route to confirmation dialog if active.
        if let Some(action) = self.confirm_action.take() {
            return match key.code {
                KeyCode::Char('y') => {
                    self.pending_action = Some(match action {
                        ConfirmAction::Approve { approval_id } => {
                            PendingAction::Approve { approval_id }
                        }
                        ConfirmAction::LearnApprove {
                            approval_id,
                            learn_domain,
                            learn_path,
                        } => PendingAction::ApproveAndLearn {
                            approval_id,
                            learn_domain,
                            learn_path,
                        },
                    });
                    ScreenAction::AsyncAction
                }
                _ => ScreenAction::EndInput,
            };
        }

        match key.code {
            // Navigation.
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.approvals.is_empty() && self.selected > 0 {
                    self.selected -= 1;
                    self.detail = None;
                }
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.approvals.len() {
                    self.selected += 1;
                    self.detail = None;
                }
                ScreenAction::Noop
            }

            // Approve: requires confirmation.
            // SECURITY: auto-promotes to LearnApprove when the pending request
            // has unresolved domains or paths — without learning, execution
            // would fail because the domain/path is not in any allowlist.
            //
            // The approval_id and learn fields are captured NOW so a concurrent
            // tick cannot shift the selection or overwrite detail between this
            // keypress and the subsequent `[y]` confirmation.
            KeyCode::Char('a') if self.detail.is_some() && self.selected_is_pending() => {
                let Some(approval_id) = self.selected_id().map(str::to_string) else {
                    return ScreenAction::Noop;
                };
                self.confirm_action = Some(if self.has_unresolved() {
                    ConfirmAction::LearnApprove {
                        approval_id,
                        learn_domain: self.first_unresolved_domain().map(str::to_string),
                        learn_path: self.first_unresolved_path().map(str::to_string),
                    }
                } else {
                    ConfirmAction::Approve { approval_id }
                });
                ScreenAction::BeginInput
            }

            // Learn + approve: explicit key kept for discoverability.
            KeyCode::Char('l')
                if self.detail.is_some() && self.selected_is_pending() && self.has_unresolved() =>
            {
                let Some(approval_id) = self.selected_id().map(str::to_string) else {
                    return ScreenAction::Noop;
                };
                self.confirm_action = Some(ConfirmAction::LearnApprove {
                    approval_id,
                    learn_domain: self.first_unresolved_domain().map(str::to_string),
                    learn_path: self.first_unresolved_path().map(str::to_string),
                });
                ScreenAction::BeginInput
            }

            // Deny: open inline text input for reason.
            // The approval_id is captured NOW, not when Enter is pressed.
            KeyCode::Char('d') if self.detail.is_some() && self.selected_is_pending() => {
                let Some(approval_id) = self.selected_id().map(str::to_string) else {
                    return ScreenAction::Noop;
                };
                self.deny_input = Some(DenyInput {
                    approval_id,
                    input: TextInput::new(" Deny reason (Enter to submit, Esc to cancel) ", 256),
                });
                ScreenAction::BeginInput
            }

            // Filter cycling: f advances the status filter.
            KeyCode::Char('f') => {
                self.status_filter = self.status_filter.next();
                self.approvals.clear();
                self.selected = 0;
                self.detail = None;
                ScreenAction::Noop
            }

            // Navigate to Dashboard on Enter (when empty, suggestive).
            KeyCode::Enter if self.approvals.is_empty() => ScreenAction::Navigate(0),

            _ => ScreenAction::Noop,
        }
    }

    fn handle_action<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<FlashMessage>> + Send + 'a>>
    {
        Box::pin(async move {
            let action = self.pending_action.take()?;

            // Clear stale detail so the next render shows "Loading…" until
            // the post-mutation tick refreshes it.
            self.detail = None;

            match action {
                PendingAction::Approve { approval_id } => {
                    match client
                        .approve_approval(auth, &approval_id, None, None)
                        .await
                    {
                        Ok(_) => Some(FlashMessage::success("✓ Approved")),
                        Err(e) => Some(FlashMessage::error(format!("Approve failed: {e}"))),
                    }
                }

                PendingAction::ApproveAndLearn {
                    approval_id,
                    learn_domain,
                    learn_path,
                } => {
                    match client
                        .approve_approval(
                            auth,
                            &approval_id,
                            learn_domain.as_deref(),
                            learn_path.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => {
                            let mut msg = "✓ Approved".to_string();
                            if let Some(d) = &learn_domain {
                                msg.push_str(&format!(" +domain:{d}"));
                            }
                            if let Some(p) = &learn_path {
                                msg.push_str(&format!(" +path:{p}"));
                            }
                            Some(FlashMessage::success(msg))
                        }
                        Err(e) => Some(FlashMessage::error(format!("Approve failed: {e}"))),
                    }
                }

                PendingAction::Deny {
                    approval_id,
                    reason,
                } => {
                    let reason_opt = if reason.is_empty() {
                        None
                    } else {
                        Some(reason.as_str())
                    };
                    match client.deny_approval(auth, &approval_id, reason_opt).await {
                        Ok(_) => {
                            if reason.is_empty() {
                                Some(FlashMessage::success("✗ Denied"))
                            } else {
                                Some(FlashMessage::success(format!("✗ Denied: {reason}")))
                            }
                        }
                        Err(e) => Some(FlashMessage::error(format!("Deny failed: {e}"))),
                    }
                }
            }
        })
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.tick_count = self.tick_count.wrapping_add(1);

            // Fetch approvals list with the active status filter.
            match client
                .list_approvals(auth, self.status_filter.api_param(), Some(50))
                .await
            {
                Ok(mut list) => {
                    self.error = None;

                    // In All mode, sort pending items first so the operator
                    // sees actionable requests at the top while still being
                    // able to verify recently-resolved ones below.
                    if self.status_filter == StatusFilter::All {
                        list.sort_by(|a, b| {
                            let a_pending = a["status"].as_str() == Some("pending");
                            let b_pending = b["status"].as_str() == Some("pending");
                            b_pending.cmp(&a_pending)
                        });
                    }

                    // Identity of the selected approval, captured before the
                    // list is replaced. The list may reorder or gain entries
                    // above the cursor between ticks; re-anchoring by ID keeps
                    // the highlight on the same request so an operator never
                    // approves a different one than the one they were viewing.
                    let prev_id = self.selected_id().map(str::to_string);
                    self.approvals = list;

                    if self.approvals.is_empty() {
                        self.selected = 0;
                        self.detail = None;
                        return;
                    }

                    // Re-anchor selection to the previously-selected ID.
                    match prev_id {
                        Some(ref id) => {
                            match self
                                .approvals
                                .iter()
                                .position(|a| a["approval_id"].as_str() == Some(id.as_str()))
                            {
                                Some(idx) => self.selected = idx,
                                None => {
                                    // The selected approval is gone (resolved or
                                    // expired): clamp and reload detail.
                                    self.selected = self.selected.min(self.approvals.len() - 1);
                                    self.detail = None;
                                }
                            }
                        }
                        None => {
                            self.selected = self.selected.min(self.approvals.len() - 1);
                        }
                    }
                }
                Err(ClientError::NotReachable(msg)) => {
                    self.error = Some(format!("Gate unreachable: {msg}"));
                    return;
                }
                Err(ClientError::Http { status: 404, .. }) => {
                    self.approvals.clear();
                    self.selected = 0;
                    self.detail = None;
                    self.error = None;
                    return;
                }
                Err(e) => {
                    self.error = Some(format!("Error: {e}"));
                    return;
                }
            }

            // Fetch detail for the selected approval (if not already loaded).
            if self.detail.is_none() {
                if let Some(id) = self.selected_id().map(str::to_string) {
                    match client.get_approval(auth, &id).await {
                        Ok(d) => {
                            self.detail = Some(d);
                            // Clear any stale detail-fetch error from a previous tick.
                            self.error = None;
                        }
                        Err(e) => {
                            self.error = Some(format!("Detail: {e}"));
                        }
                    }
                }
            } else {
                // Detail is loaded — clear any lingering detail-fetch error
                // that may have been set on a previous tick before recovery.
                if self
                    .error
                    .as_ref()
                    .is_some_and(|e| e.starts_with("Detail:"))
                {
                    self.error = None;
                }
            }
        })
    }

    fn tab_label(&self) -> &'static str {
        "Approvals"
    }

    fn badge_count(&self) -> usize {
        self.approvals
            .iter()
            .filter(|a| a["status"].as_str() == Some("pending"))
            .count()
    }

    fn is_modal(&self) -> bool {
        self.deny_input.is_some() || self.confirm_action.is_some()
    }

    fn status_hint(&self) -> &str {
        if self.has_unresolved() {
            "[a]pprove  [l]earn+approve  [d]eny  [f]ilter  [↑↓/jk]navigate  [q]uit"
        } else {
            "[a]pprove  [d]eny  [f]ilter  [↑↓/jk]navigate  [q]uit"
        }
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("a", "Approve selected (pending only)"),
            ("l", "Learn domain/path + approve (pending only)"),
            ("d", "Deny (pending only, opens reason input)"),
            ("f", "Cycle status filter (All/Pending/Approved/Denied)"),
            ("↑/k", "Move cursor up"),
            ("↓/j", "Move cursor down"),
            ("Enter", "Go to Dashboard (when empty)"),
        ]
    }
}

// Helpers

/// Format time remaining until expiry as a human-readable string.
fn format_remaining(expires_at: &str) -> String {
    let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return String::new();
    };
    let now = chrono::Utc::now();
    let remaining = dt.signed_duration_since(now);
    if remaining.num_seconds() <= 0 {
        return "expired".into();
    }
    let mins = remaining.num_minutes();
    let secs = remaining.num_seconds() % 60;
    format!("{mins}m{secs:02}s")
}

/// Resolve expiry timestamp to a style based on urgency.
///
/// Closer expiry => more prominent color to draw operator attention.
fn expiry_age_style(expires_at: &str, now: &chrono::DateTime<Utc>, theme: &Theme) -> Style {
    let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return theme.dim;
    };
    let remaining_secs = dt.signed_duration_since(now).num_seconds();
    if remaining_secs <= 0 {
        theme.status_error
    } else if remaining_secs < AGE_DIM_SECS {
        theme.status_warn
    } else if remaining_secs < AGE_FAINT_SECS {
        Style::default()
    } else {
        theme.dim
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build an ApprovalsScreen with realistic API response data.
    fn screen_with_approvals(approvals: Vec<Value>) -> ApprovalsScreen {
        let mut screen = ApprovalsScreen::new();
        screen.approvals = approvals;
        screen
    }

    /// Realistic approval entry matching the actual API response shape.
    fn pending_approval(id: &str, action: &str) -> Value {
        json!({
            "approval_id": id,
            "status": "pending",
            "action_id": action,
            "principal": "agent-1",
            "session_id": "sess-1",
            "request_hash": "sha256:abc",
            "created_at": "2026-01-01T00:00:00Z",
        })
    }

    fn approved_approval(id: &str) -> Value {
        json!({
            "approval_id": id,
            "status": "approved",
            "action_id": "http_post",
            "principal": "agent-1",
            "session_id": "sess-1",
            "request_hash": "sha256:abc",
            "created_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:01:00Z",
            "receipt_id": "rcpt-1",
        })
    }

    // -- Selection with real API shapes --

    #[test]
    fn selected_id_reads_approval_id_from_api_shape() {
        let screen = screen_with_approvals(vec![pending_approval("019e-aaa", "http_post")]);
        assert_eq!(screen.selected_id(), Some("019e-aaa"));
    }

    #[test]
    fn selected_id_none_when_empty() {
        let screen = screen_with_approvals(vec![]);
        assert_eq!(screen.selected_id(), None);
    }

    #[test]
    fn selected_status_reads_from_api_shape() {
        let screen = screen_with_approvals(vec![approved_approval("019e-bbb")]);
        assert_eq!(screen.selected_status(), Some("approved"));
    }

    #[test]
    fn selected_is_pending_true_for_pending() {
        let screen = screen_with_approvals(vec![pending_approval("019e-ccc", "fs_write")]);
        assert!(screen.selected_is_pending());
    }

    #[test]
    fn selected_is_pending_false_for_approved() {
        let screen = screen_with_approvals(vec![approved_approval("019e-ddd")]);
        assert!(!screen.selected_is_pending());
    }

    // -- Unresolved domain/path detection (approval detail) --

    #[test]
    fn has_unresolved_with_domains() {
        let mut screen = ApprovalsScreen::new();
        screen.detail = Some(json!({
            "unresolved_domains": ["example.com"],
            "action_id": "http_post",
        }));
        assert!(screen.has_unresolved());
    }

    #[test]
    fn has_unresolved_with_paths() {
        let mut screen = ApprovalsScreen::new();
        screen.detail = Some(json!({
            "unresolved_paths": ["src/main.rs"],
            "action_id": "fs_write",
        }));
        assert!(screen.has_unresolved());
    }

    #[test]
    fn has_unresolved_false_when_empty_arrays() {
        let mut screen = ApprovalsScreen::new();
        screen.detail = Some(json!({
            "unresolved_domains": [],
            "unresolved_paths": [],
        }));
        assert!(!screen.has_unresolved());
    }

    #[test]
    fn has_unresolved_false_when_absent() {
        let mut screen = ApprovalsScreen::new();
        screen.detail = Some(json!({ "action_id": "http_fetch" }));
        assert!(!screen.has_unresolved());
    }

    #[test]
    fn first_unresolved_domain_extracts_correctly() {
        let mut screen = ApprovalsScreen::new();
        screen.detail = Some(json!({
            "unresolved_domains": ["api.stripe.com", "api.github.com"],
        }));
        assert_eq!(screen.first_unresolved_domain(), Some("api.stripe.com"));
    }

    #[test]
    fn first_unresolved_path_extracts_correctly() {
        let mut screen = ApprovalsScreen::new();
        screen.detail = Some(json!({
            "unresolved_paths": ["src/lib.rs"],
        }));
        assert_eq!(screen.first_unresolved_path(), Some("src/lib.rs"));
    }

    // -- TOCTOU: PendingAction captures ID at initiation, not execution --

    #[test]
    fn pending_action_captures_approval_id() {
        let action = PendingAction::Approve {
            approval_id: "019e-captured".to_string(),
        };
        match action {
            PendingAction::Approve { approval_id } => {
                assert_eq!(approval_id, "019e-captured");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn confirm_action_preserves_learn_fields() {
        let action = ConfirmAction::LearnApprove {
            approval_id: "019e-learn".to_string(),
            learn_domain: Some("api.example.com".to_string()),
            learn_path: Some("src/config.rs".to_string()),
        };
        match action {
            ConfirmAction::LearnApprove {
                approval_id,
                learn_domain,
                learn_path,
            } => {
                assert_eq!(approval_id, "019e-learn");
                assert_eq!(learn_domain.as_deref(), Some("api.example.com"));
                assert_eq!(learn_path.as_deref(), Some("src/config.rs"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deny_input_captures_approval_id_at_creation() {
        let deny = DenyInput {
            approval_id: "019e-deny".to_string(),
            input: TextInput::new("reason", 256),
        };
        assert_eq!(deny.approval_id, "019e-deny");
    }

    // -- format_remaining --

    #[test]
    fn format_remaining_returns_empty_for_invalid_timestamp() {
        assert_eq!(format_remaining("not-a-date"), "");
    }

    #[test]
    fn format_remaining_returns_expired_for_past() {
        assert_eq!(format_remaining("2020-01-01T00:00:00Z"), "expired");
    }

    // -- StatusFilter cycling --

    #[test]
    fn status_filter_cycles_correctly() {
        let mut f = StatusFilter::All;
        f = f.next();
        assert_eq!(f.api_param(), Some("pending"));
        f = f.next();
        assert_eq!(f.api_param(), Some("approved"));
        f = f.next();
        assert_eq!(f.api_param(), Some("denied"));
        f = f.next();
        assert_eq!(f.api_param(), None); // back to All
    }

    // -- Selection re-anchoring after list refresh --

    #[test]
    fn selection_clamps_when_list_shrinks() {
        let mut screen = screen_with_approvals(vec![
            pending_approval("a", "x"),
            pending_approval("b", "y"),
            pending_approval("c", "z"),
        ]);
        screen.selected = 2; // pointing at "c"

        // List shrinks to 1 item — selected must clamp.
        screen.approvals = vec![pending_approval("a", "x")];
        let clamped = screen
            .selected
            .min(screen.approvals.len().saturating_sub(1));
        assert_eq!(clamped, 0);
    }
}
