//! Screen 1 — Dashboard.
//!
//! Compact health status bar at top, full-height activity feed below.
//! The health bar is a dense 2-line summary of gate state, dependencies,
//! posture, and budget. The activity feed shows the most recent audit
//! events with decision indicators, risk badges, and age-styled timestamps.

use chrono::Utc;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row};
use ratatui::Frame;
use serde_json::Value;

use latchgate_client::{AuditParams, ClientError, GateClient, OperatorAuth};
use latchgate_config::PostureDetail;

use super::formatting::{decision_indicator, format_uptime, timestamp_age_style, truncate};
use super::screen::{ScreenAction, TuiScreen};
use super::theme::Theme;
use super::widgets::{self, EmptyState, ScrollableTable};

// DashboardScreen

pub(crate) struct DashboardScreen {
    status: Option<Value>,
    recent_events: Vec<Value>,
    error: Option<String>,
    /// Cached chain verification result (expensive — refreshed periodically).
    chain_status: Option<Value>,
    /// Tick counter for throttling chain verification.
    tick_count: usize,
    /// Per-protection posture details from the active config.
    posture_details: Vec<PostureDetail>,
    /// Set by `r` — forces the next tick to re-verify the hash chain.
    force_refresh: bool,
}

impl DashboardScreen {
    pub fn new() -> Self {
        Self {
            status: None,
            recent_events: Vec::new(),
            error: None,
            chain_status: None,
            tick_count: 0,
            posture_details: Vec::new(),
            force_refresh: false,
        }
    }

    fn field_str<'a>(&'a self, key: &str) -> &'a str {
        self.status
            .as_ref()
            .and_then(|s| s[key].as_str())
            .unwrap_or("-")
    }

    fn field_u64(&self, key: &str) -> Option<u64> {
        self.status.as_ref().and_then(|s| s[key].as_u64())
    }

    fn dep_healthy(&self, dep: &str) -> Option<bool> {
        self.status
            .as_ref()
            .and_then(|s| s["dependencies"][dep].as_bool())
    }

    fn budget_u64(&self, key: &str) -> Option<u64> {
        self.status.as_ref().and_then(|s| s["budget"][key].as_u64())
    }

    // -- Rendering -----------------------------------------------------------

    /// Compact 2-line health summary at the top of the dashboard.
    fn render_health_bar(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let gate_status = self.field_str("status");
        let status_style = match gate_status {
            "ok" => theme.status_ok,
            "degraded" | "draining" => theme.status_warn,
            _ => theme.status_error,
        };
        let status_label = match gate_status {
            "ok" => "Running",
            "degraded" => "Degraded",
            "draining" => "Draining",
            other => other,
        };

        let uptime = self
            .field_u64("uptime_seconds")
            .map(format_uptime)
            .unwrap_or_else(|| "-".into());

        let actions = self
            .field_u64("actions_registered")
            .map(|n| format!("{n}"))
            .unwrap_or_else(|| "-".into());

        let redis_dot = health_dot(self.dep_healthy("redis"), theme);
        let opa_dot = health_dot(self.dep_healthy("opa"), theme);

        // Line 1: status, uptime, actions, pending approvals, deps.
        let mut line1 = vec![
            Span::styled("  Status ", theme.header),
            Span::styled(format!("● {status_label}"), status_style),
            Span::raw("  "),
            Span::styled("Up ", theme.header),
            Span::raw(uptime),
            Span::raw("  "),
            Span::styled("Actions ", theme.header),
            Span::raw(actions),
        ];

        // Pending approvals — prominent when > 0.
        if let Some(pending) = self.field_u64("pending_approvals") {
            line1.push(Span::raw("  "));
            line1.push(Span::styled("Pending ", theme.header));
            if pending > 0 {
                line1.push(Span::styled(format!("⚠ {pending}"), theme.status_warn));
            } else {
                line1.push(Span::styled("0", theme.status_ok));
            }
        }

        line1.push(Span::raw("  "));
        line1.push(Span::styled("Redis ", theme.header));
        line1.push(redis_dot);
        line1.push(Span::raw("  "));
        line1.push(Span::styled("OPA ", theme.header));
        line1.push(opa_dot);

        // Append posture badge if available.
        let posture = self.field_str("security_posture");
        if posture != "-" {
            let posture_style = match posture {
                "PRODUCTION" => theme.status_ok,
                _ => theme.status_warn,
            };
            line1.push(Span::raw("  "));
            line1.push(Span::styled(format!("● {posture}"), posture_style));
        }

        frame.render_widget(Paragraph::new(Line::from(line1)), area);

        // Line 2: ledger + budget (if area has room).
        if area.height >= 2 {
            let mut line2: Vec<Span<'_>> = Vec::with_capacity(12);

            // Ledger status.
            line2.push(Span::styled("  Ledger ", theme.header));
            match &self.chain_status {
                Some(v) => {
                    let event_count = v["total_events"].as_u64().unwrap_or(0);
                    let ok = v["intact"].as_bool().unwrap_or(false);
                    if ok {
                        line2.push(Span::styled(
                            format!("● intact ({event_count} events)"),
                            theme.status_ok,
                        ));
                    } else {
                        let at = v["broken_at"].as_str().unwrap_or("?");
                        line2.push(Span::styled(
                            format!("✗ broken at {at}"),
                            theme.status_error,
                        ));
                    }
                }
                None => line2.push(Span::styled("–", theme.dim)),
            }

            // Budget.
            if let (Some(used), Some(limit)) = (self.budget_u64("used"), self.budget_u64("limit")) {
                let remaining = limit.saturating_sub(used);
                let pct = if limit > 0 {
                    (used as f64 / limit as f64 * 100.0) as u64
                } else {
                    0
                };
                line2.push(Span::raw("  "));
                line2.push(Span::styled("Budget ", theme.header));
                let budget_style = if pct > 90 {
                    theme.status_error
                } else if pct > 75 {
                    theme.status_warn
                } else {
                    theme.status_ok
                };
                line2.push(Span::styled(
                    format!("{remaining}/{limit} ({pct}% used)"),
                    budget_style,
                ));
            }

            let line2_area = Rect::new(area.x, area.y + 1, area.width, 1);
            frame.render_widget(Paragraph::new(Line::from(line2)), line2_area);
        }

        // Line 3: posture breakdown when any protection is relaxed.
        let mut next_y = area.y + 2;
        if !self.posture_details.is_empty() {
            let relaxed: Vec<&PostureDetail> = self
                .posture_details
                .iter()
                .filter(|d| !d.enforced)
                .collect();
            if !relaxed.is_empty() && next_y < area.bottom() {
                let mut spans: Vec<Span<'_>> = Vec::with_capacity(relaxed.len() * 3 + 2);
                spans.push(Span::styled("  Relaxed ", theme.header));
                for (i, d) in relaxed.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::styled("  ", theme.dim));
                    }
                    spans.push(Span::styled(
                        format!("⚠ {}: {}", d.name, d.status),
                        theme.status_warn,
                    ));
                }
                let line3_area = Rect::new(area.x, next_y, area.width, 1);
                frame.render_widget(Paragraph::new(Line::from(spans)), line3_area);
                next_y += 1;
            }
        }

        // Error overlay on the health bar.
        if let Some(ref err) = self.error {
            if next_y < area.bottom() {
                let err_area = Rect::new(area.x + 2, next_y, area.width.saturating_sub(4), 1);
                frame.render_widget(
                    Paragraph::new(Span::styled(err.as_str(), theme.status_error)),
                    err_area,
                );
            }
        }
    }

    /// Full-height activity feed with event consolidation.
    fn render_activity_feed(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border)
            .title(" Recent Activity ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let header =
            Row::new(vec!["  Time", "Decision", "Action", "Principal", "Risk"]).style(theme.header);
        let widths = [
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(18),
            Constraint::Min(12),
            Constraint::Length(6),
        ];

        let now = Utc::now();

        // Consolidate: hide pending_approval events superseded by a terminal
        // decision sharing the same approval_id.
        let resolved: std::collections::HashSet<&str> = self
            .recent_events
            .iter()
            .filter(|ev| ev["decision"].as_str().unwrap_or("") != "pending_approval")
            .filter_map(|ev| ev["approval_id"].as_str())
            .collect();

        let rows: Vec<Row<'_>> = self
            .recent_events
            .iter()
            .filter(|ev| {
                if ev["decision"].as_str() == Some("pending_approval") {
                    if let Some(aid) = ev["approval_id"].as_str() {
                        return !resolved.contains(aid);
                    }
                }
                true
            })
            .map(|ev| {
                let ts_raw = ev["timestamp"].as_str().unwrap_or("");
                let ts_display = ts_raw.get(11..19).unwrap_or("-");
                let ts_style = timestamp_age_style(ts_raw, &now, theme);

                let decision = ev["decision"].as_str().unwrap_or("-");
                let action = ev["action_id"].as_str().unwrap_or("-");
                let principal = ev["principal"].as_str().unwrap_or("-");
                let risk = ev["risk_level"].as_str().unwrap_or("");

                let (dot, decision_style) = decision_indicator(decision, theme);

                Row::new(vec![
                    Line::from(Span::styled(format!("  {ts_display}"), ts_style)),
                    Line::from(Span::styled(format!("{dot} {decision}"), decision_style)),
                    Line::from(Span::raw(truncate(action, 18))),
                    Line::from(Span::styled(truncate(principal, 20), theme.dim)),
                    Line::from(if risk.is_empty() {
                        Span::styled("–", theme.dim)
                    } else {
                        widgets::risk_badge(risk, theme)
                    }),
                ])
            })
            .collect();

        frame.render_widget(
            ScrollableTable::new(rows, widths)
                .header(header)
                .selected(0)
                .empty(
                    EmptyState::new("No recent events.", theme)
                        .hint("Activity appears here as requests are processed"),
                ),
            inner,
        );
    }
}

// TuiScreen

impl TuiScreen for DashboardScreen {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        // Health bar height: 2 base + optional posture breakdown + optional error.
        let has_relaxed = self.posture_details.iter().any(|d| !d.enforced);
        let mut health_height: u16 = 2;
        if has_relaxed {
            health_height += 1;
        }
        if self.error.is_some() {
            health_height += 1;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(health_height), Constraint::Min(6)])
            .split(area);

        self.render_health_bar(chunks[0], frame, theme);
        self.render_activity_feed(chunks[1], frame, theme);
    }

    fn handle_key(&mut self, key: KeyEvent, _theme: &Theme) -> ScreenAction {
        match key.code {
            KeyCode::Enter => ScreenAction::Navigate(1),
            KeyCode::Char('r') => {
                self.force_refresh = true;
                ScreenAction::AsyncAction
            }
            _ => ScreenAction::Noop,
        }
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.tick_count += 1;

            match client.status(auth).await {
                Ok(s) => {
                    self.status = Some(s);
                    self.error = None;
                }
                Err(ClientError::NotReachable(msg)) => {
                    self.error = Some(format!("Gate unreachable: {msg}"));
                }
                Err(ClientError::Http { status: 404, .. }) => {
                    self.error = None;
                }
                Err(e) => {
                    self.error = Some(format!("Status: {e}"));
                }
            }

            let params = AuditParams {
                limit: Some(30),
                ..Default::default()
            };
            match client.audit_events(auth, &params).await {
                Ok(events) => self.recent_events = events,
                Err(ClientError::Http { status: 404, .. }) => {
                    self.recent_events.clear();
                }
                Err(e) => {
                    if self.error.is_none() {
                        self.error = Some(format!("Activity: {e}"));
                    }
                }
            }

            // Chain verification is expensive — run on first tick, every 30th,
            // or when the operator forced a refresh.
            if self.tick_count == 1 || self.tick_count.is_multiple_of(30) || self.force_refresh {
                if let Ok(v) = client.verify_chain(auth).await {
                    self.chain_status = Some(v);
                }
            }
            self.force_refresh = false;
        })
    }

    fn update_config(&mut self, config: &latchgate_config::Config) {
        self.posture_details = config.posture_details();
    }

    fn tab_label(&self) -> &'static str {
        "Dashboard"
    }

    fn status_hint(&self) -> &str {
        "[Enter]approvals  [r]efresh"
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        &[("Enter", "Go to Approvals screen"), ("r", "Force refresh")]
    }
}

// Helpers

/// Compact health dot for dependency indicators.
fn health_dot<'a>(healthy: Option<bool>, theme: &Theme) -> Span<'a> {
    match healthy {
        Some(true) => Span::styled("● ok", theme.status_ok),
        Some(false) => Span::styled("● down", theme.status_error),
        None => Span::styled("–", theme.dim),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Realistic status response from `GET /v1/status`.
    fn status_response(pending: u64, total_calls: u64) -> Value {
        json!({
            "version": "0.1.0",
            "uptime_seconds": 3600,
            "pending_approvals": pending,
            "total_calls": total_calls,
            "actions_registered": 87,
            "state_backend": "sqlite",
            "dependencies": {
                "redis": true,
                "opa": true
            }
        })
    }

    /// Realistic audit event from `GET /v1/audit`.
    fn audit_event(decision: &str, action: &str, approval_id: Option<&str>) -> Value {
        let mut ev = json!({
            "trace_id": format!("tr_{decision}_{action}"),
            "event_type": "action_call",
            "timestamp": "2026-05-31T17:30:00Z",
            "decision": decision,
            "action_id": action,
            "principal": "agent-1",
            "risk_level": "medium",
        });
        if let Some(aid) = approval_id {
            ev["approval_id"] = json!(aid);
        }
        ev
    }

    #[test]
    fn field_str_reads_nested_values() {
        let mut screen = DashboardScreen::new();
        screen.status = Some(status_response(0, 100));
        assert_eq!(screen.field_str("version"), "0.1.0");
        assert_eq!(screen.field_str("state_backend"), "sqlite");
    }

    #[test]
    fn field_str_returns_dash_for_missing() {
        let mut screen = DashboardScreen::new();
        screen.status = Some(json!({}));
        assert_eq!(screen.field_str("nonexistent"), "-");
    }

    #[test]
    fn dep_healthy_reads_from_status() {
        let mut screen = DashboardScreen::new();
        screen.status = Some(status_response(0, 0));
        assert_eq!(screen.dep_healthy("redis"), Some(true));
    }

    #[test]
    fn dep_healthy_none_when_absent() {
        let mut screen = DashboardScreen::new();
        screen.status = Some(json!({ "dependencies": {} }));
        assert_eq!(screen.dep_healthy("redis"), None);
    }

    #[test]
    fn resolved_approvals_hide_superseded_pending() {
        let events = [
            audit_event("pending_approval", "http_post", Some("appr-1")),
            audit_event("allow", "http_post", Some("appr-1")),
        ];

        let resolved: std::collections::HashSet<&str> = events
            .iter()
            .filter(|ev| ev["decision"].as_str().unwrap_or("") != "pending_approval")
            .filter_map(|ev| ev["approval_id"].as_str())
            .collect();

        let visible: Vec<_> = events
            .iter()
            .filter(|ev| {
                if ev["decision"].as_str() == Some("pending_approval") {
                    if let Some(aid) = ev["approval_id"].as_str() {
                        return !resolved.contains(aid);
                    }
                }
                true
            })
            .collect();

        // Only the terminal "allow" should remain — "pending_approval" is superseded.
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0]["decision"].as_str(), Some("allow"));
    }
}
