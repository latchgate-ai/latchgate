//! TUI application shell: event loop, screen navigation, rendering.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::{execute, terminal};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use latchgate_client::{GateClient, OperatorAuth};
use latchgate_config::Config;

use crate::input::{FlashMessage, FlashStyle, InputAction, TextInput};
use crate::screen::{ScreenAction, TuiScreen};
use crate::theme::Theme;
use crate::{DoctorRunner, GateOps, SetupOps};

const MIN_COLS: u16 = 80;
const MIN_ROWS: u16 = 24;
const TICK_INTERVAL: Duration = Duration::from_secs(3);
const FLASH_TTL_SUCCESS: Duration = Duration::from_secs(5);
const FLASH_TTL_ERROR: Duration = Duration::from_secs(10);

/// Health-probe timeout inside `tick_active`. Must fail fast so the event
/// loop stays responsive when the gate is unresponsive or half-open.
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Screen-tick timeout inside `tick_active`. Bounds how long a screen's
/// data-refresh I/O can block input handling. Individual requests are
/// already bounded by the transport-layer timeout, but a screen may issue
/// multiple sequential calls; this is the aggregate ceiling.
const SCREEN_TICK_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for async actions (approve, deny, learn, etc.). Prevents an
/// unresponsive gate from blocking the TUI indefinitely. On timeout the
/// action silently fails — the operator can retry.
const ACTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Crate version shown in the status bar.
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Revoke double-confirm state machine

enum RevokeStage {
    /// First confirm: ConfirmDialog (y/n).
    Confirm,
    /// Second confirm: type "REVOKE" in a TextInput.
    TypeConfirm,
}

// App

struct App {
    screens: Vec<Box<dyn TuiScreen>>,
    active_screen: usize,
    flash: Option<FlashMessage>,
    input_mode: bool,
    show_help: bool,
    client: GateClient,
    auth: OperatorAuth,
    config: Config,
    setup: Arc<dyn SetupOps>,
    gate_ops: Option<Arc<dyn GateOps>>,
    theme: Theme,
    // Reconnect backoff state.
    gate_connected: bool,
    reconnect_backoff: Duration,
    next_reconnect: Instant,
    /// True once ephemeral auth upgrade has been attempted for the current
    /// connection. Reset on disconnect so a new attempt fires after the
    /// next reconnect.
    auth_upgrade_attempted: bool,
    // Revoke epoch flow.
    revoke_stage: Option<RevokeStage>,
    revoke_input: Option<TextInput>,
    // Gate down confirm flow.
    gate_down_confirm: bool,
    /// Multi-line diagnostic text shown in a modal overlay when a gate
    /// restart fails.  Dismissed on any keypress.  Unlike `FlashMessage`,
    /// this has no TTL — it stays visible until the operator acknowledges it.
    diagnostic: Option<String>,
}

impl App {
    fn new(
        client: GateClient,
        auth: OperatorAuth,
        cfg: Config,
        doctor: Arc<dyn DoctorRunner>,
        setup: Arc<dyn SetupOps>,
        gate_ops: Option<Arc<dyn GateOps>>,
    ) -> Self {
        let screens: Vec<Box<dyn TuiScreen>> = vec![
            Box::new(crate::dashboard::DashboardScreen::new()),
            Box::new(crate::approvals::ApprovalsScreen::new()),
            Box::new(crate::actions::ActionsScreen::new(Arc::clone(&setup))),
            Box::new(crate::activity::ActivityScreen::new()),
            Box::new(crate::allowlists::AllowlistsScreen::new()),
            Box::new(crate::config::ConfigScreen::new(
                cfg.clone(),
                doctor,
                Arc::clone(&setup),
            )),
        ];

        Self {
            screens,
            active_screen: 0,
            flash: None,
            input_mode: false,
            show_help: false,
            client,
            auth,
            config: cfg,
            setup,
            gate_ops,
            theme: Theme::default(),
            gate_connected: true,
            reconnect_backoff: Duration::from_secs(1),
            next_reconnect: Instant::now(),
            auth_upgrade_attempted: false,
            revoke_stage: None,
            revoke_input: None,
            gate_down_confirm: false,
            diagnostic: None,
        }
    }

    /// Poll data for the active screen, respecting reconnect backoff.
    ///
    /// Both the health probe and the screen data refresh are wrapped in
    /// hard timeouts so a dead or half-open gate socket can never freeze
    /// the event loop. These are belt-and-suspenders on top of the
    /// transport-layer UDS timeout.
    /// Phase 1 of tick: probe gate health, manage reconnect state, upgrade
    /// ephemeral auth. Returns `true` if the gate is healthy and the caller
    /// should proceed to `tick_screen`.
    ///
    /// Separated from the screen tick so the event loop can render a frame
    /// between the health probe and the (potentially slow) data refresh,
    /// keeping spinners and input responsive.
    async fn tick_health(&mut self) -> bool {
        let now = Instant::now();

        if !self.gate_connected && now < self.next_reconnect {
            return false;
        }

        let healthy = tokio::time::timeout(HEALTH_PROBE_TIMEOUT, self.client.healthz())
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);

        if healthy {
            let was_disconnected = !self.gate_connected;
            if was_disconnected {
                self.gate_connected = true;
                self.reconnect_backoff = Duration::from_secs(1);
            }

            if self.auth.is_ephemeral() && !self.auth_upgrade_attempted {
                self.auth_upgrade_attempted = true;
                self.try_upgrade_auth();
            }

            true
        } else {
            if self.gate_connected {
                self.auth_upgrade_attempted = false;
            }
            self.gate_connected = false;
            self.next_reconnect = now + self.reconnect_backoff;
            self.reconnect_backoff = (self.reconnect_backoff * 2).min(MAX_BACKOFF);
            false
        }
    }

    /// Phase 2 of tick: refresh the active screen's data.
    ///
    /// Bounded by `SCREEN_TICK_TIMEOUT` so a slow gate never blocks the
    /// event loop indefinitely.
    async fn tick_screen(&mut self) {
        let client = &self.client;
        let auth = &self.auth;
        let _ = tokio::time::timeout(
            SCREEN_TICK_TIMEOUT,
            self.screens[self.active_screen].tick(client, auth),
        )
        .await;
    }

    /// Combined tick — retained for callsites that don't need a render
    /// between phases (e.g. the initial tick before the event loop starts).
    async fn tick_active(&mut self) {
        if self.tick_health().await {
            self.tick_screen().await;
        }
    }

    /// Apply the result of a [`GateOps::start`] call to app state.
    ///
    /// On success, replaces the client, auth, and config, resets reconnect
    /// state, propagates the new config to all screens, and sets a success
    /// flash.  On failure, either sets a diagnostic modal (for restart
    /// operations where the gate was already stopped) or a transient flash
    /// (for start-only operations).
    fn apply_start_result(
        &mut self,
        result: Result<(Config, OperatorAuth), String>,
        success_msg: &str,
        diagnostic_on_error: bool,
    ) {
        match result {
            Ok((config, auth)) => match GateClient::from_config(&config) {
                Ok(c) => {
                    self.client = c;
                    self.auth = auth;
                    self.config = config;
                    self.gate_connected = true;
                    self.reconnect_backoff = Duration::from_secs(1);
                    // Reset so ephemeral auth auto-discovery retries on the
                    // next healthy tick after this (re)start.
                    self.auth_upgrade_attempted = false;
                    for screen in &mut self.screens {
                        screen.update_config(&self.config);
                    }
                    self.set_flash(FlashMessage::success(success_msg));
                }
                Err(e) => {
                    self.set_flash(FlashMessage::error(format!("Client init failed: {e}")));
                }
            },
            Err(e) => {
                if diagnostic_on_error {
                    self.diagnostic = Some(e);
                } else {
                    self.set_flash(FlashMessage::error(format!("Start failed: {e}")));
                }
            }
        }
    }

    /// Attempt to discover real operator credentials and replace ephemeral auth.
    ///
    /// Called exactly once per connection attempt. Re-reads the config from
    /// disk (it may have changed since `latchgate init` ran) and tries
    /// [`auto_discover_operator_auth`]. On success, rebuilds the client and
    /// propagates the new config to all screens.
    fn try_upgrade_auth(&mut self) {
        // Re-read config to pick up credentials written by `latchgate init`.
        // If the config file is missing or unparseable, there is nothing to
        // discover — bail without touching state.
        let config = match latchgate_config::Config::load() {
            Ok(c) => c,
            Err(_) => {
                self.set_flash(FlashMessage::error(
                    "⚠ No config found — admin actions will fail. \
                     Run `latchgate init` or provide --operator-key.",
                ));
                return;
            }
        };

        match latchgate_client::auto_discover_operator_auth(&config) {
            Ok(new_auth) => {
                self.auth = new_auth;
                self.config = config;
                if let Ok(c) = GateClient::from_config(&self.config) {
                    self.client = c;
                }
                for screen in &mut self.screens {
                    screen.update_config(&self.config);
                }
                self.set_flash(FlashMessage::success(
                    "✓ Operator credentials discovered — authenticated",
                ));
            }
            Err(_) => {
                self.set_flash(FlashMessage::error(
                    "⚠ No operator credentials found — admin actions will fail. \
                     Run `latchgate init` or provide --operator-key.",
                ));
            }
        }
    }

    async fn handle_action(&mut self) -> Option<FlashMessage> {
        let client = &self.client;
        let auth = &self.auth;
        self.screens[self.active_screen]
            .handle_action(client, auth)
            .await
    }

    fn switch_screen(&mut self, idx: usize) {
        if idx < self.screens.len() {
            self.active_screen = idx;
            self.input_mode = false;
            self.show_help = false;
        }
    }

    fn set_flash(&mut self, msg: FlashMessage) {
        self.flash = Some(msg);
    }

    fn expire_flash(&mut self) {
        if let Some(ref flash) = self.flash {
            let ttl = match flash.style {
                FlashStyle::Error => FLASH_TTL_ERROR,
                _ => FLASH_TTL_SUCCESS,
            };
            if flash.created_at.elapsed() >= ttl {
                self.flash = None;
            }
        }
    }

    /// Execute an init plan and update the config screen.
    fn execute_init(&mut self, plan: &crate::InitPlan) -> Result<FlashMessage, FlashMessage> {
        match self.setup.execute_init(plan) {
            Ok(new_config) => {
                self.config = new_config;
                for screen in &mut self.screens {
                    screen.update_config(&self.config);
                }
                self.client = match GateClient::from_config(&self.config) {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(FlashMessage::error(format!("client init failed: {e}")));
                    }
                };
                Ok(FlashMessage::success(format!(
                    "✓ Initialized with preset '{}'. Configure principals/operators, then run `latchgate up`.",
                    plan.preset.name,
                )))
            }
            Err(e) => Err(FlashMessage::error(format!("Init failed: {e}"))),
        }
    }

    /// Cancel the revoke flow and restore normal input mode.
    fn cancel_revoke(&mut self) {
        self.revoke_stage = None;
        self.revoke_input = None;
        self.input_mode = false;
    }

    fn handle_key(&mut self, key: ratatui::crossterm::event::KeyEvent) -> ScreenAction {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return ScreenAction::Quit;
        }

        // Diagnostic overlay: any keypress dismisses.
        if self.diagnostic.is_some() {
            self.diagnostic = None;
            return ScreenAction::Noop;
        }

        // Revoke flow intercepts all keys when active.
        if self.revoke_stage.is_some() {
            return self.handle_revoke_key(key);
        }

        // Gate-down confirm intercepts all keys when active.
        if self.gate_down_confirm {
            return self.handle_gate_down_key(key);
        }

        // Help overlay: `?` toggles (not in input mode).
        if !self.input_mode && key.code == KeyCode::Char('?') {
            self.show_help = !self.show_help;
            return ScreenAction::Noop;
        }

        // Any key dismisses help overlay.
        if self.show_help {
            self.show_help = false;
            return ScreenAction::Noop;
        }

        if !self.input_mode {
            match key.code {
                KeyCode::Char('q') => return ScreenAction::Quit,
                KeyCode::Char(c @ '1'..='6') => {
                    // On the Setup screen (last tab), digits 1–6 address
                    // sub-tabs.  Forward them to the screen handler instead
                    // of consuming them for global navigation.
                    let setup_idx = self.screens.len() - 1;
                    if self.active_screen == setup_idx && c <= '6' {
                        // Fall through to screen handler below.
                    } else {
                        let idx = (c as usize) - ('1' as usize);
                        return ScreenAction::Navigate(idx);
                    }
                }
                KeyCode::Tab => {
                    let next = (self.active_screen + 1) % self.screens.len();
                    return ScreenAction::Navigate(next);
                }
                KeyCode::BackTab => {
                    let prev = if self.active_screen == 0 {
                        self.screens.len() - 1
                    } else {
                        self.active_screen - 1
                    };
                    return ScreenAction::Navigate(prev);
                }
                // Global: Shift+R => revoke epoch.
                KeyCode::Char('R') => {
                    self.revoke_stage = Some(RevokeStage::Confirm);
                    self.input_mode = true;
                    return ScreenAction::Noop;
                }
                // Global: Shift+S => gate down (with confirm).
                KeyCode::Char('S') => {
                    if let Some(ref ops) = self.gate_ops {
                        if ops.can_stop() {
                            self.gate_down_confirm = true;
                            self.input_mode = true;
                            return ScreenAction::Noop;
                        }
                    }
                    return ScreenAction::Flash(FlashMessage::success(
                        "Gate is externally managed — stop from the host",
                    ));
                }
                _ => {}
            }
        } else {
            // ── Input mode — global escape hatch + clean-state nav ────
            //
            // Esc always delegates to the screen for clean cancellation
            // (which may prompt to discard if dirty).  When the screen
            // returns EndInput, clear the lock.
            if key.code == KeyCode::Esc {
                let action = self.screens[self.active_screen].handle_key(key, &self.theme);
                if matches!(action, ScreenAction::EndInput) {
                    self.input_mode = false;
                }
                return action;
            }

            // When the screen is not a modal input surface, allow global
            // panel navigation so the user is never trapped. A modal screen
            // (edit/create) owns all keys while open; only `Esc`, handled
            // above, exits it.
            if !self.screens[self.active_screen].is_modal() {
                match key.code {
                    KeyCode::Char(c @ '1'..='6') => {
                        let idx = (c as usize) - ('1' as usize);
                        self.input_mode = false;
                        return ScreenAction::Navigate(idx);
                    }
                    KeyCode::Tab => {
                        let next = (self.active_screen + 1) % self.screens.len();
                        self.input_mode = false;
                        return ScreenAction::Navigate(next);
                    }
                    KeyCode::BackTab => {
                        let prev = if self.active_screen == 0 {
                            self.screens.len() - 1
                        } else {
                            self.active_screen - 1
                        };
                        self.input_mode = false;
                        return ScreenAction::Navigate(prev);
                    }
                    _ => {}
                }
            }
        }

        self.screens[self.active_screen].handle_key(key, &self.theme)
    }

    /// Key handling within the revoke double-confirm flow.
    fn handle_revoke_key(&mut self, key: ratatui::crossterm::event::KeyEvent) -> ScreenAction {
        match self.revoke_stage {
            Some(RevokeStage::Confirm) => match key.code {
                KeyCode::Char('y') => {
                    self.revoke_stage = Some(RevokeStage::TypeConfirm);
                    self.revoke_input = Some(TextInput::new(
                        " Type REVOKE to confirm (Esc to cancel) ",
                        6,
                    ));
                    ScreenAction::Noop
                }
                _ => {
                    self.cancel_revoke();
                    ScreenAction::Noop
                }
            },
            Some(RevokeStage::TypeConfirm) => {
                if let Some(ref mut input) = self.revoke_input {
                    match input.handle_key(key) {
                        InputAction::Submit(text) => {
                            self.cancel_revoke();
                            if text.trim() == "REVOKE" {
                                ScreenAction::RevokeEpoch
                            } else {
                                self.set_flash(FlashMessage::error(
                                    "Revoke cancelled — confirmation text didn't match",
                                ));
                                ScreenAction::Noop
                            }
                        }
                        InputAction::Cancel => {
                            self.cancel_revoke();
                            ScreenAction::Noop
                        }
                        InputAction::Continue => ScreenAction::Noop,
                    }
                } else {
                    self.cancel_revoke();
                    ScreenAction::Noop
                }
            }
            None => ScreenAction::Noop,
        }
    }

    /// Key handling within the gate-down confirmation.
    fn handle_gate_down_key(&mut self, key: ratatui::crossterm::event::KeyEvent) -> ScreenAction {
        match key.code {
            KeyCode::Char('y') => {
                self.gate_down_confirm = false;
                self.input_mode = false;
                ScreenAction::GateDown
            }
            _ => {
                self.gate_down_confirm = false;
                self.input_mode = false;
                ScreenAction::Noop
            }
        }
    }

    fn render(&self, frame: &mut Frame) {
        let area = frame.area();

        if area.width < MIN_COLS || area.height < MIN_ROWS {
            let msg = format!(
                "Terminal too small (need {MIN_COLS}×{MIN_ROWS}, have {}×{})",
                area.width, area.height,
            );
            let y = area.height / 2;
            frame.render_widget(
                Paragraph::new(msg).style(self.theme.status_warn),
                Rect::new(0, y, area.width, 1),
            );
            return;
        }

        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // title bar
                Constraint::Length(2), // tab row (labels + rule)
                Constraint::Min(0),    // screen content
                Constraint::Length(2), // status bar
            ])
            .split(area);

        self.render_title_bar(outer[0], frame);
        self.render_tab_row(outer[1], frame);
        self.screens[self.active_screen].render(outer[2], frame, &self.theme);
        self.render_status(outer[3], frame);

        // Overlays — highest-priority last.
        if self.show_help {
            self.render_help_overlay(area, frame);
        }

        if self.revoke_stage.is_some() {
            self.render_revoke_overlay(area, frame);
        }

        if self.gate_down_confirm {
            self.render_gate_down_confirm(area, frame);
        }

        if self.diagnostic.is_some() {
            self.render_diagnostic_overlay(area, frame);
        }
    }

    fn render_title_bar(&self, area: Rect, frame: &mut Frame) {
        let screen_name = self.screens[self.active_screen].tab_label();

        // Right side: connection dot + pending badge.
        let pending: usize = self.screens.iter().map(|s| s.badge_count()).sum();
        let mut right_spans: Vec<Span<'_>> = Vec::new();

        if !self.gate_connected {
            right_spans.push(Span::styled("○ disconnected", self.theme.status_error));
        } else if self.auth.is_ephemeral() {
            right_spans.push(Span::styled("⚠ no credentials", self.theme.status_warn));
        } else if self.config.posture.any_relaxed() {
            right_spans.push(Span::styled("⚠ DEV — NOT SECURE", self.theme.status_error));
        } else {
            right_spans.push(Span::styled("● PRODUCTION", self.theme.status_ok));
            if pending > 0 {
                right_spans.push(Span::styled(
                    format!(" ⚠ {pending}"),
                    self.theme.status_warn,
                ));
            }
        }
        right_spans.push(Span::raw(" "));

        let left_text = " LatchGate";
        let left_len = left_text.chars().count();
        let right_len: usize = right_spans.iter().map(|s| s.content.chars().count()).sum();
        let center_len = screen_name.chars().count();
        let total = area.width as usize;

        let mut spans: Vec<Span<'_>> = Vec::with_capacity(8);
        spans.push(Span::styled(left_text, self.theme.branding));

        // The centered screen name is also shown in the tab row, so it is
        // optional here. Render it only when the brand, name, and status fit
        // with at least one column of separation on each side; otherwise drop
        // it and right-align the status so nothing overlaps at minimum width.
        let need_center = left_len + 1 + center_len + 1 + right_len;
        if center_len > 0 && total >= need_center {
            let center_pos = total.saturating_sub(center_len) / 2;
            // Clamp so the left gap is always ≥ 1 and the right gap ≥ 1.
            let center_pos = center_pos
                .max(left_len + 1)
                .min(total.saturating_sub(center_len + right_len + 1));
            let gap_left = center_pos - left_len;
            let gap_right = total - (center_pos + center_len) - right_len;
            spans.push(Span::raw(" ".repeat(gap_left)));
            spans.push(Span::styled(screen_name, self.theme.title_screen));
            spans.push(Span::raw(" ".repeat(gap_right)));
        } else {
            // No room for the centered name: pad straight to the status block.
            let gap = total.saturating_sub(left_len + right_len);
            spans.push(Span::raw(" ".repeat(gap)));
        }
        spans.extend(right_spans);

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_tab_row(&self, area: Rect, frame: &mut Frame) {
        if area.height < 2 {
            return;
        }

        let label_area = Rect::new(area.x, area.y, area.width, 1);
        let rule_area = Rect::new(area.x, area.y + 1, area.width, 1);

        let mut label_spans: Vec<Span<'_>> = Vec::with_capacity(self.screens.len() * 4);
        let mut rule_spans: Vec<Span<'_>> = Vec::with_capacity(self.screens.len() * 3);

        for (i, screen) in self.screens.iter().enumerate() {
            let name = screen.tab_label();
            let badge = screen.badge_count();
            let is_active = i == self.active_screen;

            let tab_text = if badge > 0 {
                format!("{name}({badge})")
            } else {
                name.to_string()
            };

            let label_style = if is_active {
                self.theme.tab_active
            } else {
                self.theme.tab_inactive
            };
            let (rule_ch, rule_style) = if is_active {
                ("━", self.theme.branding)
            } else {
                ("─", self.theme.separator)
            };

            // Dimmed digit shortcut + space.
            let digit = format!("{}", i + 1);
            label_spans.push(Span::styled(digit, self.theme.dim));
            rule_spans.push(Span::styled("─", self.theme.separator));

            // Padded label.
            let padded = format!(" {tab_text} ");
            let pad_width = padded.chars().count();
            label_spans.push(Span::styled(padded, label_style));
            rule_spans.push(Span::styled(rule_ch.repeat(pad_width), rule_style));

            // Separator between tabs.
            if i + 1 < self.screens.len() {
                label_spans.push(Span::styled("│", self.theme.separator));
                rule_spans.push(Span::raw(" "));
            }
        }

        frame.render_widget(Paragraph::new(Line::from(label_spans)), label_area);
        frame.render_widget(Paragraph::new(Line::from(rule_spans)), rule_area);
    }

    fn render_status(&self, area: Rect, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1)])
            .split(area);

        // Line 1: flash message or reconnect indicator.
        if !self.gate_connected {
            let secs = self
                .next_reconnect
                .saturating_duration_since(Instant::now())
                .as_secs();
            let msg = format!(" ⚠ Gate unreachable — reconnecting in {secs}s…");
            let line = Line::from(Span::styled(msg, self.theme.status_warn));
            frame.render_widget(Paragraph::new(line), chunks[0]);
        } else if let Some(ref flash) = self.flash {
            let style = flash.ratatui_style(&self.theme);
            // One leading space of padding, so the budget for the message body
            // is width - 1. Reserve one more cell for the ellipsis when the
            // text overflows. `Span` is byte-indexed but we slice on character
            // boundaries to stay correct for multi-byte glyphs.
            let budget = (chunks[0].width as usize).saturating_sub(1);
            let count = flash.text.chars().count();
            let display = if count > budget && budget > 1 {
                let kept: String = flash.text.chars().take(budget - 1).collect();
                format!(" {kept}…")
            } else {
                format!(" {}", flash.text)
            };
            let line = Line::from(Span::styled(display, style));
            frame.render_widget(Paragraph::new(line), chunks[0]);
        }

        // Line 2: context-adaptive key hints + right-aligned version.
        let hint = if self.input_mode {
            "Enter submit  Esc cancel"
        } else {
            self.screens[self.active_screen].status_hint()
        };

        let version_str = format!("v{VERSION} ");
        let version_len = version_str.chars().count();

        let hint_prefix = format!(" {hint}");
        let hint_len = hint_prefix.chars().count();
        let global_hint = "[Shift-R]revoke  [Shift-S]stop  [1-6]screen  [?]help  [q]uit";
        let global_len = global_hint.chars().count();

        // Pad between global hint and version to push version to the right.
        let used = hint_len + 2 + global_len;
        let gap = (area.width as usize).saturating_sub(used + version_len);

        let line = Line::from(vec![
            Span::styled(hint_prefix, self.theme.key_hint),
            Span::raw("  "),
            Span::styled(global_hint, self.theme.dim),
            Span::raw(" ".repeat(gap)),
            Span::styled(version_str, self.theme.dim),
        ]);
        frame.render_widget(Paragraph::new(line), chunks[1]);
    }

    fn render_help_overlay(&self, area: Rect, frame: &mut Frame) {
        let keys = self.screens[self.active_screen].help_keys();
        let screen_label = self.screens[self.active_screen].tab_label();

        // Global keys always shown.
        let global_keys: &[(&str, &str)] = &[
            ("1-6", "Switch to screen"),
            ("Tab", "Next screen"),
            ("Shift-Tab", "Previous screen"),
            ("Shift-R", "Revoke all grants (emergency)"),
            ("Shift-S", "Stop gate (when started via `up`)"),
            ("q", "Quit"),
            ("Ctrl-C", "Quit (even in input mode)"),
            ("?", "Toggle this help"),
        ];

        let total_lines = keys.len() + global_keys.len() + 5; // headers + spacing
        let width = 56u16.min(area.width.saturating_sub(4));
        let height = (total_lines as u16 + 2).min(area.height.saturating_sub(4));
        let x = area.width.saturating_sub(width) / 2;
        let y = area.height.saturating_sub(height) / 2;
        let popup = Rect::new(x, y, width, height);

        frame.render_widget(Clear, popup);

        let title = format!(" {screen_label} — Help ");
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.modal_border_type)
            .border_style(self.theme.border_double)
            .title(title);
        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(total_lines);

        if !keys.is_empty() {
            lines.push(Line::from(Span::styled(
                " Screen keys:",
                self.theme.header.add_modifier(Modifier::BOLD),
            )));
            for (key, desc) in keys {
                lines.push(Line::from(vec![
                    Span::styled(format!("   {key:<14}"), self.theme.header),
                    Span::raw(*desc),
                ]));
            }
            lines.push(Line::default());
        }

        lines.push(Line::from(Span::styled(
            " Global keys:",
            self.theme.header.add_modifier(Modifier::BOLD),
        )));
        for (key, desc) in global_keys {
            lines.push(Line::from(vec![
                Span::styled(format!("   {key:<14}"), self.theme.header),
                Span::raw(*desc),
            ]));
        }

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    fn render_revoke_overlay(&self, area: Rect, frame: &mut Frame) {
        match self.revoke_stage {
            Some(RevokeStage::Confirm) => {
                // Red-styled DOUBLE-border ConfirmDialog.
                let question = "REVOKE ALL GRANTS — invalidate every outstanding execution grant?";
                let content_width = question.len() as u16 + 4;
                let width = content_width.clamp(24, area.width.saturating_sub(4));
                let height = 5u16.min(area.height.saturating_sub(2));

                let x = area.x + (area.width.saturating_sub(width)) / 2;
                let y = area.y + (area.height.saturating_sub(height)) / 2;
                let popup = Rect::new(x, y, width, height);

                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(self.theme.modal_border_type)
                    .border_style(self.theme.status_error)
                    .title(Span::styled(
                        " ⚠ Emergency Revoke ",
                        self.theme.status_error.add_modifier(Modifier::BOLD),
                    ));

                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                if inner.width > 0 && inner.height > 0 {
                    let lines = vec![
                        Line::from(Span::styled(question, self.theme.status_error)),
                        Line::default(),
                        Line::from(vec![
                            Span::styled("[y]", self.theme.header),
                            Span::styled("es  ", self.theme.dim),
                            Span::styled("[n]", self.theme.header),
                            Span::styled("o", self.theme.dim),
                        ]),
                    ];
                    frame.render_widget(
                        Paragraph::new(lines)
                            .alignment(Alignment::Center)
                            .wrap(Wrap { trim: false }),
                        inner,
                    );
                }
            }
            Some(RevokeStage::TypeConfirm) => {
                // Centered popup with TextInput for "REVOKE" confirmation.
                let width = 52u16.min(area.width.saturating_sub(4));
                let height = 7u16.min(area.height.saturating_sub(2));

                let x = area.x + (area.width.saturating_sub(width)) / 2;
                let y = area.y + (area.height.saturating_sub(height)) / 2;
                let popup = Rect::new(x, y, width, height);

                frame.render_widget(Clear, popup);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(self.theme.modal_border_type)
                    .border_style(self.theme.status_error)
                    .title(Span::styled(
                        " ⚠ Confirm Revoke ",
                        self.theme.status_error.add_modifier(Modifier::BOLD),
                    ));

                let inner = block.inner(popup);
                frame.render_widget(block, popup);

                if inner.width > 0 && inner.height > 0 {
                    let msg_area = Rect::new(inner.x, inner.y, inner.width, 1);
                    frame.render_widget(
                        Paragraph::new(Line::from(Span::styled(
                            "This is irreversible. All active grants will be invalidated.",
                            self.theme.status_warn,
                        )))
                        .alignment(Alignment::Center),
                        msg_area,
                    );

                    if inner.height > 2 {
                        let input_area = Rect::new(
                            inner.x,
                            inner.y + 2,
                            inner.width,
                            3.min(inner.height.saturating_sub(2)),
                        );
                        if let Some(ref input) = self.revoke_input {
                            input.render(input_area, frame, &self.theme);
                        }
                    }
                }
            }
            None => {}
        }
    }

    fn render_gate_down_confirm(&self, area: Rect, frame: &mut Frame) {
        let question = "Stop the gate? Docker containers will be torn down.";
        let content_width = question.len() as u16 + 4;
        let width = content_width.clamp(24, area.width.saturating_sub(4));
        let height = 5u16.min(area.height.saturating_sub(2));

        let x = area.x + (area.width.saturating_sub(width)) / 2;
        let y = area.y + (area.height.saturating_sub(height)) / 2;
        let popup = Rect::new(x, y, width, height);

        frame.render_widget(Clear, popup);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.modal_border_type)
            .border_style(self.theme.status_warn)
            .title(Span::styled(
                " Stop Gate ",
                self.theme.status_warn.add_modifier(Modifier::BOLD),
            ));

        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        if inner.width > 0 && inner.height > 0 {
            let lines = vec![
                Line::from(Span::styled(question, self.theme.status_warn)),
                Line::default(),
                Line::from(vec![
                    Span::styled("[y]", self.theme.header),
                    Span::styled("es  ", self.theme.dim),
                    Span::styled("[n]", self.theme.header),
                    Span::styled("o", self.theme.dim),
                ]),
            ];
            frame.render_widget(
                Paragraph::new(lines)
                    .alignment(Alignment::Center)
                    .wrap(Wrap { trim: false }),
                inner,
            );
        }
    }

    /// Render a modal overlay with multi-line diagnostic text (e.g. gate log
    /// tail after a failed restart).  Sized to content, capped to the
    /// terminal area.
    fn render_diagnostic_overlay(&self, area: Rect, frame: &mut Frame) {
        let text = match self.diagnostic {
            Some(ref t) => t.as_str(),
            None => return,
        };

        let content_lines: Vec<&str> = text.lines().collect();
        // +2 for the dismiss hint + blank separator.
        let body_lines = content_lines.len() + 2;

        let width = 72u16.min(area.width.saturating_sub(4));
        let height = (body_lines as u16 + 2) // +2 for border
            .clamp(6, area.height.saturating_sub(4));

        let x = area.x + (area.width.saturating_sub(width)) / 2;
        let y = area.y + (area.height.saturating_sub(height)) / 2;
        let popup = Rect::new(x, y, width, height);

        frame.render_widget(Clear, popup);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.modal_border_type)
            .border_style(self.theme.status_error)
            .title(Span::styled(
                " Gate Start Failed ",
                self.theme.status_error.add_modifier(Modifier::BOLD),
            ));

        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(content_lines.len() + 2);
        for l in &content_lines {
            lines.push(Line::from(Span::styled(
                format!(" {l}"),
                self.theme.status_error,
            )));
        }
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            " Press any key to dismiss",
            self.theme.key_hint,
        )));

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

// Entry point

pub async fn run(
    config: &Config,
    auth: Option<OperatorAuth>,
    json_mode: bool,
    doctor: Arc<dyn DoctorRunner>,
    setup: Arc<dyn SetupOps>,
    gate_ops: Option<Arc<dyn GateOps>>,
    first_launch: bool,
) -> i32 {
    if json_mode {
        eprintln!("error: TUI is not supported with --json");
        return 1;
    }

    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to initialize client: {e}");
            return 1;
        }
    };

    // In first-launch mode, skip the healthz check — gate isn't running yet.
    if !first_launch && !client.healthz().await.unwrap_or(false) {
        eprintln!("error: gate is not running — start with `latchgate serve` or `latchgate up`");
        return 1;
    }

    let auth = match auth {
        Some(a) => a,
        None => OperatorAuth::ephemeral(),
    };

    install_panic_hook();

    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: terminal setup failed: {e}");
            return 1;
        }
    };

    let mut app = App::new(client, auth, config.clone(), doctor, setup, gate_ops);

    // First-launch: start on the Setup tab (last tab).
    if first_launch {
        app.switch_screen(app.screens.len() - 1);
    }
    app.tick_active().await;

    let mut event_stream = EventStream::new();
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.reset();

    let result = loop {
        if terminal.draw(|frame| app.render(frame)).is_err() {
            break 1;
        }

        tokio::select! {
            _ = tick.tick() => {
                // Phase 1: health probe (≤2s).
                let should_tick = app.tick_health().await;

                // Render between phases so spinners advance and input
                // is processed even when the screen tick is slow.
                if terminal.draw(|frame| app.render(frame)).is_err() {
                    break 1;
                }

                // Phase 2: screen data refresh (≤5s).
                if should_tick {
                    app.tick_screen().await;
                }
                app.expire_flash();
            }

            maybe_event = event_stream.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) => {
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }

                        match app.handle_key(key) {
                            ScreenAction::Quit => break 0,
                            ScreenAction::Navigate(idx) => {
                                app.switch_screen(idx);
                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::Flash(msg) => app.set_flash(msg),
                            ScreenAction::AsyncAction => {
                                app.input_mode = false;
                                let result = tokio::time::timeout(
                                    ACTION_TIMEOUT,
                                    app.handle_action(),
                                )
                                .await;
                                match result {
                                    Ok(Some(msg)) => app.set_flash(msg),
                                    Ok(None) => {}
                                    Err(_) => {
                                        app.set_flash(FlashMessage::error(
                                            "Action timed out — the gate may be unresponsive",
                                        ));
                                    }
                                }

                                // If the screen now has a pending confirmation,
                                // re-enter input mode so global keys (q, 1-6)
                                // don't leak through the confirm dialog.
                                if app.screens[app.active_screen].needs_confirm_input() {
                                    app.input_mode = true;
                                }

                                // Deferred restart: async actions (e.g. preset
                                // activation) that need a gate restart set a
                                // flag since they can't return GateRestart.
                                if app.screens[app.active_screen].take_restart_request() {
                                    if let Some(ref ops) = app.gate_ops {
                                        if ops.can_stop() || ops.can_start() {
                                            if ops.can_stop() {
                                                if let Err(e) = ops.stop() {
                                                    app.set_flash(FlashMessage::error(
                                                        format!("Restart: stop failed: {e}"),
                                                    ));
                                                    app.tick_active().await;
                                                    tick.reset();
                                                    continue;
                                                }
                                            }
                                            if ops.can_start() {
                                                drop(event_stream);
                                                restore_terminal(&mut terminal);
                                                let result = ops.start().await;
                                                reenter_terminal(&mut terminal);
                                                event_stream = EventStream::new();
                                                app.apply_start_result(
                                                    result,
                                                    "✓ Gate restarted — changes applied",
                                                    true,
                                                );
                                            }
                                        } else {
                                            app.set_flash(FlashMessage::success(
                                                "Gate is externally managed — \
                                                 restart from the host",
                                            ));
                                        }
                                    }
                                }

                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::RevokeEpoch => {
                                app.input_mode = false;
                                if app.auth.is_ephemeral() {
                                    app.set_flash(FlashMessage::error(
                                        "Cannot revoke — no operator credentials. \
                                         Run `latchgate init` or provide --operator-key.",
                                    ));
                                } else {
                                    match app.client.revoke_all(&app.auth).await {
                                        Ok(_) => app.set_flash(FlashMessage::success(
                                            "✓ All grants revoked — new epoch started",
                                        )),
                                        Err(e) => app.set_flash(FlashMessage::error(
                                            format!("Revoke failed: {e}"),
                                        )),
                                    }
                                }
                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::GateUp => {
                                if app.gate_connected {
                                    app.set_flash(FlashMessage::success(
                                        "Gate is already running",
                                    ));
                                } else if let Some(ref ops) = app.gate_ops {
                                    if ops.can_start() {
                                        drop(event_stream);
                                        restore_terminal(&mut terminal);
                                        let result = ops.start().await;
                                        reenter_terminal(&mut terminal);
                                        event_stream = EventStream::new();
                                        app.apply_start_result(
                                            result,
                                            "✓ Gate started",
                                            false,
                                        );
                                        tick.reset();
                                    } else {
                                        app.set_flash(FlashMessage::success(
                                            "Cannot start — an up session already exists",
                                        ));
                                    }
                                } else {
                                    app.set_flash(FlashMessage::success(
                                        "Start gate with `latchgate up` from the CLI",
                                    ));
                                }
                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::GateDown => {
                                if let Some(ref ops) = app.gate_ops {
                                    match ops.stop() {
                                        Ok(()) => {
                                            app.set_flash(FlashMessage::success(
                                                "✓ Gate stopped",
                                            ));
                                        }
                                        Err(e) => {
                                            app.set_flash(FlashMessage::error(
                                                format!("Stop failed: {e}"),
                                            ));
                                        }
                                    }
                                }
                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::GateRestart => {
                                app.input_mode = false;
                                if let Some(ref ops) = app.gate_ops {
                                    if !ops.can_stop() && !ops.can_start() {
                                        app.set_flash(FlashMessage::success(
                                            "Gate is externally managed — restart from the host",
                                        ));
                                    } else {
                                        if ops.can_stop() {
                                            if let Err(e) = ops.stop() {
                                                app.set_flash(FlashMessage::error(
                                                    format!("Restart: stop failed: {e}"),
                                                ));
                                                app.tick_active().await;
                                                tick.reset();
                                                continue;
                                            }
                                        }

                                        if ops.can_start() {
                                            drop(event_stream);
                                            restore_terminal(&mut terminal);
                                            let result = ops.start().await;
                                            reenter_terminal(&mut terminal);
                                            event_stream = EventStream::new();
                                            app.apply_start_result(
                                                result,
                                                "✓ Gate restarted — changes applied",
                                                true,
                                            );
                                        }
                                    }
                                } else {
                                    app.set_flash(FlashMessage::success(
                                        "Start gate with `latchgate up` from the CLI",
                                    ));
                                }
                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::GateReload => {
                                app.input_mode = false;
                                if let Some(ref ops) = app.gate_ops {
                                    if ops.can_reload() {
                                        match ops.reload().await {
                                            Ok(result) => {
                                                app.set_flash(FlashMessage::success(format!(
                                                    "✓ Reloaded — {} actions, policy {}",
                                                    result.actions, result.policy_version,
                                                )));
                                            }
                                            Err(e) => {
                                                app.set_flash(FlashMessage::error(format!(
                                                    "Reload failed: {e}"
                                                )));
                                            }
                                        }
                                    } else {
                                        app.set_flash(FlashMessage::success(
                                            "Gate does not support hot reload — restart from the host",
                                        ));
                                    }
                                }
                                app.tick_active().await;
                                tick.reset();
                            }
                            ScreenAction::BeginInput => app.input_mode = true,
                            ScreenAction::EndInput => app.input_mode = false,
                            ScreenAction::SuspendForEditor(path) => {
                                drop(event_stream);
                                suspend_for_editor(&mut terminal, &path);
                                event_stream = EventStream::new();
                                tick.reset();
                            }
                            ScreenAction::RunInit => {
                                drop(event_stream);
                                restore_terminal(&mut terminal);

                                // Run the init wizard (takes over terminal).
                                let plan_result = crate::wizard::run_wizard(true, false);

                                reenter_terminal(&mut terminal);
                                event_stream = EventStream::new();
                                tick.reset();

                                match plan_result {
                                    Ok(plan) => {
                                        match app.execute_init(&plan) {
                                            Ok(_msg) => {
                                                // Show a single actionable message. The
                                                // init details were already printed by
                                                // the wizard; the operator needs to know
                                                // what to do next.
                                                app.set_flash(FlashMessage::success(
                                                    "✓ Init complete. Press q to exit, then run: latchgate up"
                                                        .to_string(),
                                                ));
                                            }
                                            Err(msg) => app.set_flash(msg),
                                        }
                                    }
                                    Err(e) => {
                                        if e != "cancelled" {
                                            app.set_flash(FlashMessage::error(e));
                                        }
                                    }
                                }
                            }
                            ScreenAction::Noop => {}
                        }
                    }
                    Some(Ok(Event::Resize(_, _))) => {}
                    Some(Err(_)) => break 1,
                    None => break 0,
                    _ => {}
                }
            }
        }
    };

    restore_terminal(&mut terminal);
    result
}

// Terminal management

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stderr>>> {
    terminal::enable_raw_mode()?;
    let mut stderr = io::stderr();
    execute!(
        stderr,
        terminal::EnterAlternateScreen,
        ratatui::crossterm::event::EnableMouseCapture,
    )?;
    Terminal::new(CrosstermBackend::new(stderr))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stderr>>) {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
        ratatui::crossterm::event::DisableMouseCapture,
    );
    let _ = terminal.show_cursor();
}

/// Re-enter the alternate screen after a terminal suspension.
///
/// Counterpart to [`restore_terminal`].  Used after gate start operations
/// and editor suspensions to return control to the TUI.
fn reenter_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stderr>>) {
    let _ = terminal::enable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        terminal::EnterAlternateScreen,
        ratatui::crossterm::event::EnableMouseCapture,
    );
    let _ = terminal.hide_cursor();
    let _ = terminal.clear();
}

fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stderr(), terminal::LeaveAlternateScreen);
        original_hook(info);
    }));
}

fn suspend_for_editor(terminal: &mut Terminal<CrosstermBackend<io::Stderr>>, path: &Path) {
    restore_terminal(terminal);

    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());

    let status = std::process::Command::new(&editor).arg(path).status();

    match status {
        Ok(s) if !s.success() => {
            eprintln!("editor exited with {s}");
        }
        Err(e) => {
            eprintln!("failed to launch editor '{editor}': {e}");
            std::thread::sleep(Duration::from_secs(2));
        }
        _ => {}
    }

    reenter_terminal(terminal);
}
