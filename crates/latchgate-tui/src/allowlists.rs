//! Screen 5 — Allowlists.
//!
//! Combined view for per-action learned domains and path globs.  Both entity
//! types share an identical interaction model ([`LearnedListScreen`]) and are
//! toggled via a sub-tab row at the top of the screen.
//!
//! Keys `d` / `p` switch between Domains and Paths.  All other keys delegate
//! to the active inner screen.
//!
//! Data sources (via the inner screens):
//! - `GateClient::list_actions()` — action ID list for the action selector.
//! - `GateClient::list_domains / list_paths` — entries per action.
//! - `GateClient::add_domain / add_path` — add entry.
//! - `GateClient::remove_domain / remove_path` — remove entry.
//! - `GateClient::clear_domains / clear_paths` — remove all for action.

use std::future::Future;
use std::pin::Pin;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use latchgate_client::{GateClient, OperatorAuth};

use super::domains::DomainsScreen;
use super::input::FlashMessage;
use super::paths::PathsScreen;
use super::screen::{ScreenAction, TuiScreen};
use super::theme::Theme;

// Mode

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Domains,
    Paths,
}

// AllowlistsScreen

pub(crate) struct AllowlistsScreen {
    mode: Mode,
    domains: DomainsScreen,
    paths: PathsScreen,
}

impl AllowlistsScreen {
    pub fn new() -> Self {
        Self {
            mode: Mode::Domains,
            domains: DomainsScreen::new(),
            paths: PathsScreen::new(),
        }
    }

    fn active(&self) -> &dyn TuiScreen {
        match self.mode {
            Mode::Domains => &self.domains,
            Mode::Paths => &self.paths,
        }
    }

    fn active_mut(&mut self) -> &mut dyn TuiScreen {
        match self.mode {
            Mode::Domains => &mut self.domains,
            Mode::Paths => &mut self.paths,
        }
    }

    /// Render the `[d] Domains | [p] Paths` sub-tab header.
    fn render_subtabs(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let entries: [(&str, &str, Mode); 2] =
            [("d", "Domains", Mode::Domains), ("p", "Paths", Mode::Paths)];

        let mut spans: Vec<Span<'_>> = Vec::with_capacity(8);
        spans.push(Span::raw(" "));

        for (i, &(key, label, m)) in entries.iter().enumerate() {
            let style = if m == self.mode {
                theme.subtab_active
            } else {
                theme.subtab_inactive
            };
            spans.push(Span::styled(format!("[{key}]"), theme.dim));
            spans.push(Span::styled(format!(" {label} "), style));

            if i + 1 < entries.len() {
                spans.push(Span::styled("│", theme.separator));
            }
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

// TuiScreen

impl TuiScreen for AllowlistsScreen {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);

        self.render_subtabs(chunks[0], frame, theme);
        self.active().render(chunks[1], frame, theme);
    }

    fn handle_key(&mut self, key: KeyEvent, theme: &Theme) -> ScreenAction {
        // Mode-switch keys are suppressed when the inner screen owns input.
        if !self.active().is_modal() {
            match key.code {
                KeyCode::Char('d') if self.mode != Mode::Domains => {
                    self.mode = Mode::Domains;
                    return ScreenAction::Noop;
                }
                KeyCode::Char('p') if self.mode != Mode::Paths => {
                    self.mode = Mode::Paths;
                    return ScreenAction::Noop;
                }
                _ => {}
            }
        }
        self.active_mut().handle_key(key, theme)
    }

    fn handle_action<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> Pin<Box<dyn Future<Output = Option<FlashMessage>> + Send + 'a>> {
        match self.mode {
            Mode::Domains => self.domains.handle_action(client, auth),
            Mode::Paths => self.paths.handle_action(client, auth),
        }
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        match self.mode {
            Mode::Domains => self.domains.tick(client, auth),
            Mode::Paths => self.paths.tick(client, auth),
        }
    }

    fn tab_label(&self) -> &'static str {
        "Allowlists"
    }

    fn is_modal(&self) -> bool {
        self.active().is_modal()
    }

    fn status_hint(&self) -> &str {
        "[d]omains  [p]aths  [a]dd  [x]remove  [c]lear  [/]jump  [\u{2190}\u{2192}]action  [\u{2191}\u{2193}]navigate"
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        match self.mode {
            Mode::Domains => &DOMAINS_HELP,
            Mode::Paths => &PATHS_HELP,
        }
    }
}

// Help key tables

static DOMAINS_HELP: [(&str, &str); 10] = [
    ("d", "Switch to Domains (active)"),
    ("p", "Switch to Paths"),
    ("\u{2190}/h", "Previous action"),
    ("\u{2192}/l", "Next action"),
    (
        "/",
        "Filter actions by name (\u{2191}\u{2193} select, Enter go)",
    ),
    ("\u{2191}/k", "Move cursor up"),
    ("\u{2193}/j", "Move cursor down"),
    ("a", "Add domain"),
    ("x", "Remove selected domain"),
    ("c", "Clear all domains for action"),
];

static PATHS_HELP: [(&str, &str); 10] = [
    ("d", "Switch to Domains"),
    ("p", "Switch to Paths (active)"),
    ("\u{2190}/h", "Previous action"),
    ("\u{2192}/l", "Next action"),
    (
        "/",
        "Filter actions by name (\u{2191}\u{2193} select, Enter go)",
    ),
    ("\u{2191}/k", "Move cursor up"),
    ("\u{2193}/j", "Move cursor down"),
    ("a", "Add path glob"),
    ("x", "Remove selected path"),
    ("c", "Clear all paths for action"),
];

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_to_domains() {
        let screen = AllowlistsScreen::new();
        assert_eq!(screen.mode, Mode::Domains);
    }

    #[test]
    fn tab_label_is_allowlists() {
        let screen = AllowlistsScreen::new();
        assert_eq!(screen.tab_label(), "Allowlists");
    }

    #[test]
    fn help_keys_change_with_mode() {
        let mut screen = AllowlistsScreen::new();
        let domains_help = screen.help_keys();
        assert_eq!(domains_help[0].0, "d");
        assert!(domains_help[0].1.contains("active"));

        screen.mode = Mode::Paths;
        let paths_help = screen.help_keys();
        assert_eq!(paths_help[1].0, "p");
        assert!(paths_help[1].1.contains("active"));
    }

    #[test]
    fn is_modal_delegates_to_active() {
        let screen = AllowlistsScreen::new();
        // Fresh screen — no input open, not modal.
        assert!(!screen.is_modal());
    }
}
