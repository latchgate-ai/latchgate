//! Screen abstraction for the TUI.

use std::path::PathBuf;

use std::future::Future;
use std::pin::Pin;

use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;

use latchgate_client::{GateClient, OperatorAuth};

use super::input::FlashMessage;
use super::theme::Theme;

// ScreenAction

pub(crate) enum ScreenAction {
    Noop,
    Navigate(usize),
    Flash(FlashMessage),
    Quit,
    BeginInput,
    EndInput,
    AsyncAction,
    SuspendForEditor(PathBuf),
    RunInit,
    /// Emergency revoke — invalidate all outstanding execution grants.
    RevokeEpoch,
    /// Suspend TUI and run the `up` flow to start the gate.
    GateUp,
    /// Confirm and tear down the gate process.
    GateDown,
    /// Stop and restart the gate to pick up manifest/config changes.
    ///
    /// Retained as an escape hatch for cases where transport or identity
    /// config changed and a full restart is required (e.g. `latchgate up --reset`).
    #[allow(dead_code)]
    GateRestart,
    /// Hot-reload manifests and policy data without restarting the gate.
    GateReload,
}

// TuiScreen trait

pub(crate) trait TuiScreen: Send {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme);
    fn handle_key(&mut self, key: KeyEvent, theme: &Theme) -> ScreenAction;

    fn handle_action<'a>(
        &'a mut self,
        _client: &'a GateClient,
        _auth: &'a OperatorAuth,
    ) -> Pin<Box<dyn Future<Output = Option<FlashMessage>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    fn tab_label(&self) -> &'static str;

    /// Badge count shown on the tab label (e.g. pending approvals).
    ///
    /// Returns 0 by default. Override to display a count badge like
    /// `Approvals(3)` in the tab row.
    fn badge_count(&self) -> usize {
        0
    }

    /// Status bar key hints, context-adaptive per screen state.
    fn status_hint(&self) -> &str {
        "[1-6]screen  [Tab]next  [q]uit"
    }

    /// Key/description pairs for the help overlay.
    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Called after init or config change to refresh internal state.
    /// Default no-op; ConfigScreen overrides.
    fn update_config(&mut self, _config: &latchgate_config::Config) {}

    /// Consume a deferred gate-restart request set by an async action.
    ///
    /// Async handlers (`handle_action`) return `Option<FlashMessage>` and
    /// cannot signal `ScreenAction::GateRestart`. When an async operation
    /// (e.g. preset activation) needs a restart, it sets an internal flag
    /// which the event loop drains via this method after `handle_action`
    /// completes.
    ///
    /// Returns `true` exactly once per request, resetting the flag.
    fn take_restart_request(&mut self) -> bool {
        false
    }

    /// Whether the screen currently has a pending confirmation that requires
    /// modal key handling (prevents global keys like `q` from firing).
    ///
    /// Checked by the event loop after `handle_action` completes to re-enter
    /// input mode when an async action left a confirmation pending.
    fn needs_confirm_input(&self) -> bool {
        false
    }

    /// Whether the screen is currently a **modal input surface** that should
    /// own all key input while open.
    ///
    /// When `true` and `input_mode` is active, global navigation keys
    /// (`1`–`8`, `Tab`) are suppressed and routed to the screen instead, so a
    /// keystroke aimed at a field (e.g. a digit) can never leak out to tab
    /// navigation. `Esc` remains the always-available exit (it maps to a clean
    /// cancel or a discard prompt), so the user is never trapped.
    /// When `false`, global nav is allowed even in input mode.
    fn is_modal(&self) -> bool {
        false
    }
}
