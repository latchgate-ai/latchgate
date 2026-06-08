//! Setup wizard for `latchgate init`.
//!
//! Self-contained ratatui wizard that replaces the dialoguer-based prompts.
//! Synchronous (blocking event loop) since `init::run()` is not async.
//!
//! Four steps:
//! 1. Install location (Project / User).
//! 2. Identity provider (peercred / none ⚠).
//! 3. Signing keys (persistent / ephemeral ⚠).
//! 4. Preset selection from embedded catalog.
//!
//! Returns an [`InitPlan`] or an error if the user cancels.

use std::io::{self, IsTerminal};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::{execute, terminal};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};

use latchgate_embed::embedded_presets::{self};

use crate::{IdentityChoice, InitPlan, InstallLocation, SigningChoice};

use super::theme::Theme;

// Public entry point

/// Run the interactive TUI wizard. Returns an [`InitPlan`] or an error
/// message (including user cancellation).
pub fn run_wizard(force: bool, include_examples: bool) -> Result<InitPlan, String> {
    if !io::stdin().is_terminal() {
        return Err("stdin is not a terminal — use --preset <name> to specify a preset".into());
    }

    let theme = Theme::default();

    terminal::enable_raw_mode().map_err(|e| format!("terminal setup: {e}"))?;
    let mut stderr = io::stderr();
    let _ = execute!(stderr, terminal::EnterAlternateScreen);
    let backend = CrosstermBackend::new(stderr);
    let mut terminal = Terminal::new(backend).map_err(|e| format!("terminal setup: {e}"))?;

    let result = run_steps(&mut terminal, &theme, force, include_examples);

    // Always restore, even on error.
    let _ = terminal::disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), terminal::LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

// Wizard steps

fn run_steps(
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
    theme: &Theme,
    force: bool,
    include_examples: bool,
) -> Result<InitPlan, String> {
    // Step 1: location.
    let locations = vec![
        ("Project", "./.latchgate/   (isolated per-project state)"),
        (
            "User",
            "~/.config/latchgate/   (one config for this machine)",
        ),
    ];
    let loc_idx = select_step(
        terminal,
        theme,
        "LatchGate Setup  [1/4]  Install Location",
        "Where should LatchGate store its configuration?",
        &locations,
    )?;
    let location = if loc_idx == 0 {
        InstallLocation::Project
    } else {
        InstallLocation::User
    };

    // Step 2: identity provider.
    let identity_items = vec![
        ("peercred", "UID-based caller identity (recommended)"),
        (
            "none  \u{26A0}",
            "INSECURE: no caller identity — localhost only",
        ),
    ];
    let identity_idx = select_step(
        terminal,
        theme,
        "LatchGate Setup  [2/4]  Identity Provider",
        "How will callers be authenticated?",
        &identity_items,
    )?;
    let identity = if identity_idx == 0 {
        IdentityChoice::Peercred
    } else {
        IdentityChoice::None
    };

    // Step 3: signing keys.
    let signing_items = vec![
        (
            "persistent",
            "Generate Ed25519 keys — receipts verifiable across restarts (recommended)",
        ),
        (
            "ephemeral  \u{26A0}",
            "INSECURE: receipts unverifiable after restart",
        ),
    ];
    let signing_idx = select_step(
        terminal,
        theme,
        "LatchGate Setup  [3/4]  Signing Keys",
        "How should receipts and grants be signed?",
        &signing_items,
    )?;
    let signing = if signing_idx == 0 {
        SigningChoice::Persistent
    } else {
        SigningChoice::Ephemeral
    };

    // Step 4: preset.
    let presets = embedded_presets::list_builtin();
    let preset_items: Vec<(&str, String)> = presets
        .iter()
        .map(|p| (p.name.as_str(), p.description.clone()))
        .collect();
    let preset_refs: Vec<(&str, &str)> =
        preset_items.iter().map(|(n, d)| (*n, d.as_str())).collect();
    let preset_idx = select_step(
        terminal,
        theme,
        "LatchGate Setup  [4/4]  Preset",
        "Select a security preset for your use case:",
        &preset_refs,
    )?;
    let Some(preset) = presets.into_iter().nth(preset_idx) else {
        return Err("preset selection out of range".into());
    };

    Ok(InitPlan {
        preset,
        location,
        identity,
        signing,
        include_examples,
        force,
    })
}

/// Generic selection step. Returns the selected index or an error on cancel.
fn select_step(
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
    theme: &Theme,
    title: &str,
    prompt: &str,
    items: &[(&str, &str)],
) -> Result<usize, String> {
    let mut selected: usize = 0;

    loop {
        let sel = selected;
        terminal
            .draw(|frame| {
                render_selector(frame, theme, title, prompt, items, sel);
            })
            .map_err(|e| format!("render: {e}"))?;

        // Blocking read.
        let ev = event::read().map_err(|e| format!("input: {e}"))?;
        if let Event::Key(key) = ev {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected + 1 < items.len() {
                        selected += 1;
                    }
                }
                KeyCode::Enter => return Ok(selected),
                KeyCode::Esc | KeyCode::Char('q') => {
                    return Err("cancelled".into());
                }
                _ => {}
            }
        }
    }
}

// Rendering

fn render_selector(
    frame: &mut Frame,
    theme: &Theme,
    title: &str,
    prompt: &str,
    items: &[(&str, &str)],
    selected: usize,
) {
    let area = frame.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title + prompt.
            Constraint::Min(4),    // Selection list.
            Constraint::Length(1), // Hint bar.
        ])
        .split(area);

    // Title + prompt.
    let title_block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(theme.dim);
    let title_inner = title_block.inner(outer[0]);
    frame.render_widget(title_block, outer[0]);
    if title_inner.height >= 2 {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    format!("  {title}"),
                    theme.header.add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(format!("  {prompt}"), theme.dim)),
            ]),
            title_inner,
        );
    }

    // Selection list.
    let list_items: Vec<ListItem<'_>> = items
        .iter()
        .enumerate()
        .map(|(i, (name, desc))| {
            let base = if i == selected {
                theme.selected.add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let marker = if i == selected { "▸ " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(marker, base),
                Span::styled(format!("{name:<20} "), base),
                Span::styled(*desc, if i == selected { base } else { theme.dim }),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(selected));
    let list = List::new(list_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_active),
    );
    frame.render_stateful_widget(list, outer[1], &mut state);

    // Hint bar.
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " [↑↓]select  [Enter]confirm  [Esc]cancel",
            theme.key_hint,
        ))),
        outer[2],
    );
}
