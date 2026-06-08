//! Color palette and style definitions.
//!
//! 256-color indexed palette. No true-color. Inherits terminal background.
//!
//! Brand identity: LatchGate teal on dark.
//!   Primary (36)   — brand teal, active elements, branding.
//!   Teal (72)      — secondary teal, sub-tab active.
//!   Deep (30)      — muted teal, borders, structural.
//!   Success (78)   — green, passing, approved.
//!   Warning (220)  — amber, pending, caution.
//!   Error (167)    — muted red, denied, failed.
//!   Muted (245)    — gray, hints, inactive text.
//!   Faint (240)    — darker gray, structural.
//!   Surface (236)  — selection background.
//!   Dark (16)      — near-black, badge foreground on bright bg.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::BorderType;

pub(crate) struct Theme {
    // Chrome.
    pub border: Style,
    pub border_active: Style,
    pub border_double: Style,
    pub branding: Style,
    pub title_screen: Style,
    pub tab_active: Style,
    pub tab_inactive: Style,
    pub subtab_active: Style,
    pub subtab_inactive: Style,
    // Border types.
    pub content_border_type: BorderType,
    pub modal_border_type: BorderType,
    // Status.
    pub status_ok: Style,
    pub status_warn: Style,
    pub status_error: Style,
    // Badges (background + foreground, for bracketed labels).
    pub badge_low: Style,
    pub badge_med: Style,
    pub badge_high: Style,
    pub badge_crit: Style,
    // Flash.
    pub flash_success: Style,
    pub flash_error: Style,
    pub flash_info: Style,
    // Content.
    pub selected: Style,
    pub header: Style,
    pub dim: Style,
    pub key_hint: Style,
    // Decoration.
    pub separator: Style,
}

impl Default for Theme {
    fn default() -> Self {
        let primary = Color::Indexed(36); // #00af87 — brand teal
        let teal = Color::Indexed(72); // #5faf87 — secondary teal
        let deep = Color::Indexed(30); // #008787 — muted teal
        let success = Color::Indexed(78); // green
        let warning = Color::Indexed(220); // amber
        let error = Color::Indexed(167); // #d75f5f — muted red
        let muted = Color::Indexed(245); // gray text
        let faint = Color::Indexed(240); // structural gray
        let surface = Color::Indexed(236); // selection bg
        let dark = Color::Indexed(16); // near-black for badge fg

        Self {
            border: Style::default().fg(faint),
            border_active: Style::default().fg(deep),
            border_double: Style::default().fg(warning),
            branding: Style::default().fg(primary).add_modifier(Modifier::BOLD),
            title_screen: Style::default().fg(teal),
            // Bold primary — box-drawing rules provide the underline.
            tab_active: Style::default().fg(primary).add_modifier(Modifier::BOLD),
            tab_inactive: Style::default().fg(muted),
            subtab_active: Style::default().fg(teal).add_modifier(Modifier::BOLD),
            subtab_inactive: Style::default().fg(faint),
            content_border_type: BorderType::Rounded,
            modal_border_type: BorderType::Double,
            status_ok: Style::default().fg(success),
            status_warn: Style::default().fg(warning),
            status_error: Style::default().fg(error).add_modifier(Modifier::BOLD),
            badge_low: Style::default().fg(dark).bg(success),
            badge_med: Style::default().fg(dark).bg(warning),
            badge_high: Style::default().fg(Color::Indexed(255)).bg(error),
            badge_crit: Style::default()
                .fg(Color::Indexed(255))
                .bg(error)
                .add_modifier(Modifier::BOLD),
            flash_success: Style::default().fg(success),
            flash_error: Style::default().fg(error).add_modifier(Modifier::BOLD),
            flash_info: Style::default().fg(teal),
            selected: Style::default().bg(surface).add_modifier(Modifier::BOLD),
            header: Style::default().fg(primary).add_modifier(Modifier::BOLD),
            dim: Style::default().fg(muted),
            key_hint: Style::default().fg(muted),
            separator: Style::default().fg(faint),
        }
    }
}
