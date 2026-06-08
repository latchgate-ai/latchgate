//! Reusable input widgets shared across TUI screens.
//!
//! - [`TextInput`] — single-line text editor for deny reasons, domain
//!   names, principal IDs, etc.
//! - [`FlashMessage`] — ephemeral notification rendered in the status bar.

use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthChar;

use super::theme::Theme;

// TextInput

/// Single-line text input with cursor movement and basic editing.
///
/// Supports: character insert, backspace, delete, left/right cursor,
/// Home/End, Ctrl-U (clear line). No multi-line.
pub(crate) struct TextInput {
    content: String,
    /// Cursor position as a byte offset into `content`.
    cursor: usize,
    label: String,
    max_len: usize,
}

/// Result of processing a key event in a [`TextInput`].
pub(crate) enum InputAction {
    /// Key consumed, keep editing.
    Continue,
    /// User pressed Enter — submit the current value.
    Submit(String),
    /// User pressed Esc — cancel input.
    Cancel,
}

/// Visible window of a [`TextInput`] for a given column width: the styled
/// segments around the cursor plus left/right truncation flags.
struct Viewport {
    before: String,
    cursor_char: char,
    after: String,
    left_trunc: bool,
    right_trunc: bool,
}

impl TextInput {
    /// Create a new text input.
    ///
    /// `max_len` limits the character count (0 = unlimited).
    pub fn new(label: &str, max_len: usize) -> Self {
        Self {
            content: String::new(),
            cursor: 0,
            label: label.to_string(),
            max_len,
        }
    }

    /// Create a text input pre-filled with an initial value.
    ///
    /// The cursor is placed at the end of the initial content.
    /// If `max_len > 0`, the initial value is truncated to fit.
    pub fn with_initial(label: &str, max_len: usize, initial: &str) -> Self {
        let content: String = if max_len > 0 {
            initial.chars().take(max_len).collect()
        } else {
            initial.to_string()
        };
        let cursor = content.len();
        Self {
            content,
            cursor,
            label: label.to_string(),
            max_len,
        }
    }

    /// Process a key event. The caller should match on the returned
    /// [`InputAction`] to decide whether to keep, submit, or cancel.
    pub fn handle_key(&mut self, key: KeyEvent) -> InputAction {
        match key.code {
            KeyCode::Enter => InputAction::Submit(self.content.clone()),
            KeyCode::Esc => InputAction::Cancel,

            // Ctrl-U: clear line.
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.content.clear();
                self.cursor = 0;
                InputAction::Continue
            }

            // Character insert.
            KeyCode::Char(c) => {
                if self.max_len == 0 || self.content.chars().count() < self.max_len {
                    self.content.insert(self.cursor, c);
                    self.cursor += c.len_utf8();
                }
                InputAction::Continue
            }

            // Backspace: delete character before cursor.
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let prev = prev_char_boundary(&self.content, self.cursor);
                    self.content.drain(prev..self.cursor);
                    self.cursor = prev;
                }
                InputAction::Continue
            }

            // Delete: delete character after cursor.
            KeyCode::Delete => {
                if self.cursor < self.content.len() {
                    let next = next_char_boundary(&self.content, self.cursor);
                    self.content.drain(self.cursor..next);
                }
                InputAction::Continue
            }

            // Cursor movement.
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor = prev_char_boundary(&self.content, self.cursor);
                }
                InputAction::Continue
            }
            KeyCode::Right => {
                if self.cursor < self.content.len() {
                    self.cursor = next_char_boundary(&self.content, self.cursor);
                }
                InputAction::Continue
            }
            KeyCode::Home => {
                self.cursor = 0;
                InputAction::Continue
            }
            KeyCode::End => {
                self.cursor = self.content.len();
                InputAction::Continue
            }

            _ => InputAction::Continue,
        }
    }

    /// Render the input field with a visible cursor and horizontal scrolling.
    ///
    /// The text is windowed to the inner width so the cursor is always on
    /// screen: when the cursor would fall past the right edge, the view scrolls
    /// to keep it visible. Truncation on either side is signalled with `‹`/`›`.
    /// Widths are measured in display columns (East-Asian width aware), so wide
    /// glyphs do not push the cursor off by one.
    pub fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_active)
            .title(self.label.as_str());

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let view = self.viewport(inner.width as usize);

        let mut spans = Vec::with_capacity(5);
        if view.left_trunc {
            spans.push(Span::styled("‹", theme.dim));
        }
        spans.push(Span::raw(view.before));
        spans.push(Span::styled(
            view.cursor_char.to_string(),
            Style::default().add_modifier(Modifier::REVERSED),
        ));
        spans.push(Span::raw(view.after));
        if view.right_trunc {
            spans.push(Span::styled("›", theme.dim));
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), inner);
    }

    /// Compute the visible window of the input for a given column width.
    ///
    /// Pure function over `(content, cursor, width)` — the rendering counterpart
    /// in [`Self::render`] only maps the result to styled spans. Extracted so
    /// the windowing arithmetic (scrolling, indicator reservation, wide-glyph
    /// accounting) is unit-testable without a terminal backend.
    fn viewport(&self, width: usize) -> Viewport {
        let chars: Vec<(char, usize)> = self.content.chars().map(|c| (c, char_cols(c))).collect();
        let cursor_idx = self.content[..self.cursor].chars().count();
        let cursor_col: usize = chars[..cursor_idx].iter().map(|(_, w)| *w).sum();

        // Scroll so the cursor stays inside the window.
        let scroll = cursor_col.saturating_sub(width.saturating_sub(1));
        let left_trunc = scroll > 0;

        // The cursor cell is always rendered — either a content character or
        // the end-of-input space. Reserve its column width unconditionally.
        let cursor_cw = chars.get(cursor_idx).map_or(1, |(_, w)| *w);

        // Reserve all structural columns up front: left indicator (0/1), cursor
        // cell, and one column for a potential right indicator. Remaining space
        // goes to content characters. The right indicator column is reclaimed
        // below if nothing was dropped.
        let reserved = usize::from(left_trunc) + cursor_cw + 1;
        let content_budget = width.saturating_sub(reserved);

        let mut col = 0usize;
        let mut before = String::new();
        let mut cursor_char = ' ';
        let mut after = String::new();
        let mut content_emitted = 0usize;
        let mut right_trunc = false;

        for (i, &(ch, cw)) in chars.iter().enumerate() {
            if col + cw <= scroll {
                col += cw;
                continue;
            }
            if i == cursor_idx {
                cursor_char = ch;
                col += cw;
                continue;
            }
            if content_emitted + cw > content_budget {
                right_trunc = true;
                break;
            }
            if i < cursor_idx {
                before.push(ch);
            } else {
                after.push(ch);
            }
            content_emitted += cw;
            col += cw;
        }

        Viewport {
            before,
            cursor_char,
            after,
            left_trunc,
            right_trunc,
        }
    }

    /// Current input value.
    #[allow(dead_code)]
    pub fn value(&self) -> &str {
        &self.content
    }
}

/// Find the byte offset of the previous character boundary.
fn prev_char_boundary(s: &str, pos: usize) -> usize {
    s[..pos]
        .char_indices()
        .next_back()
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// Display columns occupied by a single character.
///
/// Control characters (which `unicode_width` reports as `None`) are treated as
/// zero-width so they never advance the cursor viewport.
fn char_cols(c: char) -> usize {
    UnicodeWidthChar::width(c).unwrap_or(0)
}

/// Find the byte offset of the next character boundary.
fn next_char_boundary(s: &str, pos: usize) -> usize {
    s[pos..]
        .char_indices()
        .nth(1)
        .map(|(i, _)| pos + i)
        .unwrap_or(s.len())
}

// FlashMessage

/// Style variant for a flash message.
pub(crate) enum FlashStyle {
    Success,
    Error,
    Info,
}

/// Ephemeral notification displayed in the status bar.
///
/// Created by screen actions (approve, deny, error). Cleared automatically
/// after one tick cycle (~3 s) by [`App::expire_flash`](super::App).
pub(crate) struct FlashMessage {
    pub text: String,
    pub style: FlashStyle,
    pub created_at: Instant,
}

impl FlashMessage {
    pub fn success(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: FlashStyle::Success,
            created_at: Instant::now(),
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: FlashStyle::Error,
            created_at: Instant::now(),
        }
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: FlashStyle::Info,
            created_at: Instant::now(),
        }
    }

    /// Resolve this flash message's style to a ratatui [`Style`].
    pub fn ratatui_style(&self, theme: &Theme) -> Style {
        match self.style {
            FlashStyle::Success => theme.flash_success,
            FlashStyle::Error => theme.flash_error,
            FlashStyle::Info => theme.flash_info,
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn text_input_basic_typing() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('h')));
        input.handle_key(key(KeyCode::Char('i')));
        assert_eq!(input.value(), "hi");
    }

    #[test]
    fn text_input_backspace() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('a')));
        input.handle_key(key(KeyCode::Char('b')));
        input.handle_key(key(KeyCode::Backspace));
        assert_eq!(input.value(), "a");
    }

    #[test]
    fn text_input_cursor_movement() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('a')));
        input.handle_key(key(KeyCode::Char('c')));
        input.handle_key(key(KeyCode::Left));
        input.handle_key(key(KeyCode::Char('b')));
        assert_eq!(input.value(), "abc");
    }

    #[test]
    fn text_input_ctrl_u_clears() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('h')));
        input.handle_key(key(KeyCode::Char('i')));
        input.handle_key(ctrl(KeyCode::Char('u')));
        assert_eq!(input.value(), "");
    }

    #[test]
    fn text_input_max_len() {
        let mut input = TextInput::new("test", 3);
        input.handle_key(key(KeyCode::Char('a')));
        input.handle_key(key(KeyCode::Char('b')));
        input.handle_key(key(KeyCode::Char('c')));
        input.handle_key(key(KeyCode::Char('d')));
        assert_eq!(input.value(), "abc");
    }

    #[test]
    fn text_input_submit() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('y')));
        let result = input.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, InputAction::Submit(s) if s == "y"));
    }

    #[test]
    fn text_input_cancel() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('y')));
        let result = input.handle_key(key(KeyCode::Esc));
        assert!(matches!(result, InputAction::Cancel));
    }

    #[test]
    fn text_input_utf8_handling() {
        let mut input = TextInput::new("test", 0);
        input.handle_key(key(KeyCode::Char('é')));
        input.handle_key(key(KeyCode::Char('ñ')));
        assert_eq!(input.value(), "éñ");
        input.handle_key(key(KeyCode::Backspace));
        assert_eq!(input.value(), "é");
    }

    #[test]
    fn with_initial_prefills_content() {
        let input = TextInput::with_initial("test", 0, "hello");
        assert_eq!(input.value(), "hello");
    }

    #[test]
    fn with_initial_cursor_at_end() {
        let mut input = TextInput::with_initial("test", 0, "abc");
        input.handle_key(key(KeyCode::Char('d')));
        assert_eq!(input.value(), "abcd");
    }

    #[test]
    fn with_initial_respects_max_len() {
        let input = TextInput::with_initial("test", 3, "abcdef");
        assert_eq!(input.value(), "abc");
    }

    #[test]
    fn with_initial_empty() {
        let input = TextInput::with_initial("test", 10, "");
        assert_eq!(input.value(), "");
    }

    // -- viewport (horizontal scrolling) -------------------------------------

    /// Build an input with a specific content and cursor (char index).
    fn at(content: &str, cursor_chars: usize) -> TextInput {
        let mut input = TextInput::with_initial("l", 0, content);
        // `with_initial` places the cursor at the end; walk it left to target.
        let total = content.chars().count();
        for _ in 0..total.saturating_sub(cursor_chars) {
            input.handle_key(key(KeyCode::Left));
        }
        input
    }

    #[test]
    fn viewport_short_text_no_truncation() {
        let v = at("hello", 5).viewport(20);
        assert!(!v.left_trunc);
        assert!(!v.right_trunc);
        assert_eq!(v.before, "hello");
        assert_eq!(v.cursor_char, ' ');
        assert_eq!(v.after, "");
    }

    #[test]
    fn viewport_cursor_at_end_scrolls_left() {
        // 20 chars, width 10: the cursor at end must stay visible. Content
        // between the visible window and the cursor gets squeezed out by the
        // cursor reservation, so the right indicator correctly appears.
        let content: String = "a".repeat(20);
        let v = at(&content, 20).viewport(10);
        assert!(v.left_trunc, "left edge must be truncated");
        assert!(v.right_trunc, "squeezed chars produce right indicator");
        let cols = usize::from(v.left_trunc)
            + v.before.chars().map(char_cols).sum::<usize>()
            + char_cols(v.cursor_char)
            + usize::from(v.right_trunc);
        assert!(cols <= 10, "total {cols} exceeds width 10");
    }

    #[test]
    fn viewport_cursor_in_middle_truncates_both_sides() {
        let content: String = (0..30).map(|_| 'x').collect();
        let v = at(&content, 15).viewport(10);
        assert!(v.left_trunc);
        assert!(v.right_trunc);
    }

    #[test]
    fn viewport_cursor_at_start_only_right_truncation() {
        let content: String = (0..30).map(|_| 'x').collect();
        let v = at(&content, 0).viewport(10);
        assert!(!v.left_trunc);
        assert!(v.right_trunc);
    }

    #[test]
    fn viewport_never_exceeds_width() {
        // Total visible columns (indicators + before + cursor + after) must
        // never exceed the available width, for any cursor position.
        let content: String = (0..40).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
        let len = content.chars().count();
        for cursor in 0..=len {
            let v = at(&content, cursor).viewport(12);
            let cols = usize::from(v.left_trunc)
                + v.before.chars().map(char_cols).sum::<usize>()
                + char_cols(v.cursor_char)
                + v.after.chars().map(char_cols).sum::<usize>()
                + usize::from(v.right_trunc);
            assert!(cols <= 12, "cursor={cursor} produced {cols} cols > 12");
        }
    }

    #[test]
    fn viewport_wide_glyphs_counted_by_display_width() {
        // CJK glyphs are two columns each; width 6 fits two of them + cursor.
        let v = at("漢字漢字漢字", 6).viewport(6);
        // Cursor at end, content overflows: left-truncated, cursor visible.
        assert!(v.left_trunc);
        let cols = usize::from(v.left_trunc)
            + v.before.chars().map(char_cols).sum::<usize>()
            + char_cols(v.cursor_char);
        assert!(cols <= 6);
    }

    #[test]
    fn char_cols_handles_control_and_wide() {
        assert_eq!(char_cols('a'), 1);
        assert_eq!(char_cols('漢'), 2);
        assert_eq!(char_cols('\u{0}'), 0);
    }
}
