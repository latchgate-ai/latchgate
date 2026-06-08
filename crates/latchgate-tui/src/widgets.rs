//! Reusable compound widgets for the LatchGate TUI.
//!
//! These build on ratatui primitives to provide the visual vocabulary shared
//! across all screens: status cards, risk badges, meters, spinners,
//! scrollable tables, and modal dialogs. Every widget uses the [`Theme`] for
//! consistent styling.

use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    StatefulWidget, Table, TableState, Widget, Wrap,
};
use ratatui::Frame;

use super::theme::Theme;

// RiskBadge — inline styled span

/// Return a styled `Span` rendering a bracketed risk label, e.g. `[HIGH]`.
///
/// Uses badge styles from the theme (colored background + contrasting fg)
/// for maximum visibility in dense table rows.
pub(crate) fn risk_badge<'a>(level: &str, theme: &Theme) -> Span<'a> {
    let (label, style) = match level {
        "low" => ("[LOW]", theme.badge_low),
        "medium" => ("[MED]", theme.badge_med),
        "high" => ("[HIGH]", theme.badge_high),
        "critical" => ("[CRIT]", theme.badge_crit),
        _ => ("[???]", theme.dim),
    };
    Span::styled(label.to_string(), style)
}

// KeyValueRow — label: value line

/// Build a `Line` with a fixed-width label and a value span.
///
/// `label_width` controls the column reserved for the label (padded with
/// trailing spaces). The value span carries its own styling.
///
/// ```text
/// Status     ● Running
/// Uptime     4d 12h 3m
/// ```
pub(crate) fn key_value_line<'a>(
    label: &'a str,
    value: Span<'a>,
    label_width: usize,
    theme: &Theme,
) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<label_width$}"), theme.header),
        value,
    ])
}

// EmptyState — centered placeholder for empty lists

/// Centered dim message displayed when a list has no items.
///
/// Optionally includes a key-hint below the message (e.g. "[a] to add").
pub(crate) struct EmptyState<'a> {
    message: &'a str,
    hint: Option<&'a str>,
    style: Style,
    hint_style: Style,
}

impl<'a> EmptyState<'a> {
    pub fn new(message: &'a str, theme: &Theme) -> Self {
        Self {
            message,
            hint: None,
            style: theme.dim,
            hint_style: theme.key_hint,
        }
    }

    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = Some(hint);
        self
    }
}

impl Widget for EmptyState<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }

        let mut lines = vec![Line::from(Span::styled(self.message, self.style))];
        if let Some(hint) = self.hint {
            lines.push(Line::from(Span::styled(hint, self.hint_style)));
        }

        let block_height = lines.len() as u16;
        let y_offset = area.height.saturating_sub(block_height) / 2;
        let centered = Rect::new(
            area.x,
            area.y + y_offset,
            area.width,
            block_height.min(area.height),
        );

        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .render(centered, buf);
    }
}

// Spinner — braille animation for loading states

/// Braille-character spinner rendered in a single cell.
///
/// Pass a monotonically increasing `tick` counter (e.g. from the screen's
/// tick loop) to animate. The spinner cycles through 8 braille frames:
/// `⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷`.
pub(crate) struct Spinner {
    tick: usize,
    style: Style,
}

/// Braille rotation frames — each glyph shifts the dot pattern by one
/// position, creating a smooth clockwise spin in a single cell.
const BRAILLE_FRAMES: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

impl Spinner {
    pub fn new(tick: usize, theme: &Theme) -> Self {
        Self {
            tick,
            style: theme.dim,
        }
    }
}

impl Widget for Spinner {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let ch = BRAILLE_FRAMES[self.tick % BRAILLE_FRAMES.len()];
        buf.set_string(area.x, area.y, ch.to_string(), self.style);
    }
}

// ScrollableTable — Table + Scrollbar + EmptyState

/// Compound widget combining a [`Table`] with an automatic vertical
/// [`Scrollbar`] and an [`EmptyState`] fallback.
///
/// The scrollbar appears only when the item count exceeds the visible
/// viewport height. When there are no rows and an [`EmptyState`] is
/// configured, the empty message is rendered instead.
///
/// ```ignore
/// ScrollableTable::new(rows, widths)
///     .header(header_row)
///     .selected(self.selected)
///     .block(bordered_block)
///     .empty(EmptyState::new("Nothing here.", theme))
///     .render(area, buf);
/// ```
pub(crate) struct ScrollableTable<'a> {
    rows: Vec<Row<'a>>,
    header: Option<Row<'a>>,
    widths: Vec<Constraint>,
    selected: usize,
    block: Option<Block<'a>>,
    empty: Option<EmptyState<'a>>,
}

impl<'a> ScrollableTable<'a> {
    pub fn new(rows: Vec<Row<'a>>, widths: impl Into<Vec<Constraint>>) -> Self {
        Self {
            rows,
            header: None,
            widths: widths.into(),
            selected: 0,
            block: None,
            empty: None,
        }
    }

    /// Set the header row displayed above the data rows.
    pub fn header(mut self, header: Row<'a>) -> Self {
        self.header = Some(header);
        self
    }

    /// Set the currently selected row index.
    pub fn selected(mut self, idx: usize) -> Self {
        self.selected = idx;
        self
    }

    /// Wrap the table in a bordered [`Block`].
    #[allow(dead_code)]
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    /// Set the placeholder widget shown when `rows` is empty.
    pub fn empty(mut self, empty: EmptyState<'a>) -> Self {
        self.empty = Some(empty);
        self
    }
}

impl Widget for ScrollableTable<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Resolve optional block => content area.
        let content_area = if let Some(block) = self.block {
            let inner = block.inner(area);
            block.render(area, buf);
            inner
        } else {
            area
        };

        if content_area.width == 0 || content_area.height == 0 {
            return;
        }

        // Empty fallback.
        if self.rows.is_empty() {
            if let Some(empty) = self.empty {
                empty.render(content_area, buf);
            }
            return;
        }

        // Snapshot values consumed by Table::new / header moves.
        let total = self.rows.len();
        let selected = self.selected;
        let has_header = self.header.is_some();

        let mut table = Table::new(self.rows, self.widths);
        if let Some(header) = self.header {
            table = table.header(header);
        }

        let mut table_state = TableState::default();
        table_state.select(Some(selected));
        StatefulWidget::render(table, content_area, buf, &mut table_state);

        // Vertical scrollbar when rows exceed the visible viewport.
        let header_height = u16::from(has_header);
        let visible = content_area.height.saturating_sub(header_height) as usize;
        if total > visible {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
            let mut sb_state = ScrollbarState::new(total).position(selected);
            StatefulWidget::render(scrollbar, content_area, buf, &mut sb_state);
        }
    }
}

// ConfirmDialog — centered modal overlay

/// Render a centered confirmation modal on top of existing content.
///
/// Clears the area behind the dialog and draws a double-bordered box with
/// the question text and `[y]es / [n]o` prompt. Call from the screen's
/// `render` method after all other widgets.
pub(crate) fn render_confirm_dialog(area: Rect, frame: &mut Frame, theme: &Theme, question: &str) {
    use unicode_width::UnicodeWidthStr;

    // Width: fit the question (display columns) with padding, clamped to the
    // available area. Char/byte length would mis-size multi-byte questions.
    let q_cols = question.width() as u16;
    let max_width = area.width.saturating_sub(4).max(24);
    let width = (q_cols + 4).clamp(24, max_width);

    // Height: the question may wrap across several rows at this width. Reserve
    // the wrapped question rows + a blank line + the [y]/[n] prompt + borders,
    // clamped to the available area so it never overflows the screen.
    let inner_w = width.saturating_sub(2).max(1) as usize;
    let q_rows = wrapped_rows(q_cols as usize, inner_w);
    let height = (q_rows as u16 + 4).clamp(5, area.height.saturating_sub(2).max(5));

    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.modal_border_type)
        .border_style(theme.border_double)
        .title(" Confirm ");

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let lines = vec![
        Line::from(Span::styled(question, theme.status_warn)),
        Line::default(),
        Line::from(vec![
            Span::styled("[y]", theme.header),
            Span::styled("es  ", theme.dim),
            Span::styled("[n]", theme.header),
            Span::styled("o", theme.dim),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        inner,
    );
}

/// Number of rows `content_cols` columns of text occupy when wrapped to
/// `inner_w` columns. Always at least 1.
fn wrapped_rows(content_cols: usize, inner_w: usize) -> usize {
    if inner_w == 0 {
        return 1;
    }
    content_cols.div_ceil(inner_w).max(1)
}

// Panel helpers — bordered content areas with zero-size guard

/// Render a bordered panel and return the usable inner `Rect`.
///
/// Returns `None` if the inner area collapses to zero in either dimension
/// (terminal too small). Callers use `let Some(inner) = ... else { return };`
/// to short-circuit — no indentation churn from closure wrapping.
pub(crate) fn begin_panel(
    frame: &mut Frame,
    area: Rect,
    title: impl Into<Line<'static>>,
    border_style: Style,
    theme: &Theme,
) -> Option<Rect> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.content_border_type)
        .border_style(border_style)
        .title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    (inner.width > 0 && inner.height > 0).then_some(inner)
}

/// Active-border panel (primary content areas, lists, forms).
pub(crate) fn begin_active_panel(
    frame: &mut Frame,
    area: Rect,
    title: impl Into<Line<'static>>,
    theme: &Theme,
) -> Option<Rect> {
    begin_panel(frame, area, title, theme.border_active, theme)
}

/// Inactive-border panel (detail panes, secondary content).
pub(crate) fn begin_detail_panel(
    frame: &mut Frame,
    area: Rect,
    title: impl Into<Line<'static>>,
    theme: &Theme,
) -> Option<Rect> {
    begin_panel(frame, area, title, theme.border, theme)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn test_theme() -> Theme {
        Theme::default()
    }

    #[test]
    fn risk_badge_returns_correct_labels() {
        let theme = test_theme();
        assert_eq!(risk_badge("low", &theme).content.as_ref(), "[LOW]");
        assert_eq!(risk_badge("medium", &theme).content.as_ref(), "[MED]");
        assert_eq!(risk_badge("high", &theme).content.as_ref(), "[HIGH]");
        assert_eq!(risk_badge("critical", &theme).content.as_ref(), "[CRIT]");
        assert_eq!(risk_badge("unknown", &theme).content.as_ref(), "[???]");
    }

    #[test]
    fn key_value_line_has_two_spans() {
        let theme = test_theme();
        let line = key_value_line("Label:", Span::raw("value"), 10, &theme);
        assert_eq!(line.spans.len(), 2);
    }

    #[test]
    fn empty_state_renders_without_panic() {
        let theme = test_theme();
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        EmptyState::new("No items found.", &theme)
            .hint("[a] to add")
            .render(area, &mut buf);
    }

    #[test]
    fn empty_state_zero_area() {
        let theme = test_theme();
        let area = Rect::new(0, 0, 0, 0);
        let mut buf = Buffer::empty(area);
        EmptyState::new("Nothing.", &theme).render(area, &mut buf);
    }

    // -- Spinner tests --

    #[test]
    fn spinner_renders_without_panic() {
        let theme = test_theme();
        let area = Rect::new(0, 0, 1, 1);
        let mut buf = Buffer::empty(area);
        Spinner::new(0, &theme).render(area, &mut buf);
    }

    #[test]
    fn spinner_cycles_through_all_frames() {
        let theme = test_theme();
        let area = Rect::new(0, 0, 1, 1);
        for tick in 0..16 {
            let mut buf = Buffer::empty(area);
            Spinner::new(tick, &theme).render(area, &mut buf);
        }
    }

    #[test]
    fn spinner_zero_area() {
        let theme = test_theme();
        let area = Rect::new(0, 0, 0, 0);
        let mut buf = Buffer::empty(area);
        Spinner::new(5, &theme).render(area, &mut buf);
    }

    #[test]
    fn spinner_frame_matches_tick() {
        let theme = test_theme();
        let area = Rect::new(0, 0, 2, 1);
        for (tick, expected) in BRAILLE_FRAMES.iter().enumerate() {
            let mut buf = Buffer::empty(area);
            Spinner::new(tick, &theme).render(area, &mut buf);
            let cell = buf.cell((area.x, area.y)).unwrap();
            assert_eq!(cell.symbol(), &expected.to_string(), "tick={tick}");
        }
    }

    // -- ScrollableTable tests --

    #[test]
    fn scrollable_table_renders_without_panic() {
        let theme = test_theme();
        let header = Row::new(vec!["Name", "Value"]).style(theme.header);
        let rows = vec![Row::new(vec!["a", "1"]), Row::new(vec!["b", "2"])];
        let widths = [Constraint::Min(10), Constraint::Length(8)];
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        ScrollableTable::new(rows, widths)
            .header(header)
            .selected(0)
            .render(area, &mut buf);
    }

    #[test]
    fn scrollable_table_empty_with_fallback() {
        let theme = test_theme();
        let rows: Vec<Row<'_>> = Vec::new();
        let widths = [Constraint::Min(10)];
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        ScrollableTable::new(rows, widths)
            .empty(EmptyState::new("No items.", &theme))
            .render(area, &mut buf);
    }

    #[test]
    fn scrollable_table_empty_without_fallback() {
        let rows: Vec<Row<'_>> = Vec::new();
        let widths = [Constraint::Min(10)];
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        ScrollableTable::new(rows, widths).render(area, &mut buf);
    }

    #[test]
    fn scrollable_table_zero_area() {
        let rows = vec![Row::new(vec!["a"])];
        let widths = [Constraint::Min(10)];
        let area = Rect::new(0, 0, 0, 0);
        let mut buf = Buffer::empty(area);
        ScrollableTable::new(rows, widths).render(area, &mut buf);
    }

    #[test]
    fn scrollable_table_many_rows_triggers_scrollbar() {
        let theme = test_theme();
        let rows: Vec<Row<'_>> = (0..100)
            .map(|i| Row::new(vec![format!("row {i}")]))
            .collect();
        let widths = [Constraint::Min(10)];
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        ScrollableTable::new(rows, widths)
            .header(Row::new(vec!["Name"]).style(theme.header))
            .selected(50)
            .render(area, &mut buf);
    }

    #[test]
    fn scrollable_table_with_block() {
        let theme = test_theme();
        let rows = vec![Row::new(vec!["a", "1"])];
        let widths = [Constraint::Min(10), Constraint::Length(5)];
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_active);
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        ScrollableTable::new(rows, widths)
            .block(block)
            .selected(0)
            .render(area, &mut buf);
    }

    #[test]
    fn scrollable_table_selected_beyond_rows() {
        let theme = test_theme();
        let rows = vec![Row::new(vec!["only"])];
        let widths = [Constraint::Min(10)];
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        // selected=99 on 1 row — must not panic.
        ScrollableTable::new(rows, widths)
            .header(Row::new(vec!["Name"]).style(theme.header))
            .selected(99)
            .render(area, &mut buf);
    }

    // -- wrapped_rows --

    #[test]
    fn wrapped_rows_fits_single_line() {
        assert_eq!(wrapped_rows(10, 20), 1);
    }

    #[test]
    fn wrapped_rows_exact_multiple() {
        assert_eq!(wrapped_rows(40, 20), 2);
    }

    #[test]
    fn wrapped_rows_rounds_up() {
        assert_eq!(wrapped_rows(41, 20), 3);
    }

    #[test]
    fn wrapped_rows_empty_is_one() {
        assert_eq!(wrapped_rows(0, 20), 1);
    }

    #[test]
    fn wrapped_rows_zero_width_is_one() {
        assert_eq!(wrapped_rows(50, 0), 1);
    }
}
