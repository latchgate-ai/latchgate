//! Text formatting and rendering helpers for the TUI crate.

use chrono::Utc;
use ratatui::style::Style;

use super::theme::Theme;

// Text truncation

/// Truncate a string to `max` characters, appending `…` if shortened.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

// Decision rendering

/// Decision column indicator: returns `(dot_char, style)` for a decision
/// string. Used by the dashboard activity feed and the activity screen.
pub(crate) fn decision_indicator<'a>(decision: &str, theme: &Theme) -> (&'a str, Style) {
    match decision {
        "allow" => ("●", theme.status_ok),
        "allow_unverified" => ("⚠", theme.status_warn),
        "deny" => ("✗", theme.status_error),
        "pending_approval" => ("⏳", theme.status_warn),
        "error" => ("⚠", theme.status_warn),
        _ => ("·", theme.dim),
    }
}

// Timestamp age styling

/// Timestamp age threshold: normal => dim.
const AGE_DIM_SECS: i64 = 5 * 60;

/// Timestamp age threshold: dim => faint.
const AGE_FAINT_SECS: i64 = 30 * 60;

/// Resolve an RFC 3339 timestamp to a style based on its age relative to
/// `now`. Implements a three-tier color fade:
///
/// - `<5 min`: default (normal text)
/// - `<30 min`: dim
/// - `≥30 min`: faint (separator gray)
pub(crate) fn timestamp_age_style(ts: &str, now: &chrono::DateTime<Utc>, theme: &Theme) -> Style {
    let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) else {
        return theme.dim;
    };
    let age_secs = now.signed_duration_since(dt).num_seconds();
    if age_secs >= AGE_FAINT_SECS {
        theme.separator
    } else if age_secs >= AGE_DIM_SECS {
        theme.dim
    } else {
        Style::default()
    }
}

// Uptime formatting

/// Format a duration in seconds as a compact human-readable string.
///
/// Returns `"4d 12h 3m"`, `"2h 45m"`, or `"3m"` depending on magnitude.
pub(crate) fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

// JSON array helpers

/// Join a JSON array of strings with commas.
///
/// Filters out non-string values. Returns an empty string if the array
/// is empty or contains no strings.
pub(crate) fn join_str_array(arr: &[serde_json::Value]) -> String {
    arr.iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // -- truncate ---

    #[test]
    fn short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn long_string_truncated() {
        let result = truncate("hello world", 5);
        assert_eq!(result, "hell…");
    }

    #[test]
    fn empty_string() {
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn multibyte_characters() {
        let result = truncate("héllo wörld", 5);
        assert_eq!(result.chars().count(), 5);
        assert!(result.ends_with('…'));
    }

    // -- decision_indicator ---

    #[test]
    fn decision_allow_returns_ok_style() {
        let theme = Theme::default();
        let (dot, style) = decision_indicator("allow", &theme);
        assert_eq!(dot, "●");
        assert_eq!(style, theme.status_ok);
    }

    #[test]
    fn decision_deny_returns_error_style() {
        let theme = Theme::default();
        let (dot, style) = decision_indicator("deny", &theme);
        assert_eq!(dot, "✗");
        assert_eq!(style, theme.status_error);
    }

    #[test]
    fn decision_pending_returns_warn_style() {
        let theme = Theme::default();
        let (dot, style) = decision_indicator("pending_approval", &theme);
        assert_eq!(dot, "⏳");
        assert_eq!(style, theme.status_warn);
    }

    #[test]
    fn decision_unknown_returns_dim() {
        let theme = Theme::default();
        let (dot, style) = decision_indicator("whatever", &theme);
        assert_eq!(dot, "·");
        assert_eq!(style, theme.dim);
    }

    // -- timestamp_age_style ---

    #[test]
    fn recent_timestamp_returns_default() {
        let theme = Theme::default();
        let now = Utc::now();
        let ts = now.to_rfc3339();
        let style = timestamp_age_style(&ts, &now, &theme);
        assert_eq!(style, Style::default());
    }

    #[test]
    fn six_minute_old_returns_dim() {
        let theme = Theme::default();
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(6 * 60);
        let ts = old.to_rfc3339();
        let style = timestamp_age_style(&ts, &now, &theme);
        assert_eq!(style, theme.dim);
    }

    #[test]
    fn thirty_one_minute_old_returns_separator() {
        let theme = Theme::default();
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(31 * 60);
        let ts = old.to_rfc3339();
        let style = timestamp_age_style(&ts, &now, &theme);
        assert_eq!(style, theme.separator);
    }

    #[test]
    fn invalid_timestamp_returns_dim() {
        let theme = Theme::default();
        let now = Utc::now();
        let style = timestamp_age_style("not-a-timestamp", &now, &theme);
        assert_eq!(style, theme.dim);
    }

    #[test]
    fn boundary_exactly_five_minutes() {
        let theme = Theme::default();
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(AGE_DIM_SECS);
        let ts = old.to_rfc3339();
        let style = timestamp_age_style(&ts, &now, &theme);
        assert_eq!(style, theme.dim);
    }

    #[test]
    fn boundary_exactly_thirty_minutes() {
        let theme = Theme::default();
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(AGE_FAINT_SECS);
        let ts = old.to_rfc3339();
        let style = timestamp_age_style(&ts, &now, &theme);
        assert_eq!(style, theme.separator);
    }

    // -- format_uptime ---

    #[test]
    fn uptime_days() {
        assert_eq!(format_uptime(4 * 86_400 + 12 * 3_600 + 180), "4d 12h 3m");
    }

    #[test]
    fn uptime_hours() {
        assert_eq!(format_uptime(2 * 3_600 + 45 * 60), "2h 45m");
    }

    #[test]
    fn uptime_minutes_only() {
        assert_eq!(format_uptime(180), "3m");
    }

    #[test]
    fn uptime_zero() {
        assert_eq!(format_uptime(0), "0m");
    }

    #[test]
    fn uptime_seconds_below_minute() {
        assert_eq!(format_uptime(59), "0m");
    }

    #[test]
    #[allow(unused_variables)]
    fn timestamp_age_style_with_utc_timezone() {
        let theme = Theme::default();
        let now = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts = "2025-06-15T11:50:00+00:00";
        let style = timestamp_age_style(ts, &now, &theme);
        // 10 minutes => dim
        assert_eq!(style, theme.dim);
    }

    // -- join_str_array ---

    #[test]
    fn join_str_array_basic() {
        use serde_json::json;
        let arr = vec![json!("a"), json!("b"), json!("c")];
        assert_eq!(join_str_array(&arr), "a, b, c");
    }

    #[test]
    fn join_str_array_empty() {
        let arr: Vec<serde_json::Value> = vec![];
        assert_eq!(join_str_array(&arr), "");
    }

    #[test]
    fn join_str_array_skips_non_strings() {
        use serde_json::json;
        let arr = vec![json!("a"), json!(42), json!("b"), json!(null)];
        assert_eq!(join_str_array(&arr), "a, b");
    }
}
