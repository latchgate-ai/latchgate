//! Text formatting utilities for CLI display.

/// Truncate a string to at most `max` characters, appending `…` if shortened.
///
/// Operates on Unicode scalar values (not bytes), so multi-byte codepoints
/// are never split. Returns the original string when it fits within `max`.
pub fn truncate(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world", 5), "hell…");
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn truncate_max_one_returns_ellipsis() {
        assert_eq!(truncate("hello", 1), "…");
    }

    #[test]
    fn truncate_max_zero_returns_ellipsis() {
        // Degenerate case: no room for content, ellipsis is the best we can do.
        assert_eq!(truncate("hello", 0), "…");
    }

    #[test]
    fn truncate_multibyte_no_panic() {
        // 'é' is 2 bytes in UTF-8. Byte-indexed slicing at max-1 would panic.
        let result = truncate("héllo wörld", 5);
        assert_eq!(result.chars().count(), 5);
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_cjk_no_panic() {
        let result = truncate("你好世界测试", 4);
        assert_eq!(result.chars().count(), 4);
        assert_eq!(result, "你好世…");
    }

    #[test]
    fn truncate_emoji_no_panic() {
        let result = truncate("🔒🔑🛡️💻🖥️", 3);
        assert!(result.chars().count() <= 3);
        assert!(result.ends_with('…'));
    }
}
