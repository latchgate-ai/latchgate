//! Sanitization for untrusted strings entering logs, audit events, metrics,
//! and HTTP response bodies.

/// Strip control characters from an untrusted string and cap its length.
///
/// Used at every boundary where an attacker-controlled `reason` enters an
/// audit event, a log line, a Prometheus scrape, or an HTTP response body.
/// Control characters (U+0000-U+001F, U+007F, and the C1 range U+0080-U+009F)
/// are each replaced with a single ASCII space — leaving structure visible
/// while eliminating newline / ANSI-escape injection, CR-based log splitting,
/// and terminal-control payloads.
///
/// The length cap is applied in *bytes* against the sanitized output, not in
/// chars against the input, so an adversary cannot expand a small character
/// count into an unbounded byte count via multi-byte sequences. Truncation
/// respects UTF-8 boundaries; a partial multi-byte codepoint at the limit is
/// dropped entirely rather than producing invalid UTF-8.
///
/// Zero allocation when the input is already clean and within the limit.
#[must_use]
pub fn sanitize_for_log(s: &str, max_len_bytes: usize) -> std::borrow::Cow<'_, str> {
    // Fast path: already clean and within the byte budget — borrow the
    // input directly with zero allocation.
    if s.len() <= max_len_bytes && !s.chars().any(is_control_or_del) {
        return std::borrow::Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len().min(max_len_bytes));
    for ch in s.chars() {
        let replacement = if is_control_or_del(ch) { ' ' } else { ch };
        let need = replacement.len_utf8();
        if out.len() + need > max_len_bytes {
            break;
        }
        out.push(replacement);
    }
    std::borrow::Cow::Owned(out)
}

/// Return true for any Unicode code point that would be hostile in a log
/// line: the C0 control range, DEL, and the C1 control range.
#[inline]
fn is_control_or_del(ch: char) -> bool {
    matches!(ch, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}')
}

#[cfg(test)]
mod tests {
    // The control-character classifier is pinned once by covering each class
    // boundary: LF (C0), ANSI ESC (C0 mid-range), DEL + C1. Adding one test
    // per control codepoint would test std's char-range matching, not our
    // sanitization contract.

    #[test]
    fn sanitize_replaces_newline_with_space() {
        let input = "line1\nline2";
        assert_eq!(super::sanitize_for_log(input, 500), "line1 line2");
    }

    #[test]
    fn sanitize_replaces_ansi_escape() {
        let input = "\x1b[31mred\x1b[0m";
        assert_eq!(super::sanitize_for_log(input, 500), " [31mred [0m");
    }

    #[test]
    fn sanitize_replaces_del_and_c1_controls() {
        let input = "x\u{007F}y\u{0085}z";
        assert_eq!(super::sanitize_for_log(input, 500), "x y z");
    }

    #[test]
    fn sanitize_truncates_to_byte_budget() {
        let input = "a".repeat(1000);
        let out = super::sanitize_for_log(&input, 10);
        assert_eq!(out.len(), 10);
        assert_eq!(out, "aaaaaaaaaa");
    }

    #[test]
    fn sanitize_preserves_utf8_boundaries_on_truncate() {
        // `ł` is two bytes in UTF-8 (0xC5 0x82). With a 5-byte budget we can
        // fit two complete `ł` sequences (4 bytes) but not a third — the
        // function must stop cleanly instead of producing invalid UTF-8.
        let input = "łłł";
        let out = super::sanitize_for_log(input, 5);
        assert_eq!(out, "łł");
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }
}
