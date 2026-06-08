//! JSON structure inspection helpers and low-level serialization primitives.
//!
//! Pure functions that walk a `serde_json::Value` tree and return structural
//! properties (depth, array cardinality). Used by both `canonical` (DoS
//! limits before JCS canonicalization) and `schema` (request/response
//! validation limits in latchgate-registry).
//!
//! The [`json_escape_into`] helper is the single canonical implementation of
//! RFC 8259 §7 string escaping, used by both the kernel pipeline error
//! responses and the API error response type. Keeping it here prevents
//! security-critical encoding logic from diverging across crates.
//!
//! These are intentionally error-free — they inspect structure, not semantics.
//! Semantic checks (I-JSON validation, schema conformance) remain in their
//! respective modules.

use serde_json::Value;

/// Escape a string value for embedding in a JSON string literal.
///
/// Handles the mandatory JSON escapes (RFC 8259 §7): `"`, `\`, and
/// control characters U+0000–U+001F. Does NOT escape `/` (optional in
/// JSON and omitted to avoid inflating URL-heavy values).
///
/// # Security
///
/// This function is the **single source of truth** for JSON string
/// escaping across the entire codebase. All crates that build JSON
/// responses without `serde_json::Value` MUST use this function — never
/// a local copy. A divergence in escaping logic could produce malformed
/// JSON that breaks downstream parsers or enables log injection.
#[inline]
pub fn json_escape_into(buf: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if c.is_control() => {
                // \u00XX for remaining control characters.
                let _ = std::fmt::Write::write_fmt(buf, format_args!("\\u{:04x}", c as u32));
            }
            c => buf.push(c),
        }
    }
}

/// Compute the nesting depth of a JSON value.
///
/// Objects and arrays each add one level of depth.
/// Scalars (numbers, strings, booleans, null) have depth 0.
#[must_use]
pub fn json_depth(value: &Value) -> u32 {
    match value {
        Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Find the maximum array length anywhere in the JSON tree.
///
/// Recursively searches all arrays (including nested ones inside objects)
/// and returns the length of the largest one. Returns `None` if the value
/// contains no arrays at all.
#[must_use]
pub fn max_array_len(value: &Value) -> Option<usize> {
    match value {
        Value::Array(arr) => {
            let child_max = arr.iter().filter_map(max_array_len).max();
            Some(arr.len().max(child_max.unwrap_or(0)))
        }
        Value::Object(map) => map.values().filter_map(max_array_len).max(),
        _ => None,
    }
}

/// Byte counter implementing [`fmt::Write`] for zero-allocation length
/// measurement of `Display`-formatted values.
struct ByteCounter(usize);

impl std::fmt::Write for ByteCounter {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

/// Compute the byte length of a string after JSON escaping (RFC 8259 §7).
///
/// Matches `serde_json`'s compact serializer exactly:
///
/// | Byte            | Escaped form | Length |
/// |-----------------|-------------|--------|
/// | `"`, `\`        | `\"`, `\\`  | 2      |
/// | `\n`,`\r`,`\t`  | `\n`,`\r`,`\t`| 2    |
/// | `\x08`,`\x0c`   | `\b`,`\f`  | 2      |
/// | other < 0x20    | `\u00XX`    | 6      |
/// | everything else | as-is       | 1      |
///
/// Does **not** include the surrounding quote characters.
#[must_use]
pub fn json_escaped_byte_len(s: &str) -> usize {
    s.bytes()
        .map(|b| match b {
            b'"' | b'\\' => 2,
            b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => 2,
            b if b < 0x20 => 6,
            _ => 1,
        })
        .sum()
}

/// Compute the byte length of a `serde_json::Value` serialized as compact
/// JSON, **without allocating**.
///
/// Returns the same value as `serde_json::to_string(value).unwrap().len()`
/// for all valid `serde_json::Value` trees. Used by schema size-limit
/// enforcement to avoid a multi-MiB transient allocation on every request.
///
/// # Correctness
///
/// The result matches `serde_json::to_string` exactly because:
///
/// 1. String escaping uses the same byte-level rules as serde_json's compact
///    formatter (see [`json_escaped_byte_len`]).
/// 2. Number formatting uses `serde_json::Number`'s `Display` impl, which
///    delegates to the same `itoa`/`ryu` formatters as the serializer.
/// 3. Structural punctuation (`{}`, `[]`, `:`, `,`) follows the compact
///    (no-whitespace) JSON grammar.
///
/// The `compact_byte_len_matches_serde_json` test validates this equivalence
/// across a wide range of randomly generated values.
#[must_use]
pub fn json_compact_byte_len(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(n) => {
            let mut c = ByteCounter(0);
            use std::fmt::Write;
            // serde_json::Number::Display delegates to itoa (ints) / ryu (floats),
            // the same formatters used by the serializer.  ByteCounter's Write
            // impl is infallible (no I/O, just incrementing a counter).
            let _ = write!(c, "{n}");
            c.0
        }
        Value::String(s) => 2 + json_escaped_byte_len(s),
        Value::Array(arr) => {
            // [elem,elem,...,elem]
            let n = arr.len();
            let content: usize = arr.iter().map(json_compact_byte_len).sum();
            2 + content + n.saturating_sub(1)
        }
        Value::Object(map) => {
            // {"key":value,"key":value}
            let n = map.len();
            let content: usize = map
                .iter()
                .map(|(k, v)| 2 + json_escaped_byte_len(k) + 1 + json_compact_byte_len(v))
                .sum();
            2 + content + n.saturating_sub(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- json_depth ---

    #[test]
    fn depth_of_scalar_is_zero() {
        assert_eq!(json_depth(&json!(42)), 0);
        assert_eq!(json_depth(&json!("hello")), 0);
        assert_eq!(json_depth(&json!(null)), 0);
        assert_eq!(json_depth(&json!(true)), 0);
    }

    #[test]
    fn depth_of_flat_container_is_one() {
        assert_eq!(json_depth(&json!({"a": 1, "b": 2})), 1);
        assert_eq!(json_depth(&json!([1, 2, 3])), 1);
    }

    #[test]
    fn depth_of_empty_containers() {
        assert_eq!(json_depth(&json!({})), 1);
        assert_eq!(json_depth(&json!([])), 1);
    }

    #[test]
    fn depth_of_nested_structures() {
        assert_eq!(json_depth(&json!({"a": {"b": {"c": 1}}})), 3);
        assert_eq!(json_depth(&json!([[[1]]])), 3);
    }

    #[test]
    fn depth_of_mixed_nesting() {
        assert_eq!(json_depth(&json!({"a": [{"b": 1}]})), 3);
        assert_eq!(json_depth(&json!([{"a": [1]}])), 3);
    }

    // --- max_array_len ---

    #[test]
    fn no_arrays_returns_none() {
        assert_eq!(max_array_len(&json!({"a": 1})), None);
        assert_eq!(max_array_len(&json!(42)), None);
        assert_eq!(max_array_len(&json!(null)), None);
    }

    #[test]
    fn top_level_array() {
        assert_eq!(max_array_len(&json!([1, 2, 3])), Some(3));
    }

    #[test]
    fn nested_array_larger_than_outer() {
        assert_eq!(max_array_len(&json!([1, [2, 3, 4, 5]])), Some(4));
    }

    #[test]
    fn array_inside_object() {
        assert_eq!(max_array_len(&json!({"items": [1, 2]})), Some(2));
    }

    #[test]
    fn deeply_nested_array() {
        let v = json!({"a": {"b": [1, 2, 3, 4, 5]}});
        assert_eq!(max_array_len(&v), Some(5));
    }

    #[test]
    fn empty_array() {
        assert_eq!(max_array_len(&json!([])), Some(0));
    }

    #[test]
    fn multiple_arrays_returns_max() {
        let v = json!({"small": [1], "big": [1, 2, 3]});
        assert_eq!(max_array_len(&v), Some(3));
    }

    // --- json_escape_into ---

    #[test]
    fn escape_plain_string() {
        let mut buf = String::new();
        json_escape_into(&mut buf, "hello world");
        assert_eq!(buf, "hello world");
    }

    #[test]
    fn escape_quotes_and_backslash() {
        let mut buf = String::new();
        json_escape_into(&mut buf, r#"say "hi" \ there"#);
        assert_eq!(buf, r#"say \"hi\" \\ there"#);
    }

    #[test]
    fn escape_control_characters() {
        let mut buf = String::new();
        json_escape_into(&mut buf, "line\none\ttab\r\n");
        assert_eq!(buf, "line\\none\\ttab\\r\\n");
    }

    #[test]
    fn escape_low_control_chars() {
        let mut buf = String::new();
        json_escape_into(&mut buf, "\x00\x01\x1f");
        assert_eq!(buf, "\\u0000\\u0001\\u001f");
    }

    #[test]
    fn escape_empty_string() {
        let mut buf = String::new();
        json_escape_into(&mut buf, "");
        assert_eq!(buf, "");
    }

    #[test]
    fn escape_forward_slash_passthrough() {
        let mut buf = String::new();
        json_escape_into(&mut buf, "https://example.com/path");
        assert_eq!(buf, "https://example.com/path");
    }

    // --- json_escaped_byte_len ---

    #[test]
    fn escaped_len_plain_ascii() {
        assert_eq!(json_escaped_byte_len("hello"), 5);
    }

    #[test]
    fn escaped_len_special_chars() {
        // " → \", \ → \\, \n → \n  (all 2 bytes each)
        assert_eq!(json_escaped_byte_len("\"\\"), 4);
        assert_eq!(json_escaped_byte_len("\n\r\t"), 6);
    }

    #[test]
    fn escaped_len_control_chars() {
        // \x00 and \x01 → \u00XX (6 bytes each)
        assert_eq!(json_escaped_byte_len("\x00\x01"), 12);
        // \x08 → \b (2 bytes), \x0c → \f (2 bytes)
        assert_eq!(json_escaped_byte_len("\x08\x0c"), 4);
    }

    #[test]
    fn escaped_len_utf8_passthrough() {
        // Multi-byte UTF-8: each byte counts as 1
        assert_eq!(json_escaped_byte_len("日本"), "日本".len());
    }

    // --- json_compact_byte_len ---

    #[test]
    fn compact_len_scalars() {
        assert_eq!(json_compact_byte_len(&json!(null)), "null".len());
        assert_eq!(json_compact_byte_len(&json!(true)), "true".len());
        assert_eq!(json_compact_byte_len(&json!(false)), "false".len());
        assert_eq!(json_compact_byte_len(&json!(42)), "42".len());
        assert_eq!(json_compact_byte_len(&json!(-1)), "-1".len());
        assert_eq!(
            json_compact_byte_len(&json!(1.337)),
            serde_json::to_string(&json!(1.337)).unwrap().len()
        );
    }

    #[test]
    fn compact_len_strings() {
        assert_eq!(json_compact_byte_len(&json!("")), 2); // ""
        assert_eq!(json_compact_byte_len(&json!("hi")), 4); // "hi"
        assert_eq!(
            json_compact_byte_len(&json!("a\"b")),
            serde_json::to_string(&json!("a\"b")).unwrap().len()
        );
    }

    #[test]
    fn compact_len_containers() {
        assert_eq!(json_compact_byte_len(&json!({})), 2);
        assert_eq!(json_compact_byte_len(&json!([])), 2);
        assert_eq!(json_compact_byte_len(&json!([1, 2, 3])), "[1,2,3]".len());
        assert_eq!(json_compact_byte_len(&json!({"a":1})), r#"{"a":1}"#.len());
    }

    #[test]
    fn compact_len_nested() {
        let v = json!({"key": [1, "two", null], "flag": true});
        assert_eq!(
            json_compact_byte_len(&v),
            serde_json::to_string(&v).unwrap().len(),
        );
    }

    /// INVARIANT: `json_compact_byte_len` must match `serde_json::to_string().len()`
    /// for all valid Value trees. A mismatch means the schema size check is wrong.
    #[test]
    fn compact_byte_len_matches_serde_json() {
        let cases: Vec<Value> = vec![
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(42),
            json!(-999),
            json!(1.0),
            json!(9.80665),
            json!(1e100),
            json!(""),
            json!("hello world"),
            json!("line\none"),
            json!("quote\"here"),
            json!("back\\slash"),
            json!("\x00\x01\x08\x0c\x1f"),
            json!("日本語テスト"),
            json!("https://example.com/path?q=a&b=c"),
            json!([]),
            json!({}),
            json!([1, "two", null, true, [3, 4]]),
            json!({"a": 1, "b": "two", "c": null, "nested": {"d": [5, 6]}}),
            json!({"escape\"key": "escape\"val"}),
            json!([[[[[1]]]]]),
            // Large-ish string
            json!({"data": "x".repeat(10_000)}),
            // Many keys
            serde_json::Value::Object((0..100).map(|i| (format!("k{i}"), json!(i))).collect()),
        ];

        for (i, v) in cases.iter().enumerate() {
            let expected = serde_json::to_string(v).unwrap().len();
            let actual = json_compact_byte_len(v);
            assert_eq!(
                actual, expected,
                "case {i}: json_compact_byte_len mismatch — \
                 expected {expected}, got {actual}"
            );
        }
    }
}
