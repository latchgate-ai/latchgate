//! YAML parsing and serialization for flat secret key-value maps.

use std::collections::BTreeMap;

/// Parse a flat YAML string as a `BTreeMap<String, String>`.
///
/// SOPS-encrypted secrets files are expected to be flat key: value maps.
/// Nested structures are not supported and produce an error.
pub(crate) fn parse_yaml_map(yaml: &str) -> Result<BTreeMap<String, String>, String> {
    let trimmed = yaml.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return Ok(BTreeMap::new());
    }

    let mut map = BTreeMap::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line == "{}" {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("invalid YAML line (no ':'): {line}"))?;

        let key = key.trim().to_string();
        let mut value = value.trim().to_string();

        // Strip surrounding quotes if present (YAML scalar quoting).
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }

        if key.is_empty() {
            return Err(format!("invalid YAML line (empty key): {line}"));
        }
        map.insert(key, value);
    }

    Ok(map)
}

/// Serialize a flat map back to YAML.
pub(crate) fn serialize_yaml_map(map: &BTreeMap<String, String>) -> String {
    if map.is_empty() {
        return "{}\n".to_string();
    }
    let mut out = String::new();
    for (k, v) in map {
        if needs_yaml_quoting(v) {
            out.push_str(&format!("{k}: \"{}\"\n", yaml_escape(v)));
        } else {
            out.push_str(&format!("{k}: {v}\n"));
        }
    }
    out
}

/// Check if a YAML scalar value needs quoting.
pub(crate) fn needs_yaml_quoting(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    v.contains(':')
        || v.contains('#')
        || v.contains('"')
        || v.contains('\'')
        || v.contains('\n')
        || v.contains('\\')
        || v.starts_with(' ')
        || v.ends_with(' ')
        || v.starts_with('{')
        || v.starts_with('[')
        || v.starts_with('&')
        || v.starts_with('*')
        || v.starts_with('!')
        || v.starts_with('|')
        || v.starts_with('>')
        || v.starts_with('%')
        || v.starts_with('@')
        || v.starts_with('`')
        || matches!(
            v.to_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "null" | "~"
        )
}

/// Escape a string for double-quoted YAML scalar.
pub(crate) fn yaml_escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_after_comment() {
        let input = "# LatchGate secrets (SOPS-encrypted)\n{}\n";
        let map = parse_yaml_map(input).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn bare_empty_object() {
        let map = parse_yaml_map("{}").unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn empty_string() {
        let map = parse_yaml_map("").unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn values_with_comment_and_empty_object() {
        let input = "# comment\nFOO: bar\n{}\nBAZ: qux\n";
        let map = parse_yaml_map(input).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["FOO"], "bar");
        assert_eq!(map["BAZ"], "qux");
    }
}
