//! Compile-time embedded presets for `latchgate init`.
//!
//! Presets are declarative TOML files that encode a security posture:
//! which manifests to extract, and how the initial ACL is shaped.
//! They replace the hardcoded `UseCase` enum with a data-driven system.
//!
//! # Resolution order
//!
//! 1. Absolute or relative file path (custom preset)
//! 2. `~/.config/latchgate/presets/<name>.toml` (user presets)
//! 3. Built-in embedded presets (this module)
//!
//! # Security
//!
//! - Every embedded preset is validated at test time via `all_embedded_presets_are_valid`.
//! - The `permissive` preset refuses to apply outside `dev_mode`.
//! - `wildcard_grant = "all"` is flagged with a `_WARNING` field in the
//!   generated `data.json`.

use std::path::{Path, PathBuf};

use include_dir::{include_dir, Dir};

/// The `definitions/presets/` directory, embedded at compile time.
static PRESETS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../definitions/presets");

// Preset data model

#[derive(Debug, Clone)]
pub struct Preset {
    pub name: String,
    pub description: String,
    pub manifests: ManifestSelector,
    pub wildcard_grant: WildcardGrant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestSelector {
    All,
    None,
    Tagged(String),
    Listed(Vec<String>),
}

impl ManifestSelector {
    /// Serialize to the string format used in preset TOML files.
    pub fn to_toml_value(&self) -> String {
        match self {
            Self::All => "all".into(),
            Self::None => "none".into(),
            Self::Tagged(tag) => format!("tagged:{tag}"),
            Self::Listed(ids) => format!("listed:{}", ids.join(",")),
        }
    }
}

/// Controls which extracted actions are auto-granted to the wildcard
/// principal (`*`) in the generated `data.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WildcardGrant {
    /// Every extracted action. Requires `dev_mode`.
    All,
    /// No actions — everything requires a named principal.
    None,
    /// Actions with `risk_level` strictly below this threshold.
    RiskBelow(latchgate_core::RiskLevel),
}

impl WildcardGrant {
    /// Whether the given risk level passes this grant filter.
    pub fn allows(&self, risk: latchgate_core::RiskLevel) -> bool {
        match self {
            Self::All => true,
            Self::None => false,
            Self::RiskBelow(threshold) => risk_ord(risk) < risk_ord(*threshold),
        }
    }

    /// Whether this grant level requires dev_mode.
    pub fn requires_dev_mode(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Serialize to the string format used in preset TOML files.
    pub fn to_toml_value(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::None => "none",
            Self::RiskBelow(latchgate_core::RiskLevel::Low) => "risk_below:low",
            Self::RiskBelow(latchgate_core::RiskLevel::Medium) => "risk_below:medium",
            Self::RiskBelow(latchgate_core::RiskLevel::High) => "risk_below:high",
            Self::RiskBelow(latchgate_core::RiskLevel::Critical) => "risk_below:critical",
        }
    }
}

/// Numeric ordering for risk levels (Low=0, Medium=1, High=2, Critical=3).
fn risk_ord(r: latchgate_core::RiskLevel) -> u8 {
    match r {
        latchgate_core::RiskLevel::Low => 0,
        latchgate_core::RiskLevel::Medium => 1,
        latchgate_core::RiskLevel::High => 2,
        latchgate_core::RiskLevel::Critical => 3,
    }
}

// Public API

/// List all built-in presets (name + description).
pub fn list_builtin() -> Vec<Preset> {
    let mut presets: Vec<Preset> = PRESETS_DIR
        .files()
        .filter_map(|file| {
            let contents = std::str::from_utf8(file.contents()).ok()?;
            parse_preset(contents).ok()
        })
        .collect();
    presets.sort_by(|a, b| a.name.cmp(&b.name));
    presets
}

/// Resolve a preset by name or path.
///
/// Resolution order:
/// 1. If `name_or_path` contains a path separator or ends in `.toml`, treat
///    as a file path.
/// 2. `~/.config/latchgate/presets/<name>.toml`
/// 3. Built-in embedded preset.
pub fn resolve(name_or_path: &str) -> Result<Preset, PresetError> {
    // Path-based resolution.
    if name_or_path.contains(std::path::MAIN_SEPARATOR)
        || name_or_path.contains('/')
        || name_or_path.ends_with(".toml")
    {
        let path = Path::new(name_or_path);
        if !path.exists() {
            return Err(PresetError::FileNotFound(name_or_path.to_string()));
        }
        let contents = std::fs::read_to_string(path).map_err(|e| PresetError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        return parse_preset(&contents);
    }

    // User config directory.
    if let Some(path) = user_preset_path(name_or_path) {
        if path.exists() {
            let contents = std::fs::read_to_string(&path).map_err(|e| PresetError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            return parse_preset(&contents);
        }
    }

    // Built-in embedded.
    let filename = format!("{name_or_path}.toml");
    for file in PRESETS_DIR.files() {
        let fname = file.path().file_name().and_then(|f| f.to_str());
        if fname == Some(&filename) {
            let contents = std::str::from_utf8(file.contents())
                .map_err(|_| PresetError::InvalidUtf8(filename.clone()))?;
            return parse_preset(contents);
        }
    }

    Err(PresetError::NotFound(name_or_path.to_string()))
}

/// Export a built-in preset's raw TOML source for customization.
pub fn export_builtin(name: &str) -> Result<String, PresetError> {
    let filename = format!("{name}.toml");
    for file in PRESETS_DIR.files() {
        let fname = file.path().file_name().and_then(|f| f.to_str());
        if fname == Some(&filename) {
            return std::str::from_utf8(file.contents())
                .map(|s| s.to_string())
                .map_err(|_| PresetError::InvalidUtf8(filename));
        }
    }
    Err(PresetError::NotFound(name.to_string()))
}

// Parsing

/// Raw TOML structure for deserialization.
#[derive(serde::Deserialize)]
struct PresetFile {
    preset: PresetRaw,
}

#[derive(serde::Deserialize)]
struct PresetRaw {
    name: String,
    description: String,
    manifests: String,
    policy: PolicyRaw,
}

#[derive(serde::Deserialize)]
struct PolicyRaw {
    wildcard_grant: String,
}

/// Parse and validate a preset from TOML text.
fn parse_preset(toml_text: &str) -> Result<Preset, PresetError> {
    let raw: PresetFile =
        toml::from_str(toml_text).map_err(|e| PresetError::Parse(e.to_string()))?;

    let manifests = parse_manifest_selector(&raw.preset.manifests)?;
    let wildcard_grant = parse_wildcard_grant(&raw.preset.policy.wildcard_grant)?;

    if raw.preset.name.is_empty() {
        return Err(PresetError::Validation(
            "preset name must not be empty".into(),
        ));
    }

    if raw.preset.description.is_empty() {
        return Err(PresetError::Validation(
            "preset description must not be empty".into(),
        ));
    }

    Ok(Preset {
        name: raw.preset.name,
        description: raw.preset.description,
        manifests,
        wildcard_grant,
    })
}

fn parse_manifest_selector(s: &str) -> Result<ManifestSelector, PresetError> {
    match s {
        "all" => Ok(ManifestSelector::All),
        "none" => Ok(ManifestSelector::None),
        s if s.starts_with("tagged:") => {
            let tag = &s["tagged:".len()..];
            if tag.is_empty() {
                return Err(PresetError::Validation(
                    "manifests = \"tagged:\" requires a non-empty tag name".into(),
                ));
            }
            Ok(ManifestSelector::Tagged(tag.to_string()))
        }
        s if s.starts_with("listed:") => {
            let csv = &s["listed:".len()..];
            let ids: Vec<String> = csv
                .split(',')
                .map(|id| id.trim().to_string())
                .filter(|id| !id.is_empty())
                .collect();
            if ids.is_empty() {
                return Err(PresetError::Validation(
                    "manifests = \"listed:\" requires at least one action ID".into(),
                ));
            }
            Ok(ManifestSelector::Listed(ids))
        }
        other => Err(PresetError::Validation(format!(
            "invalid manifests selector: {other:?} — expected \"all\", \"tagged:<tag>\", or \"listed:<id,...>\""
        ))),
    }
}

fn parse_wildcard_grant(s: &str) -> Result<WildcardGrant, PresetError> {
    match s {
        "all" => Ok(WildcardGrant::All),
        "none" => Ok(WildcardGrant::None),
        "risk_below:medium" => Ok(WildcardGrant::RiskBelow(latchgate_core::RiskLevel::Medium)),
        "risk_below:high" => Ok(WildcardGrant::RiskBelow(latchgate_core::RiskLevel::High)),
        "risk_below:critical" => Ok(WildcardGrant::RiskBelow(latchgate_core::RiskLevel::Critical)),
        other => Err(PresetError::Validation(format!(
            "invalid wildcard_grant: {other:?} — expected \"all\", \"none\", or \"risk_below:{{medium|high|critical}}\""
        ))),
    }
}

/// Resolve `~/.config/latchgate/presets/<name>.toml`.
fn user_preset_path(name: &str) -> Option<PathBuf> {
    latchgate_config::UserDirs::resolve().ok().map(|dirs| {
        dirs.config_dir()
            .join("presets")
            .join(format!("{name}.toml"))
    })
}

// Error

#[derive(Debug, thiserror::Error)]
pub enum PresetError {
    #[error("preset not found: {0}")]
    NotFound(String),

    #[error("preset file not found: {0}")]
    FileNotFound(String),

    #[error("preset file is not valid UTF-8: {0}")]
    InvalidUtf8(String),

    #[error("preset parse error: {0}")]
    Parse(String),

    #[error("preset validation error: {0}")]
    Validation(String),

    #[error("I/O error at '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_presets_are_valid() {
        let presets = list_builtin();
        assert!(
            !presets.is_empty(),
            "no presets embedded — check include_dir path"
        );
        // Verify each parses cleanly.
        for file in PRESETS_DIR.files() {
            let filename = file.path().display().to_string();
            let contents = std::str::from_utf8(file.contents())
                .unwrap_or_else(|_| panic!("preset {filename} is not UTF-8"));
            parse_preset(contents)
                .unwrap_or_else(|e| panic!("preset {filename} failed validation: {e}"));
        }
    }

    #[test]
    fn builtin_names_are_unique() {
        let presets = list_builtin();
        let mut seen = std::collections::HashSet::new();
        for p in &presets {
            assert!(seen.insert(&p.name), "duplicate preset name: {}", p.name);
        }
    }

    #[test]
    fn resolve_builtin_by_name() {
        let preset = resolve("agent").expect("agent must resolve");
        assert_eq!(preset.name, "agent");
        assert_eq!(preset.manifests, ManifestSelector::Tagged("agent".into()));
        assert_eq!(
            preset.wildcard_grant,
            WildcardGrant::RiskBelow(latchgate_core::RiskLevel::High)
        );
    }

    #[test]
    fn resolve_nonexistent_fails() {
        assert!(resolve("__no_such_preset__").is_err());
    }

    #[test]
    fn export_builtin_returns_toml() {
        let toml = export_builtin("lockdown").expect("lockdown must export");
        assert!(toml.contains("wildcard_grant"));
        assert!(toml.contains("lockdown"));
    }

    #[test]
    fn permissive_requires_dev_mode() {
        let preset = resolve("permissive").unwrap();
        assert!(preset.wildcard_grant.requires_dev_mode());
    }

    #[test]
    fn lockdown_grants_nothing() {
        let preset = resolve("lockdown").unwrap();
        assert!(!preset.wildcard_grant.allows(latchgate_core::RiskLevel::Low));
    }

    #[test]
    fn risk_below_high_allows_low_and_medium() {
        let grant = WildcardGrant::RiskBelow(latchgate_core::RiskLevel::High);
        assert!(grant.allows(latchgate_core::RiskLevel::Low));
        assert!(grant.allows(latchgate_core::RiskLevel::Medium));
        assert!(!grant.allows(latchgate_core::RiskLevel::High));
        assert!(!grant.allows(latchgate_core::RiskLevel::Critical));
    }

    #[test]
    fn risk_below_medium_allows_only_low() {
        let grant = WildcardGrant::RiskBelow(latchgate_core::RiskLevel::Medium);
        assert!(grant.allows(latchgate_core::RiskLevel::Low));
        assert!(!grant.allows(latchgate_core::RiskLevel::Medium));
        assert!(!grant.allows(latchgate_core::RiskLevel::High));
    }

    #[test]
    fn parse_invalid_manifest_selector() {
        assert!(parse_manifest_selector("invalid").is_err());
        assert!(parse_manifest_selector("tagged:").is_err());
    }

    #[test]
    fn parse_invalid_wildcard_grant() {
        assert!(parse_wildcard_grant("invalid").is_err());
        assert!(parse_wildcard_grant("risk_below:low").is_err());
    }
}
