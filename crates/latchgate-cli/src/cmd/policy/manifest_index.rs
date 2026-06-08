//! Manifest index — action metadata for validation + sink derivation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use latchgate_registry::manifest::ActionSpec;

/// Per-action metadata extracted from manifest files.
pub(crate) struct ManifestInfo {
    pub sinks: Vec<Arc<str>>,
    pub risk_label: &'static str,
}

pub(crate) type ManifestIndex = BTreeMap<String, ManifestInfo>;

/// Build an index of action_id => ManifestInfo from all manifests on disk.
pub(crate) fn build_manifest_index(manifests_dir: &Path) -> Result<ManifestIndex, String> {
    let mut index = BTreeMap::new();

    let entries = std::fs::read_dir(manifests_dir)
        .map_err(|e| format!("cannot read {}: {e}", manifests_dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read manifest entry: {e}"))?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

        let spec = ActionSpec::from_yaml(&contents)
            .map_err(|e| format!("invalid manifest {}: {e}", path.display()))?;

        let risk_label = match spec.risk_level {
            latchgate_core::RiskLevel::Low => "low",
            latchgate_core::RiskLevel::Medium => "medium",
            latchgate_core::RiskLevel::High => "high",
            latchgate_core::RiskLevel::Critical => "critical",
        };

        index.insert(
            spec.action_id,
            ManifestInfo {
                sinks: spec.declared_side_effects,
                risk_label,
            },
        );
    }

    Ok(index)
}

/// Derive the union of all sinks for a set of actions.
pub(crate) fn derive_sinks(
    actions: &BTreeSet<String>,
    index: &ManifestIndex,
) -> BTreeSet<Arc<str>> {
    let mut sinks = BTreeSet::new();
    for aid in actions {
        if let Some(info) = index.get(aid) {
            for sink in &info.sinks {
                sinks.insert(sink.clone());
            }
        }
    }
    sinks
}

/// Suggest the closest action ID for a typo.
pub(crate) fn suggest_action(typo: &str, index: &ManifestIndex) -> Option<String> {
    let typo_lower = typo.to_lowercase();
    index
        .keys()
        .find(|k| {
            let k_lower = k.to_lowercase();
            k_lower.contains(&typo_lower)
                || typo_lower.contains(&k_lower)
                || edit_distance(&typo_lower, &k_lower) <= 3
        })
        .cloned()
}

/// Minimal Levenshtein distance for typo suggestion.
pub(crate) fn edit_distance(a: &str, b: &str) -> usize {
    let b_bytes = b.as_bytes();
    let n = b_bytes.len();
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for (i, a_byte) in a.bytes().enumerate() {
        curr[0] = i + 1;
        for (j, &b_byte) in b_bytes.iter().enumerate() {
            let cost = if a_byte == b_byte { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}
