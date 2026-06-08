//! JCS (RFC 8785) canonicalization and SHA-256 hashing.
//!
//! Provides deterministic JSON serialization for content-addressable hashing.
//! Used for `request_hash`, `action_digest`, and approval integrity checks.

use super::json::json_depth;
use serde_json::Value;
use serde_json_canonicalizer::to_string as jcs_canonicalize;

/// Limits enforced before canonicalization (DoS protection).
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // SECURITY: conservative defaults to prevent DoS on the canonicalizer.
            max_bytes: 64 * 1024,
            max_depth: 32,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("input exceeds max size ({size} > {max})")]
    TooLarge { size: usize, max: usize },

    #[error("input exceeds max depth ({depth} > {max})")]
    TooDeep { depth: u32, max: u32 },

    #[error("input is not valid I-JSON: {reason}")]
    NotIJson { reason: String },

    #[error("canonicalization failed: {0}")]
    Canonicalize(String),
}

/// Compute canonical hash of a JSON value (JCS RFC 8785 + SHA-256).
///
/// Validates I-JSON subset and enforces size/depth limits before hashing.
#[must_use = "discarding the hash loses integrity binding"]
pub fn canonical_hash(value: &Value, limits: &Limits) -> Result<String, CanonicalError> {
    let canonical = validated_canonical(value, limits)?;
    Ok(super::hash::sha256_digest(canonical.as_bytes()))
}

/// Compute canonical hash and return the canonical byte length alongside it.
#[must_use = "discarding the hash loses integrity binding"]
pub fn canonical_hash_with_len(
    value: &Value,
    limits: &Limits,
) -> Result<(String, usize), CanonicalError> {
    let canonical = validated_canonical(value, limits)?;
    let len = canonical.len();
    Ok((super::hash::sha256_digest(canonical.as_bytes()), len))
}

/// Canonicalize a JSON value to bytes (JCS RFC 8785) without hashing.
#[must_use = "discarding the canonical form loses integrity binding"]
pub fn canonicalize(value: &Value, limits: &Limits) -> Result<Vec<u8>, CanonicalError> {
    let canonical = validated_canonical(value, limits)?;
    Ok(canonical.into_bytes())
}

/// Validate, canonicalize, and enforce limits on a JSON value.
///
/// Shared implementation for [`canonical_hash`], [`canonical_hash_with_len`],
/// and [`canonicalize`]. Produces a single JCS serialization pass — no
/// speculative `serde_json::to_string` for the size check.
///
/// # Limit measurement
///
/// `max_bytes` is enforced on the canonical (JCS) form rather than the
/// compact `serde_json::to_string` output. Both representations are compact
/// JSON (no whitespace); they differ only in key ordering. The byte lengths
/// are identical for any value without duplicate keys (which `serde_json`
/// never produces). This is the correct measurement point because the
/// canonical form is the artifact that is hashed and persisted.
fn validated_canonical(value: &Value, limits: &Limits) -> Result<String, CanonicalError> {
    // SECURITY: depth check first — O(n) tree walk, no allocation. Bounds
    // the complexity of the subsequent canonicalization pass.
    let depth = json_depth(value);
    if depth > limits.max_depth {
        return Err(CanonicalError::TooDeep {
            depth,
            max: limits.max_depth,
        });
    }

    // SECURITY: reject non-I-JSON values (NaN, ±Infinity) that break JCS
    // determinism. Also O(n), no allocation.
    validate_ijson(value)?;

    // Single serialization pass: JCS canonicalization (RFC 8785).
    let canonical =
        jcs_canonicalize(value).map_err(|e| CanonicalError::Canonicalize(e.to_string()))?;

    // SECURITY: enforce size limit on the canonical output to prevent DoS.
    if canonical.len() > limits.max_bytes {
        return Err(CanonicalError::TooLarge {
            size: canonical.len(),
            max: limits.max_bytes,
        });
    }

    Ok(canonical)
}

/// Validate that a JSON value is in the I-JSON subset (RFC 7493).
///
/// Rejects NaN, Infinity, -Infinity. These break JCS determinism.
fn validate_ijson(value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f.is_nan() || f.is_infinite() {
                    return Err(CanonicalError::NotIJson {
                        reason: format!("non-finite number: {f}"),
                    });
                }
            }
            Ok(())
        }
        Value::Array(arr) => arr.iter().try_for_each(validate_ijson),
        Value::Object(map) => map.values().try_for_each(validate_ijson),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_limits() -> Limits {
        Limits::default()
    }

    // --- Golden test vectors (canonical form => SHA-256) ---
    // These MUST match cross-lang (TypeScript SDK) when implemented.
    // Verified independently via: echo -n '<canonical>' | sha256sum

    #[test]
    fn golden_empty_object() {
        let hash = canonical_hash(&json!({}), &default_limits()).unwrap();
        assert_eq!(
            hash,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn golden_empty_array() {
        let hash = canonical_hash(&json!([]), &default_limits()).unwrap();
        assert_eq!(
            hash,
            "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
    }

    #[test]
    fn golden_simple_object() {
        // JCS: {"a":1,"b":2}
        let hash = canonical_hash(&json!({"a": 1, "b": 2}), &default_limits()).unwrap();
        assert_eq!(
            hash,
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn golden_nested_object() {
        // JCS: {"a":[],"z":{"a":1,"b":2}}
        let hash =
            canonical_hash(&json!({"z": {"b": 2, "a": 1}, "a": []}), &default_limits()).unwrap();
        assert_eq!(
            hash,
            "sha256:b36780a102e55932432e64250650c86a1ec30e170bf5384936f87d7499322a4a"
        );
    }

    #[test]
    fn golden_mixed_types() {
        let hash = canonical_hash(
            &json!({"bool": true, "null": null, "str": "hello", "num": 42, "arr": [1, 2]}),
            &default_limits(),
        )
        .unwrap();
        assert_eq!(
            hash,
            "sha256:1105e61c1c1a50cb15b6ada0943f223f1b3697ac5ad471f788774c8b1d04a719"
        );
    }

    // --- Key order invariance ---

    #[test]
    fn key_order_does_not_affect_hash() {
        let a = canonical_hash(&json!({"b": 1, "a": 2}), &default_limits()).unwrap();
        let b = canonical_hash(&json!({"a": 2, "b": 1}), &default_limits()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn nested_key_order_does_not_affect_hash() {
        let a = canonical_hash(
            &json!({"x": {"c": 3, "a": 1}, "a": true}),
            &default_limits(),
        )
        .unwrap();
        let b = canonical_hash(
            &json!({"a": true, "x": {"a": 1, "c": 3}}),
            &default_limits(),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    // --- Whitespace invariance ---

    #[test]
    fn whitespace_does_not_affect_hash() {
        let compact: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let spaced: Value = serde_json::from_str("{\n  \"a\" : 1 ,\n  \"b\" : 2\n}").unwrap();
        assert_eq!(
            canonical_hash(&compact, &default_limits()).unwrap(),
            canonical_hash(&spaced, &default_limits()).unwrap(),
        );
    }

    // --- I-JSON validation ---

    #[test]
    fn accepts_valid_ijson_types() {
        assert!(validate_ijson(&json!(null)).is_ok());
        assert!(validate_ijson(&json!(true)).is_ok());
        assert!(validate_ijson(&json!("hello")).is_ok());
        assert!(validate_ijson(&json!(42)).is_ok());
        assert!(validate_ijson(&json!(3.15)).is_ok());
        assert!(validate_ijson(&json!([1, "two", null])).is_ok());
        assert!(validate_ijson(&json!({"a": {"b": [1]}})).is_ok());
    }

    #[test]
    fn serde_json_rejects_non_finite_numbers() {
        // serde_json without "arbitrary_precision" cannot represent NaN/Infinity
        // as Number. This is itself a safety property we rely on.
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
        assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
        assert!(serde_json::Number::from_f64(f64::NEG_INFINITY).is_none());
    }

    // --- Unicode stability ---

    #[test]
    fn unicode_produces_stable_hash() {
        let a = canonical_hash(&json!({"emoji": "🎉", "jp": "日本語"}), &default_limits()).unwrap();
        let b = canonical_hash(&json!({"jp": "日本語", "emoji": "🎉"}), &default_limits()).unwrap();
        assert_eq!(a, b, "key order must not affect hash");
        assert_eq!(
            a, "sha256:fa688a766099feeb34886acae72139f91571403841f9fc6fc1099b2fe4fbac23",
            "unicode hash must match golden.json vector"
        );
    }

    // --- Float stability ---

    #[test]
    fn float_produces_stable_hash() {
        let a = canonical_hash(&json!({"val": 1.0}), &default_limits()).unwrap();
        let b = canonical_hash(&json!({"val": 1.0}), &default_limits()).unwrap();
        assert_eq!(a, b);
    }

    // --- Limits enforcement (canonical_hash) ---

    #[test]
    fn rejects_oversized_input() {
        let limits = Limits {
            max_bytes: 10,
            max_depth: 32,
        };
        let big = json!({"key": "a long value that exceeds limit"});
        assert!(matches!(
            canonical_hash(&big, &limits),
            Err(CanonicalError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_too_deep_input() {
        let limits = Limits {
            max_bytes: 64 * 1024,
            max_depth: 2,
        };
        let deep = json!({"a": {"b": {"c": 1}}});
        assert!(matches!(
            canonical_hash(&deep, &limits),
            Err(CanonicalError::TooDeep { .. })
        ));
    }

    // --- canonicalize() ---

    #[test]
    fn canonicalize_sorts_keys() {
        let bytes = canonicalize(&json!({"b": 1, "a": 2}), &default_limits()).unwrap();
        assert_eq!(bytes, b"{\"a\":2,\"b\":1}");
    }

    #[test]
    fn canonicalize_rejects_oversized_input() {
        let limits = Limits {
            max_bytes: 10,
            max_depth: 32,
        };
        let big = json!({"key": "a long value that exceeds limit"});
        assert!(matches!(
            canonicalize(&big, &limits),
            Err(CanonicalError::TooLarge { .. })
        ));
    }

    #[test]
    fn canonicalize_rejects_too_deep_input() {
        let limits = Limits {
            max_bytes: 64 * 1024,
            max_depth: 1,
        };
        let deep = json!({"a": {"b": 1}});
        assert!(matches!(
            canonicalize(&deep, &limits),
            Err(CanonicalError::TooDeep { .. })
        ));
    }

    // --- Property tests: hash stability under random input ---

    use rand::Rng;

    /// Generate a random JSON value with bounded depth and size.
    fn random_json(rng: &mut impl Rng, depth: u32) -> serde_json::Value {
        if depth == 0 {
            // Leaf values only.
            match rng.gen_range(0..4) {
                0 => json!(rng.gen::<i32>()),
                1 => json!(rng.gen::<bool>()),
                2 => {
                    let len = rng.gen_range(0..20);
                    let s: String = (0..len)
                        .map(|_| rng.gen_range(b'a'..=b'z') as char)
                        .collect();
                    json!(s)
                }
                _ => json!(null),
            }
        } else {
            match rng.gen_range(0..3) {
                0 => {
                    // Object with random keys.
                    let n = rng.gen_range(0..5);
                    let mut map = serde_json::Map::new();
                    for i in 0..n {
                        let key = format!("k{i}_{}", rng.gen_range(0..100u32));
                        map.insert(key, random_json(rng, depth - 1));
                    }
                    serde_json::Value::Object(map)
                }
                1 => {
                    // Array.
                    let n = rng.gen_range(0..5);
                    let arr: Vec<_> = (0..n).map(|_| random_json(rng, depth - 1)).collect();
                    serde_json::Value::Array(arr)
                }
                _ => random_json(rng, 0), // leaf
            }
        }
    }

    /// PROPERTY: calling canonical_hash twice on the same value always
    /// returns the same hash. Violations indicate non-determinism in
    /// JCS serialization or SHA-256 computation.
    #[test]
    fn property_hash_is_deterministic() {
        let mut rng = rand::thread_rng();
        let limits = default_limits();

        for _ in 0..200 {
            let val = random_json(&mut rng, 3);
            let h1 = canonical_hash(&val, &limits).unwrap();
            let h2 = canonical_hash(&val, &limits).unwrap();
            assert_eq!(h1, h2, "hash must be deterministic for: {val}");
        }
    }

    /// PROPERTY: JSON key order must not affect hash.
    /// Build the same object with keys inserted in different order.
    #[test]
    fn property_key_order_invariant() {
        let mut rng = rand::thread_rng();
        let limits = default_limits();

        for _ in 0..100 {
            let n = rng.gen_range(2..8);
            let keys: Vec<String> = (0..n).map(|i| format!("key_{i}")).collect();
            let vals: Vec<serde_json::Value> = (0..n).map(|_| random_json(&mut rng, 1)).collect();

            // Build object in original order.
            let mut map1 = serde_json::Map::new();
            for (k, v) in keys.iter().zip(vals.iter()) {
                map1.insert(k.clone(), v.clone());
            }

            // Build object in reverse order.
            let mut map2 = serde_json::Map::new();
            for (k, v) in keys.iter().rev().zip(vals.iter().rev()) {
                map2.insert(k.clone(), v.clone());
            }

            let h1 = canonical_hash(&serde_json::Value::Object(map1), &limits).unwrap();
            let h2 = canonical_hash(&serde_json::Value::Object(map2), &limits).unwrap();
            assert_eq!(h1, h2, "key order must not affect hash");
        }
    }

    /// PROPERTY: serialize => deserialize => hash must equal original hash.
    /// Round-trip through serde_json must preserve hash identity.
    #[test]
    fn property_serde_roundtrip_preserves_hash() {
        let mut rng = rand::thread_rng();
        let limits = default_limits();

        for _ in 0..200 {
            let val = random_json(&mut rng, 3);
            let h1 = canonical_hash(&val, &limits).unwrap();

            let serialized = serde_json::to_string(&val).unwrap();
            let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            let h2 = canonical_hash(&deserialized, &limits).unwrap();

            assert_eq!(h1, h2, "round-trip must preserve hash for: {val}");
        }
    }

    // --- F2: Cross-lang test vectors from definitions/test_vectors/jcs/golden.json ---

    /// Verify that the Rust canonical_hash matches the golden test vectors
    /// in `definitions/test_vectors/jcs/golden.json`. These same vectors MUST be
    /// used by TypeScript and Python SDKs to ensure cross-lang compatibility.
    #[test]
    fn golden_vectors_match_spec_file() {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate must be inside crates/")
            .parent()
            .expect("crates/ must be inside workspace root");
        let golden_path = workspace_root.join("definitions/test_vectors/jcs/golden.json");

        let contents = std::fs::read_to_string(&golden_path).unwrap_or_else(|e| {
            panic!(
                "cannot read golden vectors at {}: {e}",
                golden_path.display()
            )
        });
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&contents).expect("golden.json must be valid JSON array");

        assert!(
            !vectors.is_empty(),
            "golden.json must contain at least one vector"
        );

        let limits = default_limits();
        for (i, v) in vectors.iter().enumerate() {
            let desc = v["description"].as_str().unwrap_or("(no description)");
            let input = &v["input"];
            let expected_hash = v["sha256"]
                .as_str()
                .unwrap_or_else(|| panic!("vector {i} ({desc}) missing 'sha256' field"));

            let actual_hash = canonical_hash(input, &limits)
                .unwrap_or_else(|e| panic!("vector {i} ({desc}) canonicalization failed: {e}"));

            assert_eq!(
                actual_hash, expected_hash,
                "vector {i} ({desc}): hash mismatch — cross-lang compatibility broken"
            );
        }
    }

    // --- serde_json feature flag invariants ---
    //
    // These tests detect accidental activation of serde_json features that would
    // silently break integrity hashing. Cargo feature unification means a SINGLE
    // crate adding `serde_json = { features = ["preserve_order"] }` enables it
    // workspace-wide. These tests catch that at `cargo test` time.

    /// INVARIANT: serde_json::Map must iterate in sorted (BTreeMap) order.
    ///
    /// `preserve_order` replaces BTreeMap with IndexMap (insertion order).
    /// This breaks `compute_plan_hash()` and `ApprovedExecutionPlan::finalize()`
    /// because both use `serde_json::to_string()` on structs containing Value
    /// fields — the serialized bytes (and thus the hash) depend on map key order.
    ///
    /// JCS canonicalization sorts keys independently, but the plan hash and
    /// grant signable hash do NOT use JCS — they hash raw serde_json output.
    #[test]
    fn serde_json_map_must_iterate_in_sorted_order() {
        let mut map = serde_json::Map::new();
        // Insert in reverse alphabetical order.
        map.insert("z".into(), json!(1));
        map.insert("m".into(), json!(2));
        map.insert("a".into(), json!(3));

        let serialized = serde_json::to_string(&Value::Object(map)).unwrap();
        assert_eq!(
            serialized, r#"{"a":3,"m":2,"z":1}"#,
            "CRITICAL: serde_json `preserve_order` feature is active — \
             this breaks plan hash determinism. \
             A crate in the workspace has `serde_json = {{ features = [\"preserve_order\"] }}`. \
             Find and remove it: `grep -r preserve_order */Cargo.toml`"
        );
    }

    /// INVARIANT: serde_json numbers must use IEEE 754 f64 equality semantics.
    ///
    /// `arbitrary_precision` stores numbers as internal strings. This means
    /// `"1.0"` and `"1.00"` parse to DIFFERENT Values (different strings),
    /// breaking the identity `parse(a) == parse(b)` when `a` and `b` are
    /// mathematically equal but textually different.
    ///
    /// JCS relies on IEEE 754 normalization for number determinism. With
    /// `arbitrary_precision`, the canonicalizer receives string-backed numbers
    /// that may not round-trip through the same normalized form.
    #[test]
    fn serde_json_numbers_must_use_ieee754_equality() {
        let a: Value = serde_json::from_str(r#"{"x": 1.0}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"x": 1.00}"#).unwrap();
        assert_eq!(
            a, b,
            "CRITICAL: serde_json `arbitrary_precision` feature is active — \
             this breaks JCS canonical hashing. \
             `1.0` and `1.00` must parse to the same Value (IEEE 754 f64). \
             A crate in the workspace has `serde_json = {{ features = [\"arbitrary_precision\"] }}`. \
             Find and remove it: `grep -r arbitrary_precision */Cargo.toml`"
        );

        // Verify that canonical hashing is also identical.
        let limits = default_limits();
        let ha = canonical_hash(&a, &limits).unwrap();
        let hb = canonical_hash(&b, &limits).unwrap();
        assert_eq!(
            ha, hb,
            "CRITICAL: `1.0` and `1.00` produce different canonical hashes — \
             serde_json `arbitrary_precision` breaks JCS determinism"
        );
    }
}
