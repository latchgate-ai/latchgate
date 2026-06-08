#![no_main]
//! Fuzz the integrity backbone: `canonical_hash` and `canonicalize`.
//!
//! Properties tested:
//! - No panics on arbitrary structured JSON + limits.
//! - Determinism: identical input always produces identical output.
//! - Cross-function parity: `canonical_hash` and `canonicalize` agree on
//!   accept/reject for any (value, limits) pair.
//! - Hash correctness: `canonical_hash(v)` == `sha256(canonicalize(v))`.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use latchgate_core::crypto::canonical::{canonical_hash, canonicalize, Limits};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ── Structured JSON generator ───────────────────────────────────────────────

#[derive(Debug)]
struct FuzzInput {
    value: Value,
    max_bytes: usize,
    max_depth: u32,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            value: gen_value(u, 4)?,
            max_bytes: u.int_in_range(1..=128_000_usize)?,
            max_depth: u.int_in_range(1..=64_u32)?,
        })
    }
}

fn gen_value(u: &mut Unstructured, depth: u8) -> arbitrary::Result<Value> {
    if depth == 0 {
        return gen_leaf(u);
    }
    match u.int_in_range(0..=4_u8)? {
        0..=1 => gen_leaf(u),
        2 => {
            let len = u.int_in_range(0..=8_u8)?;
            (0..len)
                .map(|_| gen_value(u, depth - 1))
                .collect::<arbitrary::Result<Vec<_>>>()
                .map(Value::Array)
        }
        _ => {
            let len = u.int_in_range(0..=6_u8)?;
            let mut map = serde_json::Map::with_capacity(len as usize);
            for _ in 0..len {
                let key: String = u.arbitrary()?;
                map.insert(key, gen_value(u, depth - 1)?);
            }
            Ok(Value::Object(map))
        }
    }
}

fn gen_leaf(u: &mut Unstructured) -> arbitrary::Result<Value> {
    match u.int_in_range(0..=4_u8)? {
        0 => Ok(Value::Null),
        1 => u.arbitrary::<bool>().map(Value::Bool),
        2 => Ok(Value::Number(u.arbitrary::<i64>()?.into())),
        3 => {
            let f: f64 = u.arbitrary()?;
            Ok(serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number))
        }
        _ => u.arbitrary::<String>().map(Value::String),
    }
}

// ── Fuzz harness ────────────────────────────────────────────────────────────

fuzz_target!(|input: FuzzInput| {
    let limits = Limits {
        max_bytes: input.max_bytes,
        max_depth: input.max_depth,
    };

    let hash_result = canonical_hash(&input.value, &limits);
    let canon_result = canonicalize(&input.value, &limits);

    // Property: accept/reject parity.
    assert_eq!(
        hash_result.is_ok(),
        canon_result.is_ok(),
        "canonical_hash and canonicalize must agree on accept/reject",
    );

    if let (Ok(hash), Ok(ref canonical_bytes)) = (&hash_result, &canon_result) {
        // Property: hash correctness.
        let digest = Sha256::digest(canonical_bytes);
        let expected = format!("sha256:{}", hex::encode(digest));
        assert_eq!(hash, &expected, "hash must equal sha256(canonical_bytes)");

        // Property: determinism.
        let hash2 = canonical_hash(&input.value, &limits).unwrap();
        assert_eq!(hash, &hash2, "canonical_hash must be deterministic");

        let canon2 = canonicalize(&input.value, &limits).unwrap();
        assert_eq!(
            canonical_bytes, &canon2,
            "canonicalize must be deterministic",
        );
    }
});
