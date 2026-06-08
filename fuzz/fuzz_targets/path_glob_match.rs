#![no_main]
//! Fuzz the fs allow/deny rules: `GlobPattern`.
//!
//! Properties tested:
//! - No panics on arbitrary pattern + path combinations.
//! - `as_str()` always returns the original pattern string.
//! - No ReDoS-style stalls (enforced by libFuzzer's timeout).

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use latchgate_core::fs_path::GlobPattern;

#[derive(Debug)]
struct FuzzInput {
    pattern: String,
    paths: Vec<String>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let pattern: String = u.arbitrary()?;
        let count = u.int_in_range(1..=8_u8)?;
        let paths = (0..count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<String>>>()?;
        Ok(Self { pattern, paths })
    }
}

fuzz_target!(|input: FuzzInput| {
    let Ok(glob) = GlobPattern::new(&input.pattern) else {
        return;
    };

    // Property: as_str() fidelity.
    assert_eq!(
        glob.as_str(),
        input.pattern,
        "as_str() must return the original pattern",
    );

    // Property: matches must not panic (stalls caught by libFuzzer timeout).
    for path in &input.paths {
        let _ = glob.matches(path);
    }

    // Property: determinism.
    for path in &input.paths {
        let a = glob.matches(path);
        let b = glob.matches(path);
        assert_eq!(a, b, "matches must be deterministic for path: {path}");
    }
});
