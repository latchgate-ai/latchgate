//! Operator DPoP proof-of-possession verification.
//!
//! Verifies that an operator presenting a token also controls the private key
//! bound to that token's `dpop_jkt` configuration. This prevents a stolen
//! `api_key` from granting operator access without the corresponding key.
//!
//! # Flow
//!
//! 1. Parse `Authorization` header: `DPoP <token>`.
//! 2. Match token to an `OperatorCredential` by constant-time `api_key` comparison.
//! 3. Verify the `DPoP` header proof JWT against the credential's `dpop_jkt`.
//! 4. Return `OperatorAuthContext` with identity, authn method, and sender binding.
//!
//! # Security properties
//!
//! - Constant-time token comparison prevents timing attacks.
//! - DPoP proof is request-bound (`htm`, `htu`), time-bound (`iat`), and
//!   token-bound (`ath`). Replay is prevented by `jti` cache.
//! - All operator credentials require `dpop_jkt` — enforced at startup by
//!   `Config::validate_operator_auth()`.

use std::collections::HashMap;
use std::sync::Arc;

use latchgate_config::OperatorCredential;
use latchgate_core::constant_time_eq;

use super::key_cache::DPoPKeyCache;
use super::verify::{verify_dpop_proof, DPoPVerifyError, DpopRejectKind};
use crate::ReplayCache;

/// Authentication method used by an operator.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OperatorAuthnMethod {
    /// DPoP proof-of-possession (RFC 9449).
    #[serde(rename = "operator_dpop")]
    Dpop,
}

impl OperatorAuthnMethod {
    /// Wire-format string for audit events and evidence payloads.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dpop => "operator_dpop",
        }
    }
}

impl std::fmt::Display for OperatorAuthnMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Recorded in audit events and the evidence plane for forensic attribution.
#[derive(Debug, Clone)]
pub struct OperatorAuthContext {
    /// Operator identity from the credential configuration.
    pub operator_id: Arc<str>,

    /// Authentication method used.
    pub authn_method: OperatorAuthnMethod,

    /// JWK thumbprint of the operator's DPoP key (sender binding).
    pub sender_binding: Arc<str>,

    /// `jti` from the DPoP proof (for forensic correlation).
    pub proof_jti: Arc<str>,
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorAuthError {
    #[error("missing Authorization header")]
    MissingAuthHeader,

    #[error("invalid Authorization scheme: expected 'DPoP <token>'")]
    InvalidScheme,

    #[error("invalid operator token")]
    InvalidToken,

    #[error("no operator authentication configured")]
    NotConfigured,

    #[error("DPoP header required but missing")]
    MissingDpopHeader,

    #[error("operator DPoP proof invalid: {reason}")]
    InvalidDpopProof {
        kind: DpopRejectKind,
        reason: String,
    },

    #[error(
        "operator DPoP key binding failed: proof thumbprint does not match configured dpop_jkt"
    )]
    KeyBindingFailed,

    #[error("operator DPoP proof replay detected: jti {jti}")]
    ReplayDetected { jti: String },

    #[error("replay cache unavailable")]
    ReplayCacheUnavailable,
}

/// Authenticate an operator request using DPoP proof-of-possession.
pub async fn verify_operator_auth(
    authorization: Option<&str>,
    dpop_header: Option<&str>,
    expected_htm: &str,
    expected_htu: &str,
    credentials: &HashMap<String, OperatorCredential>,
    replay_cache: &ReplayCache,
    key_cache: &DPoPKeyCache,
) -> Result<OperatorAuthContext, OperatorAuthError> {
    let header = authorization.ok_or(OperatorAuthError::MissingAuthHeader)?;

    let token = header
        .strip_prefix("DPoP ")
        .ok_or(OperatorAuthError::InvalidScheme)?;

    let dpop_proof = dpop_header.ok_or(OperatorAuthError::MissingDpopHeader)?;

    verify_dpop_operator(
        token,
        dpop_proof,
        expected_htm,
        expected_htu,
        credentials,
        replay_cache,
        key_cache,
    )
    .await
}

/// Verify operator DPoP: match token, verify proof, check key binding.
async fn verify_dpop_operator(
    token: &str,
    dpop_proof: &str,
    expected_htm: &str,
    expected_htu: &str,
    credentials: &HashMap<String, OperatorCredential>,
    replay_cache: &ReplayCache,
    key_cache: &DPoPKeyCache,
) -> Result<OperatorAuthContext, OperatorAuthError> {
    let (operator_id, cred) = find_operator_by_token(token, credentials)?;

    let expected_jkt = cred.dpop_jkt.as_deref().ok_or({
        // Credential exists but has no dpop_jkt. This should not happen in
        // production (startup validation catches it). Fail-closed.
        OperatorAuthError::KeyBindingFailed
    })?;

    let claims = verify_dpop_proof(
        dpop_proof,
        expected_htm,
        expected_htu,
        token, // ath = SHA-256(token) — binds proof to this specific operator token
        expected_jkt,
        key_cache,
    )
    .map_err(|e| match e {
        DPoPVerifyError::InvalidProof {
            kind: DpopRejectKind::BadKey,
            ..
        } => OperatorAuthError::KeyBindingFailed,
        DPoPVerifyError::InvalidProof { kind, reason } => {
            OperatorAuthError::InvalidDpopProof { kind, reason }
        }
        DPoPVerifyError::ClockError => OperatorAuthError::InvalidDpopProof {
            kind: DpopRejectKind::BadIat,
            reason: "system clock error: cannot validate timestamps".into(),
        },
    })?;

    match replay_cache.check_and_store_jti(&claims.jti).await {
        Ok(()) => {} // New jti — not a replay.
        Err(crate::replay::ReplayError::AlreadySeen { .. }) => {
            return Err(OperatorAuthError::ReplayDetected { jti: claims.jti });
        }
        Err(_) => {
            return Err(OperatorAuthError::ReplayCacheUnavailable);
        }
    }

    Ok(OperatorAuthContext {
        operator_id: Arc::from(operator_id),
        authn_method: OperatorAuthnMethod::Dpop,
        sender_binding: Arc::from(expected_jkt),
        proof_jti: Arc::from(claims.jti),
    })
}

/// Find operator by constant-time api_key comparison.
///
/// SECURITY: iterates EVERY credential in the map before returning, regardless
/// of where the matching entry appears. Early-returning on first match would
/// make response time correlate with the operator's iteration position in the
/// HashMap — a weak but real timing side channel. Total work is now a function
/// of `credentials.len()` only.
///
/// The first matching entry wins on the rare case of duplicate api_keys
/// (should never happen; config validation enforces uniqueness).
fn find_operator_by_token<'a>(
    token: &str,
    credentials: &'a HashMap<String, OperatorCredential>,
) -> Result<(String, &'a OperatorCredential), OperatorAuthError> {
    let token_bytes = token.as_bytes();
    let mut matched: Option<(String, &'a OperatorCredential)> = None;
    for (operator_id, cred) in credentials {
        // constant_time_eq compares every byte; adding a second match after
        // the first does not stash the result, so timing is independent of
        // match position.
        let is_match = constant_time_eq(token_bytes, cred.api_key.as_bytes());
        if is_match && matched.is_none() {
            matched = Some((operator_id.clone(), cred));
        }
        // Continue iterating unconditionally — no early return.
    }
    matched.ok_or(OperatorAuthError::InvalidToken)
}

#[cfg(test)]
mod tests {
    use super::super::key_cache::DPoPKeyCache;
    use super::*;

    // --- find_operator_by_token ---

    fn test_credentials() -> HashMap<String, OperatorCredential> {
        let mut creds = HashMap::new();
        creds.insert(
            "bob".into(),
            OperatorCredential {
                api_key: "key-bob-secret".into(),
                dpop_jkt: Some("placeholder-jkt".into()),
            },
        );
        creds
    }

    #[test]
    fn find_operator_constant_time() {
        let creds = test_credentials();
        let (id, _) = find_operator_by_token("key-bob-secret", &creds).unwrap();
        assert_eq!(id, "bob");
    }

    #[test]
    fn find_operator_wrong_key() {
        let creds = test_credentials();
        assert!(find_operator_by_token("wrong", &creds).is_err());
    }

    /// SECURITY regression: `find_operator_by_token` MUST iterate the full
    /// credential map regardless of where the matching entry appears in the
    /// HashMap's internal order. An early return on first match would leak
    /// the matching operator's iteration position through request latency —
    /// a weak but real side channel that aids enumeration of valid tokens
    /// and narrows brute-force search.
    ///
    /// With early return on an N-entry map, matching the first-iterated key
    /// takes ~1 unit of work and matching the last-iterated key takes ~N.
    /// Without early return, both cost ~N.
    ///
    /// The test builds a 512-entry map, measures per-call time for the
    /// first- and last-iterated matching keys, and fails if the ratio
    /// exceeds 3x — a ceiling chosen to tolerate CI noise (typically under
    /// 2x) while still catching the ~512x gap that a regression would
    /// introduce. `constant_time_eq` is used inside the loop, which
    /// guarantees per-comparison cost is independent of the matching byte
    /// position within a single key; the only remaining timing leak would
    /// be loop-count dependence, which this test closes.
    #[test]
    fn find_operator_timing_independent_of_position() {
        use std::hint::black_box;
        use std::time::Instant;

        // Large enough that an early return would produce a clearly
        // detectable gap (~Nx with N=512) while keeping the test fast.
        const MAP_SIZE: usize = 512;
        // Warm-up iterations amortize cache effects and JIT-like first-run
        // costs of the allocator/hasher. Measurement iterations are chosen
        // so each measured sample is ~tens of milliseconds on a modest
        // machine, well above clock resolution noise.
        const WARMUP_ITERS: u32 = 200;
        const MEASURE_ITERS: u32 = 5_000;
        // 3x is conservative: true ratio without early return is ~1.0 ± CI
        // noise; true ratio *with* early return would be ~MAP_SIZE.
        const MAX_RATIO: f64 = 3.0;

        // Build a map with MAX_SIZE distinct credentials, each api_key the
        // same length so constant_time_eq's per-call cost is uniform.
        let mut creds: HashMap<String, OperatorCredential> = HashMap::with_capacity(MAP_SIZE);
        for i in 0..MAP_SIZE {
            creds.insert(
                format!("op-{i:04}"),
                OperatorCredential {
                    api_key: format!("api-key-secret-value-{i:04}"),
                    dpop_jkt: None,
                },
            );
        }

        // Capture the HashMap's actual iteration order. Rust HashMap
        // ordering is randomised per-process, so we must discover it at
        // runtime rather than assume insertion order.
        let iteration_order: Vec<String> = creds.values().map(|c| c.api_key.clone()).collect();
        assert_eq!(iteration_order.len(), MAP_SIZE);
        let first_key = iteration_order[0].clone();
        let last_key = iteration_order[MAP_SIZE - 1].clone();

        // Warm up with an arbitrary miss so branch predictors and caches
        // settle before either measurement starts.
        for _ in 0..WARMUP_ITERS {
            let _ = find_operator_by_token(black_box("warmup-miss"), black_box(&creds));
        }

        let measure = |token: &str| -> u128 {
            let start = Instant::now();
            for _ in 0..MEASURE_ITERS {
                let _ = find_operator_by_token(black_box(token), black_box(&creds));
            }
            start.elapsed().as_nanos()
        };

        // Measure both, twice in interleaved order so transient system
        // noise (scheduler, thermal, etc.) is less likely to bias a single
        // position. Sum of interleaved samples is the comparison target.
        let t_first_a = measure(&first_key);
        let t_last_a = measure(&last_key);
        let t_last_b = measure(&last_key);
        let t_first_b = measure(&first_key);
        let t_first = t_first_a + t_first_b;
        let t_last = t_last_a + t_last_b;

        let (hi, lo) = (t_first.max(t_last), t_first.min(t_last));
        // Avoid division-by-zero on absurdly fast or broken clocks. If the
        // loop genuinely measured zero nanoseconds, either the compiler
        // elided it (black_box failure) or the clock is broken — both are
        // test infrastructure failures, not regressions.
        assert!(
            lo > 0,
            "measured zero elapsed time — compiler elided the call or clock is broken"
        );
        let ratio = hi as f64 / lo as f64;
        assert!(
            ratio < MAX_RATIO,
            "timing ratio first:last = {ratio:.2}x exceeds {MAX_RATIO}x ceiling \
             (t_first = {t_first} ns, t_last = {t_last} ns over {MEASURE_ITERS} iters x 2 samples \
             on a {MAP_SIZE}-entry map) — likely regression to early-return lookup"
        );
    }

    // --- Scheme parsing (via verify_operator_auth) ---

    #[tokio::test]
    async fn missing_auth_header_is_rejected() {
        let creds = HashMap::new();
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();
        let result = verify_operator_auth(
            None,
            None,
            "POST",
            "https://example.com/v1/approvals/x/approve",
            &creds,
            &cache,
            &key_cache,
        )
        .await;
        assert!(matches!(result, Err(OperatorAuthError::MissingAuthHeader)));
    }

    #[tokio::test]
    async fn invalid_scheme_is_rejected() {
        let creds = HashMap::new();
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();
        let result = verify_operator_auth(
            Some("Basic dXNlcjpwYXNz"),
            None,
            "POST",
            "https://example.com/v1/approvals/x/approve",
            &creds,
            &cache,
            &key_cache,
        )
        .await;
        assert!(matches!(result, Err(OperatorAuthError::InvalidScheme)));
    }

    #[tokio::test]
    async fn bearer_scheme_is_rejected() {
        let creds = HashMap::new();
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();
        let result = verify_operator_auth(
            Some("Bearer some-token"),
            None,
            "POST",
            "https://example.com/v1/approvals/x/approve",
            &creds,
            &cache,
            &key_cache,
        )
        .await;
        assert!(matches!(result, Err(OperatorAuthError::InvalidScheme)));
    }

    #[tokio::test]
    async fn dpop_without_proof_header_is_rejected() {
        let mut creds = HashMap::new();
        creds.insert(
            "alice".into(),
            OperatorCredential {
                api_key: "token-alice".into(),
                dpop_jkt: Some("jkt-placeholder".into()),
            },
        );
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();
        let result = verify_operator_auth(
            Some("DPoP token-alice"),
            None, // no DPoP header
            "POST",
            "https://example.com/v1/approvals/x/approve",
            &creds,
            &cache,
            &key_cache,
        )
        .await;
        assert!(matches!(result, Err(OperatorAuthError::MissingDpopHeader)));
    }

    use crate::dpop::{
        compute_ath, compute_jwk_thumbprint, generate_dpop_keypair, sign_dpop_proof,
    };

    const TEST_HTU: &str = "https://gate.example.com/v1/approvals/appr-001/approve";
    const TEST_HTM: &str = "POST";

    /// Build operator credentials with a real DPoP keypair. Returns
    /// (credentials, api_key, signing_key) so tests can produce proofs.
    fn dpop_credential() -> (
        HashMap<String, OperatorCredential>,
        String,
        crate::dpop::DPoPSigningKey,
    ) {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let api_key = "operator-token-alice-12345".to_string();

        let mut creds = HashMap::new();
        creds.insert(
            "alice".into(),
            OperatorCredential {
                api_key: api_key.clone(),
                dpop_jkt: Some(jkt),
            },
        );
        (creds, api_key, sk)
    }

    /// Sign a DPoP proof for a given operator token.
    fn operator_proof(sk: &crate::dpop::DPoPSigningKey, token: &str) -> String {
        let ath = compute_ath(token);
        let jti = uuid::Uuid::now_v7().to_string();
        sign_dpop_proof(sk, TEST_HTM, TEST_HTU, &ath, &jti).unwrap()
    }

    #[tokio::test]
    async fn valid_dpop_proof_is_accepted() {
        let (creds, api_key, sk) = dpop_credential();
        let proof = operator_proof(&sk, &api_key);
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();

        let ctx = verify_operator_auth(
            Some(&format!("DPoP {api_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await
        .unwrap();

        assert_eq!(&*ctx.operator_id, "alice");
        assert_eq!(ctx.authn_method, OperatorAuthnMethod::Dpop);
        assert!(!ctx.sender_binding.is_empty(), "sender_binding must be set");
        assert!(!ctx.proof_jti.is_empty(), "proof_jti must be recorded");
    }

    #[tokio::test]
    async fn dpop_proof_signed_by_wrong_key_is_rejected() {
        let (creds, api_key, _sk) = dpop_credential();
        // Sign with a DIFFERENT key than the one configured in dpop_jkt.
        let (wrong_sk, _) = generate_dpop_keypair().unwrap();
        let proof = operator_proof(&wrong_sk, &api_key);
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();

        let result = verify_operator_auth(
            Some(&format!("DPoP {api_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(OperatorAuthError::KeyBindingFailed)
                    | Err(OperatorAuthError::InvalidDpopProof { .. })
            ),
            "wrong key must be rejected, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn dpop_proof_replay_is_rejected() {
        let (creds, api_key, sk) = dpop_credential();
        let proof = operator_proof(&sk, &api_key);
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();

        // First use — accepted.
        let result1 = verify_operator_auth(
            Some(&format!("DPoP {api_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await;
        assert!(result1.is_ok(), "first use must succeed");

        // Replay — rejected.
        let result2 = verify_operator_auth(
            Some(&format!("DPoP {api_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await;
        assert!(
            matches!(result2, Err(OperatorAuthError::ReplayDetected { .. })),
            "replayed proof must be rejected, got: {result2:?}"
        );
    }

    #[tokio::test]
    async fn dpop_proof_with_wrong_token_binding_is_rejected() {
        let (creds, api_key, sk) = dpop_credential();
        // Sign proof bound to a different token.
        let proof = operator_proof(&sk, "wrong-token-value");
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();

        let result = verify_operator_auth(
            Some(&format!("DPoP {api_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await;

        assert!(
            matches!(result, Err(OperatorAuthError::InvalidDpopProof { .. })),
            "wrong ath must be rejected, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn dpop_proof_with_wrong_htu_is_rejected() {
        let (creds, api_key, sk) = dpop_credential();
        let ath = compute_ath(&api_key);
        let jti = uuid::Uuid::now_v7().to_string();
        // Proof bound to a different URL.
        let proof = sign_dpop_proof(
            &sk,
            TEST_HTM,
            "https://evil.com/v1/approvals/x/approve",
            &ath,
            &jti,
        )
        .unwrap();
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();

        let result = verify_operator_auth(
            Some(&format!("DPoP {api_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await;

        assert!(
            matches!(result, Err(OperatorAuthError::InvalidDpopProof { .. })),
            "wrong htu must be rejected, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn dpop_with_wrong_api_key_is_rejected() {
        let (creds, _api_key, sk) = dpop_credential();
        let wrong_key = "completely-wrong-token";
        let proof = operator_proof(&sk, wrong_key);
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let key_cache = DPoPKeyCache::new();

        let result = verify_operator_auth(
            Some(&format!("DPoP {wrong_key}")),
            Some(&proof),
            TEST_HTM,
            TEST_HTU,
            &creds,
            &cache,
            &key_cache,
        )
        .await;

        assert!(
            matches!(result, Err(OperatorAuthError::InvalidToken)),
            "wrong api_key must be rejected, got: {result:?}"
        );
    }
}
