//! DPoP proof verifier (RFC 9449).
//!
//! Server-side verification: validates that an incoming proof was signed by the
//! key committed to in the Lease's `cnf.jkt` claim, is bound to the current
//! request, and is within the permitted time window.
//!
//! Client-side operations (key generation, proof signing) and shared types
//! live in the parent module (`crate::dpop`).
//!
//! Returns `DPoPVerifyError` on failure. The caller (`auth`) converts
//! this to `AuthError` via the `From` impl, keeping the enforcement boundary
//! in the gate module.

use base64ct::{Base64UrlUnpadded, Encoding};
use latchgate_core::constant_time_eq;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

use super::key_cache::DPoPKeyCache;
use super::{compute_ath, compute_jwk_thumbprint, normalize_htu, unix_now, DPoPClaims};

/// Closed set of DPoP rejection categories used as Prometheus metric labels.
///
/// SECURITY (cardinality): `DPoPVerifyError::InvalidProof` carries a free-form
/// human-readable `reason` string that may contain attacker-controlled content
/// (typ/alg values, htu/htm strings from the JWT). Using that string directly
/// as a Prometheus label would allow an attacker to create an unbounded number
/// of label combinations, exhausting allocator memory and crashing scrapers.
///
/// This enum is the only value that must appear in `dpop_rejects_total` labels.
/// Every variant maps to a short, static `&'static str` via `as_metric_label()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopRejectKind {
    /// JWT is structurally malformed: wrong number of segments, bad base64url,
    /// or payload/header is not valid JSON.
    Malformed,
    /// JWT header claims are invalid: wrong `typ`, `alg`, missing or
    /// malformed `jwk`, wrong `kty`/`crv`, or missing `x`/`y` coordinates.
    BadHeader,
    /// Key binding failure: bad EC point, thumbprint computation error, or
    /// the embedded JWK thumbprint does not match the Lease's `cnf.jkt`.
    BadKey,
    /// Signature is structurally invalid or does not verify against the
    /// embedded public key.
    BadSig,
    /// `htm` claim does not match the expected HTTP method.
    BadHtm,
    /// `htu` claim does not match the expected request URI, or htu
    /// normalisation failed.
    BadHtu,
    /// `iat` claim is outside the permitted time window.
    BadIat,
    /// `ath` claim does not match the SHA-256 hash of the presented access
    /// token.
    BadAth,
}

impl DpopRejectKind {
    /// Return the static Prometheus label string for this rejection kind.
    ///
    /// These strings are the *only* values that should ever appear as the
    /// `reason` label on `dpop_rejects_total`. Adding a new variant here is a
    /// deliberate, reviewed change — not an accident caused by formatted errors.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadHeader => "bad_header",
            Self::BadKey => "bad_key",
            Self::BadSig => "bad_sig",
            Self::BadHtm => "bad_htm",
            Self::BadHtu => "bad_htu",
            Self::BadIat => "bad_iat",
            Self::BadAth => "bad_ath",
        }
    }
}

/// Errors from DPoP proof verification.
///
/// Converted to `AuthError` at the pipeline boundary via `From`.
/// This type exists so the `dpop` module has no dependency on `gate`.
#[derive(Debug, thiserror::Error)]
pub enum DPoPVerifyError {
    /// Proof is structurally invalid, fails a binding check, or is outside
    /// the permitted time window. The request MUST be denied.
    ///
    /// `kind` is a closed enum used for Prometheus labels — never use `reason`
    /// as a metric label directly (cardinality DoS).
    ///
    /// SECURITY: construct this variant through [`DPoPVerifyError::invalid_proof`]
    /// (never struct-literal) so `reason` is sanitized once at write time.
    /// The `reason` field may be derived from JWT header values (`typ`, `alg`,
    /// `kty`, `crv`, etc.) or payload claims (`htm`, `htu`), all of which are
    /// attacker-controlled. Emitting raw control characters into log lines,
    /// audit events, or HTTP bodies enables log injection.
    #[error("invalid DPoP proof: {reason}")]
    InvalidProof {
        kind: DpopRejectKind,
        reason: String,
    },

    /// System clock is before Unix epoch — cannot validate timestamps.
    ///
    /// SECURITY: fail-closed; a broken clock would allow iat window bypass.
    #[error("clock error: system time is before Unix epoch")]
    ClockError,
}

impl DPoPVerifyError {
    /// Maximum `reason` length for DPoP rejection diagnostics.
    ///
    /// DPoP rejection reasons are short diagnostic strings (claim mismatches,
    /// header validation messages). Capping keeps audit events and log lines
    /// bounded when an attacker supplies an oversized header or claim.
    const REASON_MAX_BYTES: usize = 200;

    /// Construct an `InvalidProof` error with a sanitized reason.
    ///
    /// SECURITY: this is the single construction path for `InvalidProof`.
    /// `reason` is stripped of control characters and truncated via
    /// [`latchgate_core::sanitize_for_log`] so downstream consumers (log
    /// aggregators, audit events, HTTP bodies) never see raw attacker input.
    pub fn invalid_proof(kind: DpopRejectKind, reason: impl Into<String>) -> Self {
        let raw = reason.into();
        Self::InvalidProof {
            kind,
            reason: latchgate_core::sanitize_for_log(&raw, Self::REASON_MAX_BYTES).into_owned(),
        }
    }
}

/// Maximum age of a DPoP proof's `iat` claim in seconds.
///
/// SECURITY: limits the replay window even if jti replay detection is
/// temporarily unavailable. 60 s follows the RFC 9449 server recommendation.
const IAT_MAX_AGE_SECS: u64 = 60;

/// Permitted forward clock skew for `iat` claims in seconds.
///
/// Allows clients with slightly fast clocks without meaningfully widening
/// the replay window.
const IAT_CLOCK_SKEW_SECS: u64 = 5;

/// Verify a DPoP proof against the current request and bound Lease JWT.
///
/// `key_cache` accelerates repeat requests from the same agent: on cache
/// hit, header parsing, JWK extraction, and thumbprint verification are
/// skipped. The ECDSA signature is always verified (RFC 9449 §4.3).
///
/// Validation order (fail-closed at each step):
///
/// **Cache miss (first proof from this key):**
/// 1. Structure: three-part JWT, valid base64url segments.
/// 2. Header: `typ` == `"dpop+jwt"`, `alg` == `"ES256"`.
/// 3. JWK: `kty=EC`, `crv=P-256`, valid x/y coordinates.
/// 4. Key binding: `thumbprint(jwk) == cnf_jkt` (sender constraint).
/// 5. Signature valid using the extracted key (then cached under `cnf_jkt`).
///
/// **Cache hit (repeat proof from the same key):**
/// 1. Structure: three-part JWT, valid base64url segments.
/// 2. Signature valid using the cached key.
///
/// **Both paths (always):**
/// 7. Required payload claims present and well-typed.
/// 8. `htm` == `expected_htm` (normalised to uppercase).
/// 9. `htu` == `expected_htu` (RFC 9449 §4.2.2 normalisation).
/// 10. `iat` within `[now − 60 s, now + 5 s]`.
/// 11. `ath` == `SHA-256(lease_jwt)` — proof bound to this specific token.
///
/// Returns `DPoPClaims` on success. The caller (Gate anti-replay step) is
/// responsible for jti uniqueness via the Redis SETNX cache.
///
/// Fails closed: any failure returns `Err(DPoPVerifyError)`.
pub fn verify_dpop_proof(
    proof: &str,
    expected_htm: &str,
    expected_htu: &str,
    lease_jwt: &str,
    cnf_jkt: &str,
    key_cache: &DPoPKeyCache,
) -> Result<DPoPClaims, DPoPVerifyError> {
    // 1. Split into header / payload / signature
    let parts: Vec<&str> = proof.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::Malformed,
            "malformed JWT: expected exactly 3 dot-separated segments",
        ));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    // ── Resolve verifying key ─────────────────────────────────────────
    //
    // Cache hit:  use the previously-verified key directly. Header
    //             parsing, JWK extraction, and thumbprint check are
    //             skipped — the cnf.jkt → key binding was established
    //             on initial insertion and is secured by SHA-256
    //             preimage resistance.
    //
    // Cache miss: full header parse → JWK validation → EC point
    //             construction → thumbprint binding check.
    let (vk, cache_hit) = match key_cache.get(cnf_jkt) {
        Some(cached_vk) => (cached_vk, true),
        None => (extract_bound_key(header_b64, cnf_jkt)?, false),
    };

    // ── Verify ECDSA signature (mandatory per RFC 9449, every request) ──
    let sec1_public_key = vk.to_encoded_point(false);

    let sig_bytes = b64url_decode(sig_b64, "signature", DpopRejectKind::BadSig)?;

    verify_sig(
        sec1_public_key.as_bytes(),
        header_b64,
        payload_b64,
        &sig_bytes,
    )?;

    // ── Cache on miss (after successful signature verification) ──────
    //
    // SECURITY: insertion only after proof-of-possession. The thumbprint
    // binding alone would suffice (SHA-256 preimage resistance guarantees
    // the cached key matches cnf_jkt), but verifying the signature first
    // means we never cache a key that hasn't appeared in a valid proof.
    if !cache_hit {
        key_cache.insert(cnf_jkt.to_owned(), vk);
    }

    let payload_bytes = b64url_decode(payload_b64, "payload", DpopRejectKind::Malformed)?;
    let payload: DPoPClaims = serde_json::from_slice(&payload_bytes).map_err(|e| {
        DPoPVerifyError::invalid_proof(
            DpopRejectKind::Malformed,
            format!("payload claims invalid or missing required fields: {e}"),
        )
    })?;

    let expected_htm_upper = expected_htm.to_ascii_uppercase();
    if payload.htm != expected_htm_upper {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadHtm,
            format!(
                "htm mismatch: expected '{expected_htm_upper}', got '{}'",
                payload.htm
            ),
        ));
    }

    let expected_htu_norm = normalize_htu(expected_htu).map_err(|e| {
        DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadHtu,
            format!("expected_htu normalisation failed: {e}"),
        )
    })?;
    let proof_htu_norm = normalize_htu(&payload.htu).map_err(|e| {
        DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadHtu,
            format!("proof htu normalisation failed: {e}"),
        )
    })?;
    if proof_htu_norm != expected_htu_norm {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadHtu,
            format!("htu mismatch: expected '{expected_htu_norm}', got '{proof_htu_norm}'"),
        ));
    }

    let now = unix_now().map_err(|_| DPoPVerifyError::ClockError)?;
    validate_iat_window(payload.iat, now)?;

    // SECURITY: ath binds this proof to the exact access token presented.
    // Without this, a valid proof could be replayed with a different token.
    //
    // SECURITY: comparison is constant-time on the SHA-256-of-lease digest;
    // see the rationale on the thumbprint check above.
    let expected_ath = compute_ath(lease_jwt);
    if !constant_time_eq(payload.ath.as_bytes(), expected_ath.as_bytes()) {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadAth,
            "ath does not match SHA-256 of the presented access token",
        ));
    }

    Ok(payload)
}

/// Extract and validate the P-256 verifying key from a DPoP proof header,
/// verifying that its JWK thumbprint matches the Lease's `cnf.jkt`.
///
/// Called on cache miss. Performs:
/// 1. Header JSON parsing and structural validation (typ, alg, jwk, kty, crv).
/// 2. JWK x/y coordinate extraction and base64url decoding.
/// 3. EC point construction (SEC1 uncompressed → `P256VerifyingKey`).
/// 4. JWK thumbprint computation and binding check against `cnf_jkt`.
///
/// Does **not** verify the ECDSA signature — the caller does that after
/// this function returns, for both cache-hit and cache-miss paths.
fn extract_bound_key(header_b64: &str, cnf_jkt: &str) -> Result<P256VerifyingKey, DPoPVerifyError> {
    let header_bytes = b64url_decode(header_b64, "header", DpopRejectKind::Malformed)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| {
        DPoPVerifyError::invalid_proof(DpopRejectKind::Malformed, "JWT header is not valid JSON")
    })?;

    // SECURITY: `typ` MUST be "dpop+jwt" per RFC 9449 §4.2. This prevents a
    // DPoP proof from being substituted as a bearer token or vice versa.
    match header.get("typ").and_then(|v| v.as_str()) {
        Some("dpop+jwt") => {}
        other => {
            return Err(DPoPVerifyError::invalid_proof(
                DpopRejectKind::BadHeader,
                format!("typ must be 'dpop+jwt', got {other:?}"),
            ))
        }
    }

    // SECURITY: reject algorithm negotiation. Only ES256 is permitted.
    match header.get("alg").and_then(|v| v.as_str()) {
        Some("ES256") => {}
        other => {
            return Err(DPoPVerifyError::invalid_proof(
                DpopRejectKind::BadHeader,
                format!("alg must be 'ES256', got {other:?}"),
            ))
        }
    }

    let jwk = header.get("jwk").ok_or_else(|| {
        DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadHeader,
            "'jwk' header claim is required in DPoP proofs",
        )
    })?;

    match jwk.get("kty").and_then(|v| v.as_str()) {
        Some("EC") => {}
        other => {
            return Err(DPoPVerifyError::invalid_proof(
                DpopRejectKind::BadHeader,
                format!("jwk.kty must be 'EC', got {other:?}"),
            ))
        }
    }
    match jwk.get("crv").and_then(|v| v.as_str()) {
        Some("P-256") => {}
        other => {
            return Err(DPoPVerifyError::invalid_proof(
                DpopRejectKind::BadHeader,
                format!("jwk.crv must be 'P-256', got {other:?}"),
            ))
        }
    }

    let x_b64 = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
        DPoPVerifyError::invalid_proof(DpopRejectKind::BadHeader, "jwk.x is required")
    })?;
    let y_b64 = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
        DPoPVerifyError::invalid_proof(DpopRejectKind::BadHeader, "jwk.y is required")
    })?;

    let x_bytes = Base64UrlUnpadded::decode_vec(x_b64).map_err(|_| {
        DPoPVerifyError::invalid_proof(DpopRejectKind::BadHeader, "invalid base64url in jwk.x")
    })?;
    let y_bytes = Base64UrlUnpadded::decode_vec(y_b64).map_err(|_| {
        DPoPVerifyError::invalid_proof(DpopRejectKind::BadHeader, "invalid base64url in jwk.y")
    })?;

    let sec1_public_key = build_sec1_uncompressed(&x_bytes, &y_bytes);

    let vk = P256VerifyingKey::from_sec1_bytes(&sec1_public_key).map_err(|_| {
        DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadKey,
            "invalid P-256 public key (point not on curve)",
        )
    })?;

    // SECURITY: sender constraint — the JWK thumbprint of the extracted key
    // must match cnf.jkt from the already-verified Lease JWT. This binds the
    // DPoP proof to the key committed at lease issuance.
    //
    // SECURITY: constant-time comparison. The values are not secret in this
    // protocol, but timing-leak resistance on digest-equality is policy and
    // costs nothing.
    let thumbprint = compute_jwk_thumbprint(x_b64, y_b64).map_err(|e| {
        DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadKey,
            format!("JWK thumbprint computation failed: {e}"),
        )
    })?;
    if !constant_time_eq(thumbprint.as_bytes(), cnf_jkt.as_bytes()) {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadKey,
            "DPoP key thumbprint does not match lease cnf.jkt (key binding failure)",
        ));
    }

    Ok(vk)
}

fn b64url_decode(s: &str, label: &str, kind: DpopRejectKind) -> Result<Vec<u8>, DPoPVerifyError> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| {
        DPoPVerifyError::invalid_proof(kind, format!("invalid base64url encoding in JWT {label}"))
    })
}

/// Reconstruct a P-256 verifying key from raw x/y coordinate bytes.
///
/// Uses SEC1 uncompressed point encoding: 0x04 || x (32 bytes) || y (32 bytes).
fn build_sec1_uncompressed(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    sec1
}

fn verify_sig(
    sec1_public_key: &[u8],
    header_b64: &str,
    payload_b64: &str,
    sig_bytes: &[u8],
) -> Result<(), DPoPVerifyError> {
    let signing_input = format!("{header_b64}.{payload_b64}");
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, sec1_public_key);
    public_key
        .verify(signing_input.as_bytes(), sig_bytes)
        .map_err(|_| {
            DPoPVerifyError::invalid_proof(DpopRejectKind::BadSig, "signature verification failed")
        })
}

/// Validate that `iat` falls within `[now - max_age, now + skew]`.
///
/// SECURITY: tight window limits token reuse even if jti replay detection
/// is temporarily unavailable. Proofs outside the window are always denied.
fn validate_iat_window(iat: i64, now: u64) -> Result<(), DPoPVerifyError> {
    let now_i = now as i64;
    let max_age = IAT_MAX_AGE_SECS as i64;
    let skew = IAT_CLOCK_SKEW_SECS as i64;

    if iat < now_i - max_age {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadIat,
            format!("iat too old: {iat} (now={now_i}, max_age={max_age}s)"),
        ));
    }
    if iat > now_i + skew {
        return Err(DPoPVerifyError::invalid_proof(
            DpopRejectKind::BadIat,
            format!("iat too far in future: {iat} (now={now_i}, allowed_skew={skew}s)"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpop::key_cache::DPoPKeyCache;
    use crate::dpop::{
        compute_ath, compute_jwk_thumbprint, generate_dpop_keypair, normalize_htu, sign_dpop_proof,
        sign_jwt_es256, unix_now, DPoPClaims,
    };

    const TEST_HTM: &str = "POST";
    const TEST_HTU: &str = "https://gate.example.com/v1/actions/http_fetch/execute";

    fn fake_lease() -> String {
        "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig".to_string()
    }

    fn test_cache() -> DPoPKeyCache {
        DPoPKeyCache::with_capacity(16)
    }

    fn make_proof(htm: &str, htu: &str, jti: &str, lease: &str) -> (String, String) {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let ath = compute_ath(lease);
        let proof = sign_dpop_proof(&sk, htm, htu, &ath, jti).unwrap();
        (cnf_jkt, proof)
    }

    #[test]
    fn valid_proof_round_trip() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-001", &lease);
        let claims =
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache).unwrap();
        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.jti, "jti-001");
        assert_eq!(claims.ath, compute_ath(&lease));
    }

    #[test]
    fn htm_case_insensitive_in_request() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof("post", TEST_HTU, "jti-002", &lease);
        verify_dpop_proof(&proof, "post", TEST_HTU, &lease, &cnf_jkt, &cache).unwrap();
    }

    #[test]
    fn wrong_method_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof("POST", TEST_HTU, "jti-010", &lease);
        assert!(matches!(
            verify_dpop_proof(&proof, "GET", TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadHtm,
                ..
            })
        ));
    }

    #[test]
    fn wrong_url_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-011", &lease);
        let wrong_htu = "https://gate.example.com/v1/actions/other_action/execute";
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, wrong_htu, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadHtu,
                ..
            })
        ));
    }

    #[test]
    fn expired_iat_is_denied() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);
        let old_iat = (unix_now().unwrap() as i64) - (IAT_MAX_AGE_SECS as i64) - 10;

        let header = serde_json::json!({
            "typ": "dpop+jwt", "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y }
        });
        let payload = DPoPClaims {
            jti: "jti-expired".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: old_iat,
            ath,
        };
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadIat,
                ..
            })
        ));
    }

    #[test]
    fn future_iat_beyond_skew_is_denied() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);
        let future_iat = (unix_now().unwrap() as i64) + (IAT_CLOCK_SKEW_SECS as i64) + 60;

        let header = serde_json::json!({
            "typ": "dpop+jwt", "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y }
        });
        let payload = DPoPClaims {
            jti: "jti-future".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: future_iat,
            ath,
        };
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadIat,
                ..
            })
        ));
    }

    #[test]
    fn wrong_key_binding_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let (_, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-020", &lease);
        let (_, other_pk) = generate_dpop_keypair().unwrap();
        let wrong_jkt = compute_jwk_thumbprint(&other_pk.x, &other_pk.y).unwrap();
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &wrong_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadKey,
                ..
            })
        ));
    }

    #[test]
    fn wrong_ath_is_denied() {
        let real_lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-030", &real_lease);
        let different_lease = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJvdGhlciJ9.sig2";
        assert!(matches!(
            verify_dpop_proof(
                &proof,
                TEST_HTM,
                TEST_HTU,
                different_lease,
                &cnf_jkt,
                &cache
            ),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadAth,
                ..
            })
        ));
    }

    #[test]
    fn tampered_header_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-040", &lease);
        let mut parts: Vec<String> = proof.splitn(3, '.').map(String::from).collect();
        parts[0].push('X');
        let tampered = parts.join(".");
        assert!(matches!(
            verify_dpop_proof(&tampered, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof { .. })
        ));
    }

    #[test]
    fn tampered_payload_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-041", &lease);
        let mut parts: Vec<String> = proof.splitn(3, '.').map(String::from).collect();
        parts[1].push('X');
        let tampered = parts.join(".");
        assert!(matches!(
            verify_dpop_proof(&tampered, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof { .. })
        ));
    }

    #[test]
    fn wrong_key_signature_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);
        let (sk_a, pk_a) = generate_dpop_keypair().unwrap();
        let (_, pk_b) = generate_dpop_keypair().unwrap();

        let header_b = serde_json::json!({
            "typ": "dpop+jwt", "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": pk_b.x, "y": pk_b.y }
        });
        let payload = DPoPClaims {
            jti: "jti-042".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: unix_now().unwrap() as i64,
            ath,
        };
        let proof = sign_jwt_es256(&sk_a, &header_b, &payload).unwrap();
        // The embedded JWK (pk_b) does not match cnf_jkt_a. In the cache-miss
        // path, the thumbprint binding check in `extract_bound_key` catches this
        // before signature verification — producing BadKey, not BadSig.
        let cnf_jkt_a = compute_jwk_thumbprint(&pk_a.x, &pk_a.y).unwrap();
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt_a, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadKey,
                ..
            })
        ));
    }

    #[test]
    fn invalid_ec_point_is_denied() {
        let (sk, _pk) = generate_dpop_keypair().unwrap();

        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);

        // Intentionally invalid coordinates: not a valid P-256 point.
        let bad_x = Base64UrlUnpadded::encode_string(&[0u8; 32]);
        let bad_y = Base64UrlUnpadded::encode_string(&[0u8; 32]);

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": bad_x,
                "y": bad_y
            }
        });

        let payload = DPoPClaims {
            jti: "jti-invalid-point".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: unix_now().unwrap() as i64,
            ath,
        };

        // Sign with a real key, but advertise an invalid public key.
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();

        assert!(matches!(
            verify_dpop_proof(
                &proof,
                TEST_HTM,
                TEST_HTU,
                &lease,
                "dummy-thumbprint",
                &cache,
            ),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadSig,
                ..
            }) | Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadKey,
                ..
            })
        ));
    }

    #[test]
    fn missing_jwk_header_is_denied() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256" });
        let payload = DPoPClaims {
            jti: "jti-050".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: unix_now().unwrap() as i64,
            ath,
        };
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadHeader,
                ..
            })
        ));
    }

    #[test]
    fn wrong_typ_is_denied() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let header = serde_json::json!({
            "typ": "JWT", "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y }
        });
        let payload = DPoPClaims {
            jti: "jti-051".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: unix_now().unwrap() as i64,
            ath,
        };
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();
        assert!(matches!(
            verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadHeader,
                ..
            })
        ));
    }

    #[test]
    fn two_part_token_is_denied() {
        let lease = fake_lease();
        let cache = test_cache();
        let (cnf_jkt, _) = make_proof(TEST_HTM, TEST_HTU, "jti-053", &lease);
        assert!(matches!(
            verify_dpop_proof("only.two", TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::Malformed,
                ..
            })
        ));
    }

    #[test]
    fn cache_hit_reuses_key_across_proofs() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);

        // First proof: cache miss — populates the cache.
        let proof1 = sign_dpop_proof(&sk, TEST_HTM, TEST_HTU, &ath, "jti-cache-1").unwrap();
        let claims1 =
            verify_dpop_proof(&proof1, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache).unwrap();
        assert_eq!(cache.len(), 1, "cache miss must insert an entry");

        // Second proof (same key, different jti): cache hit — no new entry.
        let proof2 = sign_dpop_proof(&sk, TEST_HTM, TEST_HTU, &ath, "jti-cache-2").unwrap();
        let claims2 =
            verify_dpop_proof(&proof2, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache).unwrap();
        assert_eq!(cache.len(), 1, "cache hit must not grow the cache");

        assert_eq!(claims1.htm, claims2.htm);
        assert_eq!(claims1.ath, claims2.ath);
        assert_ne!(
            claims1.jti, claims2.jti,
            "proofs must have distinct jti values"
        );
    }

    #[test]
    fn failed_binding_does_not_populate_cache() {
        let lease = fake_lease();
        let cache = test_cache();
        let (_, proof) = make_proof(TEST_HTM, TEST_HTU, "jti-no-cache", &lease);
        let (_, other_pk) = generate_dpop_keypair().unwrap();
        let wrong_jkt = compute_jwk_thumbprint(&other_pk.x, &other_pk.y).unwrap();

        // Verification fails (thumbprint mismatch) — cache must stay empty.
        assert!(verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &wrong_jkt, &cache).is_err());
        assert!(
            cache.is_empty(),
            "failed key binding must not populate the cache"
        );
    }

    /// SECURITY: a stolen Lease JWT (which reveals `cnf.jkt`) must not
    /// grant access without the corresponding DPoP private key. This test
    /// verifies the cache-hit path: the legitimate key is cached, then an
    /// attacker presents a proof signed with a different key. The cached
    /// key must cause signature verification to fail, and the cache entry
    /// must survive so the legitimate client is not disrupted.
    #[test]
    fn cache_hit_wrong_signature_is_denied_and_cache_survives() {
        let (sk_legit, pk_legit) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk_legit.x, &pk_legit.y).unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);

        // Legitimate client populates the cache.
        let legit_proof =
            sign_dpop_proof(&sk_legit, TEST_HTM, TEST_HTU, &ath, "jti-legit").unwrap();
        verify_dpop_proof(&legit_proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache).unwrap();
        assert_eq!(cache.len(), 1);

        // Attacker signs a proof with a different key but presents the
        // same cnf_jkt (stolen from the Lease). The cache-hit path must
        // use the cached (legitimate) key and reject the signature.
        let (sk_attacker, _) = generate_dpop_keypair().unwrap();
        let attacker_proof =
            sign_dpop_proof(&sk_attacker, TEST_HTM, TEST_HTU, &ath, "jti-attack").unwrap();
        assert!(matches!(
            verify_dpop_proof(
                &attacker_proof,
                TEST_HTM,
                TEST_HTU,
                &lease,
                &cnf_jkt,
                &cache
            ),
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadSig,
                ..
            })
        ));

        // Cache must survive the failed attempt — the legitimate client
        // must not be disrupted.
        assert_eq!(cache.len(), 1, "failed verify must not evict cache entry");

        // Legitimate client can still authenticate.
        let legit_proof2 =
            sign_dpop_proof(&sk_legit, TEST_HTM, TEST_HTU, &ath, "jti-legit-2").unwrap();
        verify_dpop_proof(&legit_proof2, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache).unwrap();
    }

    /// SECURITY: on cache miss, if `extract_bound_key` succeeds (valid
    /// header, thumbprint matches `cnf_jkt`) but signature verification
    /// fails, the key must NOT be inserted into the cache. This prevents
    /// a DoS vector where an attacker floods proofs with valid headers
    /// but invalid signatures to pollute the cache.
    #[test]
    fn failed_sig_on_cache_miss_does_not_populate_cache() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);

        // Sign a valid proof, then corrupt the payload segment so the
        // header (and thus extract_bound_key) succeeds but signature
        // verification fails.
        let proof = sign_dpop_proof(&sk, TEST_HTM, TEST_HTU, &ath, "jti-sigfail").unwrap();
        let mut parts: Vec<String> = proof.splitn(3, '.').map(String::from).collect();
        parts[1].push('X'); // corrupt payload → sig mismatch
        let tampered = parts.join(".");

        assert!(
            verify_dpop_proof(&tampered, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache).is_err()
        );
        assert!(
            cache.is_empty(),
            "failed signature verification must not populate the cache"
        );
    }

    /// SECURITY regression: attacker-controlled header and payload fields
    /// (`typ`, `alg`, `kty`, `crv`, `htm`, `htu`) end up inside
    /// `DPoPVerifyError::reason`, which propagates to structured logs, audit
    /// events, and HTTP response bodies. Raw control bytes in those sinks
    /// enable log-line injection, CR-based log splitting, ANSI terminal
    /// escape attacks, and NUL-truncation of downstream parsers. Every
    /// construction of `DPoPVerifyError::InvalidProof` MUST route through
    /// [`DPoPVerifyError::invalid_proof`], which scrubs the reason via
    /// `latchgate_core::sanitize_for_log` and caps it at `REASON_MAX_BYTES`.
    ///
    /// This regression drives two disjoint failure paths — a header field
    /// (`typ`) rejected before signature verification, and a payload field
    /// (`htm`) rejected only after the full header, signature, and key
    /// binding have passed — and asserts that neither surfaces raw control
    /// bytes, neither exceeds the byte cap, and neither is emptied by
    /// over-aggressive stripping.
    #[test]
    fn invalid_proof_reason_strips_control_characters() {
        // Mixed attacker payload: every class of byte the sanitizer must
        // neutralise (NUL, TAB, LF, CR, ESC + ANSI SGR, DEL, a C1 control)
        // alongside a printable multibyte codepoint that MUST survive.
        const INJECTION: &str = "x\n\r\t\u{1b}[31mINJECT\u{1b}[0m\u{00}\u{7f}\u{85}ż";

        fn assert_reason_is_safe(reason: &str) {
            for ch in reason.chars() {
                assert!(
                    !matches!(ch, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}'),
                    "sanitized reason still contains control char {ch:?} in {reason:?}"
                );
            }
            assert!(
                reason.len() <= DPoPVerifyError::REASON_MAX_BYTES,
                "sanitized reason exceeds REASON_MAX_BYTES ({}): len={}, reason={reason:?}",
                DPoPVerifyError::REASON_MAX_BYTES,
                reason.len(),
            );
            // Defence against over-aggressive stripping: the diagnostic text
            // around the injection must still reach the sink, otherwise an
            // attacker could blind operators by submitting an all-control
            // payload.
            assert!(
                !reason.is_empty(),
                "sanitized reason is empty — stripping removed all context"
            );
        }

        let (sk, pk) = generate_dpop_keypair().unwrap();
        let cnf_jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let lease = fake_lease();
        let cache = test_cache();
        let ath = compute_ath(&lease);

        // --- Path A: header field (`typ`). Rejected at the first header
        //             validation step, before signature and key binding. ---
        let header = serde_json::json!({
            "typ": format!("dpop+jwt{INJECTION}"),
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y },
        });
        let payload = DPoPClaims {
            jti: "jti-injection-typ".into(),
            htm: "POST".into(),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: unix_now().unwrap() as i64,
            ath: ath.clone(),
        };
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();
        match verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache) {
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadHeader,
                reason,
            }) => assert_reason_is_safe(&reason),
            other => panic!("expected BadHeader for typ injection, got {other:?}"),
        }

        // --- Path B: payload field (`htm`). Rejected only after `typ`,
        //             `alg`, `jwk`, signature, key binding, and payload
        //             parse have all succeeded — a very different code
        //             path through the verifier. ---
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y },
        });
        let payload = DPoPClaims {
            jti: "jti-injection-htm".into(),
            htm: format!("POST{INJECTION}"),
            htu: normalize_htu(TEST_HTU).unwrap(),
            iat: unix_now().unwrap() as i64,
            ath,
        };
        let proof = sign_jwt_es256(&sk, &header, &payload).unwrap();
        match verify_dpop_proof(&proof, TEST_HTM, TEST_HTU, &lease, &cnf_jkt, &cache) {
            Err(DPoPVerifyError::InvalidProof {
                kind: DpopRejectKind::BadHtm,
                reason,
            }) => assert_reason_is_safe(&reason),
            other => panic!("expected BadHtm for htm injection, got {other:?}"),
        }
    }

    /// SECURITY regression: every DpopRejectKind variant must map to a known,
    /// static label string. This test ensures no variant silently falls through
    /// to a dynamic value that could introduce unbounded Prometheus cardinality.
    #[test]
    fn all_reject_kinds_have_static_metric_labels() {
        let known_labels = [
            "malformed",
            "bad_header",
            "bad_key",
            "bad_sig",
            "bad_htm",
            "bad_htu",
            "bad_iat",
            "bad_ath",
        ];
        let variants = [
            DpopRejectKind::Malformed,
            DpopRejectKind::BadHeader,
            DpopRejectKind::BadKey,
            DpopRejectKind::BadSig,
            DpopRejectKind::BadHtm,
            DpopRejectKind::BadHtu,
            DpopRejectKind::BadIat,
            DpopRejectKind::BadAth,
        ];
        for v in variants {
            let label = v.as_metric_label();
            assert!(
                known_labels.contains(&label),
                "DpopRejectKind variant produced unexpected label {label:?} — \
                 add it to known_labels or this is a cardinality regression"
            );
        }
    }
}
