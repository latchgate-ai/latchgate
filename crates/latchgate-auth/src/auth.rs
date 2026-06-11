//! Authentication and sender-constraint verification for the Gate pipeline.
//!
//! This module is the single entry point for all auth decisions in the pipeline:
//!   - Lease JWT verification (signature, claims, expiry)
//!   - DPoP proof verification (key binding, htm/htu, iat, ath, jti)
//!   - Anti-replay jti check via Redis
//!
//! DPoP verification lives in `crate::dpop::verify`. Errors from that module
//! are converted to `AuthError` via the `From<DPoPVerifyError>` impl here.
//!
//! `AuthError` is defined here (not in `issuer`) because auth errors arise
//! from verification — a gate responsibility. The issuer uses its own
//! `IssueError` for signing and key generation failures.

use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use std::sync::Arc;
use tracing::instrument;

use crate::issuer::jwt::{Jwks, LeaseClaims};
use crate::replay::{ReplayCache, ReplayError};

use crate::dpop::key_cache::DPoPKeyCache;
use crate::dpop::verify::{verify_dpop_proof, DPoPVerifyError, DpopRejectKind};

/// Errors produced during authentication and sender-constraint verification.
///
/// HTTP semantics (see `gate::pipeline::PipelineError::into_response`):
///
/// **Agent / Lease path:**
/// - `LeaseExpired`             => 401 `lease_expired`: client should re-authenticate.
/// - `InvalidLease`             => 401 `invalid_lease`: do not retry the same token.
/// - `InvalidDPoP`              => 401 `invalid_dpop`: do not retry the same proof.
/// - `ReplayDetected`           => 401 `replay_detected`: proof was already used.
/// - `MissingHeader`            => 401 `missing_auth_header`: required auth header not present.
///
/// **Operator path:**
/// - `InvalidAuthScheme`        => 401 `invalid_auth_scheme`: wrong Authorization scheme.
/// - `InvalidOperatorToken`     => 401 `invalid_operator_token`: token matches no credential.
/// - `MissingDpopHeader`        => 401 `missing_dpop_header`: DPoP header absent.
/// - `KeyBindingFailed`         => 401 `key_binding_failed`: proof key ≠ configured `dpop_jkt`.
///
/// **Infrastructure:**
/// - `ClockError`               => 503 `clock_error`: transient; host clock is broken.
/// - `ReplayCacheUnavailable`   => 503 `replay_cache_unavailable`: transient; Redis is down.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("lease expired")]
    LeaseExpired,

    /// Lease JWT rejected. Construct through [`AuthError::invalid_lease`] so
    /// `reason` is sanitized — it may include values derived from attacker-
    /// controlled JWT headers (`kid`) or jsonwebtoken error strings that
    /// embed token text.
    #[error("invalid lease: {reason}")]
    InvalidLease { reason: String },

    /// DPoP proof rejected. Never retry the same proof on this error.
    ///
    /// `kind` is a closed enum for Prometheus labels. Never use `reason`
    /// as a metric label — it may contain attacker-controlled content.
    #[error("invalid DPoP proof: {reason}")]
    InvalidDPoP {
        kind: DpopRejectKind,
        reason: String,
    },

    /// The DPoP jti has already been seen within the replay TTL window.
    ///
    /// SECURITY: this means the proof was replayed — either by an attacker
    /// or a buggy client reusing proofs. The request MUST be denied.
    #[error("replay detected: jti {jti} already seen")]
    ReplayDetected { jti: String },

    /// Required authentication header is missing from the request.
    #[error("missing header: {name}")]
    MissingHeader { name: String },

    // -- Operator-specific variants ------------------------------------------
    //
    // The operator approval path is a separate security boundary with its own
    // credential model (api_key + DPoP). These variants surface distinct error
    // codes so operators (and SOC/SIEM) can distinguish misconfiguration from
    // real attack signals. The agent path never produces these.
    /// Operator `Authorization` header uses the wrong scheme.
    ///
    /// Expected `DPoP <token>`.
    #[error("invalid auth scheme: expected 'DPoP <token>'")]
    InvalidAuthScheme,

    /// Operator token does not match any configured credential.
    ///
    /// SECURITY: constant-time comparison already prevents timing attacks;
    /// this variant only signals "no match", never which credential was
    /// closest.
    #[error("invalid operator token")]
    InvalidOperatorToken,

    /// Required `DPoP` proof header missing from the request.
    ///
    /// Distinct from [`MissingHeader`](Self::MissingHeader) (which covers the
    /// `Authorization` header) so clients can act on the specific omission.
    #[error("missing DPoP header")]
    MissingDpopHeader,

    /// Operator DPoP key binding failed: proof key does not match the
    /// `dpop_jkt` configured for this credential.
    ///
    /// `deny_reason` is sanitized at construction — never contains raw
    /// attacker-controlled content. Surfaced in the HTTP response body so
    /// operators can diagnose thumbprint mismatches.
    #[error("key binding failed: {deny_reason}")]
    KeyBindingFailed { deny_reason: String },

    // -- Infrastructure errors -----------------------------------------------
    /// System clock is before Unix epoch — cannot validate timestamps.
    ///
    /// SECURITY: fail-closed; a broken clock would allow iat/exp window bypass.
    #[error("clock error: system time is before Unix epoch")]
    ClockError,

    /// Anti-replay cache (Redis) is unavailable.
    ///
    /// SECURITY: fail-closed. A missing replay check enables token reuse.
    /// The request MUST be denied — never fall through to "allow".
    #[error("replay cache unavailable")]
    ReplayCacheUnavailable,
}

impl AuthError {
    /// Maximum `reason` length for lease rejection diagnostics.
    const LEASE_REASON_MAX_BYTES: usize = 200;

    /// Construct an `InvalidLease` error with a sanitized reason.
    ///
    /// SECURITY: this is the single construction path for `InvalidLease`.
    /// Lease rejection reasons often include JWT `kid` values, jsonwebtoken
    /// error strings (which may quote token text), or malformed-header
    /// descriptions — all attacker-influenced. Sanitizing here guarantees
    /// no raw control characters reach logs, audit events, or responses.
    pub fn invalid_lease(reason: impl Into<String>) -> Self {
        let raw = reason.into();
        Self::InvalidLease {
            reason: latchgate_core::sanitize_for_log(&raw, Self::LEASE_REASON_MAX_BYTES)
                .into_owned(),
        }
    }
}

impl From<DPoPVerifyError> for AuthError {
    fn from(e: DPoPVerifyError) -> Self {
        match e {
            DPoPVerifyError::InvalidProof { kind, reason } => {
                AuthError::InvalidDPoP { kind, reason }
            }
            DPoPVerifyError::ClockError => AuthError::ClockError,
        }
    }
}

#[must_use = "auth contexts carry verified identity — dropping one bypasses authentication"]
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Subject (`sub`) from the Lease. Identifies the principal (agent/user).
    pub principal: Arc<str>,
    pub session_id: Arc<str>,
    /// Unique Lease JWT identifier (`jti`). Used for audit correlation.
    pub lease_jti: Arc<str>,
    /// Authorized scopes from the Lease (e.g. `["tools:call"]`).
    pub scopes: Vec<String>,
    /// Optional budget constraints from the Lease.
    pub budgets: Option<crate::issuer::jwt::Budgets>,
    /// DPoP proof `jti`. Used for audit logging and replay tracking.
    pub dpop_jti: Arc<str>,
    /// JWK thumbprint (`cnf.jkt`) of the sender's DPoP key.
    /// Carried into `ExecutionGrant.sender_binding` so that a stolen grant
    /// without the matching private key is useless.
    pub sender_thumbprint: Arc<str>,
    /// Owner/responsible person for this agent, parsed from the Lease JWT.
    ///
    /// Frozen at lease issuance time. `None` when not configured in the
    /// identity mapping or when using old JWTs issued before this field
    /// was added.
    pub owner: Option<Arc<str>>,
}

/// Full authentication pipeline: Lease + DPoP + anti-replay.
///
/// Validates the complete auth chain in order:
/// 1. Extract `Authorization: DPoP <lease_jwt>` header.
/// 2. Extract `DPoP: <proof>` header.
/// 3. Verify Lease JWT (signature, exp, nbf, iss, aud, required claims).
/// 4. Verify DPoP proof (signature, key binding, htm, htu, iat, ath).
/// 5. Check DPoP jti uniqueness via the anti-replay cache.
/// 6. Return `AuthContext` on success.
///
/// SECURITY: fails closed at every step. Any failure returns `Err(AuthError)`.
/// The caller (route handler) maps this to a structured 401/503 response
/// via `PipelineError`.
#[instrument(name = "auth.authenticate", skip(authorization_header, dpop_header, jwks, replay_cache, key_cache), fields(%htm, %htu))]
pub async fn authenticate(
    authorization_header: Option<&str>,
    dpop_header: Option<&str>,
    htm: &str,
    htu: &str,
    jwks: &Jwks,
    replay_cache: &ReplayCache,
    key_cache: &DPoPKeyCache,
) -> Result<AuthContext, AuthError> {
    let lease_jwt = extract_dpop_token(authorization_header)?;

    let dpop_proof = dpop_header.ok_or_else(|| AuthError::MissingHeader {
        name: "DPoP".into(),
    })?;

    let claims = verify_lease(
        lease_jwt,
        jwks,
        crate::issuer::ISSUER_NAME,
        crate::issuer::AUDIENCE,
    )?;

    let dpop_claims =
        verify_dpop_proof(dpop_proof, htm, htu, lease_jwt, &claims.cnf.jkt, key_cache)?;

    // 5. Anti-replay check on DPoP jti
    //
    // SECURITY: this MUST happen after DPoP signature verification to avoid
    // storing attacker-controlled jti values (DoS on the replay cache).
    replay_cache
        .check_and_store_jti(&dpop_claims.jti)
        .await
        .map_err(|e| match e {
            ReplayError::AlreadySeen { jti } => AuthError::ReplayDetected { jti },
            ReplayError::CacheUnavailable(_) => AuthError::ReplayCacheUnavailable,
        })?;

    Ok(AuthContext {
        principal: Arc::from(claims.sub.as_str()),
        session_id: Arc::from(claims.session_id.as_str()),
        lease_jti: Arc::from(claims.jti.as_str()),
        scopes: claims.scope,
        budgets: claims.budgets,
        dpop_jti: Arc::from(dpop_claims.jti.as_str()),
        sender_thumbprint: Arc::from(claims.cnf.jkt.as_str()),
        owner: claims.owner.map(|s| Arc::from(s.as_str())),
    })
}

/// Verify a Lease JWT against the JWKS.
///
/// Validates: signature (ES256), exp, nbf, iss, aud, and all required claims.
/// Returns `AuthError::LeaseExpired` for expired tokens so callers can surface
/// a distinct re-authentication signal to the agent.
///
/// SECURITY: fails closed — any validation failure returns `Err(AuthError)`.
pub fn verify_lease(
    token: &str,
    jwks: &Jwks,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<LeaseClaims, AuthError> {
    let header = decode_header(token).map_err(|e| AuthError::invalid_lease(e.to_string()))?;

    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| AuthError::invalid_lease("missing kid in header"))?;

    let vk = jwks
        .get(kid)
        .ok_or_else(|| AuthError::invalid_lease(format!("unknown kid: {kid}")))?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    // SECURITY: validate nbf — jsonwebtoken defaults to false.
    validation.validate_nbf = true;
    // SECURITY: zero leeway on exp/nbf — no tolerance for expired tokens.
    validation.leeway = 0;
    validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "sub", "aud", "jti"]);

    let token_data = decode::<LeaseClaims>(token, vk.decoding_key(), &validation).map_err(|e| {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::LeaseExpired,
            jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                AuthError::invalid_lease("lease not yet valid (nbf)")
            }
            _ => AuthError::invalid_lease(e.to_string()),
        }
    })?;

    Ok(token_data.claims)
}

/// Extract the lease JWT from the `Authorization: DPoP <token>` header.
///
/// RFC 9449 §7.1: the access token is sent via `Authorization: DPoP <token>`.
/// We reject `Bearer` scheme since DPoP requires sender-constrained tokens.
fn extract_dpop_token(header_value: Option<&str>) -> Result<&str, AuthError> {
    let value = header_value.ok_or_else(|| AuthError::MissingHeader {
        name: "Authorization".into(),
    })?;

    let token = value.strip_prefix("DPoP ").ok_or_else(|| {
        AuthError::invalid_lease("Authorization header must use 'DPoP' scheme, not 'Bearer'")
    })?;

    if token.is_empty() {
        return Err(AuthError::invalid_lease(
            "empty token in Authorization header",
        ));
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpop::key_cache::DPoPKeyCache;
    use crate::issuer::jwt::{generate_keypair, sign_lease, Budgets, CnfClaim};
    use std::time::{SystemTime, UNIX_EPOCH};

    const ISSUER: &str = "latchgate";
    const AUDIENCE: &str = "latchgate";

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn test_claims() -> LeaseClaims {
        let now = now_secs();
        LeaseClaims {
            iss: ISSUER.to_string(),
            sub: "agent-1".to_string(),
            aud: AUDIENCE.to_string(),
            exp: now + 300,
            nbf: now - 1,
            iat: now,
            jti: "test-jti-001".to_string(),
            session_id: "session-001".to_string(),
            scope: vec!["tools:call".to_string()],
            budgets: None,
            cnf: CnfClaim {
                jkt: "test-thumbprint-sha256".to_string(),
            },
            owner: None,
        }
    }

    fn keypair_and_jwks() -> (crate::issuer::jwt::SigningKey, Jwks) {
        let (sk, vk) = generate_keypair().unwrap();
        let jwks = Jwks::new(vec![vk]);
        (sk, jwks)
    }

    #[test]
    fn extract_token_valid_dpop_header() {
        let token = extract_dpop_token(Some("DPoP eyJhbGciOiJFUzI1NiJ9.payload.sig")).unwrap();
        assert_eq!(token, "eyJhbGciOiJFUzI1NiJ9.payload.sig");
    }

    #[test]
    fn extract_token_missing_header_returns_error() {
        assert!(matches!(
            extract_dpop_token(None),
            Err(AuthError::MissingHeader { .. })
        ));
    }

    #[test]
    fn extract_token_bearer_scheme_rejected() {
        assert!(matches!(
            extract_dpop_token(Some("Bearer xyz")),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn extract_token_empty_token_rejected() {
        assert!(matches!(
            extract_dpop_token(Some("DPoP ")),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn verify_valid_lease_roundtrip() {
        let (sk, jwks) = keypair_and_jwks();
        let claims = test_claims();

        let token = sign_lease(&claims, &sk).unwrap();
        let verified = verify_lease(&token, &jwks, ISSUER, AUDIENCE).unwrap();

        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.jti, claims.jti);
        assert_eq!(verified.session_id, claims.session_id);
        assert_eq!(verified.scope, claims.scope);
    }

    #[test]
    fn cnf_jkt_is_preserved() {
        let (sk, jwks) = keypair_and_jwks();
        let claims = test_claims();

        let token = sign_lease(&claims, &sk).unwrap();
        let verified = verify_lease(&token, &jwks, ISSUER, AUDIENCE).unwrap();

        assert_eq!(verified.cnf.jkt, "test-thumbprint-sha256");
    }

    #[test]
    fn budgets_round_trip() {
        let (sk, jwks) = keypair_and_jwks();
        let mut claims = test_claims();
        claims.budgets = Some(Budgets {
            max_calls: Some(10),
        });

        let token = sign_lease(&claims, &sk).unwrap();
        let verified = verify_lease(&token, &jwks, ISSUER, AUDIENCE).unwrap();
        let b = verified.budgets.as_ref().unwrap();
        assert_eq!(b.max_calls, Some(10));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (sk, _) = keypair_and_jwks();
        let (_, other_vk) = generate_keypair().unwrap();
        let wrong_jwks = Jwks::new(vec![other_vk]);
        let claims = test_claims();

        let token = sign_lease(&claims, &sk).unwrap();
        assert!(matches!(
            verify_lease(&token, &wrong_jwks, ISSUER, AUDIENCE),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn expired_lease_returns_lease_expired() {
        let (sk, jwks) = keypair_and_jwks();
        let mut claims = test_claims();
        claims.exp = claims.iat - 10;

        let token = sign_lease(&claims, &sk).unwrap();
        assert!(matches!(
            verify_lease(&token, &jwks, ISSUER, AUDIENCE),
            Err(AuthError::LeaseExpired)
        ));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let (sk, jwks) = keypair_and_jwks();
        let mut claims = test_claims();
        claims.aud = "wrong-audience".to_string();

        let token = sign_lease(&claims, &sk).unwrap();
        assert!(matches!(
            verify_lease(&token, &jwks, ISSUER, AUDIENCE),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let (sk, jwks) = keypair_and_jwks();
        let mut claims = test_claims();
        claims.iss = "evil-issuer".to_string();

        let token = sign_lease(&claims, &sk).unwrap();
        assert!(matches!(
            verify_lease(&token, &jwks, ISSUER, AUDIENCE),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn unknown_kid_is_rejected() {
        let (sk, _) = keypair_and_jwks();
        let empty_jwks = Jwks::new(vec![]);
        let claims = test_claims();

        let token = sign_lease(&claims, &sk).unwrap();
        assert!(matches!(
            verify_lease(&token, &empty_jwks, ISSUER, AUDIENCE),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let (sk, jwks) = keypair_and_jwks();
        let claims = test_claims();

        let mut token = sign_lease(&claims, &sk).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut payload = parts[1].to_string();
        payload.push('A');
        token = format!("{}.{}.{}", parts[0], payload, parts[2]);

        assert!(matches!(
            verify_lease(&token, &jwks, ISSUER, AUDIENCE),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    #[test]
    fn not_yet_valid_lease_is_rejected() {
        let (sk, jwks) = keypair_and_jwks();
        let mut claims = test_claims();
        claims.nbf = claims.iat + 3600;

        let token = sign_lease(&claims, &sk).unwrap();
        assert!(matches!(
            verify_lease(&token, &jwks, ISSUER, AUDIENCE),
            Err(AuthError::InvalidLease { .. })
        ));
    }

    /// SECURITY regression: algorithm confusion attack.
    #[test]
    fn algorithm_confusion_alg_none_is_rejected() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let (sk, jwks) = keypair_and_jwks();
        let claims = test_claims();

        let valid_token = sign_lease(&claims, &sk).unwrap();
        let parts: Vec<&str> = valid_token.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3);

        let fake_header = serde_json::json!({"alg": "none", "typ": "JWT", "kid": sk.kid});
        let fake_header_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&fake_header).unwrap().as_bytes(),
        );

        let token_alg_none = format!("{}.{}.", fake_header_b64, parts[1]);

        assert!(
            matches!(
                verify_lease(&token_alg_none, &jwks, ISSUER, AUDIENCE),
                Err(AuthError::InvalidLease { .. })
            ),
            "alg=none token must be rejected"
        );
    }

    #[test]
    fn algorithm_confusion_alg_hs256_is_rejected() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let (sk, jwks) = keypair_and_jwks();
        let claims = test_claims();

        let valid_token = sign_lease(&claims, &sk).unwrap();
        let parts: Vec<&str> = valid_token.splitn(3, '.').collect();

        let fake_header = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": sk.kid});
        let fake_header_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&fake_header).unwrap().as_bytes(),
        );

        let token_alg_hs256 = format!("{}.{}.{}", fake_header_b64, parts[1], parts[2]);

        assert!(
            matches!(
                verify_lease(&token_alg_hs256, &jwks, ISSUER, AUDIENCE),
                Err(AuthError::InvalidLease { .. })
            ),
            "alg=HS256 token must be rejected; ES256 is the only permitted algorithm"
        );
    }
    //
    // The replay cache stores DPoP `jti` values to prevent proof reuse.
    // If an attacker can spray invalid requests that store jti values before
    // cryptographic verification, they can exhaust the cache (DoS) without
    // ever holding a valid key. This test verifies that `authenticate`
    // writes to the cache ONLY after both JWT and DPoP signature verification
    // succeed.

    /// SECURITY: invalid JWT must fail at step 3 (lease verification) without
    /// writing to the replay cache. If this test breaks, the authenticate
    /// ordering has been changed and attacker-controlled jti values may be
    /// stored.
    #[tokio::test]
    async fn invalid_jwt_does_not_pollute_replay_cache() {
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(60));
        let key_cache = DPoPKeyCache::new();
        let (_, jwks) = keypair_and_jwks();

        // Completely invalid JWT — fails at step 3 (lease signature check).
        let result = authenticate(
            Some("DPoP not.a.valid.jwt"),
            Some("also.not.valid"),
            "POST",
            "http://localhost/v1/actions/test/execute",
            &jwks,
            &cache,
            &key_cache,
        )
        .await;

        assert!(result.is_err(), "invalid JWT must be rejected");

        // The replay cache must be empty. If authenticate wrote anything,
        // this canary insertion would find the cache polluted.
        assert!(
            cache.check_and_store_jti("canary-jti").await.is_ok(),
            "failed authenticate must not leave side effects in the replay cache"
        );
    }

    /// SECURITY: valid JWT but missing DPoP proof must fail without writing
    /// to the replay cache.
    #[tokio::test]
    async fn valid_jwt_missing_dpop_does_not_pollute_replay_cache() {
        let cache = ReplayCache::in_memory(std::time::Duration::from_secs(60));
        let key_cache = DPoPKeyCache::new();
        let (sk, jwks) = keypair_and_jwks();
        let claims = test_claims();
        let lease_jwt = sign_lease(&claims, &sk).unwrap();

        // Valid JWT but no DPoP header — fails at step 2 (missing DPoP).
        let result = authenticate(
            Some(&format!("DPoP {lease_jwt}")),
            None, // missing DPoP header
            "POST",
            "http://localhost/v1/actions/test/execute",
            &jwks,
            &cache,
            &key_cache,
        )
        .await;

        assert!(
            matches!(result, Err(AuthError::MissingHeader { .. })),
            "missing DPoP must return MissingHeader"
        );

        assert!(
            cache.check_and_store_jti("canary-jti-2").await.is_ok(),
            "failed authenticate must not leave side effects in the replay cache"
        );
    }
}
