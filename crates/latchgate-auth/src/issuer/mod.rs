//! Embedded Lease Issuer.
//!
//! The `Issuer` holds the signing key and issues Lease JWTs bound to a
//! client's DPoP key via `cnf.jkt` (RFC 9449). It also serves the
//! JWKS endpoint so consumers can verify issued leases.
//!
//! # Security properties
//!
//! - Keys are generated using OS CSPRNG (`rand::OsRng`) at startup.
//! - Lease TTL defaults to 300 s (see `Config::lease_ttl_seconds`).
//! - `cnf.jkt` is computed from the client-supplied DPoP JWK, binding the
//!   lease to the client's private key. Theft of the lease JWT alone is
//!   useless without the corresponding DPoP key.
//! - JTI is UUID v7 (time-ordered, unique) — used for anti-replay in Redis.
//! - Scopes are validated at issuance: built-in scopes are always accepted;
//!   custom scopes must pass `namespace:name` format validation
//!   (`[a-z0-9:_-]`, 4–64 chars). Clients cannot self-assert arbitrary scopes.

pub mod jwt;

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::dpop::compute_jwk_thumbprint;

pub use jwt::{Jwks, LeaseClaims, VerifyingKey};

/// Built-in scopes with well-known semantics that are always accepted.
///
/// Custom scopes are also accepted provided they pass
/// `is_valid_scope_format`.
pub const BUILTIN_SCOPES: &[&str] = &["tools:call", "audit:read"];

/// Return `true` if `scope` is acceptable for issuance.
///
/// Accepts built-in scopes unconditionally. Accepts custom scopes that pass
/// `namespace:name` format validation: `[a-z0-9:_-]` characters, 4–64 chars
/// total, not starting or ending with `:`.
fn is_valid_scope(scope: &str) -> bool {
    if BUILTIN_SCOPES.contains(&scope) {
        return true;
    }
    is_valid_scope_format(scope)
}

/// Validate a custom scope's format.
///
/// Rules: `namespace:name` pattern, `[a-z0-9:_-]` characters only, 4–64
/// characters total, first character `[a-z]`, no leading or trailing `:`.
///
/// Exposed for use in manifest validation.
pub fn is_valid_scope_format(scope: &str) -> bool {
    if scope.len() < 4 || scope.len() > 64 {
        return false;
    }
    if !scope.starts_with(|c: char| c.is_ascii_lowercase()) {
        return false;
    }
    if scope.ends_with(':') {
        return false;
    }
    if !scope.contains(':') {
        return false;
    }
    scope
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ':' || c == '_' || c == '-')
}

/// Embedded Lease Issuer. Holds the signing key and issues Lease JWTs.
///
/// Created once at startup; shared via `Arc<Issuer>` in `AppState`.
pub struct Issuer {
    signing_key: jwt::SigningKey,
    jwks: Jwks,
    jwks_response: JwksResponse,
    lease_ttl_seconds: u64,
}

impl Issuer {
    /// Create a new Issuer with a freshly generated ES256 keypair.
    pub fn new(lease_ttl_seconds: u64, _max_lease_ttl_seconds: u64) -> Result<Self, IssueError> {
        let sk = P256SigningKey::random(&mut rand::rngs::OsRng);

        let private_pem = sk
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| IssueError::KeyGeneration(e.to_string()))?;

        let pk = p256::PublicKey::from(sk.verifying_key());

        let public_pem = pk
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| IssueError::KeyGeneration(e.to_string()))?;

        // Extract x,y coordinates for JWKS JSON response.
        let point = p256::ecdsa::VerifyingKey::from(&sk).to_encoded_point(false);
        let x_bytes = point
            .x()
            .ok_or_else(|| IssueError::KeyGeneration("missing x coordinate".into()))?;
        let y_bytes = point
            .y()
            .ok_or_else(|| IssueError::KeyGeneration("missing y coordinate".into()))?;
        let x_b64 = Base64UrlUnpadded::encode_string(x_bytes);
        let y_b64 = Base64UrlUnpadded::encode_string(y_bytes);

        // kid = first 16 hex chars of SHA-256(SPKI DER).
        let kid = jwt::derive_kid(&pk).map_err(|e| IssueError::KeyGeneration(e.to_string()))?;

        let (encoding_key, decoding_key) = jwt::build_jwt_keys(&private_pem, &public_pem)
            .map_err(|e| IssueError::KeyGeneration(e.to_string()))?;

        let signing_key = jwt::SigningKey {
            kid: kid.clone(),
            inner: encoding_key,
        };
        let verifying_key = VerifyingKey::new(kid.clone(), decoding_key);

        let jwks_response = JwksResponse {
            keys: vec![JwkEntry {
                kty: "EC".into(),
                crv: "P-256".into(),
                kid,
                use_: "sig".into(),
                alg: "ES256".into(),
                x: x_b64,
                y: y_b64,
            }],
        };

        let jwks = Jwks::new(vec![verifying_key]);

        Ok(Self {
            signing_key,
            jwks,
            jwks_response,
            lease_ttl_seconds,
        })
    }

    /// Issue a Lease JWT bound to the client's DPoP key.
    ///
    /// The `session_id` is always a server-issued UUID v7 (opaque session handle).
    /// The `sub` claim is set to `verified_principal` when provided by the
    /// identity layer, otherwise falls back to `session_id`.
    ///
    /// # Parameters
    ///
    /// - `request`: client-supplied DPoP key, scopes, and budgets.
    /// - `verified_principal`: authenticated principal from the identity provider.
    ///   When `Some`, this becomes the `sub` claim in the Lease JWT. When `None`
    ///   (dev/test with NoneProvider), `sub` falls back to the server-issued
    ///   `session_id`.
    #[instrument(skip(self, request), fields(session_id = tracing::field::Empty))]
    pub fn issue_lease(
        &self,
        request: &IssueLeaseRequest,
        verified_principal: Option<&str>,
        owner: Option<&str>,
    ) -> Result<IssueLeaseResponse, IssueError> {
        // SECURITY: session_id is an opaque server-issued handle — the client
        // has no say in their session identity. Used for budget keying and
        // correlation. The principal (sub claim) comes from the identity layer.
        let session_id = uuid::Uuid::now_v7().to_string();
        tracing::Span::current().record("session_id", session_id.as_str());

        // sub = verified principal from identity layer, or session_id fallback.
        let sub = verified_principal
            .map(|p| p.to_string())
            .unwrap_or_else(|| session_id.clone());

        // Validate DPoP key type and curve.
        if request.dpop_jwk.kty != "EC" {
            return Err(IssueError::InvalidRequest {
                reason: format!("dpop_jwk.kty must be 'EC', got '{}'", request.dpop_jwk.kty),
            });
        }
        if request.dpop_jwk.crv != "P-256" {
            return Err(IssueError::InvalidRequest {
                reason: format!(
                    "dpop_jwk.crv must be 'P-256', got '{}'",
                    request.dpop_jwk.crv
                ),
            });
        }

        if request.scopes.is_empty() {
            return Err(IssueError::InvalidRequest {
                reason: "scopes must not be empty".into(),
            });
        }

        // SECURITY: validate every requested scope.
        //
        // Built-in scopes (BUILTIN_SCOPES) are always accepted. Custom scopes
        // must pass format validation: `namespace:name` with `[a-z0-9:_-]`,
        // 4–64 characters, first char lowercase alpha, no leading/trailing `:`.
        //
        // This prevents clients from self-asserting arbitrary scope strings
        // that could confuse downstream enforcement in OPA or audit records.
        for scope in &request.scopes {
            if !is_valid_scope(scope) {
                return Err(IssueError::InvalidRequest {
                    reason: format!(
                        "invalid scope '{scope}': must be a known built-in scope \
                         ({BUILTIN_SCOPES:?}) or a custom scope in 'namespace:name' format \
                         with [a-z0-9:_-] characters (4–64 chars)"
                    ),
                });
            }
        }

        let jkt =
            compute_jwk_thumbprint(&request.dpop_jwk.x, &request.dpop_jwk.y).map_err(|e| {
                IssueError::InvalidRequest {
                    reason: format!("failed to compute JWK thumbprint: {e}"),
                }
            })?;

        let now = now_secs()?;
        let ttl = self
            .lease_ttl_seconds
            .min(latchgate_core::security_constants::MAX_LEASE_TTL_SECS);
        let exp = now + ttl;
        let jti = uuid::Uuid::now_v7().to_string();
        let jti_for_response = jti.clone();

        let claims = LeaseClaims {
            iss: ISSUER_NAME.to_string(),
            sub,
            aud: AUDIENCE.to_string(),
            exp,
            nbf: now,
            iat: now,
            jti,
            session_id: session_id.clone(),
            scope: request.scopes.clone(),
            budgets: request.budgets.clone(),
            cnf: jwt::CnfClaim { jkt },
            owner: owner.map(|s| s.to_string()),
        };

        let token = jwt::sign_lease(&claims, &self.signing_key)
            .map_err(|e| IssueError::Signing(e.to_string()))?;

        let expires_at = format_timestamp(exp);

        Ok(IssueLeaseResponse {
            lease_jwt: token,
            session_id,
            lease_jti: jti_for_response,
            expires_at,
            fs_root: None,
        })
    }

    /// Returns the JWKS for internal lease verification (used by `gate::auth`).
    pub fn jwks(&self) -> &Jwks {
        &self.jwks
    }

    /// Returns the JWKS JSON response for `GET /.well-known/jwks.json`.
    pub fn jwks_response(&self) -> &JwksResponse {
        &self.jwks_response
    }
}

pub const ISSUER_NAME: &str = "latchgate";

pub const AUDIENCE: &str = "latchgate";

#[derive(Debug, Clone, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwkEntry {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueLeaseRequest {
    pub scopes: Vec<String>,
    pub dpop_jwk: DpopJwk,
    /// Optional budget constraints for this lease. When present, the Gate
    /// will initialise stateful budget counters in Redis and enforce them
    /// atomically on every action call.
    #[serde(default)]
    pub budgets: Option<jwt::Budgets>,
    /// Per-session filesystem root requested by the client.
    ///
    /// When present, the API handler validates this path against
    /// `fs_root_allowed_prefixes` before storing it in the session map.
    /// The issuer passes it through without inspection — validation is
    /// not the issuer's responsibility.
    ///
    /// SECURITY: this field is an opaque string at the auth layer.
    /// It is NOT embedded in the JWT. It enters the session map
    /// keyed by the server-issued session_id, which IS in the JWT.
    #[serde(default)]
    pub fs_root: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DpopJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize)]
pub struct IssueLeaseResponse {
    pub lease_jwt: String,
    /// Server-issued opaque session identifier. This is the principal that
    /// will appear in policy decisions and audit records for this lease.
    /// Clients must not assume any particular format.
    pub session_id: String,
    /// Unique identifier for this lease (UUID v7). Recorded in audit events
    /// for forensic correlation between issuance and subsequent action calls.
    pub lease_jti: String,
    pub expires_at: String,
    /// Canonical filesystem root bound to this session, if accepted.
    /// Absent when no `fs_root` was requested or when the gate does not
    /// support per-session roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_root: Option<String>,
}

/// Errors from lease issuance.
///
/// HTTP semantics (mapped in the handler):
/// - `InvalidRequest` => 400 Bad Request
/// - `Signing`        => 500 Internal Server Error
/// - `KeyGeneration`  => 500 Internal Server Error
/// - `ClockError`     => 503 Service Unavailable
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("invalid request: {reason}")]
    InvalidRequest { reason: String },

    /// SECURITY: fail-closed — a broken clock could produce leases with
    /// arbitrary exp/iat, bypassing TTL enforcement.
    #[error("clock error: system time is before Unix epoch")]
    ClockError,
}

/// Current Unix timestamp in seconds. Fails closed on clock error.
fn now_secs() -> Result<u64, IssueError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| IssueError::ClockError)
}

/// Format a Unix timestamp as RFC 3339 UTC string.
///
/// Manual implementation avoids pulling in `chrono` for a single function.
fn format_timestamp(secs: u64) -> String {
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(secs / 86400);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_issuer() -> Issuer {
        Issuer::new(300, 3600).expect("issuer creation must succeed in tests")
    }

    fn test_dpop_jwk() -> DpopJwk {
        let (_, pk) = crate::dpop::generate_dpop_keypair().unwrap();
        DpopJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: pk.x,
            y: pk.y,
        }
    }

    fn test_request() -> IssueLeaseRequest {
        IssueLeaseRequest {
            scopes: vec!["tools:call".into()],
            dpop_jwk: test_dpop_jwk(),
            budgets: None,
            fs_root: None,
        }
    }

    // --- Issuer creation ---

    #[test]
    fn issuer_new_succeeds() {
        let issuer = test_issuer();
        assert!(!issuer.jwks_response().keys.is_empty());
    }

    #[test]
    fn jwks_response_has_correct_structure() {
        let issuer = test_issuer();
        let jwks = issuer.jwks_response();
        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "EC");
        assert_eq!(key.crv, "P-256");
        assert_eq!(key.alg, "ES256");
        assert_eq!(key.use_, "sig");
        assert_eq!(key.kid.len(), 16);
        assert!(!key.x.is_empty());
        assert!(!key.y.is_empty());
    }

    #[test]
    fn jwks_response_serializes_to_valid_json() {
        let issuer = test_issuer();
        let json = serde_json::to_value(issuer.jwks_response()).unwrap();
        assert!(json["keys"].is_array());
        assert_eq!(json["keys"][0]["kty"], "EC");
        // SECURITY: "use" field must be present (serde rename from use_).
        assert_eq!(json["keys"][0]["use"], "sig");
    }

    // --- Lease issuance ---

    #[test]
    fn issue_lease_returns_valid_jwt() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        assert_eq!(
            resp.lease_jwt.split('.').count(),
            3,
            "lease must be a 3-part JWT"
        );
        assert!(!resp.expires_at.is_empty());
    }

    #[test]
    fn issued_lease_verifiable_with_jwks() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();

        let claims =
            crate::auth::verify_lease(&resp.lease_jwt, issuer.jwks(), ISSUER_NAME, AUDIENCE)
                .expect("issued lease must verify against issuer's JWKS");

        assert_eq!(claims.iss, ISSUER_NAME);
        assert_eq!(claims.aud, AUDIENCE);
        assert_eq!(claims.scope, vec!["tools:call".to_string()]);
        assert!(!claims.session_id.is_empty());
        assert_eq!(claims.session_id, resp.session_id);
    }

    #[test]
    fn owner_claim_roundtrips_through_jwt() {
        let issuer = test_issuer();
        let resp = issuer
            .issue_lease(&test_request(), None, Some("alice@company.com"))
            .unwrap();
        let claims =
            crate::auth::verify_lease(&resp.lease_jwt, issuer.jwks(), ISSUER_NAME, AUDIENCE)
                .unwrap();
        assert_eq!(
            claims.owner.as_deref(),
            Some("alice@company.com"),
            "owner claim must survive JWT encode/decode roundtrip"
        );
    }

    #[test]
    fn owner_claim_absent_when_none() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        let claims =
            crate::auth::verify_lease(&resp.lease_jwt, issuer.jwks(), ISSUER_NAME, AUDIENCE)
                .unwrap();
        assert!(
            claims.owner.is_none(),
            "owner claim must be None when not provided"
        );
    }

    #[test]
    fn cnf_jkt_matches_dpop_jwk_thumbprint() {
        let issuer = test_issuer();
        let req = test_request();
        let expected_jkt = compute_jwk_thumbprint(&req.dpop_jwk.x, &req.dpop_jwk.y).unwrap();
        let resp = issuer.issue_lease(&req, None, None).unwrap();
        let claims =
            crate::auth::verify_lease(&resp.lease_jwt, issuer.jwks(), ISSUER_NAME, AUDIENCE)
                .unwrap();
        assert_eq!(
            claims.cnf.jkt, expected_jkt,
            "cnf.jkt must match the thumbprint of the provided DPoP JWK"
        );
    }

    #[test]
    fn each_lease_has_unique_jti() {
        let issuer = test_issuer();
        let req = test_request();
        let resp1 = issuer.issue_lease(&req, None, None).unwrap();
        let resp2 = issuer.issue_lease(&req, None, None).unwrap();
        let jti1 = extract_jti(&resp1.lease_jwt);
        let jti2 = extract_jti(&resp2.lease_jwt);
        assert_ne!(jti1, jti2, "each lease must have a unique jti");
    }

    #[test]
    fn lease_jti_in_response_matches_jwt_jti() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        let jwt_jti = extract_jti(&resp.lease_jwt);
        assert_eq!(
            resp.lease_jti, jwt_jti,
            "lease_jti in response must match the jti claim in the JWT"
        );
    }

    #[test]
    fn expires_at_is_rfc3339_utc() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        assert!(
            resp.expires_at.ends_with('Z'),
            "expires_at must end with Z (UTC)"
        );
        assert!(
            resp.expires_at.contains('T'),
            "expires_at must contain T separator"
        );
    }

    #[test]
    fn lease_ttl_clamped_to_max() {
        let issuer = Issuer::new(7200, 3600).unwrap();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        let claims =
            crate::auth::verify_lease(&resp.lease_jwt, issuer.jwks(), ISSUER_NAME, AUDIENCE)
                .unwrap();
        let ttl = claims.exp - claims.iat;
        assert_eq!(ttl, 3600, "TTL must be clamped to max_lease_ttl_seconds");
    }

    // --- Negative cases: DPoP key validation ---

    #[test]
    fn rejects_non_ec_key_type() {
        let issuer = test_issuer();
        let mut req = test_request();
        req.dpop_jwk.kty = "RSA".into();
        assert!(matches!(
            issuer.issue_lease(&req, None, None),
            Err(IssueError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn rejects_non_p256_curve() {
        let issuer = test_issuer();
        let mut req = test_request();
        req.dpop_jwk.crv = "P-384".into();
        assert!(matches!(
            issuer.issue_lease(&req, None, None),
            Err(IssueError::InvalidRequest { .. })
        ));
    }

    // --- Negative cases: scope validation ---

    #[test]
    fn rejects_empty_scopes() {
        let issuer = test_issuer();
        let mut req = test_request();
        req.scopes.clear();
        assert!(matches!(
            issuer.issue_lease(&req, None, None),
            Err(IssueError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn rejects_scope_with_invalid_characters() {
        let issuer = test_issuer();
        let mut req = test_request();
        req.scopes = vec!["admin:everything!".into()];
        let err = issuer.issue_lease(&req, None, None).unwrap_err();
        assert!(
            matches!(&err, IssueError::InvalidRequest { reason } if reason.contains("admin:everything!")),
            "error must name the offending scope: {err}"
        );
    }

    #[test]
    fn rejects_scope_with_uppercase() {
        let issuer = test_issuer();
        let mut req = test_request();
        req.scopes = vec!["Email:send".into()];
        assert!(matches!(
            issuer.issue_lease(&req, None, None),
            Err(IssueError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn rejects_scope_without_separator() {
        let issuer = test_issuer();
        let mut req = test_request();
        req.scopes = vec!["toolscall".into()];
        let err = issuer.issue_lease(&req, None, None).unwrap_err();
        assert!(
            matches!(&err, IssueError::InvalidRequest { reason } if reason.contains("toolscall")),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mix_of_valid_and_invalid_scopes() {
        let issuer = test_issuer();
        let req = IssueLeaseRequest {
            scopes: vec!["tools:call".into(), "lateral:move!".into()],
            dpop_jwk: test_dpop_jwk(),
            budgets: None,
            fs_root: None,
        };
        assert!(matches!(
            issuer.issue_lease(&req, None, None),
            Err(IssueError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn accepts_valid_custom_scope() {
        let issuer = test_issuer();
        let req = IssueLeaseRequest {
            scopes: vec!["tools:call".into(), "email:send".into()],
            dpop_jwk: test_dpop_jwk(),
            budgets: None,
            fs_root: None,
        };
        assert!(issuer.issue_lease(&req, None, None).is_ok());
    }

    #[test]
    fn accepts_audit_read_builtin_scope() {
        let issuer = test_issuer();
        let req = IssueLeaseRequest {
            scopes: vec!["tools:call".into(), "audit:read".into()],
            dpop_jwk: test_dpop_jwk(),
            budgets: None,
            fs_root: None,
        };
        assert!(issuer.issue_lease(&req, None, None).is_ok());
    }

    #[test]
    fn each_issued_lease_has_unique_server_session_id() {
        let issuer = test_issuer();
        let req = test_request();
        let resp1 = issuer.issue_lease(&req, None, None).unwrap();
        let resp2 = issuer.issue_lease(&req, None, None).unwrap();
        assert_ne!(
            resp1.session_id, resp2.session_id,
            "server must generate a distinct session_id per issuance"
        );
    }

    // --- fs_root field ---

    #[test]
    fn fs_root_field_accepted_by_deserializer() {
        let json = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": { "kty": "EC", "crv": "P-256", "x": "a", "y": "b" },
            "fs_root": "/home/user/project"
        });
        let req: IssueLeaseRequest =
            serde_json::from_value(json).expect("fs_root must be accepted by deny_unknown_fields");
        assert_eq!(req.fs_root.as_deref(), Some("/home/user/project"));
    }

    #[test]
    fn fs_root_absent_defaults_to_none() {
        let json = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": { "kty": "EC", "crv": "P-256", "x": "a", "y": "b" }
        });
        let req: IssueLeaseRequest = serde_json::from_value(json).unwrap();
        assert!(req.fs_root.is_none());
    }

    #[test]
    fn response_omits_fs_root_when_none() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            !json.as_object().unwrap().contains_key("fs_root"),
            "fs_root must be omitted when None (skip_serializing_if)"
        );
    }

    #[test]
    fn issuer_returns_fs_root_none() {
        let issuer = test_issuer();
        let resp = issuer.issue_lease(&test_request(), None, None).unwrap();
        assert!(
            resp.fs_root.is_none(),
            "issuer must return fs_root: None — the API handler sets it after validation"
        );
    }

    // --- is_valid_scope unit tests ---

    #[test]
    fn builtin_scopes_are_always_valid() {
        for scope in BUILTIN_SCOPES {
            assert!(
                is_valid_scope(scope),
                "built-in scope must be valid: {scope}"
            );
        }
    }

    #[test]
    fn custom_scope_valid_format_accepted() {
        assert!(is_valid_scope("email:send"));
        assert!(is_valid_scope("file:write"));
        assert!(is_valid_scope("db:mutate"));
        assert!(is_valid_scope("s3:put-object"));
        assert!(is_valid_scope("ci:trigger_build"));
    }

    #[test]
    fn custom_scope_invalid_format_rejected() {
        assert!(!is_valid_scope("Email:send")); // uppercase
        assert!(!is_valid_scope("emailsend")); // no separator
        assert!(!is_valid_scope(":send")); // leading colon
        assert!(!is_valid_scope("email:")); // trailing colon
        assert!(!is_valid_scope("a:b")); // too short
        assert!(!is_valid_scope("email:send!")); // invalid char
        assert!(!is_valid_scope("email:send/write")); // slash
    }

    // --- format_timestamp ---

    #[test]
    fn format_timestamp_unix_epoch() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_known_date() {
        // 2024-01-15 12:30:45 UTC = 1705321845
        assert_eq!(format_timestamp(1705321845), "2024-01-15T12:30:45Z");
    }

    #[test]
    fn format_timestamp_leap_year_feb29() {
        // 2024-02-29 00:00:00 UTC = 1709164800 (2024 is a leap year)
        assert_eq!(format_timestamp(1709164800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn format_timestamp_year_boundary() {
        // 2024-12-31 23:59:59 UTC = 1735689599
        assert_eq!(format_timestamp(1735689599), "2024-12-31T23:59:59Z");
        // 2025-01-01 00:00:00 UTC = 1735689600
        assert_eq!(format_timestamp(1735689600), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_current_era() {
        // 2026-02-24 15:00:00 UTC = 1771945200
        assert_eq!(format_timestamp(1771945200), "2026-02-24T15:00:00Z");
    }

    // --- Helpers ---

    fn extract_jti(token: &str) -> String {
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = Base64UrlUnpadded::decode_vec(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        payload["jti"].as_str().unwrap().to_string()
    }
}
