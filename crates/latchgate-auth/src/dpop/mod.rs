//! DPoP primitives (RFC 9449).
//!
//! Single module for all DPoP operations: shared types, client-side signing,
//! and server-side verification.
//!
//! - **This file** — shared types (`DPoPClaims`, `DPoPSigningKey`, etc.),
//!   shared helpers (`compute_jwk_thumbprint`, `compute_ath`, `normalize_htu`),
//!   and client-side signing (`generate_dpop_keypair`, `sign_dpop_proof`).
//! - **`verify`** — server-side proof verification, called by `auth`.
//!
//! The signing/verification split keeps client SDK concerns separate from
//! enforcement logic while sharing types and cryptographic helpers.

pub mod operator;
pub mod verify;

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{
    signature::Signer, Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json_canonicalizer::to_string as jcs_canonicalize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors from DPoP client operations (key generation and proof signing).
///
/// These are distinct from `gate::auth::AuthError`, which covers verification
/// failures. Client errors indicate problems with the caller's input or the
/// host environment, not with an incoming proof.
///
/// HTTP semantics (SDK / CLI usage):
/// - `KeyGeneration` => 500 (internal; operator action required)
/// - `SigningFailed` => 500 (internal; operator action required)
/// - `ClockError`    => 503 (transient; host clock malfunction)
/// - `InvalidUri`    => caller passed a malformed HTU string
#[derive(Debug, thiserror::Error)]
pub enum DPoPError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// System clock is before Unix epoch — cannot produce a valid `iat`.
    ///
    /// SECURITY: a broken clock would allow crafting proofs with arbitrary
    /// timestamps. Fail-closed rather than substituting a default.
    #[error("system clock error: time is before Unix epoch")]
    ClockError,

    /// The provided HTU is not a valid absolute URI.
    #[error("invalid URI: {0}")]
    InvalidUri(String),
}

/// DPoP signing key (ES256 / P-256).
pub struct DPoPSigningKey {
    inner: P256SigningKey,
    /// Base64url-encoded EC x coordinate (no padding).
    pub x: String,
    /// Base64url-encoded EC y coordinate (no padding).
    pub y: String,
}

impl DPoPSigningKey {
    /// Load a DPoP signing key from a PKCS#8 or SEC1 PEM-encoded file.
    ///
    /// Supports both `-----BEGIN PRIVATE KEY-----` (PKCS#8) and
    /// `-----BEGIN EC PRIVATE KEY-----` (SEC1). The key must be P-256 (ES256).
    ///
    /// # Security
    ///
    /// The PEM file SHOULD have restrictive permissions (0o600). This function
    /// does NOT enforce that — callers may warn on loose permissions.
    pub fn from_pem(pem_str: &str) -> Result<Self, DPoPError> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;

        // Try PKCS#8 first, then SEC1.
        let sk = SigningKey::from_pkcs8_pem(pem_str)
            .or_else(|_| {
                use p256::elliptic_curve::SecretKey;
                SecretKey::<p256::NistP256>::from_sec1_pem(pem_str)
                    .map(|secret| SigningKey::from(&secret))
            })
            .map_err(|e| DPoPError::KeyGeneration(format!("failed to parse PEM: {e}")))?;

        let (x, y) = extract_xy(sk.verifying_key())?;
        Ok(Self { inner: sk, x, y })
    }

    /// Compute the JWK thumbprint of this key's public component.
    ///
    /// Convenience wrapper around [`compute_jwk_thumbprint`].
    pub fn thumbprint(&self) -> Result<String, DPoPError> {
        compute_jwk_thumbprint(&self.x, &self.y)
    }

    /// Access the underlying P-256 signing key.
    ///
    /// Needed for PEM serialization (PKCS#8 export) in `latchgate operator keygen`.
    pub fn as_inner(&self) -> &P256SigningKey {
        &self.inner
    }
}

pub struct DPoPPublicKey {
    /// Base64url-encoded EC x coordinate (no padding).
    pub x: String,
    /// Base64url-encoded EC y coordinate (no padding).
    pub y: String,
}

/// Claims from a DPoP proof JWT.
///
/// Shared between the signing path and the verification path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DPoPClaims {
    /// Unique proof identifier. Caller MUST check replay via the jti cache.
    pub jti: String,
    /// HTTP method the proof is bound to (normalised to uppercase).
    pub htm: String,
    /// HTTP URI the proof is bound to (normalised: scheme+host+path only).
    pub htu: String,
    /// Issued-at timestamp (Unix seconds).
    pub iat: i64,
    /// base64url(SHA-256(access_token)). Binds the proof to a specific lease.
    pub ath: String,
}

/// Generate a fresh ES256 (P-256) DPoP keypair using the OS CSPRNG.
#[must_use = "discarding the keypair loses authentication material"]
pub fn generate_dpop_keypair() -> Result<(DPoPSigningKey, DPoPPublicKey), DPoPError> {
    let sk = P256SigningKey::random(&mut rand::rngs::OsRng);
    let (x, y) = extract_xy(sk.verifying_key())?;

    let pub_key = DPoPPublicKey {
        x: x.clone(),
        y: y.clone(),
    };
    let signing_key = DPoPSigningKey { inner: sk, x, y };

    Ok((signing_key, pub_key))
}

/// Compute the JWK SHA-256 thumbprint for a P-256 public key (RFC 7638).
///
/// The canonical form includes only the required EC members (`crv`, `kty`,
/// `x`, `y`) in lexicographic order as required by §3. Returns
/// base64url-encoded SHA-256 without padding.
///
/// Used both when signing proofs (to embed in `cnf.jkt`) and when verifying
/// (to check key binding against `cnf.jkt` in the Lease).
#[must_use = "discarding the thumbprint loses key binding"]
pub fn compute_jwk_thumbprint(x: &str, y: &str) -> Result<String, DPoPError> {
    // SECURITY: RFC 7638 §3 — only required members, lexicographic order.
    // Extra claims (kid, use, key_ops) MUST be excluded; including them
    // changes the thumbprint and silently breaks the cnf.jkt binding.
    let jwk_required = json!({
        "crv": "P-256",
        "kty": "EC",
        "x": x,
        "y": y,
    });

    // JCS sorts keys lexicographically — gives the canonical form required
    // by RFC 7638 without a separate sort implementation.
    let canonical = jcs_canonicalize(&jwk_required)
        .map_err(|e| DPoPError::KeyGeneration(format!("JWK canonicalisation failed: {e}")))?;

    let hash = Sha256::digest(canonical.as_bytes());
    Ok(Base64UrlUnpadded::encode_string(&hash))
}

/// Compute `ath`: base64url(SHA-256(lease_jwt_bytes)).
///
/// Per RFC 9449 §4.2, `ath` binds a DPoP proof to a specific access token.
/// Computed from the raw JWT string as it appears in the Authorization header.
///
/// SECURITY: hashing the raw bytes means any encoding difference breaks the
/// binding. Both signer and verifier must hash the identical byte sequence.
#[must_use]
pub fn compute_ath(lease_jwt: &str) -> String {
    let hash = Sha256::digest(lease_jwt.as_bytes());
    Base64UrlUnpadded::encode_string(&hash)
}

/// Sign a DPoP proof JWT bound to the given request and lease.
///
/// The signer's public key is embedded in the JWT header (`jwk`), allowing
/// the verifier to check key-binding without a separate key registry.
///
/// `jti` must be a unique identifier for this proof; callers should use UUID
/// v4 or v7 via `rand::OsRng`. Do NOT use sequential or predictable values.
pub fn sign_dpop_proof(
    key: &DPoPSigningKey,
    htm: &str,
    htu: &str,
    ath: &str,
    jti: &str,
) -> Result<String, DPoPError> {
    let now = unix_now()?;

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x":   key.x,
            "y":   key.y,
        }
    });

    let payload = DPoPClaims {
        jti: jti.to_string(),
        // SECURITY: normalise method to uppercase so htm comparisons in the
        // verifier are unambiguous regardless of caller casing.
        htm: htm.to_ascii_uppercase(),
        htu: normalize_htu(htu)?,
        iat: now as i64,
        ath: ath.to_string(),
    };

    sign_jwt_es256(key, &header, &payload)
}

/// Sign a JWT using ES256 (SHA-256 + P-256 ECDSA) and return compact form.
///
/// Produces `base64url(header).base64url(payload).base64url(signature)`.
///
/// This function is `pub(crate)` so that test code in `dpop::verify` can craft
/// proofs with arbitrary payloads (e.g. expired `iat`) without going through
/// the high-level `sign_dpop_proof` which enforces `iat = now`.
///
/// SECURITY: `Signer<Signature>` on `P256SigningKey` uses SHA-256 internally
/// (via `DigestSigner`), which is exactly what ES256 requires per RFC 7518 §3.4.
pub(crate) fn sign_jwt_es256(
    key: &DPoPSigningKey,
    header: &serde_json::Value,
    payload: &DPoPClaims,
) -> Result<String, DPoPError> {
    let header_b64 = Base64UrlUnpadded::encode_string(
        serde_json::to_string(header)
            .map_err(|e| DPoPError::SigningFailed(e.to_string()))?
            .as_bytes(),
    );
    let payload_b64 = Base64UrlUnpadded::encode_string(
        serde_json::to_string(payload)
            .map_err(|e| DPoPError::SigningFailed(e.to_string()))?
            .as_bytes(),
    );

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig: Signature = key.inner.sign(signing_input.as_bytes());

    // SECURITY: JWT ES256 requires raw (r || s) encoding, not DER.
    // `to_bytes()` on `p256::ecdsa::Signature` gives the 64-byte raw form.
    let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Normalise an HTTP URI for `htu` comparison (RFC 9449 §4.2.2).
///
/// Rules applied in order:
/// 1. Strip fragment (`#…`).
/// 2. Strip query string (`?…`).
/// 3. Lowercase scheme and host.
/// 4. Remove default port (80 for http, 443 for https).
/// 5. Preserve percent-encoding in path (do not decode).
///
/// SECURITY: `htu` must be derived from the server's own configured
/// `public_base_url + path`, never from `Host` or `X-Forwarded-*` headers
/// unless a trusted reverse-proxy is explicitly in the stack. Callers are
/// responsible for passing the canonical URL.
pub(crate) fn normalize_htu(htu: &str) -> Result<String, DPoPError> {
    // Strip fragment (everything after '#') then query (everything after '?').
    let no_frag = htu.split('#').next().unwrap_or(htu);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);

    let (scheme, after_scheme) = no_query
        .split_once("://")
        .ok_or_else(|| DPoPError::InvalidUri(format!("missing '://' in '{htu}'")))?;
    let scheme = scheme.to_ascii_lowercase();

    let (authority, path) = match after_scheme.split_once('/') {
        Some((auth, rest)) => (auth.to_ascii_lowercase(), format!("/{rest}")),
        None => (after_scheme.to_ascii_lowercase(), "/".to_string()),
    };

    let authority = strip_default_port(&authority, &scheme);

    Ok(format!("{scheme}://{authority}{path}"))
}

/// Return the current Unix timestamp in seconds.
///
/// SECURITY: fails closed on clock error — a broken clock would allow
/// crafting or accepting proofs with arbitrary timestamps.
pub(crate) fn unix_now() -> Result<u64, DPoPError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| DPoPError::ClockError)
}

/// Extract base64url x/y from a P-256 verifying key.
fn extract_xy(vk: &P256VerifyingKey) -> Result<(String, String), DPoPError> {
    // false = uncompressed encoding: 0x04 || x || y
    let point = vk.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| DPoPError::KeyGeneration("missing x coordinate on EC point".into()))?;
    let y = point
        .y()
        .ok_or_else(|| DPoPError::KeyGeneration("missing y coordinate on EC point".into()))?;
    Ok((
        Base64UrlUnpadded::encode_string(x),
        Base64UrlUnpadded::encode_string(y),
    ))
}

/// Strip the default port from an authority string.
///
/// Uses `rsplit_once(':')` so IPv6 addresses (`[::1]:8080`) are handled
/// correctly — the colon before the port is the last one.
fn strip_default_port(authority: &str, scheme: &str) -> String {
    if let Some((host, port)) = authority.rsplit_once(':') {
        if matches!((scheme, port), ("http", "80") | ("https", "443")) {
            return host.to_string();
        }
    }
    authority.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Key generation ---

    #[test]
    fn generate_dpop_keypair_produces_valid_keys() {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        assert!(!sk.x.is_empty());
        assert!(!sk.y.is_empty());
        assert_eq!(sk.x, pk.x);
        assert_eq!(sk.y, pk.y);
    }

    #[test]
    fn each_keypair_is_unique() {
        let (_, pk1) = generate_dpop_keypair().unwrap();
        let (_, pk2) = generate_dpop_keypair().unwrap();
        assert_ne!(pk1.x, pk2.x);
    }

    // --- JWK thumbprint ---

    #[test]
    fn thumbprint_is_stable() {
        let (_, pk) = generate_dpop_keypair().unwrap();
        let t1 = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let t2 = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn thumbprint_is_base64url_no_padding() {
        let (_, pk) = generate_dpop_keypair().unwrap();
        let t = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        assert!(!t.contains('='), "thumbprint must not contain padding");
        assert!(!t.contains('+'), "thumbprint must use base64url alphabet");
        assert!(!t.contains('/'), "thumbprint must use base64url alphabet");
        assert_eq!(t.len(), 43, "SHA-256 base64url thumbprint must be 43 chars");
    }

    #[test]
    fn different_keys_produce_different_thumbprints() {
        let (_, pk1) = generate_dpop_keypair().unwrap();
        let (_, pk2) = generate_dpop_keypair().unwrap();
        assert_ne!(
            compute_jwk_thumbprint(&pk1.x, &pk1.y).unwrap(),
            compute_jwk_thumbprint(&pk2.x, &pk2.y).unwrap()
        );
    }

    // --- compute_ath ---

    #[test]
    fn ath_is_base64url_sha256_of_token_bytes() {
        let token = "header.payload.sig";
        let ath = compute_ath(token);
        let expected = {
            let h = Sha256::digest(token.as_bytes());
            Base64UrlUnpadded::encode_string(&h)
        };
        assert_eq!(ath, expected);
    }

    #[test]
    fn ath_changes_when_token_changes() {
        assert_ne!(compute_ath("token-a"), compute_ath("token-b"));
    }

    // --- normalize_htu ---

    #[test]
    fn htu_strips_query_string() {
        assert_eq!(
            normalize_htu("https://host.example/path?q=1&r=2").unwrap(),
            "https://host.example/path"
        );
    }

    #[test]
    fn htu_strips_fragment() {
        assert_eq!(
            normalize_htu("https://host.example/path#section").unwrap(),
            "https://host.example/path"
        );
    }

    #[test]
    fn htu_strips_query_and_fragment() {
        assert_eq!(
            normalize_htu("https://host.example/path?q=1#frag").unwrap(),
            "https://host.example/path"
        );
    }

    #[test]
    fn htu_lowercases_scheme_and_host() {
        assert_eq!(
            normalize_htu("HTTPS://HOST.EXAMPLE/Path").unwrap(),
            "https://host.example/Path"
        );
    }

    #[test]
    fn htu_removes_default_https_port() {
        assert_eq!(
            normalize_htu("https://host.example:443/api").unwrap(),
            normalize_htu("https://host.example/api").unwrap()
        );
    }

    #[test]
    fn htu_removes_default_http_port() {
        assert_eq!(
            normalize_htu("http://host.example:80/api").unwrap(),
            normalize_htu("http://host.example/api").unwrap()
        );
    }

    #[test]
    fn htu_keeps_non_default_port() {
        assert_eq!(
            normalize_htu("https://host.example:8443/api").unwrap(),
            "https://host.example:8443/api"
        );
    }

    #[test]
    fn htu_without_path_defaults_to_slash() {
        assert_eq!(
            normalize_htu("https://host.example").unwrap(),
            "https://host.example/"
        );
    }

    #[test]
    fn htu_missing_scheme_is_error() {
        assert!(matches!(
            normalize_htu("host.example/path"),
            Err(DPoPError::InvalidUri(_))
        ));
    }

    #[test]
    fn htu_preserves_percent_encoding_in_path() {
        assert_eq!(
            normalize_htu("https://host.example/path%2Fsegment").unwrap(),
            "https://host.example/path%2Fsegment"
        );
    }

    // --- unix_now ---

    #[test]
    fn unix_now_returns_reasonable_timestamp() {
        // 2024-01-01 00:00:00 UTC in Unix seconds = 1704067200
        assert!(unix_now().unwrap() > 1_704_067_200);
    }
}
