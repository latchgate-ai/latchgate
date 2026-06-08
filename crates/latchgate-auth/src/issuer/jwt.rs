use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors produced during Lease issuance — key generation and signing.
///
/// HTTP semantics for the `POST /v1/leases` endpoint:
/// - `KeyGeneration` => 500 (internal; operator action required)
/// - `SigningFailed` => 500 (internal; operator action required)
#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),
}

/// Lease JWT claims issued by the embedded Issuer.
///
/// `cnf.jkt` binds the lease to the agent's DPoP key (RFC 9449 §6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeaseClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
    pub jti: String,
    pub session_id: String,
    pub scope: Vec<String>,
    /// Optional spending / rate-limit budgets for this lease.
    /// Enforced in the stateful budgets step. Omitted when unconstrained.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub budgets: Option<Budgets>,
    pub cnf: CnfClaim,
    /// Owner/responsible person for this agent, frozen at lease issuance.
    ///
    /// Propagated from `VerifiedIdentity.owner`. Carried in the JWT so
    /// every downstream consumer (audit, webhooks, approval store) has
    /// attribution without config lookups. Omitted when not configured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner: Option<String>,
}

/// Per-lease budget constraints carried inside the JWT.
///
/// Fields are individually optional; absent = unconstrained for that dimension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Budgets {
    /// Maximum number of action calls allowed under this lease.
    pub max_calls: Option<u64>,
}

/// Confirmation claim (RFC 7800). Contains the JWK thumbprint of the
/// sender's DPoP key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CnfClaim {
    /// JWK SHA-256 thumbprint (RFC 7638) of the agent's DPoP public key.
    pub jkt: String,
}

pub struct SigningKey {
    pub(crate) kid: String,
    pub(crate) inner: EncodingKey,
}

#[derive(Clone)]
pub struct VerifyingKey {
    pub(crate) kid: String,
    inner: DecodingKey,
}

impl VerifyingKey {
    /// Construct a VerifyingKey from a kid and DecodingKey.
    pub fn new(kid: String, inner: DecodingKey) -> Self {
        Self { kid, inner }
    }

    /// Key identifier. Matches the `kid` header in JWTs signed by the
    /// corresponding signing key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Expose the inner DecodingKey for verification (used by gate::auth).
    pub fn decoding_key(&self) -> &DecodingKey {
        &self.inner
    }
}

#[derive(Clone)]
pub struct Jwks {
    keys: Vec<VerifyingKey>,
}

impl Jwks {
    pub fn new(keys: Vec<VerifyingKey>) -> Self {
        Self { keys }
    }

    pub fn get(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Derive a key identifier from a P-256 public key.
///
/// Algorithm: first 16 hex characters of SHA-256(SPKI DER encoding).
pub fn derive_kid(pk: &p256::PublicKey) -> Result<String, IssuerError> {
    let public_der = pk
        .to_public_key_der()
        .map_err(|e| IssuerError::KeyGeneration(e.to_string()))?;
    let hash = Sha256::digest(public_der.as_ref());
    Ok(hex::encode(&hash[..8]))
}

/// Build a `(SigningKey, DecodingKey)` pair from PEM-encoded key material.
pub fn build_jwt_keys(
    private_pem: &str,
    public_pem: &str,
) -> Result<(EncodingKey, DecodingKey), IssuerError> {
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes())
        .map_err(|e| IssuerError::KeyGeneration(e.to_string()))?;
    let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
        .map_err(|e| IssuerError::KeyGeneration(e.to_string()))?;
    Ok((encoding_key, decoding_key))
}

/// Generate an ES256 (P-256) signing keypair.
///
/// Uses OS-provided randomness (CSPRNG). The `kid` is derived from the
/// SHA-256 of the public key's SPKI DER encoding.
pub fn generate_keypair() -> Result<(SigningKey, VerifyingKey), IssuerError> {
    let sk = P256SigningKey::random(&mut rand::rngs::OsRng);

    let private_pem = sk
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| IssuerError::KeyGeneration(e.to_string()))?;

    let pk = p256::PublicKey::from(sk.verifying_key());

    let public_pem = pk
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| IssuerError::KeyGeneration(e.to_string()))?;

    let kid = derive_kid(&pk)?;
    let (encoding_key, decoding_key) = build_jwt_keys(&private_pem, &public_pem)?;

    Ok((
        SigningKey {
            kid: kid.clone(),
            inner: encoding_key,
        },
        VerifyingKey {
            kid,
            inner: decoding_key,
        },
    ))
}

/// Sign a Lease JWT with ES256.
pub fn sign_lease(claims: &LeaseClaims, key: &SigningKey) -> Result<String, IssuerError> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());

    encode(&header, claims, &key.inner).map_err(|e| IssuerError::SigningFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn test_claims() -> LeaseClaims {
        let now = now_secs();
        LeaseClaims {
            iss: "latchgate".to_string(),
            sub: "agent-1".to_string(),
            aud: "latchgate".to_string(),
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

    #[test]
    fn generate_keypair_produces_valid_keys() {
        let (sk, vk) = generate_keypair().unwrap();
        // kid should be 16 hex chars (8 bytes of SHA-256)
        assert_eq!(sk.kid.len(), 16);
        assert_eq!(vk.kid.len(), 16);
        assert_eq!(sk.kid, vk.kid);
        assert!(sk.kid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn each_keypair_has_unique_kid() {
        let (sk1, _) = generate_keypair().unwrap();
        let (sk2, _) = generate_keypair().unwrap();
        assert_ne!(sk1.kid, sk2.kid);
    }

    #[test]
    fn sign_lease_produces_three_part_jwt() {
        let (sk, _) = generate_keypair().unwrap();
        let token = sign_lease(&test_claims(), &sk).unwrap();
        assert_eq!(
            token.split('.').count(),
            3,
            "JWT must have 3 dot-separated segments"
        );
    }

    #[test]
    fn sign_lease_embeds_kid_in_header() {
        let (sk, _) = generate_keypair().unwrap();
        let token = sign_lease(&test_claims(), &sk).unwrap();
        // Decode header manually to check kid
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = base64_decode_url(header_b64);
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["kid"], sk.kid.as_str());
    }

    #[test]
    fn budgets_none_serializes_without_field() {
        let (sk, _) = generate_keypair().unwrap();
        let claims = test_claims(); // budgets: None
        let token = sign_lease(&claims, &sk).unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64_decode_url(payload_b64);
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        // skip_serializing_if = None => field absent from JWT
        assert!(
            payload.get("budgets").is_none(),
            "budgets=None must be omitted"
        );
    }

    #[test]
    fn budgets_some_serializes_correctly() {
        let (sk, _) = generate_keypair().unwrap();
        let mut claims = test_claims();
        claims.budgets = Some(Budgets {
            max_calls: Some(10),
        });
        let token = sign_lease(&claims, &sk).unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64_decode_url(payload_b64);
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["budgets"]["max_calls"], 10);
    }

    /// Decode a base64url (no-padding) segment — test helper only.
    fn base64_decode_url(s: &str) -> Vec<u8> {
        use base64ct::{Base64UrlUnpadded, Encoding};
        Base64UrlUnpadded::decode_vec(s).unwrap()
    }
}
