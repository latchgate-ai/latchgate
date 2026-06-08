#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Identity, DPoP, Lease JWT, and anti-replay cache for LatchGate.
//!
//! This crate owns the entire authentication boundary:
//!
//! - [`identity`] — Caller identity verification at lease issuance time.
//!   Pluggable providers: `PeerCredProvider` (SO_PEERCRED), future OIDC/mTLS.
//!   Returns `VerifiedIdentity` with authenticated principal and scope limits.
//!
//! - [`dpop`] — DPoP (RFC 9449) key generation, proof signing (client-side),
//!   and proof verification (server-side). Shared types: `DPoPClaims`,
//!   `DPoPSigningKey`, `DPoPPublicKey`.
//!
//! - [`issuer`] — Lease JWT issuance with ES256 signatures, key rotation,
//!   and JWKS endpoint support.
//!
//! - **auth** — The `authenticate()` function that ties together Lease
//!   verification, DPoP proof verification, and anti-replay checking into
//!   a single pipeline step. Returns `AuthContext` on success.
//!
//! - **replay** — Redis-backed anti-replay cache (SETNX + TTL). Ensures
//!   each DPoP proof `jti` is used at most once.
//!
//! # Dependency
//!
//! Depends only on `latchgate-core` (for typed IDs if needed in the future).

pub(crate) mod auth;
pub mod dpop;
pub mod identity;
pub mod issuer;
pub(crate) mod replay;

// ── Primary re-exports ──────────────────────────────────────────────────────
// These are the items other crates import most often.

pub use auth::{authenticate, verify_lease, AuthContext, AuthError};
pub use dpop::operator::{
    verify_operator_auth as verify_operator_dpop_auth, OperatorAuthContext, OperatorAuthError,
    OperatorAuthnMethod,
};
pub use dpop::{compute_ath, compute_jwk_thumbprint, sign_dpop_proof, DPoPError, DPoPSigningKey};
pub use identity::{
    build_identity_provider, ConnectionContext, IdentityConfig, IdentityError, IdentityProvider,
    VerifiedIdentity,
};
pub use replay::ReplayCache;
