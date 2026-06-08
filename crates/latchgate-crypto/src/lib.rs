#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Ed25519 signing, verification, and key management for LatchGate.
//!
//! This crate owns all asymmetric cryptographic operations:
//!
//! - [`Ed25519Signer`] — generic Ed25519 signer with purpose-based key separation.
//! - [`GrantSigner`] / [`GrantVerifyingKeyStore`] — grant signing and verification.
//! - [`ReceiptSigner`] / [`VerifyingKeyStore`] — receipt signing and verification.
//! - [`GrantExt`] — extension trait: `sign()` and `verify_signature()` on `ExecutionGrant`.
//! - [`ReceiptExt`] — extension trait: `sign()` and `verify_with_key_store()` on `ExecutionReceipt`.
//!
//! # Crate boundary
//!
//! Domain types (`ExecutionGrant`, `ExecutionReceipt`, `ApprovedExecutionPlan`)
//! live in `latchgate-core` as pure data structs. This crate adds signing
//! and verification as extension traits, keeping `ed25519-dalek` out of the
//! leaf crate.

pub(crate) mod ed25519;
pub(crate) mod grant_ext;
pub(crate) mod grant_signer;
pub(crate) mod key_file;
pub(crate) mod receipt_ext;
pub(crate) mod receipt_signer;
pub(crate) mod verifying_keys;

pub use ed25519::{Ed25519Signer, Grant, Receipt, SigningPurpose, UnknownKeyId};
pub use grant_ext::{GrantBuilderExt, GrantExt};
pub use grant_signer::{GrantSigner, GrantVerifyingKeyStore};
pub use receipt_ext::ReceiptExt;
pub use receipt_signer::{ReceiptSigner, VerifyingKeyEntry, VerifyingKeyStore};
