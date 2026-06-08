//! Receipt retrieval with signature verification — kernel facade.

use std::sync::Arc;

use crate::AppState;
use latchgate_crypto::ReceiptExt;

/// Receipt with signature verification result.
pub struct ReceiptResponse {
    pub value: serde_json::Value,
}

/// Look up a receipt by ID, verify its signature, and return enriched JSON.
pub async fn lookup(state: &AppState, receipt_id: &str) -> Result<Option<ReceiptResponse>, String> {
    let ledger = Arc::clone(&state.ledger);
    let rid = receipt_id.to_string();

    let result = tokio::task::spawn_blocking(move || ledger.get_receipt(&rid))
        .await
        .map_err(|e| format!("receipt lookup task panicked: {e}"))?
        .map_err(|e| format!("ledger read failed: {e}"))?;

    match result {
        Some(receipt) => {
            let sig_status = receipt.verify_with_key_store(&state.crypto.verifying_key_store);
            let mut value = serde_json::to_value(&receipt)
                .map_err(|e| format!("receipt serialization failed: {e}"))?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "signature_status".to_string(),
                    serde_json::Value::String(sig_status.as_str().to_string()),
                );
            }
            Ok(Some(ReceiptResponse { value }))
        }
        None => Ok(None),
    }
}

/// JWKS entry for the receipt verifying keys endpoint.
///
/// Wraps [`latchgate_crypto::VerifyingKeyEntry`] (already `Serialize`) with
/// the standard JWKS `"use"` field. Avoids `json!()` / `BTreeMap` overhead
/// and gives compile-time field-name safety.
#[derive(serde::Serialize)]
struct JwksEntry<'a> {
    #[serde(flatten)]
    entry: &'a latchgate_crypto::VerifyingKeyEntry,
    /// JWKS `use` parameter — always `"sig"` for receipt verification keys.
    #[serde(rename = "use")]
    key_use: &'static str,
}

/// Return receipt signing public keys from the verifying key store.
pub fn receipt_verifying_keys(state: &AppState) -> Vec<serde_json::Value> {
    state
        .crypto
        .verifying_key_store
        .entries()
        .filter_map(|e| {
            let entry = JwksEntry {
                entry: e,
                key_use: "sig",
            };
            match serde_json::to_value(entry) {
                Ok(val) => Some(val),
                Err(err) => {
                    tracing::error!(kid = %e.kid, "BUG: JWKS entry serialization failed: {err}");
                    None
                }
            }
        })
        .collect()
}
