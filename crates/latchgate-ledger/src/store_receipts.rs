//! Receipt storage: persist and retrieve signed execution receipts.

use tracing::instrument;

use latchgate_core::ExecutionReceipt;

use crate::store::{LedgerError, LedgerStore};

impl LedgerStore {
    pub fn write_receipt(&self, receipt: &ExecutionReceipt) -> Result<(), LedgerError> {
        let receipt_json = serde_json::to_string(receipt)?;
        let inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;
        inner
            .conn
            .prepare_cached(
                "INSERT OR IGNORE INTO receipts (receipt_id, grant_id, receipt_json, created_at) \
             VALUES (?1, ?2, ?3, datetime('now'))",
            )?
            .execute(rusqlite::params![
                receipt.receipt_id.as_str(),
                receipt.grant_id.as_str(),
                receipt_json,
            ])?;
        Ok(())
    }

    /// Retrieve a stored [`ExecutionReceipt`] by its `receipt_id`.
    ///
    /// Returns `Ok(None)` when no receipt with the given ID exists.
    #[instrument(name = "ledger.get_receipt", skip(self), fields(%receipt_id))]
    pub fn get_receipt(&self, receipt_id: &str) -> Result<Option<ExecutionReceipt>, LedgerError> {
        self.with_reader(|conn| {
            let result = conn
                .prepare_cached("SELECT receipt_json FROM receipts WHERE receipt_id = ?1")?
                .query_row([receipt_id], |row| {
                    let json_str: String = row.get(0)?;
                    Ok(json_str)
                });
            match result {
                Ok(json_str) => {
                    let receipt: ExecutionReceipt = serde_json::from_str(&json_str)?;
                    Ok(Some(receipt))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(LedgerError::Sqlite(e)),
            }
        })
    }

    /// Export all receipts as raw JSON strings.
    ///
    /// Returns the exact `receipt_json` bytes stored in SQLite, preserving
    /// signature-covered content for external verification.
    pub fn export_receipts_raw(&self) -> Result<Vec<String>, LedgerError> {
        self.with_reader(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT receipt_json FROM receipts ORDER BY rowid ASC")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut receipts = Vec::new();
            for row in rows {
                receipts.push(row?);
            }
            Ok(receipts)
        })
    }

    /// Count total receipts.
    pub fn receipt_count(&self) -> Result<usize, LedgerError> {
        self.with_reader(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
            Ok(count as usize)
        })
    }
}

#[cfg(test)]
mod tests {

    use latchgate_core::ExecutionReceipt;

    use crate::store::LedgerStore;

    fn sample_receipt() -> ExecutionReceipt {
        use latchgate_core::types::{GrantId, ReceiptId};
        use latchgate_core::{NormalizedResult, VerificationOutcome};

        let now = chrono::Utc::now();
        let mut r = ExecutionReceipt {
            receipt_id: ReceiptId::from("rcpt-test-001"),
            grant_id: GrantId::from("grant-test-001"),
            provider_module_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            provider_receipt: std::sync::Arc::new(serde_json::json!({"status": 200})),
            normalized_result: NormalizedResult::Success {
                summary: "HTTP 200 OK".into(),
            },
            verification_outcome: VerificationOutcome::Verified {
                evidence: serde_json::json!({"status_code": 200}),
            },
            effect_evidence: vec![],
            result_hash: String::new(),
            receipt_signature: None,
            signing_key_id: None,
            started_at: now - chrono::Duration::seconds(1),
            finished_at: now,
            failure_class: None,
        };
        r.result_hash = r.compute_result_hash();
        r
    }

    #[test]
    fn write_and_get_receipt_roundtrip() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();

        store.write_receipt(&receipt).unwrap();

        let found = store.get_receipt("rcpt-test-001").unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.receipt_id.as_str(), "rcpt-test-001");
        assert_eq!(found.grant_id.as_str(), "grant-test-001");
        assert_eq!(found.result_hash, receipt.result_hash);
        assert!(found.is_fully_successful());
    }

    #[test]
    fn get_receipt_not_found() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let found = store.get_receipt("nonexistent-receipt").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn write_receipt_duplicate_is_idempotent() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();
        store.write_receipt(&receipt).unwrap();
        // Second write with same receipt_id must not fail (INSERT OR IGNORE).
        let result = store.write_receipt(&receipt);
        assert!(result.is_ok(), "duplicate receipt write must be idempotent");
    }

    // -- ExecutionIntent --
}
