//! Storage backend configuration (Redis, SQLite ledger).

use serde::Deserialize;

/// Persistent storage paths and backend selection.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct StorageConfig {
    /// Redis URL. Present => Redis backends, absent => SQLite + bounded memory.
    #[serde(default)]
    pub redis_url: Option<String>,

    /// Path to the SQLite audit ledger database.
    #[serde(default)]
    pub ledger_db_path: String,

    /// Optional JSONL audit sink for SIEM export.
    #[serde(default)]
    pub ledger_jsonl_path: Option<String>,
}
