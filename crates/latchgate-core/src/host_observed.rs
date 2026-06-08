//! Host-observed effects for BFT-style verification cross-checking.
//!
//! During provider I/O execution, the host independently records what it
//! observed at the transport layer. These observations are passed to the
//! verifier alongside the provider's self-reported output, enabling
//! cross-checking: a compromised provider cannot lie about the outcome
//! because the host saw it too.

use std::path::PathBuf;

/// Filesystem operation type, recorded in host-observed evidence.
///
/// Each variant maps 1:1 to the WIT `fs-write-mode` enum plus `read` and
/// `delete`. Serialised as `snake_case` for JSON receipts and OPA input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsOperation {
    Read,
    Create,
    Overwrite,
    Delete,
}

impl FsOperation {
    /// Canonical lowercase string matching `#[serde(rename_all = "snake_case")]`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Create => "create",
            Self::Overwrite => "overwrite",
            Self::Delete => "delete",
        }
    }
}

impl std::fmt::Display for FsOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serde helper: serialize `Option<[u8; 32]>` as a hex string.
mod hex_hash {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32-byte hex hash"))?;
                Ok(Some(arr))
            }
        }
    }
}

/// An effect independently observed by the host during provider I/O.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum HostObservedEffect {
    /// The host observed an HTTP response with this status code.
    HttpStatus {
        /// HTTP status code observed by the host transport layer.
        status: u16,
        /// Target origin (scheme + host only, path stripped for privacy).
        target: String,
    },

    /// The host observed a filesystem operation.
    ///
    /// Recorded after every successful fs host-import call. Hashes are
    /// computed by the host over the actual bytes read/written — the
    /// provider cannot influence them.
    ///
    /// Mutating operations carry before/after evidence so the verifier
    /// (and ultimately `git diff`) can reconstruct what changed.
    Fs {
        /// Which operation was performed.
        operation: FsOperation,

        /// Canonical path relative to the configured root.
        path: PathBuf,

        /// SHA-256 before mutation. Present for overwrite and delete.
        /// `None` for create (file did not exist) and read.
        ///
        /// Serializes as a hex string (`"a1b2c3..."`) for JSON interop.
        #[serde(with = "hex_hash")]
        before_hash: Option<[u8; 32]>,

        /// SHA-256 after read/write. Present for read, create, and overwrite.
        /// `None` for delete (file is gone).
        ///
        /// Serializes as a hex string (`"a1b2c3..."`) for JSON interop.
        #[serde(with = "hex_hash")]
        after_hash: Option<[u8; 32]>,

        /// File size in bytes before the operation. 0 for create and read.
        bytes_before: u64,

        /// Bytes read or written. 0 for delete.
        bytes_after: u64,

        /// Timestamp of the host observation.
        observed_at: chrono::DateTime<chrono::Utc>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_operation_as_str() {
        assert_eq!(FsOperation::Read.as_str(), "read");
        assert_eq!(FsOperation::Create.as_str(), "create");
        assert_eq!(FsOperation::Overwrite.as_str(), "overwrite");
        assert_eq!(FsOperation::Delete.as_str(), "delete");
    }

    #[test]
    fn fs_operation_display() {
        assert_eq!(FsOperation::Read.to_string(), "read");
        assert_eq!(FsOperation::Create.to_string(), "create");
        assert_eq!(FsOperation::Overwrite.to_string(), "overwrite");
        assert_eq!(FsOperation::Delete.to_string(), "delete");
    }

    #[test]
    fn fs_operation_roundtrip_serde() {
        for op in [
            FsOperation::Read,
            FsOperation::Create,
            FsOperation::Overwrite,
            FsOperation::Delete,
        ] {
            let json = serde_json::to_string(&op).unwrap();
            let back: FsOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn host_observed_fs_overwrite_serialization() {
        let effect = HostObservedEffect::Fs {
            operation: FsOperation::Overwrite,
            path: PathBuf::from("src/main.rs"),
            before_hash: Some([0xa1; 32]),
            after_hash: Some([0xd4; 32]),
            bytes_before: 1632,
            bytes_after: 1847,
            observed_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&effect).unwrap();
        assert_eq!(json["Fs"]["operation"], "overwrite");
        assert_eq!(json["Fs"]["bytes_before"], 1632);
        assert_eq!(json["Fs"]["bytes_after"], 1847);
        assert_eq!(json["Fs"]["before_hash"], "a1".repeat(32));
        assert_eq!(json["Fs"]["after_hash"], "d4".repeat(32));
    }

    #[test]
    fn host_observed_fs_create_has_no_before_hash() {
        let effect = HostObservedEffect::Fs {
            operation: FsOperation::Create,
            path: PathBuf::from("src/new.rs"),
            before_hash: None,
            after_hash: Some([0xef; 32]),
            bytes_before: 0,
            bytes_after: 256,
            observed_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&effect).unwrap();
        assert!(json["Fs"]["before_hash"].is_null());
        assert!(json["Fs"]["after_hash"].is_string());
        assert_eq!(json["Fs"]["bytes_before"], 0);
        assert_eq!(json["Fs"]["bytes_after"], 256);
    }

    #[test]
    fn host_observed_fs_delete_has_no_after_hash() {
        let effect = HostObservedEffect::Fs {
            operation: FsOperation::Delete,
            path: PathBuf::from("src/old.rs"),
            before_hash: Some([0xab; 32]),
            after_hash: None,
            bytes_before: 512,
            bytes_after: 0,
            observed_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&effect).unwrap();
        assert!(json["Fs"]["before_hash"].is_string());
        assert!(json["Fs"]["after_hash"].is_null());
        assert_eq!(json["Fs"]["bytes_before"], 512);
        assert_eq!(json["Fs"]["bytes_after"], 0);
    }

    #[test]
    fn host_observed_fs_read() {
        let effect = HostObservedEffect::Fs {
            operation: FsOperation::Read,
            path: PathBuf::from("src/lib.rs"),
            before_hash: None,
            after_hash: Some([0xcd; 32]),
            bytes_before: 0,
            bytes_after: 1024,
            observed_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&effect).unwrap();
        assert_eq!(json["Fs"]["operation"], "read");
        assert!(json["Fs"]["before_hash"].is_null());
        assert!(json["Fs"]["after_hash"].is_string());
    }

    #[test]
    fn fs_hash_hex_roundtrip() {
        let effect = HostObservedEffect::Fs {
            operation: FsOperation::Create,
            path: PathBuf::from("test.rs"),
            before_hash: None,
            after_hash: Some([0xab; 32]),
            bytes_before: 0,
            bytes_after: 100,
            observed_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&effect).unwrap();
        let back: HostObservedEffect = serde_json::from_str(&json).unwrap();
        match back {
            HostObservedEffect::Fs { after_hash, .. } => {
                assert_eq!(after_hash, Some([0xab; 32]));
            }
            _ => panic!("expected Fs variant"),
        }
    }

    #[test]
    fn http_status_variant_unchanged() {
        let effect = HostObservedEffect::HttpStatus {
            status: 200,
            target: "https://api.example.com".into(),
        };
        let json = serde_json::to_value(&effect).unwrap();
        assert_eq!(json["HttpStatus"]["status"], 200);
    }
}
