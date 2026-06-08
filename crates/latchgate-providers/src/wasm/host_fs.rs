//! Host implementation for `latchgate:io/fs` — sandboxed filesystem I/O.
//!
//! Delegates to the `fs_io` module for path validation and actual I/O.
//! Records host-observed effects for BFT cross-checking by verifiers.

use tracing::debug;

use super::latchgate;
use super::WasmHostState;

// io-fs host import — delegates to fs_io module for path validation + I/O

impl latchgate::provider::io_fs::Host for WasmHostState {
    async fn read(
        &mut self,
        req: latchgate::provider::io_fs::FsReadInput,
    ) -> Result<latchgate::provider::io_fs::FsReadOutput, latchgate::provider::io_fs::FsError> {
        debug!(
            trace_id = %self.host_io.trace_id,
            path = %req.path,
            "host_io.fs: read"
        );

        if let Err(_e) = self.host_io.check_import_allowed("latchgate:io/fs") {
            return Err(latchgate::provider::io_fs::FsError::PathNotAllowed);
        }
        if let Err(_e) = self.host_io.consume_io_call() {
            return Err(latchgate::provider::io_fs::FsError::IoError);
        }

        let config = self
            .host_io
            .fs_config
            .clone()
            .ok_or(latchgate::provider::io_fs::FsError::IoError)?;

        match crate::fs_io::fs_read(config, req.path.clone()).await {
            Ok(result) => {
                self.host_io
                    .record_observed_effect(crate::host_io::HostObservedEffect::Fs {
                        operation: latchgate_core::host_observed::FsOperation::Read,
                        path: std::path::PathBuf::from(&req.path),
                        before_hash: None,
                        after_hash: Some(result.hash),
                        bytes_before: 0,
                        bytes_after: result.size,
                        observed_at: chrono::Utc::now(),
                    });
                Ok(latchgate::provider::io_fs::FsReadOutput {
                    content: result.content,
                    hash: result.hash.to_vec(),
                    size_bytes: result.size,
                })
            }
            Err(e) => Err(map_fs_error(e)),
        }
    }

    async fn write(
        &mut self,
        req: latchgate::provider::io_fs::FsWriteInput,
    ) -> Result<latchgate::provider::io_fs::FsWriteOutput, latchgate::provider::io_fs::FsError>
    {
        debug!(
            trace_id = %self.host_io.trace_id,
            path = %req.path,
            bytes = req.content.len(),
            mode = ?req.mode,
            has_expected_hash = req.expected_before_hash.is_some(),
            "host_io.fs: write"
        );

        if let Err(_e) = self.host_io.check_import_allowed("latchgate:io/fs") {
            return Err(latchgate::provider::io_fs::FsError::PathNotAllowed);
        }
        if let Err(_e) = self.host_io.consume_io_call() {
            return Err(latchgate::provider::io_fs::FsError::IoError);
        }

        let config = self
            .host_io
            .fs_config
            .clone()
            .ok_or(latchgate::provider::io_fs::FsError::IoError)?;

        let mode = match req.mode {
            latchgate::provider::io_fs::FsWriteMode::Create => crate::fs_io::FsWriteMode::Create,
            latchgate::provider::io_fs::FsWriteMode::Overwrite => {
                crate::fs_io::FsWriteMode::Overwrite
            }
        };

        match crate::fs_io::fs_write(
            config,
            req.path.clone(),
            req.content.clone(),
            mode,
            req.expected_before_hash,
        )
        .await
        {
            Ok(result) => {
                let operation = match mode {
                    crate::fs_io::FsWriteMode::Create => {
                        latchgate_core::host_observed::FsOperation::Create
                    }
                    crate::fs_io::FsWriteMode::Overwrite => {
                        latchgate_core::host_observed::FsOperation::Overwrite
                    }
                };
                self.host_io
                    .record_observed_effect(crate::host_io::HostObservedEffect::Fs {
                        operation,
                        path: std::path::PathBuf::from(&req.path),
                        before_hash: result.before_hash,
                        after_hash: Some(result.after_hash),
                        bytes_before: result.bytes_before,
                        bytes_after: result.bytes_written,
                        observed_at: chrono::Utc::now(),
                    });
                Ok(latchgate::provider::io_fs::FsWriteOutput {
                    before_hash: result.before_hash.map(|h| h.to_vec()),
                    after_hash: result.after_hash.to_vec(),
                    bytes_before: result.bytes_before,
                    bytes_written: result.bytes_written,
                })
            }
            Err(e) => Err(map_fs_error(e)),
        }
    }

    async fn delete(
        &mut self,
        req: latchgate::provider::io_fs::FsDeleteInput,
    ) -> Result<latchgate::provider::io_fs::FsDeleteOutput, latchgate::provider::io_fs::FsError>
    {
        debug!(
            trace_id = %self.host_io.trace_id,
            path = %req.path,
            "host_io.fs: delete"
        );

        if let Err(_e) = self.host_io.check_import_allowed("latchgate:io/fs") {
            return Err(latchgate::provider::io_fs::FsError::PathNotAllowed);
        }
        if let Err(_e) = self.host_io.consume_io_call() {
            return Err(latchgate::provider::io_fs::FsError::IoError);
        }

        let config = self
            .host_io
            .fs_config
            .clone()
            .ok_or(latchgate::provider::io_fs::FsError::IoError)?;

        match crate::fs_io::fs_delete(config, req.path.clone()).await {
            Ok(result) => {
                self.host_io
                    .record_observed_effect(crate::host_io::HostObservedEffect::Fs {
                        operation: latchgate_core::host_observed::FsOperation::Delete,
                        path: std::path::PathBuf::from(&req.path),
                        before_hash: result.before_hash,
                        after_hash: None,
                        bytes_before: result.bytes_before,
                        bytes_after: 0,
                        observed_at: chrono::Utc::now(),
                    });
                Ok(latchgate::provider::io_fs::FsDeleteOutput { ok: true })
            }
            Err(e) => Err(map_fs_error(e)),
        }
    }
}

/// Map `FsHostError` to the WIT `FsError` enum.
fn map_fs_error(e: crate::fs_io::FsHostError) -> latchgate::provider::io_fs::FsError {
    use crate::fs_io::FsHostError;
    use latchgate::provider::io_fs::FsError;
    match e {
        FsHostError::OperationNotAllowed(_) => FsError::OperationNotAllowed,
        FsHostError::PathNotAllowed => FsError::PathNotAllowed,
        FsHostError::PathDenied { .. } => FsError::PathDenied,
        FsHostError::PathNotFound(_) => FsError::PathNotFound,
        FsHostError::PathInvalid(_) => FsError::PathInvalid,
        FsHostError::AlreadyExists => FsError::AlreadyExists,
        FsHostError::TooLarge { .. } => FsError::TooLarge,
        FsHostError::SymlinkEscape(_) => FsError::SymlinkEscape,
        FsHostError::Traversal => FsError::Traversal,
        FsHostError::SpecialFile(_) => FsError::SpecialFile,
        FsHostError::Conflict => FsError::Conflict,
        FsHostError::IoError(_) | FsHostError::NotConfigured => FsError::IoError,
    }
}
