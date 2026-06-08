//! Host implementation for `latchgate:io/storage` — object store put.
//!
//! SECURITY: bucket is validated against allowed_sinks. The actual store
//! target is pre-configured at startup — providers can influence only the
//! object key, not which storage backend or bucket is written to.

use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutPayload};
use tracing::debug;

use super::latchgate;
use super::WasmHostState;

impl latchgate::provider::io_storage::Host for WasmHostState {
    async fn put_object(
        &mut self,
        req: latchgate::provider::io_storage::PutRequest,
    ) -> Result<latchgate::provider::io_storage::PutReceipt, String> {
        debug!(
            trace_id = %self.host_io.trace_id,
            bucket = %req.bucket,
            key = %req.key,
            bytes = req.content.len(),
            "host_io.storage: put_object"
        );

        if let Err(e) = self.host_io.check_import_allowed("latchgate:io/storage") {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.consume_io_call() {
            return Err(format!("{e}"));
        }
        // Validate bucket against allowed_sinks. The actual store target is
        // pre-configured at startup — providers can influence only the object
        // key, not which storage backend or bucket is written to.
        if let Err(e) = self.host_io.validate_sink(&req.bucket) {
            return Err(format!("{e}"));
        }

        let store = self.resources.object_store.as_ref().ok_or_else(|| {
            "storage host import unavailable: storage_url is not configured in latchgate.toml"
                .to_string()
        })?;

        // Compute SHA-256 before consuming the content vec.
        let content_hash = latchgate_core::crypto::sha256_digest(&req.content);
        let bytes_written = req.content.len() as u64;

        // object_store path is the object key within the pre-configured store.
        // Bucket is validated above (allowed_sinks) but the store is already
        // scoped to the bucket configured in storage_url — providers cannot
        // redirect writes to a different bucket.
        let path = ObjectPath::from(req.key.as_str());

        let mut put_opts = object_store::PutOptions::default();
        if let Some(ct) = req.content_type.clone() {
            let mut attributes = object_store::Attributes::new();
            // AttributeValue is Cow<'static, str>; convert via owned String.
            attributes.insert(object_store::Attribute::ContentType, ct.into());
            put_opts.attributes = attributes;
        }

        store
            .put_opts(&path, PutPayload::from(req.content), put_opts)
            .await
            .map_err(|e| format!("object store put failed: {e}"))?;

        debug!(
            trace_id = %self.host_io.trace_id,
            bucket = %req.bucket,
            key = %req.key,
            bytes_written,
            content_hash = %content_hash,
            "host_io.storage: object stored"
        );

        Ok(latchgate::provider::io_storage::PutReceipt {
            artifact_id: format!("{}/{}", req.bucket, req.key),
            content_hash,
            bytes_written,
        })
    }
}
