//! Action Registry: manifests, digest trust, JSON Schema validation.
//!
//! The Registry is the source of truth for action metadata: what actions exist,
//! what image digests are trusted, what schemas they declare, and what runtime
//! constraints apply. It is consulted by the kernel pipeline before every action
//! execution.

pub mod manifest;
pub(crate) mod manifest_types;
pub(crate) mod manifest_validate;
pub mod schema;
pub(crate) mod store;

pub use manifest::{ActionSpec, IoSchema, ManifestError, ProviderModule, TemplateConfig};
pub use schema::{compile_schema, SchemaError, ValidationLimits};
pub use store::{
    ActionSchemas, RegistryBuilder, RegistryStore, SkippedManifest, SourceKind, StoreError,
};
