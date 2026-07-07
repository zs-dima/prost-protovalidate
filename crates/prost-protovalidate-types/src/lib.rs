//! Generated Rust types for the [`buf.validate`](https://github.com/bufbuild/protovalidate)
//! protobuf schema, built with `prost` (and optionally `prost-reflect`).
//!
//! This crate provides:
//!
//! - All message and enum types from `buf/validate/validate.proto`
//!   (e.g. [`FieldRules`], [`MessageRules`], [`OneofRules`]).
//! - [`rules_meta`] — rule ids and violation-message templates shared by the
//!   runtime evaluator and the build-time code generator.
//!
//! With the **`reflect`** feature (default), it additionally provides:
//!
//! - A shared [`DESCRIPTOR_POOL`] containing the file descriptor set for
//!   runtime reflection.
//! - Extension traits for extracting constraint annotations from descriptors:
//!   - [`FieldConstraintsExt`] — `buf.validate.field` rules on a
//!     `FieldDescriptor`.
//!   - [`MessageConstraintsExt`] — `buf.validate.message` rules on a
//!     `MessageDescriptor`.
//!   - [`OneofConstraintsExt`] — `buf.validate.oneof` rules on a
//!     `OneofDescriptor`.
//!   - [`PredefinedConstraintsExt`] — `buf.validate.predefined` rules.
//!   - [`FieldConstraintsDynExt`] / [`MessageConstraintsDynExt`] — raw
//!     `DynamicMessage` access for the runtime validator.
//! - Typed helper functions for extension extraction with concrete error types:
//!   [`field_constraints_typed`], [`message_constraints_typed`],
//!   [`oneof_constraints_typed`], [`predefined_constraints_typed`].
//!
//! Disabling `reflect` yields a slim, reflection-free build — the generated
//! prost types plus [`rules_meta`] — for consumers that only run build-time
//! generated validators.
//!
//! # Usage
//!
//! Most users do not need this crate directly — the
//! [`prost-protovalidate`](https://crates.io/crates/prost-protovalidate) crate re-exports
//! everything required for validation via its `types` module. Use this crate when you only need the
//! generated types or descriptor pool without the evaluation engine.

#![warn(missing_docs)]

#[allow(
    missing_docs,
    clippy::len_without_is_empty,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::must_use_candidate
)]
mod proto;

#[cfg(feature = "reflect")]
mod constraints;

pub mod rules_meta;

pub use proto::*;

#[cfg(feature = "reflect")]
pub use constraints::*;

/// Error returned while decoding `buf.validate` descriptor extensions.
#[derive(Debug, thiserror::Error)]
pub enum ConstraintDecodeError {
    /// The generated descriptor pool could not be decoded.
    #[error("descriptor pool initialization failed: {0}")]
    DescriptorPoolInitialization(String),

    /// The expected extension descriptor is missing from the pool.
    #[error("missing extension descriptor `{0}`")]
    MissingExtension(&'static str),

    /// The extension payload could not be decoded into the typed rule.
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
}

/// Typed decode result for descriptor extension constraints.
pub type ConstraintDecodeResult<T> = Result<Option<T>, ConstraintDecodeError>;
