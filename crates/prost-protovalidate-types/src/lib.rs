//! Generated Rust types for the [`buf.validate`](https://github.com/bufbuild/protovalidate)
//! protobuf schema, built with `prost` and `prost-reflect`.
//!
//! This crate provides:
//!
//! - All message and enum types from `buf/validate/validate.proto`
//!   (e.g. [`FieldRules`], [`MessageRules`], [`OneofRules`]).
//! - A shared [`DESCRIPTOR_POOL`] containing the file descriptor set for
//!   runtime reflection.
//! - Extension traits for extracting constraint annotations from descriptors:
//!   - [`FieldConstraintsExt`] — `buf.validate.field` rules on a
//!     [`FieldDescriptor`].
//!   - [`MessageConstraintsExt`] — `buf.validate.message` rules on a
//!     [`MessageDescriptor`].
//!   - [`OneofConstraintsExt`] — `buf.validate.oneof` rules on a
//!     [`OneofDescriptor`].
//!   - [`PredefinedConstraintsExt`] — `buf.validate.predefined` rules.
//!   - [`FieldConstraintsDynExt`] / [`MessageConstraintsDynExt`] — raw
//!     [`DynamicMessage`] access for the
//!     runtime validator.
//! - Typed helper functions for extension extraction with concrete error types:
//!   [`field_constraints_typed`], [`message_constraints_typed`],
//!   [`oneof_constraints_typed`], [`predefined_constraints_typed`].
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

use std::sync::LazyLock;

use prost::Message;
use prost_reflect::{
    DynamicMessage, ExtensionDescriptor, FieldDescriptor, MessageDescriptor, OneofDescriptor,
};

pub use proto::*;

// buf.validate extensions use field number 1159
static BUF_VALIDATE_MESSAGE: LazyLock<Option<ExtensionDescriptor>> =
    LazyLock::new(|| DESCRIPTOR_POOL.get_extension_by_name("buf.validate.message"));

static BUF_VALIDATE_ONEOF: LazyLock<Option<ExtensionDescriptor>> =
    LazyLock::new(|| DESCRIPTOR_POOL.get_extension_by_name("buf.validate.oneof"));

static BUF_VALIDATE_FIELD: LazyLock<Option<ExtensionDescriptor>> =
    LazyLock::new(|| DESCRIPTOR_POOL.get_extension_by_name("buf.validate.field"));

static BUF_VALIDATE_PREDEFINED: LazyLock<Option<ExtensionDescriptor>> =
    LazyLock::new(|| DESCRIPTOR_POOL.get_extension_by_name("buf.validate.predefined"));

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

fn decode_extension_constraints<T>(
    options: &DynamicMessage,
    extension_name: &'static str,
    extension: &'static LazyLock<Option<ExtensionDescriptor>>,
) -> ConstraintDecodeResult<T>
where
    T: Message + Default,
{
    let extension = resolve_extension_descriptor(extension_name, extension)?;
    if !options.has_extension(extension) {
        return Ok(None);
    }
    match options.get_extension(extension).as_message() {
        Some(message) => message.transcode_to::<T>().map(Some).map_err(Into::into),
        None => Ok(None),
    }
}

fn resolve_extension_descriptor(
    extension_name: &'static str,
    extension: &'static LazyLock<Option<ExtensionDescriptor>>,
) -> Result<&'static ExtensionDescriptor, ConstraintDecodeError> {
    if let Some(err) = descriptor_pool_decode_error() {
        return Err(ConstraintDecodeError::DescriptorPoolInitialization(
            err.to_string(),
        ));
    }

    extension
        .as_ref()
        .ok_or(ConstraintDecodeError::MissingExtension(extension_name))
}

/// Typed helper for extracting `buf.validate.field` rules from a field descriptor.
///
/// Prefer this API when you need a concrete, non-erased error type.
///
/// # Errors
///
/// Returns an error if the extension value cannot be transcoded to `FieldRules`.
pub fn field_constraints_typed(field: &FieldDescriptor) -> ConstraintDecodeResult<FieldRules> {
    let options = field.options();
    decode_extension_constraints(&options, "buf.validate.field", &BUF_VALIDATE_FIELD)
}

/// Typed helper for extracting `buf.validate.oneof` rules from a oneof descriptor.
///
/// # Errors
///
/// Returns an error if the extension value cannot be transcoded to `OneofRules`.
pub fn oneof_constraints_typed(oneof: &OneofDescriptor) -> ConstraintDecodeResult<OneofRules> {
    let options = oneof.options();
    decode_extension_constraints(&options, "buf.validate.oneof", &BUF_VALIDATE_ONEOF)
}

/// Typed helper for extracting `buf.validate.message` rules from a message descriptor.
///
/// Prefer this API when you need a concrete, non-erased error type.
///
/// # Errors
///
/// Returns an error if the extension value cannot be transcoded to `MessageRules`.
pub fn message_constraints_typed(
    message: &MessageDescriptor,
) -> ConstraintDecodeResult<MessageRules> {
    let options = message.options();
    decode_extension_constraints(&options, "buf.validate.message", &BUF_VALIDATE_MESSAGE)
}

/// Typed helper for extracting `buf.validate.predefined` rules from a field descriptor.
///
/// Prefer this API when you need a concrete, non-erased error type.
///
/// # Errors
///
/// Returns an error if the extension value cannot be transcoded to `PredefinedRules`.
pub fn predefined_constraints_typed(
    field: &FieldDescriptor,
) -> ConstraintDecodeResult<PredefinedRules> {
    let options = field.options();
    decode_extension_constraints(
        &options,
        "buf.validate.predefined",
        &BUF_VALIDATE_PREDEFINED,
    )
}

/// Extension trait for extracting `buf.validate.field` rules from a field descriptor.
pub trait FieldConstraintsExt {
    /// Returns the `FieldRules` for this field, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `FieldRules`.
    fn field_constraints(&self) -> ConstraintDecodeResult<FieldRules>;

    /// Returns the real (non-synthetic) oneof containing this field, if any.
    fn real_oneof(&self) -> Option<OneofDescriptor>;

    /// Returns true if this field is proto3 optional (synthetic oneof).
    fn is_optional(&self) -> bool;
}

impl FieldConstraintsExt for FieldDescriptor {
    fn field_constraints(&self) -> ConstraintDecodeResult<FieldRules> {
        field_constraints_typed(self)
    }

    fn real_oneof(&self) -> Option<OneofDescriptor> {
        self.containing_oneof().filter(|o| !o.is_synthetic())
    }

    fn is_optional(&self) -> bool {
        self.containing_oneof().is_some_and(|d| d.is_synthetic())
    }
}

/// Extension trait for extracting `buf.validate.oneof` rules from a oneof descriptor.
pub trait OneofConstraintsExt {
    /// Returns the `OneofRules` for this oneof, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `OneofRules`.
    fn oneof_constraints(&self) -> ConstraintDecodeResult<OneofRules>;

    /// Returns true if this oneof requires exactly one field to be set.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `OneofRules`.
    fn try_is_required(&self) -> Result<bool, ConstraintDecodeError> {
        Ok(self
            .oneof_constraints()?
            .is_some_and(|rules| rules.required.unwrap_or(false)))
    }
}

impl OneofConstraintsExt for OneofDescriptor {
    fn oneof_constraints(&self) -> ConstraintDecodeResult<OneofRules> {
        oneof_constraints_typed(self)
    }
}

/// Extension trait for extracting `buf.validate.message` rules from a message descriptor.
pub trait MessageConstraintsExt {
    /// Returns the `MessageRules` for this message, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `MessageRules`.
    fn message_constraints(&self) -> ConstraintDecodeResult<MessageRules>;
}

impl MessageConstraintsExt for MessageDescriptor {
    fn message_constraints(&self) -> ConstraintDecodeResult<MessageRules> {
        message_constraints_typed(self)
    }
}

/// Extension trait for extracting `buf.validate.predefined` rules from a field descriptor.
pub trait PredefinedConstraintsExt {
    /// Returns the `PredefinedRules` for this field, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `PredefinedRules`.
    fn predefined_constraints(&self) -> ConstraintDecodeResult<PredefinedRules>;
}

impl PredefinedConstraintsExt for FieldDescriptor {
    fn predefined_constraints(&self) -> ConstraintDecodeResult<PredefinedRules> {
        predefined_constraints_typed(self)
    }
}

/// Extension trait for extracting the `DynamicMessage` form of field constraints.
/// This is useful for the runtime validator which needs to read rule fields dynamically.
pub trait FieldConstraintsDynExt {
    /// Returns the raw `DynamicMessage` for the `buf.validate.field` extension.
    fn field_constraints_dynamic(&self) -> Option<DynamicMessage>;
}

impl FieldConstraintsDynExt for FieldDescriptor {
    fn field_constraints_dynamic(&self) -> Option<DynamicMessage> {
        let options = self.options();
        let Ok(extension) = resolve_extension_descriptor("buf.validate.field", &BUF_VALIDATE_FIELD)
        else {
            return None;
        };
        if !options.has_extension(extension) {
            return None;
        }
        options.get_extension(extension).as_message().cloned()
    }
}

/// Extension trait for extracting the `DynamicMessage` form of message constraints.
pub trait MessageConstraintsDynExt {
    /// Returns the raw `DynamicMessage` for the `buf.validate.message` extension.
    fn message_constraints_dynamic(&self) -> Option<DynamicMessage>;
}

impl MessageConstraintsDynExt for MessageDescriptor {
    fn message_constraints_dynamic(&self) -> Option<DynamicMessage> {
        let options = self.options();
        let Ok(extension) =
            resolve_extension_descriptor("buf.validate.message", &BUF_VALIDATE_MESSAGE)
        else {
            return None;
        };
        if !options.has_extension(extension) {
            return None;
        }
        options.get_extension(extension).as_message().cloned()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn descriptor_field(message: &str, field: &str) -> FieldDescriptor {
        DESCRIPTOR_POOL
            .get_message_by_name(message)
            .and_then(|message| message.get_field_by_name(field))
            .expect("descriptor field must exist")
    }

    #[test]
    fn typed_helpers_return_none_when_extension_is_absent() {
        let field = descriptor_field("buf.validate.FieldRules", "required");
        let message = DESCRIPTOR_POOL
            .get_message_by_name("buf.validate.FieldRules")
            .expect("message must exist");
        let oneof = message
            .oneofs()
            .find(|oneof| oneof.name() == "type")
            .expect("oneof must exist");

        assert_eq!(field_constraints_typed(&field).ok().flatten(), None);
        assert_eq!(message_constraints_typed(&message).ok().flatten(), None);
        assert_eq!(oneof_constraints_typed(&oneof).ok().flatten(), None);
    }

    #[test]
    fn typed_predefined_helper_decodes_known_extension() {
        let field = descriptor_field("buf.validate.RepeatedRules", "min_items");
        let rules = predefined_constraints_typed(&field)
            .expect("predefined extension should decode")
            .expect("predefined extension should be present");
        assert!(!rules.cel.is_empty());
    }
}
