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

use anyhow::anyhow;
use prost_reflect::{
    DynamicMessage, ExtensionDescriptor, FieldDescriptor, MessageDescriptor, OneofDescriptor,
};
use std::sync::LazyLock;

pub use proto::*;

// buf.validate extensions use field number 1159
#[allow(clippy::unwrap_used)]
static BUF_VALIDATE_MESSAGE: LazyLock<ExtensionDescriptor> = LazyLock::new(|| {
    DESCRIPTOR_POOL
        .get_extension_by_name("buf.validate.message")
        .ok_or(anyhow!("buf.validate.message extension not found"))
        .unwrap()
});

#[allow(clippy::unwrap_used)]
static BUF_VALIDATE_ONEOF: LazyLock<ExtensionDescriptor> = LazyLock::new(|| {
    DESCRIPTOR_POOL
        .get_extension_by_name("buf.validate.oneof")
        .ok_or(anyhow!("buf.validate.oneof extension not found"))
        .unwrap()
});

#[allow(clippy::unwrap_used)]
static BUF_VALIDATE_FIELD: LazyLock<ExtensionDescriptor> = LazyLock::new(|| {
    DESCRIPTOR_POOL
        .get_extension_by_name("buf.validate.field")
        .ok_or(anyhow!("buf.validate.field extension not found"))
        .unwrap()
});

#[allow(clippy::unwrap_used)]
static BUF_VALIDATE_PREDEFINED: LazyLock<ExtensionDescriptor> = LazyLock::new(|| {
    DESCRIPTOR_POOL
        .get_extension_by_name("buf.validate.predefined")
        .ok_or(anyhow!("buf.validate.predefined extension not found"))
        .unwrap()
});

/// Extension trait for extracting `buf.validate.field` rules from a field descriptor.
pub trait FieldConstraintsExt {
    /// Returns the `FieldRules` for this field, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `FieldRules`.
    fn field_constraints(&self) -> anyhow::Result<Option<FieldRules>>;

    /// Returns the real (non-synthetic) oneof containing this field, if any.
    fn real_oneof(&self) -> Option<OneofDescriptor>;

    /// Returns true if this field is proto3 optional (synthetic oneof).
    fn is_optional(&self) -> bool;
}

impl FieldConstraintsExt for FieldDescriptor {
    fn field_constraints(&self) -> anyhow::Result<Option<FieldRules>> {
        let options = self.options();
        if !options.has_extension(&BUF_VALIDATE_FIELD) {
            return Ok(None);
        }
        match options.get_extension(&BUF_VALIDATE_FIELD).as_message() {
            Some(r) => Ok(Some(r.transcode_to::<FieldRules>()?)),
            None => Ok(None),
        }
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
    /// Returns true if this oneof requires exactly one field to be set.
    fn is_required(&self) -> bool;
}

impl OneofConstraintsExt for OneofDescriptor {
    fn is_required(&self) -> bool {
        let options = self.options();
        if !options.has_extension(&BUF_VALIDATE_ONEOF) {
            return false;
        }
        options
            .get_extension(&BUF_VALIDATE_ONEOF)
            .as_message()
            .and_then(|msg| msg.transcode_to::<OneofRules>().ok())
            .is_some_and(|rules| rules.required.unwrap_or(false))
    }
}

/// Extension trait for extracting `buf.validate.message` rules from a message descriptor.
pub trait MessageConstraintsExt {
    /// Returns the `MessageRules` for this message, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `MessageRules`.
    fn message_constraints(&self) -> anyhow::Result<Option<MessageRules>>;
}

impl MessageConstraintsExt for MessageDescriptor {
    fn message_constraints(&self) -> anyhow::Result<Option<MessageRules>> {
        let options = self.options();
        if !options.has_extension(&BUF_VALIDATE_MESSAGE) {
            return Ok(None);
        }
        match options.get_extension(&BUF_VALIDATE_MESSAGE).as_message() {
            Some(r) => Ok(Some(r.transcode_to::<MessageRules>()?)),
            None => Ok(None),
        }
    }
}

/// Extension trait for extracting `buf.validate.predefined` rules from a field descriptor.
pub trait PredefinedConstraintsExt {
    /// Returns the `PredefinedRules` for this field, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension value cannot be transcoded to `PredefinedRules`.
    fn predefined_constraints(&self) -> anyhow::Result<Option<PredefinedRules>>;
}

impl PredefinedConstraintsExt for FieldDescriptor {
    fn predefined_constraints(&self) -> anyhow::Result<Option<PredefinedRules>> {
        let options = self.options();
        if !options.has_extension(&BUF_VALIDATE_PREDEFINED) {
            return Ok(None);
        }
        match options.get_extension(&BUF_VALIDATE_PREDEFINED).as_message() {
            Some(r) => Ok(Some(r.transcode_to::<PredefinedRules>()?)),
            None => Ok(None),
        }
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
        if !options.has_extension(&BUF_VALIDATE_FIELD) {
            return None;
        }
        options
            .get_extension(&BUF_VALIDATE_FIELD)
            .as_message()
            .cloned()
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
        if !options.has_extension(&BUF_VALIDATE_MESSAGE) {
            return None;
        }
        options
            .get_extension(&BUF_VALIDATE_MESSAGE)
            .as_message()
            .cloned()
    }
}
