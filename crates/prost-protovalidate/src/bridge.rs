//! Runtime bridge for validating wire-encoded messages through the
//! descriptor-driven [`Validator`].
//!
//! Used by `prost-protovalidate-build`'s `runtime_bridge` codegen mode (buffa
//! backend): messages whose rules the compile-time generator cannot cover
//! (CEL, predefined CEL, or shapes routed to the runtime) get an
//! `impl Validate` that encodes the message to protobuf wire bytes and
//! delegates here, reusing the full runtime engine — including the CEL
//! interpreter — instead of a second validation code path. Standard-only
//! messages keep their inline generated validators; only routed messages
//! reach this bridge.
//!
//! Reflection-gated: available only with the `reflect` feature (implied by
//! `cel`). CEL rules additionally require `cel`.
//!
//! The generated code references only this module's public surface
//! (`::prost_protovalidate::bridge::*`), so a consumer needs no direct
//! dependency on `prost-reflect`.

use prost_reflect::{DescriptorPool, DynamicMessage};

use crate::{
    Error, RuntimeError, ValidationError, Validator, ValidatorOption, Violation,
    normalize_edition_descriptor_set,
};

/// A descriptor pool plus a [`Validator`], built once from an embedded
/// `FileDescriptorSet` and reused across validations.
///
/// Construct once — typically in a `LazyLock` static emitted by the code
/// generator — and reuse: the inner [`Validator`] caches compiled evaluators
/// across calls.
pub struct RuntimeBridge {
    pool: DescriptorPool,
    validator: Validator,
}

impl RuntimeBridge {
    /// Build a bridge from raw `FileDescriptorSet` bytes.
    ///
    /// The bytes are edition-normalized (Edition 2023 → proto3, matching the
    /// runtime validator's decode pool) before the pool and validator are
    /// constructed — mirroring the conformance executor's suite setup. The
    /// same normalized bytes back both the decode pool and the validator's
    /// extension resolution.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor set cannot be decoded. The bytes are embedded
    /// at build time by `prost-protovalidate-build`, so a failure indicates a
    /// generator bug rather than runtime input.
    #[must_use]
    pub fn from_fds(fds: &[u8]) -> Self {
        let normalized = normalize_edition_descriptor_set(fds);
        let pool = DescriptorPool::decode(normalized.as_slice())
            .expect("prost-protovalidate bridge: embedded descriptor set must decode");
        let validator =
            Validator::with_options(&[ValidatorOption::AdditionalDescriptorSetBytes(normalized)]);
        Self { pool, validator }
    }

    /// Validate a wire-encoded message of type `full_name` against its
    /// `buf.validate` rules through the runtime [`Validator`].
    ///
    /// `wire_bytes` is the protobuf binary encoding of the message (e.g. from
    /// `buffa::Message::encode_to_vec`). The full [`Error`] is returned so
    /// callers that must distinguish `Compilation`/`Runtime` outcomes
    /// (conformance, diagnostics) can; the generated `Validate` impls collapse
    /// it to [`ValidationError`] via [`error_to_validation_error`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] for rule violations, or
    /// [`Error::Compilation`] / [`Error::Runtime`] when rule evaluation fails.
    /// Returns [`Error::Runtime`] if `full_name` is absent from the pool or the
    /// bytes fail to decode.
    pub fn validate_wire(&self, full_name: &str, wire_bytes: &[u8]) -> Result<(), Error> {
        let descriptor = self.pool.get_message_by_name(full_name).ok_or_else(|| {
            Error::Runtime(RuntimeError {
                cause: format!("bridge: message type `{full_name}` not found in descriptor pool"),
            })
        })?;
        let dynamic = DynamicMessage::decode(descriptor, wire_bytes).map_err(|e| {
            Error::Runtime(RuntimeError {
                cause: format!("bridge: failed to decode `{full_name}`: {e}"),
            })
        })?;
        self.validator.validate(&dynamic)
    }
}

/// Collapse a runtime [`Error`] into the [`ValidationError`] the
/// [`Validate`](crate::Validate) trait returns.
///
/// [`Error::Validation`] passes through unchanged. [`Error::Compilation`] and
/// [`Error::Runtime`] cannot be represented by the trait's return type, so they
/// surface as a single synthesized [`Violation`] carrying the error's cause
/// (empty `rule_id`) rather than silently succeeding — the same
/// known-limitation class as `bytes.pattern` on invalid UTF-8 in the
/// compile-time path. Callers needing to distinguish these should use
/// [`RuntimeBridge::validate_wire`] directly.
#[must_use]
pub fn error_to_validation_error(error: Error) -> ValidationError {
    match error {
        Error::Validation(err) => err,
        Error::Compilation(err) => ValidationError::single(Violation::new("", "", err.cause)),
        Error::Runtime(err) => ValidationError::single(Violation::new("", "", err.cause)),
    }
}
