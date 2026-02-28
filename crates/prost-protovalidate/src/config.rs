use std::sync::Arc;

use prost_reflect::{
    DynamicMessage, FieldDescriptor, MessageDescriptor, OneofDescriptor, ReflectMessage,
};
use prost_types::Timestamp;

/// Options for configuring the `Validator` at construction time.
#[non_exhaustive]
pub enum ValidatorOption {
    /// Stop validation on the first violation instead of collecting all.
    FailFast,

    /// Disable lazy compilation: all known message types must be
    /// pre-registered, and unknown types will produce a compilation error.
    DisableLazy,

    /// Override the function used to populate `now` in timestamp-based rules/CEL.
    NowFn(Arc<dyn Fn() -> Timestamp + Send + Sync>),

    /// Additional encoded `FileDescriptorSet` payloads used to resolve
    /// custom/proprietary rule extensions at runtime.
    AdditionalDescriptorSetBytes(Vec<u8>),

    /// Preload evaluators for these descriptors at validator construction time.
    /// Useful with `DisableLazy` to allow a fixed set of message types.
    MessageDescriptors(Vec<MessageDescriptor>),

    /// Allow unknown fields in constraint messages instead of producing a
    /// compilation error. Useful when working with newer constraint protos
    /// that contain fields not yet recognized by this library.
    AllowUnknownFields,
}

/// Options for configuring a single `Validator::validate_with` call.
#[non_exhaustive]
pub enum ValidationOption {
    /// Stop validation on the first violation instead of collecting all.
    FailFast,
    /// Override the filter for this validation call.
    Filter(Arc<dyn Filter>),
    /// Override the function used to populate `now` in timestamp-based rules/CEL.
    NowFn(Arc<dyn Fn() -> Timestamp + Send + Sync>),
}

/// Controls which fields/messages are validated.
pub trait Filter: Send + Sync {
    /// Returns true if the given message should be validated.
    fn should_validate(&self, message: &DynamicMessage, descriptor: &MessageDescriptor) -> bool;

    /// Returns true if the given field should be validated.
    /// Defaults to message-level filtering for compatibility.
    fn should_validate_field(&self, message: &DynamicMessage, _field: &FieldDescriptor) -> bool {
        let descriptor = message.descriptor();
        self.should_validate(message, &descriptor)
    }

    /// Returns true if the given oneof should be validated.
    /// Defaults to message-level filtering for compatibility.
    fn should_validate_oneof(&self, message: &DynamicMessage, _oneof: &OneofDescriptor) -> bool {
        let descriptor = message.descriptor();
        self.should_validate(message, &descriptor)
    }
}

/// A filter that always validates everything.
pub(crate) struct NopFilter;

impl Filter for NopFilter {
    fn should_validate(&self, _message: &DynamicMessage, _descriptor: &MessageDescriptor) -> bool {
        true
    }
}

/// Runtime configuration passed to evaluators during validation.
pub(crate) struct ValidationConfig {
    pub fail_fast: bool,
    pub filter: Arc<dyn Filter>,
    pub now_fn: Arc<dyn Fn() -> Timestamp + Send + Sync>,
}

/// Default timestamp factory using `SystemTime::now()`.
///
/// Shared by `ValidationConfig::default()` and `Validator::with_options()`.
pub(crate) fn default_now_fn() -> Arc<dyn Fn() -> Timestamp + Send + Sync> {
    Arc::new(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // Both casts are semantically safe:
        // - as_secs() since UNIX_EPOCH fits in i64 for billions of years
        // - subsec_nanos() is always < 1_000_000_000 which fits in i32
        #[allow(clippy::cast_possible_wrap)]
        Timestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        }
    })
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            fail_fast: false,
            filter: Arc::new(NopFilter),
            now_fn: default_now_fn(),
        }
    }
}
