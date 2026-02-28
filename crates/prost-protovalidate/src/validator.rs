use prost_reflect::ReflectMessage;
use std::sync::LazyLock;

use crate::config::{NopFilter, ValidationConfig, ValidationOption, ValidatorOption};
use crate::error::Error;

mod builder;
pub(crate) mod editions;
mod evaluator;
mod lookups;
mod rules;

use builder::Builder;
use evaluator::MessageEvaluator;

/// Thread-safe validator for Protocol Buffer messages.
///
/// Validates messages against `buf.validate` rules extracted from proto descriptors.
/// Evaluators are compiled lazily and cached for reuse.
pub struct Validator {
    builder: Builder,
    config: ValidationConfig,
}

impl Validator {
    /// Create a new `Validator` with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: Builder::new(),
            config: ValidationConfig::default(),
        }
    }

    /// Create a new `Validator` with the given options.
    #[must_use]
    pub fn with_options(options: &[ValidatorOption]) -> Self {
        let mut fail_fast = false;
        let mut disable_lazy = false;
        let mut allow_unknown_fields = false;
        let mut additional_descriptor_sets = Vec::new();
        let mut message_descriptors = Vec::new();
        let mut now_fn = crate::config::default_now_fn();

        for opt in options {
            match opt {
                ValidatorOption::FailFast => fail_fast = true,
                ValidatorOption::DisableLazy => disable_lazy = true,
                ValidatorOption::AllowUnknownFields => allow_unknown_fields = true,
                ValidatorOption::NowFn(f) => now_fn = std::sync::Arc::clone(f),
                ValidatorOption::AdditionalDescriptorSetBytes(bytes) => {
                    additional_descriptor_sets.push(bytes.clone());
                }
                ValidatorOption::MessageDescriptors(descriptors) => {
                    message_descriptors.extend(descriptors.iter().cloned());
                }
            }
        }

        let builder = Builder::with_config(
            !disable_lazy,
            allow_unknown_fields,
            &additional_descriptor_sets,
        );
        for descriptor in &message_descriptors {
            builder.preload(descriptor);
        }

        Self {
            builder,
            config: ValidationConfig {
                fail_fast,
                filter: std::sync::Arc::new(NopFilter),
                now_fn,
            },
        }
    }

    /// Validate a message against its `buf.validate` rules.
    ///
    /// # Errors
    ///
    /// Returns an `Error` containing all constraint violations found, or a
    /// compilation/runtime error if rule evaluation fails.
    pub fn validate<M: ReflectMessage>(&self, msg: &M) -> Result<(), Error> {
        self.validate_with(msg, &[])
    }

    /// Validate a message with per-call validation options.
    ///
    /// # Errors
    ///
    /// Returns an `Error` containing all constraint violations found, or a
    /// compilation/runtime error if rule evaluation fails.
    pub fn validate_with<M: ReflectMessage>(
        &self,
        msg: &M,
        options: &[ValidationOption],
    ) -> Result<(), Error> {
        let dynamic = msg.transcode_to_dynamic();
        let descriptor = dynamic.descriptor();
        let eval = self.builder.load_or_build(&descriptor);
        let cfg = effective_config(&self.config, options);
        eval.evaluate_message(&dynamic, &cfg)
    }
}

fn effective_config(base: &ValidationConfig, options: &[ValidationOption]) -> ValidationConfig {
    let mut cfg = ValidationConfig {
        fail_fast: base.fail_fast,
        filter: std::sync::Arc::clone(&base.filter),
        now_fn: std::sync::Arc::clone(&base.now_fn),
    };

    for option in options {
        match option {
            ValidationOption::FailFast => cfg.fail_fast = true,
            ValidationOption::Filter(filter) => cfg.filter = std::sync::Arc::clone(filter),
            ValidationOption::NowFn(now_fn) => cfg.now_fn = std::sync::Arc::clone(now_fn),
        }
    }

    cfg
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

static GLOBAL_VALIDATOR: LazyLock<Validator> = LazyLock::new(Validator::new);

/// Validate a message using a global `Validator` instance.
///
/// This is a convenience function that uses a shared, lazily-initialized
/// validator. For lower memory usage, prefer using a single `Validator`
/// instance rather than creating multiple instances.
///
/// # Errors
///
/// Returns an `Error` containing all constraint violations found, or a
/// compilation/runtime error if rule evaluation fails.
pub fn validate<M: ReflectMessage>(msg: &M) -> Result<(), Error> {
    GLOBAL_VALIDATOR.validate(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Filter;
    use pretty_assertions::assert_eq;
    use prost_reflect::{DynamicMessage, MessageDescriptor, ReflectMessage};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DenyFilter;

    impl Filter for DenyFilter {
        fn should_validate(
            &self,
            _message: &DynamicMessage,
            _descriptor: &MessageDescriptor,
        ) -> bool {
            false
        }
    }

    struct RuntimeFilter {
        seen_required_true: Arc<AtomicBool>,
    }

    impl Filter for RuntimeFilter {
        fn should_validate(
            &self,
            message: &DynamicMessage,
            _descriptor: &MessageDescriptor,
        ) -> bool {
            let Some(required) = message.descriptor().get_field_by_name("required") else {
                return true;
            };

            let required_is_true = message.get_field(&required).as_bool() == Some(true);
            if required_is_true {
                self.seen_required_true.store(true, Ordering::Relaxed);
            }
            !required_is_true
        }
    }

    #[test]
    fn validation_options_override_call_config_only() {
        let base = ValidationConfig::default();
        let now_fn: Arc<dyn Fn() -> prost_types::Timestamp + Send + Sync> =
            Arc::new(|| prost_types::Timestamp {
                seconds: 123,
                nanos: 456,
            });
        let options = vec![
            ValidationOption::FailFast,
            ValidationOption::Filter(Arc::new(DenyFilter)),
            ValidationOption::NowFn(Arc::clone(&now_fn)),
        ];

        let effective = effective_config(&base, &options);
        let descriptor = prost_protovalidate_types::DESCRIPTOR_POOL
            .get_message_by_name("buf.validate.FieldRules")
            .expect("message descriptor exists");
        let dynamic = prost_reflect::DynamicMessage::new(descriptor.clone());

        assert!(effective.fail_fast);
        assert_eq!((effective.now_fn)().seconds, 123);
        assert!(!effective.filter.should_validate(&dynamic, &descriptor));

        assert!(!base.fail_fast);
    }

    #[test]
    fn validate_with_keeps_existing_validate_behavior() {
        let validator = Validator::new();
        let msg = prost_protovalidate_types::BoolRules::default();

        assert!(validator.validate(&msg).is_ok());
        assert!(
            validator
                .validate_with(&msg, &[ValidationOption::FailFast])
                .is_ok()
        );
    }

    #[test]
    fn invalid_additional_descriptor_set_surfaces_compilation_error() {
        let validator =
            Validator::with_options(&[ValidatorOption::AdditionalDescriptorSetBytes(vec![
                0x01, 0x02, 0x03,
            ])]);
        let msg = prost_protovalidate_types::BoolRules::default();

        match validator.validate(&msg) {
            Ok(()) => panic!("invalid descriptor set bytes must fail validator initialization"),
            Err(Error::Compilation(err)) => {
                assert!(
                    err.cause
                        .contains("failed to decode additional descriptor set at index 0")
                );
            }
            Err(other) => panic!("unexpected error type: {other}"),
        }
    }

    #[test]
    fn invalid_additional_descriptor_set_never_panics() {
        let result = std::panic::catch_unwind(|| {
            let validator = Validator::with_options(&[
                ValidatorOption::AdditionalDescriptorSetBytes(vec![0x01, 0x02, 0x03]),
            ]);
            let msg = prost_protovalidate_types::BoolRules::default();
            validator.validate(&msg)
        });

        let validation_result = result.expect("invalid descriptor sets must not panic");
        match validation_result {
            Ok(()) => panic!("invalid descriptor set bytes must fail validator initialization"),
            Err(Error::Compilation(err)) => {
                assert!(
                    err.cause
                        .contains("failed to decode additional descriptor set at index 0")
                );
            }
            Err(other) => panic!("unexpected error type: {other}"),
        }
    }

    #[test]
    fn valid_additional_descriptor_set_keeps_validator_operational() {
        let descriptor_bytes = Vec::new();
        let validator = Validator::with_options(&[ValidatorOption::AdditionalDescriptorSetBytes(
            descriptor_bytes,
        )]);
        let msg = prost_protovalidate_types::BoolRules::default();

        assert!(validator.validate(&msg).is_ok());
    }

    #[test]
    fn message_descriptor_preload_supports_disable_lazy_with_known_messages() {
        let descriptor = prost_protovalidate_types::BoolRules::default().descriptor();
        let validator = Validator::with_options(&[
            ValidatorOption::MessageDescriptors(vec![descriptor]),
            ValidatorOption::DisableLazy,
        ]);
        let msg = prost_protovalidate_types::BoolRules::default();

        // BoolRules has no constraints on itself, so validation should pass
        assert!(validator.validate(&msg).is_ok());
    }

    #[test]
    fn runtime_filter_can_skip_based_on_message_content() {
        let validator = Validator::new();
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let mut msg = prost_reflect::DynamicMessage::new(descriptor.clone());
        let seen_required_true = Arc::new(AtomicBool::new(false));
        let required = descriptor
            .get_field_by_name("required")
            .expect("required field exists");
        msg.set_field(&required, prost_reflect::Value::Bool(true));

        assert!(
            validator
                .validate_with(
                    &msg,
                    &[ValidationOption::Filter(Arc::new(RuntimeFilter {
                        seen_required_true: Arc::clone(&seen_required_true),
                    }))],
                )
                .is_ok()
        );
        assert!(seen_required_true.load(Ordering::Relaxed));
    }
}
