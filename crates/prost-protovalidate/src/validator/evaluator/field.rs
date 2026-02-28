use prost_reflect::{DynamicMessage, ReflectMessage};
use std::sync::LazyLock;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

use super::MessageEvaluator;
use super::value::ValueEval;

static REQUIRED_RULE_DESCRIPTOR: LazyLock<prost_reflect::FieldDescriptor> = LazyLock::new(|| {
    prost_protovalidate_types::FieldRules::default()
        .descriptor()
        .get_field_by_name("required")
        .expect("field rules descriptor must contain `required`")
});

/// Evaluator for a single message field.
/// Handles required checks, ignore logic, and delegates to value evaluation.
pub(crate) struct FieldEval {
    /// The value evaluator for this field.
    pub value: ValueEval,

    /// Whether the field must be set.
    pub required: bool,

    /// Whether the field tracks presence (proto3 optional, oneof member, message field).
    pub has_presence: bool,

    /// Whether the field is proto2-required or editions `LEGACY_REQUIRED`.
    /// Such fields are always considered present on the wire,
    /// so `required` is always satisfied and `ignore_empty` never triggers.
    pub is_legacy_required: bool,

    /// The ignore behavior for this field.
    pub ignore: IgnoreMode,

    /// Compilation error for this field, if any.
    pub err: Option<crate::error::CompilationError>,
}

/// How a field's validation should be skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum IgnoreMode {
    /// Default: ignore rules if field tracks presence and is unset.
    #[default]
    Unspecified,
    /// Always skip validation for this field.
    Always,
    /// Skip validation if the field value is the zero value.
    IfZeroValue,
}

impl FieldEval {
    fn should_ignore_always(&self) -> bool {
        self.ignore == IgnoreMode::Always
    }

    fn should_ignore_empty(&self) -> bool {
        self.has_presence || self.ignore == IgnoreMode::IfZeroValue
    }
}

impl MessageEvaluator for FieldEval {
    fn tautology(&self) -> bool {
        !self.required && self.value.tautology() && self.err.is_none()
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        if self.should_ignore_always() {
            return Ok(());
        }

        let field_desc = &self.value.descriptor;
        let field_name = field_desc.name().to_string();

        if !cfg.filter.should_validate_field(msg, field_desc) {
            return Ok(());
        }

        if let Some(ref err) = self.err {
            return Err(crate::error::CompilationError {
                cause: err.cause.clone(),
            }
            .into());
        }

        // Legacy-required fields (proto2 required / editions LEGACY_REQUIRED)
        // are always considered "present" on the wire.
        let field_is_set = self.is_legacy_required || msg.has_field(field_desc);

        // Check required
        if self.required && !field_is_set {
            return Err(ValidationError::single(
                Violation::new(&field_name, "required", "value is required")
                    .with_rule_descriptor(REQUIRED_RULE_DESCRIPTOR.clone())
                    .with_rule_value(prost_reflect::Value::Bool(true))
                    .with_field_descriptor(field_desc),
            )
            .into());
        }

        // Check ignore-empty: skip if field has presence, is unset, and not legacy-required
        if self.should_ignore_empty() && !field_is_set {
            return Ok(());
        }

        let val = msg.get_field(field_desc);
        let result = self.value.evaluate_value(msg, &val, cfg, &field_name);
        enrich_field_violations(result, field_desc, &val)
    }
}

fn enrich_field_violations(
    result: Result<(), Error>,
    field_desc: &prost_reflect::FieldDescriptor,
    value: &prost_reflect::Value,
) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(Error::Validation(mut ve)) => {
            for violation in &mut ve.violations {
                let mut updated: Option<crate::violation::Violation> = None;
                if violation.field_descriptor.is_none() {
                    let current = updated.take().unwrap_or_else(|| violation.clone());
                    updated = Some(current.with_field_descriptor(field_desc));
                }
                if violation.field_value.is_none() {
                    let current = updated.take().unwrap_or_else(|| violation.clone());
                    updated = Some(current.with_field_value(value.clone()));
                }
                if let Some(updated) = updated {
                    *violation = updated;
                }
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}
