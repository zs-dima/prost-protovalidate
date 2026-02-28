pub(crate) mod bool;
pub(crate) mod bytes;
pub(crate) mod duration;
pub(crate) mod enum_rules;
pub(crate) mod field_mask;
pub(crate) mod map_rules;
pub(crate) mod number;
pub(crate) mod repeated;
pub(crate) mod string;
pub(crate) mod timestamp;

use prost_reflect::{DynamicMessage, FieldDescriptor};

use prost_protovalidate_types::FieldRules;

use crate::error::{CompilationError, Error};

use super::evaluator::Evaluator;

/// A standard-rules evaluator built from the type-specific oneof in `FieldRules`.
/// Stores pre-computed checks for fast runtime evaluation.
pub(crate) enum StandardRuleEval {
    Float(number::FloatRuleEval),
    Double(number::DoubleRuleEval),
    Int32(number::Int32RuleEval),
    Int64(number::Int64RuleEval),
    UInt32(number::UInt32RuleEval),
    UInt64(number::UInt64RuleEval),
    SInt32(number::SInt32RuleEval),
    SInt64(number::SInt64RuleEval),
    Fixed32(number::Fixed32RuleEval),
    Fixed64(number::Fixed64RuleEval),
    SFixed32(number::SFixed32RuleEval),
    SFixed64(number::SFixed64RuleEval),
    Bool(self::bool::BoolRuleEval),
    String(self::string::StringRuleEval),
    Bytes(bytes::BytesRuleEval),
    Enum(enum_rules::EnumRuleEval),
    Repeated(repeated::RepeatedRuleEval),
    Map(map_rules::MapRuleEval),
    Timestamp(timestamp::TimestampRuleEval),
    Duration(duration::DurationRuleEval),
    FieldMask(field_mask::FieldMaskRuleEval),
}

impl Evaluator for StandardRuleEval {
    fn tautology(&self) -> bool {
        match self {
            Self::Float(e) => e.tautology(),
            Self::Double(e) => e.tautology(),
            Self::Int32(e) => e.tautology(),
            Self::Int64(e) => e.tautology(),
            Self::UInt32(e) => e.tautology(),
            Self::UInt64(e) => e.tautology(),
            Self::SInt32(e) => e.tautology(),
            Self::SInt64(e) => e.tautology(),
            Self::Fixed32(e) => e.tautology(),
            Self::Fixed64(e) => e.tautology(),
            Self::SFixed32(e) => e.tautology(),
            Self::SFixed64(e) => e.tautology(),
            Self::Bool(e) => e.tautology(),
            Self::String(e) => e.tautology(),
            Self::Bytes(e) => e.tautology(),
            Self::Enum(e) => e.tautology(),
            Self::Repeated(e) => e.tautology(),
            Self::Map(e) => e.tautology(),
            Self::Timestamp(e) => e.tautology(),
            Self::Duration(e) => e.tautology(),
            Self::FieldMask(e) => e.tautology(),
        }
    }

    fn evaluate(
        &self,
        _msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &crate::config::ValidationConfig,
    ) -> Result<(), Error> {
        match self {
            Self::Float(e) => e.evaluate(val, cfg),
            Self::Double(e) => e.evaluate(val, cfg),
            Self::Int32(e) => e.evaluate(val, cfg),
            Self::Int64(e) => e.evaluate(val, cfg),
            Self::UInt32(e) => e.evaluate(val, cfg),
            Self::UInt64(e) => e.evaluate(val, cfg),
            Self::SInt32(e) => e.evaluate(val, cfg),
            Self::SInt64(e) => e.evaluate(val, cfg),
            Self::Fixed32(e) => e.evaluate(val, cfg),
            Self::Fixed64(e) => e.evaluate(val, cfg),
            Self::SFixed32(e) => e.evaluate(val, cfg),
            Self::SFixed64(e) => e.evaluate(val, cfg),
            Self::Bool(e) => e.evaluate(val, cfg),
            Self::String(e) => e.evaluate(val, cfg),
            Self::Bytes(e) => e.evaluate(val, cfg),
            Self::Enum(e) => e.evaluate(val, cfg),
            Self::Repeated(e) => e.evaluate(val, cfg),
            Self::Map(e) => e.evaluate(val, cfg),
            Self::Timestamp(e) => e.evaluate(val, cfg),
            Self::Duration(e) => e.evaluate(val, cfg),
            Self::FieldMask(e) => e.evaluate(val, cfg),
        }
    }
}

/// Build a `StandardRuleEval` from `FieldRules` for the given field kind.
pub(crate) fn build_standard_rules(
    field_rules: &FieldRules,
    _field_desc: &FieldDescriptor,
) -> Result<Option<StandardRuleEval>, CompilationError> {
    use prost_protovalidate_types::field_rules::Type;

    let Some(rule_type) = &field_rules.r#type else {
        return Ok(None);
    };

    let eval = match rule_type {
        Type::Float(r) => StandardRuleEval::Float(number::FloatRuleEval::new(r)),
        Type::Double(r) => StandardRuleEval::Double(number::DoubleRuleEval::new(r)),
        Type::Int32(r) => StandardRuleEval::Int32(number::Int32RuleEval::new(r)),
        Type::Int64(r) => StandardRuleEval::Int64(number::Int64RuleEval::new(r)),
        Type::Uint32(r) => StandardRuleEval::UInt32(number::UInt32RuleEval::new(r)),
        Type::Uint64(r) => StandardRuleEval::UInt64(number::UInt64RuleEval::new(r)),
        Type::Sint32(r) => StandardRuleEval::SInt32(number::SInt32RuleEval::new(r)),
        Type::Sint64(r) => StandardRuleEval::SInt64(number::SInt64RuleEval::new(r)),
        Type::Fixed32(r) => StandardRuleEval::Fixed32(number::Fixed32RuleEval::new(r)),
        Type::Fixed64(r) => StandardRuleEval::Fixed64(number::Fixed64RuleEval::new(r)),
        Type::Sfixed32(r) => StandardRuleEval::SFixed32(number::SFixed32RuleEval::new(r)),
        Type::Sfixed64(r) => StandardRuleEval::SFixed64(number::SFixed64RuleEval::new(r)),
        Type::Bool(r) => StandardRuleEval::Bool(self::bool::BoolRuleEval::new(r)),
        Type::String(r) => StandardRuleEval::String(self::string::StringRuleEval::new(r)?),
        Type::Bytes(r) => StandardRuleEval::Bytes(bytes::BytesRuleEval::new(r)?),
        Type::Enum(r) => StandardRuleEval::Enum(enum_rules::EnumRuleEval::new(r)),
        Type::Repeated(r) => StandardRuleEval::Repeated(repeated::RepeatedRuleEval::new(r)),
        Type::Map(r) => StandardRuleEval::Map(map_rules::MapRuleEval::new(r)),
        Type::Timestamp(r) => StandardRuleEval::Timestamp(timestamp::TimestampRuleEval::new(r)),
        Type::Duration(r) => StandardRuleEval::Duration(duration::DurationRuleEval::new(r)),
        Type::FieldMask(r) => StandardRuleEval::FieldMask(field_mask::FieldMaskRuleEval::new(r)),
        Type::Any(_) => return Ok(None),
    };

    Ok(Some(eval))
}
