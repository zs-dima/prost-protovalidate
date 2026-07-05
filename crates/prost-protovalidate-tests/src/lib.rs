#![allow(clippy::all, warnings)]

pub mod parity {
    include!(concat!(env!("OUT_DIR"), "/parity.rs"));
}

// Generated `impl Validate` blocks (references `parity::*` types).
include!(concat!(env!("OUT_DIR"), "/validate_impl.rs"));

/// Embedded file descriptor set for the test protos.
pub static FILE_DESCRIPTOR_SET_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

/// Type-erased entry point to a generated `Validate` impl: decodes the
/// concrete prost message from bytes and runs build-time validation.
pub type ValidateFn = fn(&[u8]) -> Result<(), prost_protovalidate::ValidationError>;

macro_rules! parity_entry {
    ($full_name:literal, $ty:ty) => {{
        fn run(bytes: &[u8]) -> Result<(), prost_protovalidate::ValidationError> {
            use prost::Message as _;
            use prost_protovalidate::Validate as _;
            <$ty>::decode(bytes)
                .expect("parity sweep vectors must decode into the concrete type")
                .validate()
        }
        ($full_name, run as ValidateFn)
    }};
}

/// Messages that intentionally have no generated `Validate` impl — either
/// routed to the runtime validator by the capability analyzer (CEL,
/// unsupported shapes) or carrying no rules at all. Kept next to
/// [`PARITY_REGISTRY`] so `tests/registry_coverage.rs` can prove every
/// message in the test protos is a conscious decision, not an omission.
pub static ROUTED_TO_RUNTIME: &[&str] = &[];

/// Every test message with a generated `Validate` impl, keyed by proto full
/// name. `tests/registry_coverage.rs` asserts completeness against the
/// descriptor set; `tests/parity_sweep.rs` drives both validation paths
/// through each entry and requires identical violations.
pub static PARITY_REGISTRY: &[(&str, ValidateFn)] = &[
    parity_entry!("parity.AnyTypeUrl", parity::AnyTypeUrl),
    parity_entry!("parity.Inner", parity::Inner),
    parity_entry!("parity.ParityTest", parity::ParityTest),
    parity_entry!("parity.ConstInTest", parity::ConstInTest),
    parity_entry!("parity.EqualRangeBounds", parity::EqualRangeBounds),
    parity_entry!("parity.FieldMaskTest", parity::FieldMaskTest),
    parity_entry!("parity.OptionalScalars", parity::OptionalScalars),
    parity_entry!("parity.KeywordFields", parity::KeywordFields),
    parity_entry!("parity.BytesContainsEmpty", parity::BytesContainsEmpty),
    parity_entry!(
        "parity.EnumDefinedOnlyContainers",
        parity::EnumDefinedOnlyContainers
    ),
    parity_entry!("parity.MapStringInner", parity::MapStringInner),
    parity_entry!("parity.MapKeyRules", parity::MapKeyRules),
    parity_entry!("parity.AllNumericTypes", parity::AllNumericTypes),
    parity_entry!("parity.StringRuleMatrix", parity::StringRuleMatrix),
    parity_entry!("parity.StringWellKnown", parity::StringWellKnown),
    parity_entry!("parity.BytesRuleMatrix", parity::BytesRuleMatrix),
    parity_entry!(
        "parity.DurationTimestampRules",
        parity::DurationTimestampRules
    ),
    parity_entry!("parity.MapScalarValues", parity::MapScalarValues),
    parity_entry!("parity.RepeatedScalarItems", parity::RepeatedScalarItems),
    parity_entry!("parity.RepeatedFloatUnique", parity::RepeatedFloatUnique),
    parity_entry!("parity.TimestampRelative", parity::TimestampRelative),
    parity_entry!("parity.VirtualOneof", parity::VirtualOneof),
    parity_entry!("parity.PresenceMix", parity::PresenceMix),
    parity_entry!("parity.BytesPatternRaw", parity::BytesPatternRaw),
    parity_entry!("parity.FloatFiniteRules", parity::FloatFiniteRules),
    parity_entry!(
        "parity.VirtualOneofImplicitIgnore",
        parity::VirtualOneofImplicitIgnore
    ),
    parity_entry!("parity.NestedIgnore", parity::NestedIgnore),
    parity_entry!(
        "parity.RequiredImplicitScalar",
        parity::RequiredImplicitScalar
    ),
];

/// A flattened violation tuple used for parity comparison. `for_key` is
/// included so map-key violations surface the runtime's `for_key = true`
/// marker — a real correctness contract, not cosmetic.
pub type ViolationKey = (String, String, String, String, Option<bool>);

/// Extract sorted violation tuples for order-insensitive comparison.
pub fn sorted_violations(ve: &prost_protovalidate::ValidationError) -> Vec<ViolationKey> {
    let mut v: Vec<ViolationKey> = ve
        .violations()
        .iter()
        .map(|v| {
            (
                v.field_path(),
                v.rule_id().to_string(),
                v.rule_path(),
                v.message().to_string(),
                v.for_key(),
            )
        })
        .collect();
    v.sort();
    v
}
