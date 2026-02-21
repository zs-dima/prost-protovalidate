use prost_reflect::Kind;

/// Maps a proto field kind to the expected oneof variant name in `FieldRules.type`.
#[allow(dead_code)]
pub(crate) fn expected_standard_rule(kind: &Kind) -> Option<&'static str> {
    match kind {
        Kind::Float => Some("float"),
        Kind::Double => Some("double"),
        Kind::Int32 => Some("int32"),
        Kind::Int64 => Some("int64"),
        Kind::Uint32 => Some("uint32"),
        Kind::Uint64 => Some("uint64"),
        Kind::Sint32 => Some("sint32"),
        Kind::Sint64 => Some("sint64"),
        Kind::Fixed32 => Some("fixed32"),
        Kind::Fixed64 => Some("fixed64"),
        Kind::Sfixed32 => Some("sfixed32"),
        Kind::Sfixed64 => Some("sfixed64"),
        Kind::Bool => Some("bool"),
        Kind::String => Some("string"),
        Kind::Bytes => Some("bytes"),
        Kind::Enum(_) => Some("enum"),
        Kind::Message(_) => None,
    }
}

/// Maps a well-known type full name to the expected oneof variant name in `FieldRules.type`.
#[allow(dead_code)]
pub(crate) fn expected_wkt_rule(full_name: &str) -> Option<&'static str> {
    match full_name {
        "google.protobuf.Any" => Some("any"),
        "google.protobuf.Duration" => Some("duration"),
        "google.protobuf.Timestamp" => Some("timestamp"),
        "google.protobuf.FieldMask" => Some("field_mask"),
        _ => None,
    }
}

/// Maps a wrapper type full name to the wrapped scalar rule name.
/// Returns the expected oneof variant name in `FieldRules.type` for the inner value.
pub(crate) fn expected_wrapper_rule(full_name: &str) -> Option<&'static str> {
    match full_name {
        "google.protobuf.BoolValue" => Some("bool"),
        "google.protobuf.BytesValue" => Some("bytes"),
        "google.protobuf.DoubleValue" => Some("double"),
        "google.protobuf.FloatValue" => Some("float"),
        "google.protobuf.Int32Value" => Some("int32"),
        "google.protobuf.Int64Value" => Some("int64"),
        "google.protobuf.StringValue" => Some("string"),
        "google.protobuf.UInt32Value" => Some("uint32"),
        "google.protobuf.UInt64Value" => Some("uint64"),
        _ => None,
    }
}

/// Returns true if this field descriptor refers to a message type.
pub(crate) fn is_message_field(desc: &prost_reflect::FieldDescriptor) -> bool {
    desc.kind().as_message().is_some()
}

#[cfg(test)]
mod tests {
    use prost_reflect::Kind;

    use super::{expected_standard_rule, expected_wkt_rule, expected_wrapper_rule};

    #[test]
    fn expected_wrapper_rule_matches_well_known_wrapper_types() {
        let cases = [
            ("google.protobuf.BoolValue", Some("bool")),
            ("google.protobuf.BytesValue", Some("bytes")),
            ("google.protobuf.DoubleValue", Some("double")),
            ("google.protobuf.FloatValue", Some("float")),
            ("google.protobuf.Int32Value", Some("int32")),
            ("google.protobuf.Int64Value", Some("int64")),
            ("google.protobuf.StringValue", Some("string")),
            ("google.protobuf.UInt32Value", Some("uint32")),
            ("google.protobuf.UInt64Value", Some("uint64")),
            ("foo.bar", None),
        ];

        for (full_name, expected) in cases {
            assert_eq!(expected_wrapper_rule(full_name), expected);
        }
    }

    #[test]
    fn expected_standard_and_wkt_rules_cover_expected_kinds() {
        assert_eq!(expected_standard_rule(&Kind::Float), Some("float"));
        assert_eq!(expected_standard_rule(&Kind::String), Some("string"));
        assert_eq!(expected_standard_rule(&Kind::Bool), Some("bool"));

        let enum_kind = Kind::Enum(
            prost_protovalidate_types::DESCRIPTOR_POOL
                .get_enum_by_name("buf.validate.KnownRegex")
                .expect("known regex enum should exist"),
        );
        assert_eq!(expected_standard_rule(&enum_kind), Some("enum"));

        let message_kind = Kind::Message(
            prost_protovalidate_types::DESCRIPTOR_POOL
                .get_message_by_name("buf.validate.StringRules")
                .expect("string rules message should exist"),
        );
        assert_eq!(expected_standard_rule(&message_kind), None);

        assert_eq!(expected_wkt_rule("google.protobuf.Any"), Some("any"));
        assert_eq!(
            expected_wkt_rule("google.protobuf.Duration"),
            Some("duration")
        );
        assert_eq!(
            expected_wkt_rule("google.protobuf.Timestamp"),
            Some("timestamp")
        );
        assert_eq!(
            expected_wkt_rule("google.protobuf.FieldMask"),
            Some("field_mask")
        );
        assert_eq!(expected_wkt_rule("google.protobuf.StringValue"), None);
    }
}
