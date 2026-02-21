use prost_protovalidate_types::{
    FieldConstraintsExt, FieldRules, MessageConstraintsExt, MessageRules, OneofConstraintsExt,
};
use prost_reflect::{FieldDescriptor, MessageDescriptor, OneofDescriptor};

/// Extract `buf.validate.message` rules from a message descriptor.
#[allow(dead_code)]
pub(crate) fn resolve_message_rules(desc: &MessageDescriptor) -> Option<MessageRules> {
    desc.message_constraints().ok().flatten()
}

/// Extract `buf.validate.field` rules from a field descriptor.
#[allow(dead_code)]
pub(crate) fn resolve_field_rules(desc: &FieldDescriptor) -> Option<FieldRules> {
    desc.field_constraints().ok().flatten()
}

/// Returns true if this oneof has `(buf.validate.oneof).required = true`.
#[allow(dead_code)]
pub(crate) fn is_oneof_required(desc: &OneofDescriptor) -> bool {
    desc.is_required()
}

#[cfg(test)]
mod tests {
    use super::{resolve_field_rules, resolve_message_rules};

    #[test]
    fn resolve_returns_none_for_messages_without_constraints() {
        let timestamp_desc = prost_protovalidate_types::DESCRIPTOR_POOL
            .get_message_by_name("google.protobuf.Timestamp")
            .expect("google.protobuf.Timestamp descriptor should exist");
        assert!(resolve_message_rules(&timestamp_desc).is_none());

        let no_rule_field = timestamp_desc
            .get_field_by_name("seconds")
            .expect("Timestamp.seconds field should exist");
        assert!(resolve_field_rules(&no_rule_field).is_none());
    }
}
