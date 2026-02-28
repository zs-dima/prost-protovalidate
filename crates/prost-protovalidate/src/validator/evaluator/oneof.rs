use prost_reflect::{DynamicMessage, OneofDescriptor, ReflectMessage};

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

use super::MessageEvaluator;

/// Evaluator for a proto oneof field. Checks that exactly one field is set
/// when `required` is true.
pub(crate) struct OneofEval {
    pub descriptor: OneofDescriptor,
    pub required: bool,
}

impl MessageEvaluator for OneofEval {
    fn tautology(&self) -> bool {
        !self.required
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        if !self.required {
            return Ok(());
        }

        if !cfg.filter.should_validate_oneof(msg, &self.descriptor) {
            return Ok(());
        }

        let any_set = self.descriptor.fields().any(|field| msg.has_field(&field));

        if !any_set {
            return Err(ValidationError::single(
                Violation::new(self.descriptor.name(), "required", "").without_rule_path(),
            )
            .into());
        }

        Ok(())
    }
}

/// Evaluator for message-level oneof rules (from `MessageRules.oneof`).
/// These define "virtual" oneofs across arbitrary fields.
pub(crate) struct MessageOneofEval {
    /// Field names that participate in this virtual oneof.
    pub field_names: Vec<String>,
    /// Whether exactly one field must be set.
    pub required: bool,
}

impl MessageEvaluator for MessageOneofEval {
    fn tautology(&self) -> bool {
        false
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        let descriptor = msg.descriptor();
        if !cfg.filter.should_validate(msg, &descriptor) {
            return Ok(());
        }

        let mut set_count = 0;

        for name in &self.field_names {
            if let Some(field) = descriptor.get_field_by_name(name) {
                if msg.has_field(&field) {
                    set_count += 1;
                }
            }
        }

        if set_count > 1 {
            return Err(ValidationError::single(
                Violation::new(
                    "",
                    "message.oneof",
                    format!("only one of {} can be set", self.field_names.join(", ")),
                )
                .without_rule_path(),
            )
            .into());
        }

        if self.required && set_count == 0 {
            return Err(ValidationError::single(
                Violation::new(
                    "",
                    "message.oneof",
                    format!("one of {} must be set", self.field_names.join(", ")),
                )
                .without_rule_path(),
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prost_reflect::{DynamicMessage, MessageDescriptor, OneofDescriptor, ReflectMessage};

    use super::{MessageOneofEval, OneofEval};
    use crate::config::{Filter, ValidationConfig};
    use crate::validator::evaluator::MessageEvaluator;

    struct SelectiveFilter {
        allow_messages: bool,
        allowed_oneofs: std::collections::HashSet<String>,
    }

    impl Filter for SelectiveFilter {
        fn should_validate(
            &self,
            _message: &DynamicMessage,
            _descriptor: &MessageDescriptor,
        ) -> bool {
            self.allow_messages
        }

        fn should_validate_oneof(
            &self,
            _message: &DynamicMessage,
            oneof: &OneofDescriptor,
        ) -> bool {
            self.allowed_oneofs.contains(oneof.name())
        }
    }

    #[test]
    fn oneof_eval_skips_when_oneof_is_filtered_out() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let oneof = descriptor
            .oneofs()
            .find(|oneof| oneof.name() == "type")
            .expect("field rules should contain `type` oneof");
        let message = prost_reflect::DynamicMessage::new(descriptor);

        let evaluator = OneofEval {
            descriptor: oneof,
            required: true,
        };

        let cfg = ValidationConfig {
            filter: Arc::new(SelectiveFilter {
                allow_messages: true,
                allowed_oneofs: std::collections::HashSet::new(),
            }),
            ..ValidationConfig::default()
        };

        assert!(evaluator.evaluate_message(&message, &cfg).is_ok());
    }

    #[test]
    fn oneof_eval_enforces_required_for_selected_members() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let oneof = descriptor
            .oneofs()
            .find(|oneof| oneof.name() == "type")
            .expect("field rules should contain `type` oneof");
        let message = prost_reflect::DynamicMessage::new(descriptor);

        let evaluator = OneofEval {
            descriptor: oneof.clone(),
            required: true,
        };

        let cfg = ValidationConfig {
            filter: Arc::new(SelectiveFilter {
                allow_messages: true,
                allowed_oneofs: [oneof.name().to_string()].into_iter().collect(),
            }),
            ..ValidationConfig::default()
        };

        assert!(evaluator.evaluate_message(&message, &cfg).is_err());
    }

    #[test]
    fn message_oneof_eval_skips_when_members_are_filtered_out() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let message = prost_reflect::DynamicMessage::new(descriptor);
        let evaluator = MessageOneofEval {
            field_names: vec!["required".to_string(), "ignore".to_string()],
            required: true,
        };
        let cfg = ValidationConfig {
            filter: Arc::new(SelectiveFilter {
                allow_messages: false,
                allowed_oneofs: std::collections::HashSet::new(),
            }),
            ..ValidationConfig::default()
        };

        assert!(evaluator.evaluate_message(&message, &cfg).is_ok());
    }
}
