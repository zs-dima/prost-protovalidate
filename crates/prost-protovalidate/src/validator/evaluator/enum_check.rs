use prost_reflect::{DynamicMessage, EnumDescriptor};

use prost_protovalidate_types::rules_meta::enumeration as meta;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

use super::Evaluator;

/// Evaluator that checks if an enum value corresponds to a defined variant.
pub(crate) struct DefinedEnumEval {
    pub enum_descriptor: EnumDescriptor,
}

impl Evaluator for DefinedEnumEval {
    fn tautology(&self) -> bool {
        false
    }

    fn evaluate(
        &self,
        _msg: &DynamicMessage,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(enum_number) = val.as_enum_number() else {
            return Ok(());
        };

        if self.enum_descriptor.get_value(enum_number).is_none() {
            return Err(ValidationError::single(Violation::new(
                "",
                meta::DEFINED_ONLY_ID,
                meta::DEFINED_ONLY_MESSAGE,
            ))
            .into());
        }

        Ok(())
    }
}
