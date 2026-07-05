use prost_protovalidate_types::rules_meta::boolean as meta;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct BoolRuleEval {
    r#const: Option<bool>,
}

impl BoolRuleEval {
    pub fn new(rules: &prost_protovalidate_types::BoolRules) -> Self {
        Self {
            r#const: rules.r#const,
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(v) = val.as_bool() else {
            return Ok(());
        };

        if let Some(c) = self.r#const {
            if v != c {
                return Err(ValidationError::single(Violation::new(
                    "",
                    meta::CONST_ID,
                    meta::const_message(c),
                ))
                .into());
            }
        }

        Ok(())
    }
}
