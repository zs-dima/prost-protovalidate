use std::collections::HashSet;

use prost_protovalidate_types::rules_meta::enumeration as meta;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct EnumRuleEval {
    r#const: Option<i32>,
    r#in: HashSet<i32>,
    not_in: HashSet<i32>,
}

impl EnumRuleEval {
    pub fn new(rules: &prost_protovalidate_types::EnumRules) -> Self {
        Self {
            r#const: rules.r#const,
            r#in: rules.r#in.iter().copied().collect(),
            not_in: rules.not_in.iter().copied().collect(),
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none() && self.r#in.is_empty() && self.not_in.is_empty()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(v) = val.as_enum_number() else {
            return Ok(());
        };

        let mut violations = Vec::new();

        if let Some(c) = self.r#const {
            if v != c {
                violations.push(Violation::new("", meta::CONST_ID, meta::const_message(c)));
            }
        }

        if !self.r#in.is_empty() && !self.r#in.contains(&v) {
            let values: Vec<i32> = self.r#in.iter().copied().collect();
            violations.push(Violation::new("", meta::IN_ID, meta::in_message(&values)));
        }

        if self.not_in.contains(&v) {
            let values: Vec<i32> = self.not_in.iter().copied().collect();
            violations.push(Violation::new(
                "",
                meta::NOT_IN_ID,
                meta::not_in_message(&values),
            ));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}
