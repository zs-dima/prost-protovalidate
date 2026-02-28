use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct MapRuleEval {
    min_pairs: Option<u64>,
    max_pairs: Option<u64>,
}

impl MapRuleEval {
    pub fn new(rules: &prost_protovalidate_types::MapRules) -> Self {
        Self {
            min_pairs: rules.min_pairs,
            max_pairs: rules.max_pairs,
        }
    }

    pub fn tautology(&self) -> bool {
        self.min_pairs.is_none() && self.max_pairs.is_none()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(map) = val.as_map() else {
            return Ok(());
        };

        let mut violations = Vec::new();
        // usize always fits in u64 (max usize ≤ u64::MAX on all targets)
        #[allow(clippy::cast_possible_truncation)]
        let len = map.len() as u64;

        if let Some(min) = self.min_pairs {
            if len < min {
                violations.push(Violation::new(
                    "",
                    "map.min_pairs",
                    format!("must have at least {min} entries"),
                ));
            }
        }

        if let Some(max) = self.max_pairs {
            if len > max {
                violations.push(Violation::new(
                    "",
                    "map.max_pairs",
                    format!("must have at most {max} entries"),
                ));
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}
