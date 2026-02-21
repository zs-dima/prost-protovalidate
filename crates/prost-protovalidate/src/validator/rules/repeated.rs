use std::collections::HashSet;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct RepeatedRuleEval {
    min_items: Option<u64>,
    max_items: Option<u64>,
    unique: bool,
}

impl RepeatedRuleEval {
    pub fn new(rules: &prost_protovalidate_types::RepeatedRules) -> Self {
        Self {
            min_items: rules.min_items,
            max_items: rules.max_items,
            unique: rules.unique.unwrap_or(false),
        }
    }

    pub fn tautology(&self) -> bool {
        self.min_items.is_none() && self.max_items.is_none() && !self.unique
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(list) = val.as_list() else {
            return Ok(());
        };

        let mut violations = Vec::new();
        let len = list.len() as u64;

        if let Some(min) = self.min_items {
            if len < min {
                violations.push(Violation::new(
                    "",
                    "repeated.min_items",
                    format!("must have at least {min} items"),
                ));
            }
        }

        if let Some(max) = self.max_items {
            if len > max {
                violations.push(Violation::new(
                    "",
                    "repeated.max_items",
                    format!("must have at most {max} items"),
                ));
            }
        }

        if self.unique && !is_unique(list) {
            violations.push(Violation::new(
                "",
                "repeated.unique",
                "items must be unique",
            ));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

/// Hashable key extracted from a `prost_reflect::Value` for O(n) uniqueness checking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum UniqueKey {
    Bool(bool),
    I32(i32),
    I64(i64),
    U32(u32),
    U64(u64),
    F32(u32),
    F64(u64),
    String(String),
    Bytes(Vec<u8>),
    Enum(i32),
}

fn unique_key(value: &prost_reflect::Value) -> Option<UniqueKey> {
    match value {
        prost_reflect::Value::Bool(v) => Some(UniqueKey::Bool(*v)),
        prost_reflect::Value::I32(v) => Some(UniqueKey::I32(*v)),
        prost_reflect::Value::I64(v) => Some(UniqueKey::I64(*v)),
        prost_reflect::Value::U32(v) => Some(UniqueKey::U32(*v)),
        prost_reflect::Value::U64(v) => Some(UniqueKey::U64(*v)),
        prost_reflect::Value::F32(v) => Some(UniqueKey::F32(v.to_bits())),
        prost_reflect::Value::F64(v) => Some(UniqueKey::F64(v.to_bits())),
        prost_reflect::Value::String(v) => Some(UniqueKey::String(v.clone())),
        prost_reflect::Value::Bytes(v) => Some(UniqueKey::Bytes(v.to_vec())),
        prost_reflect::Value::EnumNumber(v) => Some(UniqueKey::Enum(*v)),
        // Composite types (Message, List, Map) fall back to O(n²) equality comparison.
        _ => None,
    }
}

fn is_unique(list: &[prost_reflect::Value]) -> bool {
    // Try O(n) path first: extract hashable keys for all items.
    let keys: Option<Vec<_>> = list.iter().map(unique_key).collect();
    if let Some(keys) = keys {
        let mut seen = HashSet::with_capacity(keys.len());
        return keys.into_iter().all(|k| seen.insert(k));
    }

    // Fallback for composite types: O(n²) pairwise comparison.
    for (i, item) in list.iter().enumerate() {
        for prev in list.iter().take(i) {
            if item == prev {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ValidationConfig;

    #[test]
    fn unique_rejects_equal_values() {
        let eval = RepeatedRuleEval::new(&prost_protovalidate_types::RepeatedRules {
            unique: Some(true),
            ..Default::default()
        });
        let value = prost_reflect::Value::List(vec![
            prost_reflect::Value::I32(7),
            prost_reflect::Value::I32(7),
        ]);
        let err = eval
            .evaluate(&value, &ValidationConfig::default())
            .expect_err("duplicate list values should fail unique check");
        match err {
            Error::Validation(err) => {
                assert_eq!(err.violations.len(), 1);
                assert_eq!(err.violations[0].rule_id, "repeated.unique");
            }
            other => panic!("unexpected error type: {other}"),
        }
    }

    #[test]
    fn unique_accepts_distinct_values() {
        let eval = RepeatedRuleEval::new(&prost_protovalidate_types::RepeatedRules {
            unique: Some(true),
            ..Default::default()
        });
        let value = prost_reflect::Value::List(vec![
            prost_reflect::Value::I32(7),
            prost_reflect::Value::I32(8),
        ]);
        assert!(eval.evaluate(&value, &ValidationConfig::default()).is_ok());
    }
}
