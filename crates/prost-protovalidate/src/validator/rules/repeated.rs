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
        // usize always fits in u64 (max usize ≤ u64::MAX on all targets)
        #[allow(clippy::cast_possible_truncation)]
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

enum UniqueKeyExtraction {
    Key(UniqueKey),
    AlwaysUnique,
    Unsupported,
}

fn canonical_f32_bits(value: f32) -> Option<u32> {
    if value.is_nan() {
        // NaN is not equal to itself, so multiple NaNs do not violate uniqueness.
        return None;
    }
    Some(if value == 0.0 {
        0.0_f32.to_bits()
    } else {
        value.to_bits()
    })
}

fn canonical_f64_bits(value: f64) -> Option<u64> {
    if value.is_nan() {
        // NaN is not equal to itself, so multiple NaNs do not violate uniqueness.
        return None;
    }
    Some(if value == 0.0 {
        0.0_f64.to_bits()
    } else {
        value.to_bits()
    })
}

fn unique_key(value: &prost_reflect::Value) -> UniqueKeyExtraction {
    match value {
        prost_reflect::Value::Bool(v) => UniqueKeyExtraction::Key(UniqueKey::Bool(*v)),
        prost_reflect::Value::I32(v) => UniqueKeyExtraction::Key(UniqueKey::I32(*v)),
        prost_reflect::Value::I64(v) => UniqueKeyExtraction::Key(UniqueKey::I64(*v)),
        prost_reflect::Value::U32(v) => UniqueKeyExtraction::Key(UniqueKey::U32(*v)),
        prost_reflect::Value::U64(v) => UniqueKeyExtraction::Key(UniqueKey::U64(*v)),
        prost_reflect::Value::F32(v) => canonical_f32_bits(*v)
            .map_or(UniqueKeyExtraction::AlwaysUnique, |bits| {
                UniqueKeyExtraction::Key(UniqueKey::F32(bits))
            }),
        prost_reflect::Value::F64(v) => canonical_f64_bits(*v)
            .map_or(UniqueKeyExtraction::AlwaysUnique, |bits| {
                UniqueKeyExtraction::Key(UniqueKey::F64(bits))
            }),
        prost_reflect::Value::String(v) => UniqueKeyExtraction::Key(UniqueKey::String(v.clone())),
        prost_reflect::Value::Bytes(v) => UniqueKeyExtraction::Key(UniqueKey::Bytes(v.to_vec())),
        prost_reflect::Value::EnumNumber(v) => UniqueKeyExtraction::Key(UniqueKey::Enum(*v)),
        _ => UniqueKeyExtraction::Unsupported,
    }
}

fn is_unique(list: &[prost_reflect::Value]) -> bool {
    let mut seen = HashSet::with_capacity(list.len());
    for value in list {
        match unique_key(value) {
            UniqueKeyExtraction::Key(key) => {
                if !seen.insert(key) {
                    return false;
                }
            }
            // NaN is not equal to itself, so repeated NaNs are allowed.
            UniqueKeyExtraction::AlwaysUnique => {}
            // repeated.unique is only valid for scalar/enum element types.
            UniqueKeyExtraction::Unsupported => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

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
                assert_eq!(err.len(), 1);
                assert_eq!(err.violations()[0].rule_id(), "repeated.unique");
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

    #[test]
    fn unique_rejects_negative_zero_and_positive_zero() {
        let eval = RepeatedRuleEval::new(&prost_protovalidate_types::RepeatedRules {
            unique: Some(true),
            ..Default::default()
        });
        let value = prost_reflect::Value::List(vec![
            prost_reflect::Value::F64(-0.0),
            prost_reflect::Value::F64(0.0),
        ]);

        let err = eval
            .evaluate(&value, &ValidationConfig::default())
            .expect_err("signed and unsigned zero should be treated as equal");
        let Error::Validation(err) = err else {
            panic!("unexpected error type");
        };
        assert_eq!(err.violations()[0].rule_id(), "repeated.unique");
    }

    #[test]
    fn unique_allows_multiple_nan_values() {
        let eval = RepeatedRuleEval::new(&prost_protovalidate_types::RepeatedRules {
            unique: Some(true),
            ..Default::default()
        });
        let value = prost_reflect::Value::List(vec![
            prost_reflect::Value::F64(f64::NAN),
            prost_reflect::Value::F64(f64::NAN),
        ]);

        assert!(eval.evaluate(&value, &ValidationConfig::default()).is_ok());
    }
}
