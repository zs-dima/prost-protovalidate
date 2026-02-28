use std::collections::HashMap;

use prost_reflect::{DynamicMessage, FieldDescriptor, Value};

use crate::config::ValidationConfig;
use crate::error::{self, Error};

use super::{Evaluator, Evaluators};

/// Evaluator for a concrete value — can be a singular field value,
/// a repeated element, or a map key/value.
pub(crate) struct ValueEval {
    /// The field descriptor for this value.
    pub descriptor: FieldDescriptor,

    /// Direct evaluators for this value (standard rules, CEL, etc.).
    pub rules: Evaluators,

    /// Nested evaluators (embedded message, map items, list items).
    pub nested_rules: Evaluators,

    /// Whether to skip rules if the value is the zero/default value.
    /// Only relevant for repeated elements and map keys/values.
    pub ignore_empty: bool,

    /// The zero value for comparison (used with `ignore_empty`).
    pub zero: Option<Value>,

    /// Rule descriptor/value metadata keyed by rule id.
    pub rule_metadata: HashMap<String, (FieldDescriptor, Value)>,
}

impl ValueEval {
    pub fn new(descriptor: FieldDescriptor) -> Self {
        Self {
            descriptor,
            rules: Evaluators::new(),
            nested_rules: Evaluators::new(),
            ignore_empty: false,
            zero: None,
            rule_metadata: HashMap::new(),
        }
    }

    pub fn push_rule(&mut self, eval: Box<dyn Evaluator>) {
        self.rules.push(eval);
    }

    pub fn push_nested(&mut self, eval: Box<dyn Evaluator>) {
        self.nested_rules.push(eval);
    }

    pub fn tautology(&self) -> bool {
        self.rules.tautology() && self.nested_rules.tautology()
    }

    /// Evaluate this value with a known field path for violation reporting.
    pub fn evaluate_value(
        &self,
        msg: &DynamicMessage,
        val: &Value,
        cfg: &ValidationConfig,
        field_path: &str,
    ) -> Result<(), Error> {
        let (direct, nested) = self.evaluate_value_split(msg, val, cfg, field_path);
        let mut acc: Option<Error> = None;
        let (cont, new_acc) = error::merge_violations(acc, direct, cfg.fail_fast);
        acc = new_acc;
        if cont {
            let (_, new_acc) = error::merge_violations(acc, nested, cfg.fail_fast);
            acc = new_acc;
        }
        match acc {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Evaluate direct rules and nested rules separately.
    /// Returns `(direct_result, nested_result)`.
    /// Direct rules are constraints defined on the value itself (standard rules, CEL, etc.).
    /// Nested rules are embedded message validation, map items, list items.
    pub fn evaluate_value_split(
        &self,
        msg: &DynamicMessage,
        val: &Value,
        cfg: &ValidationConfig,
        field_path: &str,
    ) -> (Result<(), Error>, Result<(), Error>) {
        // Check ignore-empty
        if self.ignore_empty {
            if let Some(ref zero) = self.zero {
                if val == zero {
                    return (Ok(()), Ok(()));
                }
            }
        }

        // Apply direct rules
        let direct = if self.rules.is_empty() {
            Ok(())
        } else {
            let result = self.rules.evaluate(msg, val, cfg);
            let result = prepend_field_path(result, field_path, &self.descriptor);
            enrich_violations(result, val, &self.rule_metadata)
        };

        // Apply nested rules (embedded messages, map items, list items)
        let nested = if self.nested_rules.is_empty() || (direct.is_err() && cfg.fail_fast) {
            Ok(())
        } else {
            let result = self.nested_rules.evaluate(msg, val, cfg);
            let result = prepend_field_path(result, field_path, &self.descriptor);
            enrich_violations(result, val, &self.rule_metadata)
        };

        (direct, nested)
    }
}

/// Prepend the field path to all violations in an error.
fn prepend_field_path(
    result: Result<(), Error>,
    field_path: &str,
    descriptor: &FieldDescriptor,
) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(Error::Validation(mut ve)) => {
            for v in ve.violations_mut() {
                if field_path.starts_with('[') {
                    v.prepend_path(field_path);
                } else {
                    v.prepend_path_with_descriptor(field_path, descriptor);
                }
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}

fn enrich_violations(
    result: Result<(), Error>,
    value: &Value,
    rule_metadata: &HashMap<String, (FieldDescriptor, Value)>,
) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(Error::Validation(mut ve)) => {
            for violation in ve.violations_mut() {
                if let Some((rule_descriptor, rule_value)) = rule_metadata.get(violation.rule_id())
                {
                    if !violation.has_rule_descriptor() {
                        violation.set_rule_descriptor(rule_descriptor.clone());
                    }
                    if !violation.has_rule_value() {
                        violation.set_rule_value(rule_value.clone());
                    }
                }
                if !violation.has_field_value() {
                    violation.set_field_value(value.clone());
                }
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}
