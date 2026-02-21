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
        let mut acc: Option<Error> = None;

        // Check ignore-empty
        if self.ignore_empty {
            if let Some(ref zero) = self.zero {
                if val == zero {
                    return Ok(());
                }
            }
        }

        // Apply direct rules
        if !self.rules.is_empty() {
            let result = self.rules.evaluate(msg, val, cfg);
            let result = prepend_field_path(result, field_path, &self.descriptor);
            let result = enrich_violations(result, val, &self.rule_metadata);
            let (cont, new_acc) = error::merge_violations(acc, result, cfg.fail_fast);
            acc = new_acc;
            if !cont {
                return match acc {
                    Some(err) => Err(err),
                    None => Ok(()),
                };
            }
        }

        // Apply nested rules (embedded messages, map items, list items)
        if !self.nested_rules.is_empty() {
            let result = self.nested_rules.evaluate(msg, val, cfg);
            let result = prepend_field_path(result, field_path, &self.descriptor);
            let result = enrich_violations(result, val, &self.rule_metadata);
            let (_, new_acc) = error::merge_violations(acc, result, cfg.fail_fast);
            acc = new_acc;
        }

        match acc {
            Some(err) => Err(err),
            None => Ok(()),
        }
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
            for v in &mut ve.violations {
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
            for violation in &mut ve.violations {
                if let Some((rule_descriptor, rule_value)) = rule_metadata.get(&violation.rule_id) {
                    let mut updated: Option<crate::violation::Violation> = None;
                    if violation.rule_descriptor.is_none() {
                        let current = updated.take().unwrap_or_else(|| violation.clone());
                        updated = Some(current.with_rule_descriptor(rule_descriptor.clone()));
                    }
                    if violation.rule_value.is_none() {
                        let current = updated.take().unwrap_or_else(|| violation.clone());
                        updated = Some(current.with_rule_value(rule_value.clone()));
                    }
                    if let Some(updated) = updated {
                        *violation = updated;
                    }
                }

                let mut updated: Option<crate::violation::Violation> = None;
                if violation.field_value.is_none() {
                    let current = updated.take().unwrap_or_else(|| violation.clone());
                    updated = Some(current.with_field_value(value.clone()));
                }
                if let Some(updated) = updated {
                    *violation = updated;
                }
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}
