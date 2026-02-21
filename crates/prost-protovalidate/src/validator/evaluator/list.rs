use prost_reflect::DynamicMessage;

use crate::config::ValidationConfig;
use crate::error::{self, Error};

use super::Evaluator;
use super::value::ValueEval;

/// Evaluator for repeated (list) fields.
/// Iterates items and applies per-item rules.
pub(crate) struct ListEval {
    /// Per-item evaluator.
    pub item_rules: ValueEval,
}

impl Evaluator for ListEval {
    fn tautology(&self) -> bool {
        self.item_rules.tautology()
    }

    fn evaluate(
        &self,
        msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(list) = val.as_list() else {
            return Ok(());
        };

        let mut acc: Option<Error> = None;

        for (i, item) in list.iter().enumerate() {
            let item_path = format!("[{i}]");
            let result = self.item_rules.evaluate_value(msg, item, cfg, &item_path);
            let result = prepend_rule_prefix(result, "repeated.items");
            let (cont, new_acc) = error::merge_violations(acc, result, cfg.fail_fast);
            acc = new_acc;
            if !cont {
                break;
            }
        }

        match acc {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

fn prepend_rule_prefix(result: Result<(), Error>, prefix: &str) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(Error::Validation(mut ve)) => {
            for violation in &mut ve.violations {
                violation.prepend_rule_path(prefix);
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}
