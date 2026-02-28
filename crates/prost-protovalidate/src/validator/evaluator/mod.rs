pub(crate) mod any;
pub(crate) mod cel;
pub(crate) mod embedded;
pub(crate) mod enum_check;
pub(crate) mod field;
pub(crate) mod list;
pub(crate) mod map;
pub(crate) mod message;
pub(crate) mod oneof;
pub(crate) mod value;
pub(crate) mod wrapper;

use prost_reflect::DynamicMessage;

use crate::config::ValidationConfig;
use crate::error::Error;

/// Prepend a rule path prefix to all violations in an error result.
pub(crate) fn prepend_rule_prefix(result: Result<(), Error>, prefix: &str) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(Error::Validation(mut ve)) => {
            for violation in ve.violations_mut() {
                violation.prepend_rule_path(prefix);
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}

/// Evaluator for concrete field values (scalars, list items, map keys/values).
pub(crate) trait Evaluator: Send + Sync {
    /// Returns true if this evaluator always succeeds (no-op).
    fn tautology(&self) -> bool;

    /// Evaluate a value. `msg` is the containing message for context.
    fn evaluate(
        &self,
        msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error>;
}

/// Evaluator specialized for top-level message validation.
pub(crate) trait MessageEvaluator: Send + Sync {
    /// Returns true if this evaluator always succeeds.
    fn tautology(&self) -> bool;

    /// Evaluate a message.
    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error>;
}

/// A list of evaluators that are applied together to a value.
/// Violations are merged across all evaluators.
pub(crate) struct Evaluators(pub Vec<Box<dyn Evaluator>>);

impl Evaluators {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, eval: Box<dyn Evaluator>) {
        if !eval.tautology() {
            self.0.push(eval);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for Evaluators {
    fn default() -> Self {
        Self::new()
    }
}

impl Evaluator for Evaluators {
    fn tautology(&self) -> bool {
        self.0.iter().all(|e| e.tautology())
    }

    fn evaluate(
        &self,
        msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let mut acc: Option<Error> = None;
        for eval in &self.0 {
            let result = eval.evaluate(msg, val, cfg);
            let (cont, new_acc) = crate::error::merge_violations(acc, result, cfg.fail_fast);
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

/// A list of message evaluators applied together.
pub(crate) struct MessageEvaluators(pub Vec<Box<dyn MessageEvaluator>>);

impl MessageEvaluators {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, eval: Box<dyn MessageEvaluator>) {
        if !eval.tautology() {
            self.0.push(eval);
        }
    }
}

impl Default for MessageEvaluators {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageEvaluator for MessageEvaluators {
    fn tautology(&self) -> bool {
        self.0.iter().all(|e| e.tautology())
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        let mut acc: Option<Error> = None;
        for eval in &self.0 {
            let result = eval.evaluate_message(msg, cfg);
            let (cont, new_acc) = crate::error::merge_violations(acc, result, cfg.fail_fast);
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
