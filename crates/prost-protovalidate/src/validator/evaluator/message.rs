use std::sync::{Arc, RwLock};

use prost_reflect::{DynamicMessage, ReflectMessage};

use crate::config::ValidationConfig;
use crate::error::{self, CompilationError, Error};

use super::{MessageEvaluator, MessageEvaluators};

/// Top-level message evaluator state.
#[derive(Default)]
struct MessageEvalState {
    err: Option<CompilationError>,
    evaluators: MessageEvaluators,
    nested_evaluators: MessageEvaluators,
}

/// Top-level message evaluator. Holds direct evaluators (message-level rules)
/// and nested evaluators (fields + oneofs).
pub(crate) struct MessageEval {
    state: RwLock<MessageEvalState>,
}

impl MessageEval {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(MessageEvalState::default()),
        }
    }

    pub fn set_err(&self, err: CompilationError) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.err = Some(err);
    }

    pub fn compilation_error_cause(&self) -> Option<String> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.err.as_ref().map(|err| err.cause.clone())
    }

    pub fn append(&self, eval: Box<dyn MessageEvaluator>) {
        if !eval.tautology() {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.evaluators.push(eval);
        }
    }

    pub fn append_nested(&self, eval: Box<dyn MessageEvaluator>) {
        if !eval.tautology() {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.nested_evaluators.push(eval);
        }
    }
}

impl MessageEvaluator for MessageEval {
    fn tautology(&self) -> bool {
        // Always false to avoid recursion-induced tautology short-circuits.
        false
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let descriptor = msg.descriptor();
        let should_validate = cfg.filter.should_validate(msg, &descriptor);
        let mut acc: Option<Error> = None;

        if should_validate {
            if let Some(ref err) = state.err {
                return Err(CompilationError {
                    cause: err.cause.clone(),
                }
                .into());
            }

            let result = state.evaluators.evaluate_message(msg, cfg);
            let (cont, new_acc) = error::merge_violations(acc, result, cfg.fail_fast);
            acc = new_acc;
            if !cont {
                return match acc {
                    Some(err) => Err(err),
                    None => Ok(()),
                };
            }
        }

        let result = state.nested_evaluators.evaluate_message(msg, cfg);
        let (_cont, new_acc) = error::merge_violations(acc, result, cfg.fail_fast);
        acc = new_acc;

        match acc {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl MessageEvaluator for Arc<MessageEval> {
    fn tautology(&self) -> bool {
        MessageEval::tautology(self)
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        MessageEval::evaluate_message(self, msg, cfg)
    }
}
