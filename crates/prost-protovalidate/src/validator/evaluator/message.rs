use std::sync::{Arc, OnceLock};

use prost_reflect::{DynamicMessage, ReflectMessage};

use crate::config::ValidationConfig;
use crate::error::{self, CompilationError, Error};

use super::{MessageEvaluator, MessageEvaluators};

/// Top-level message evaluator state, assembled by the builder and published
/// into a [`MessageEval`] exactly once via [`MessageEval::init`].
#[derive(Default)]
pub(crate) struct MessageEvalState {
    err: Option<CompilationError>,
    evaluators: MessageEvaluators,
    nested_evaluators: MessageEvaluators,
}

impl MessageEvalState {
    pub fn with_err(err: CompilationError) -> Self {
        Self {
            err: Some(err),
            ..Self::default()
        }
    }

    pub fn set_err(&mut self, err: CompilationError) {
        self.err = Some(err);
    }

    #[cfg(feature = "cel")]
    pub fn append(&mut self, eval: Box<dyn MessageEvaluator>) {
        if !eval.tautology() {
            self.evaluators.push(eval);
        }
    }

    pub fn append_nested(&mut self, eval: Box<dyn MessageEvaluator>) {
        if !eval.tautology() {
            self.nested_evaluators.push(eval);
        }
    }
}

/// Top-level message evaluator. Holds direct evaluators (message-level rules)
/// and nested evaluators (fields + oneofs).
///
/// Built in two phases so recursive message types resolve: the builder caches
/// a placeholder `Arc<MessageEval>` before compiling, then publishes the
/// state through [`init`](Self::init) exactly once — on every exit path,
/// success or error. Placeholders become reachable from the shared cache only
/// after the build completes (the build lock serializes fills), so evaluation
/// never observes an uninitialized state; if it ever did, the message would
/// evaluate as rule-free. After `init`, reads are lock-free.
pub(crate) struct MessageEval {
    state: OnceLock<MessageEvalState>,
}

impl MessageEval {
    pub fn new() -> Self {
        Self {
            state: OnceLock::new(),
        }
    }

    /// Create an evaluator whose state is already published.
    pub fn from_state(state: MessageEvalState) -> Self {
        let eval = Self::new();
        eval.init(state);
        eval
    }

    /// Publish the built state.
    pub fn init(&self, state: MessageEvalState) {
        let already_initialized = self.state.set(state).is_err();
        debug_assert!(!already_initialized, "MessageEval::init called twice");
    }

    pub fn compilation_error_cause(&self) -> Option<String> {
        self.state
            .get()
            .and_then(|state| state.err.as_ref().map(|err| err.cause.clone()))
    }
}

impl MessageEvaluator for MessageEval {
    fn tautology(&self) -> bool {
        // Always false to avoid recursion-induced tautology short-circuits.
        false
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        let Some(state) = self.state.get() else {
            return Ok(());
        };

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

#[cfg(test)]
mod tests {
    use prost_reflect::DynamicMessage;

    use crate::config::ValidationConfig;
    use crate::error::CompilationError;

    use super::super::MessageEvaluator;
    use super::{MessageEval, MessageEvalState};

    fn test_message() -> DynamicMessage {
        let desc = prost_protovalidate_types::DESCRIPTOR_POOL
            .get_message_by_name("buf.validate.FieldRules")
            .expect("built-in descriptor pool contains FieldRules");
        DynamicMessage::new(desc)
    }

    #[test]
    fn uninitialized_placeholder_evaluates_as_rule_free() {
        let eval = MessageEval::new();
        assert!(eval.compilation_error_cause().is_none());
        assert!(
            eval.evaluate_message(&test_message(), &ValidationConfig::default())
                .is_ok()
        );
    }

    #[test]
    fn error_state_fails_every_evaluation() {
        let eval = MessageEval::from_state(MessageEvalState::with_err(CompilationError {
            cause: "nested compile failure".to_string(),
        }));
        assert_eq!(
            eval.compilation_error_cause().as_deref(),
            Some("nested compile failure")
        );

        let err = eval
            .evaluate_message(&test_message(), &ValidationConfig::default())
            .expect_err("error state must surface on evaluation");
        assert!(err.to_string().contains("nested compile failure"));
    }
}
