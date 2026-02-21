use std::sync::Arc;

use prost_reflect::DynamicMessage;

use crate::config::ValidationConfig;
use crate::error::Error;

use super::message::MessageEval;
use super::{Evaluator, MessageEvaluator};

/// Evaluator for an embedded (nested) message field.
/// Delegates validation to the nested message's evaluator.
pub(crate) struct EmbeddedMessageEval {
    /// The evaluator for the nested message type.
    pub message: Arc<MessageEval>,
}

impl Evaluator for EmbeddedMessageEval {
    fn tautology(&self) -> bool {
        self.message.tautology()
    }

    fn evaluate(
        &self,
        _msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(nested_msg) = val.as_message() else {
            return Ok(());
        };

        self.message.evaluate_message(nested_msg, cfg)
    }
}
