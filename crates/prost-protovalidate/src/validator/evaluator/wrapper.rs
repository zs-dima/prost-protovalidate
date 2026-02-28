use prost_reflect::{DynamicMessage, ReflectMessage};

use crate::config::ValidationConfig;
use crate::error::Error;

use super::{Evaluator, Evaluators};

/// Evaluator that unwraps a well-known wrapper type message (e.g.
/// `google.protobuf.StringValue`) to its inner `value` field before
/// delegating to the wrapped evaluators.
pub(crate) struct WrapperEval {
    pub inner: Evaluators,
}

impl Evaluator for WrapperEval {
    fn tautology(&self) -> bool {
        self.inner.tautology()
    }

    fn evaluate(
        &self,
        msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(wrapper_msg) = val.as_message() else {
            return Ok(());
        };
        let Some(value_field) = wrapper_msg.descriptor().get_field_by_name("value") else {
            return Ok(());
        };
        let inner_val = wrapper_msg.get_field(&value_field);
        self.inner.evaluate(msg, &inner_val, cfg)
    }
}
