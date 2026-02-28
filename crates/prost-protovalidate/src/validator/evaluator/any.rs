use std::collections::HashSet;

use prost_reflect::DynamicMessage;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

use super::Evaluator;

/// Evaluator for `google.protobuf.Any` fields.
/// Validates the `type_url` against allowed/disallowed lists.
pub(crate) struct AnyEval {
    /// Allowed type URLs (empty = no restriction).
    pub r#in: HashSet<String>,
    /// Disallowed type URLs.
    pub not_in: HashSet<String>,
}

impl Evaluator for AnyEval {
    fn tautology(&self) -> bool {
        self.r#in.is_empty() && self.not_in.is_empty()
    }

    fn evaluate(
        &self,
        _msg: &DynamicMessage,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(any_msg) = val.as_message() else {
            return Ok(());
        };

        // Get the type_url field from the Any message
        let Some(type_url) = any_msg
            .get_field_by_name("type_url")
            .and_then(|v| v.as_str().map(str::to_string))
        else {
            return Ok(());
        };

        if !self.r#in.is_empty() && !self.r#in.contains(&type_url) {
            return Err(ValidationError::single(Violation::new(
                "",
                "any.in",
                "type URL must be in the allow list",
            ))
            .into());
        }

        if self.not_in.contains(&type_url) {
            return Err(ValidationError::single(Violation::new(
                "",
                "any.not_in",
                "type URL must not be in the block list",
            ))
            .into());
        }

        Ok(())
    }
}
