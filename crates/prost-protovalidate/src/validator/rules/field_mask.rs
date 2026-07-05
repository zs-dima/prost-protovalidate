use std::collections::HashSet;

use prost_reflect::ReflectMessage;

use prost_protovalidate_types::rules_meta::field_mask as meta;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct FieldMaskRuleEval {
    r#const: Option<Vec<String>>,
    r#in: HashSet<String>,
    not_in: HashSet<String>,
}

impl FieldMaskRuleEval {
    pub fn new(rules: &prost_protovalidate_types::FieldMaskRules) -> Self {
        Self {
            r#const: rules.r#const.as_ref().map(|m| m.paths.clone()),
            r#in: rules.r#in.iter().cloned().collect(),
            not_in: rules.not_in.iter().cloned().collect(),
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none() && self.r#in.is_empty() && self.not_in.is_empty()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let msg = match val.as_message() {
            Some(m) if m.descriptor().full_name() == "google.protobuf.FieldMask" => m,
            _ => return Ok(()),
        };

        let paths = msg
            .get_field_by_name("paths")
            .map(|value| {
                value
                    .as_list()
                    .map(|list| {
                        list.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let mut violations = Vec::new();

        if let Some(expected) = &self.r#const {
            if &paths != expected {
                violations.push(Violation::new("", meta::CONST_ID, meta::CONST_MESSAGE));
            }
        }

        if !self.r#in.is_empty()
            && !paths
                .iter()
                .all(|path| self.r#in.iter().any(|allowed| path_matches(path, allowed)))
        {
            violations.push(Violation::new("", meta::IN_ID, meta::IN_MESSAGE));
        }

        if !self.not_in.is_empty()
            && paths.iter().any(|path| {
                self.not_in
                    .iter()
                    .any(|blocked| path_matches(path, blocked))
            })
        {
            violations.push(Violation::new("", meta::NOT_IN_ID, meta::NOT_IN_MESSAGE));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

fn path_matches(path: &str, prefix: &str) -> bool {
    crate::validators::fieldmask_covers(prefix, path)
}
