use std::collections::HashSet;

use regex::bytes::Regex as BytesRegex;

use crate::config::ValidationConfig;
use crate::error::{CompilationError, Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct BytesRuleEval {
    r#const: Option<Vec<u8>>,
    len: Option<u64>,
    min_len: Option<u64>,
    max_len: Option<u64>,
    pattern: Option<BytesRegex>,
    prefix: Option<Vec<u8>>,
    suffix: Option<Vec<u8>>,
    contains: Option<Vec<u8>>,
    r#in: HashSet<Vec<u8>>,
    not_in: HashSet<Vec<u8>>,
    well_known: Option<BytesWellKnown>,
}

#[derive(Debug, Clone, Copy)]
enum BytesWellKnown {
    Ip,
    Ipv4,
    Ipv6,
    Uuid,
}

impl BytesRuleEval {
    pub fn new(rules: &prost_protovalidate_types::BytesRules) -> Result<Self, CompilationError> {
        let pattern = rules
            .pattern
            .as_deref()
            .map(BytesRegex::new)
            .transpose()
            .map_err(|e| CompilationError {
                cause: format!("invalid bytes regex pattern: {e}"),
            })?;

        let well_known = rules.well_known.as_ref().and_then(|wk| {
            use prost_protovalidate_types::bytes_rules::WellKnown;
            match wk {
                WellKnown::Ip(true) => Some(BytesWellKnown::Ip),
                WellKnown::Ipv4(true) => Some(BytesWellKnown::Ipv4),
                WellKnown::Ipv6(true) => Some(BytesWellKnown::Ipv6),
                WellKnown::Uuid(true) => Some(BytesWellKnown::Uuid),
                WellKnown::Ip(false)
                | WellKnown::Ipv4(false)
                | WellKnown::Ipv6(false)
                | WellKnown::Uuid(false) => None,
            }
        });

        Ok(Self {
            r#const: rules.r#const.clone(),
            len: rules.len,
            min_len: rules.min_len,
            max_len: rules.max_len,
            pattern,
            prefix: rules.prefix.clone(),
            suffix: rules.suffix.clone(),
            contains: rules.contains.clone(),
            r#in: rules.r#in.iter().cloned().collect(),
            not_in: rules.not_in.iter().cloned().collect(),
            well_known,
        })
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
            && self.len.is_none()
            && self.min_len.is_none()
            && self.max_len.is_none()
            && self.pattern.is_none()
            && self.prefix.is_none()
            && self.suffix.is_none()
            && self.contains.is_none()
            && self.r#in.is_empty()
            && self.not_in.is_empty()
            && self.well_known.is_none()
    }

    #[allow(clippy::too_many_lines)]
    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(b) = val.as_bytes() else {
            return Ok(());
        };

        let mut violations = Vec::new();

        if let Some(ref c) = self.r#const {
            if b != c.as_slice() {
                violations.push(Violation::new(
                    "",
                    "bytes.const",
                    format!("value must be {c:?}"),
                ));
            }
        }

        let len = b.len() as u64;
        if let Some(expected) = self.len {
            if len != expected {
                violations.push(Violation::new(
                    "",
                    "bytes.len",
                    format!("value length must be {expected} bytes"),
                ));
            }
        }
        if let Some(min) = self.min_len {
            if len < min {
                violations.push(Violation::new(
                    "",
                    "bytes.min_len",
                    format!("value length must be at least {min} bytes"),
                ));
            }
        }
        if let Some(max) = self.max_len {
            if len > max {
                violations.push(Violation::new(
                    "",
                    "bytes.max_len",
                    format!("value length must be at most {max} bytes"),
                ));
            }
        }

        if let Some(ref pat) = self.pattern {
            if !pat.is_match(b) {
                violations.push(Violation::new(
                    "",
                    "bytes.pattern",
                    format!("value must match regex pattern `{}`", pat.as_str()),
                ));
            }
        }

        if let Some(ref prefix) = self.prefix {
            if !b.starts_with(prefix) {
                violations.push(Violation::new(
                    "",
                    "bytes.prefix",
                    format!("value does not have prefix {:?}", prefix),
                ));
            }
        }
        if let Some(ref suffix) = self.suffix {
            if !b.ends_with(suffix) {
                violations.push(Violation::new(
                    "",
                    "bytes.suffix",
                    format!("value does not have suffix {:?}", suffix),
                ));
            }
        }
        if let Some(ref contains) = self.contains {
            if !contains.is_empty() && !b.windows(contains.len()).any(|w| w == contains.as_slice())
            {
                violations.push(Violation::new(
                    "",
                    "bytes.contains",
                    format!("value does not contain {:?}", contains),
                ));
            }
        }

        if !self.r#in.is_empty() && !self.r#in.contains(b.as_ref()) {
            violations.push(Violation::new("", "bytes.in", "value must be in list"));
        }
        if self.not_in.contains(b.as_ref()) {
            violations.push(Violation::new(
                "",
                "bytes.not_in",
                "value must not be in list",
            ));
        }

        if let Some(wk) = self.well_known {
            match wk {
                BytesWellKnown::Ip => {
                    if b.is_empty() {
                        violations.push(Violation::new(
                            "",
                            "bytes.ip_empty",
                            "value is empty, which is not a valid IP address",
                        ));
                    } else if b.len() != 4 && b.len() != 16 {
                        violations.push(Violation::new(
                            "",
                            "bytes.ip",
                            "value must be a valid IP address",
                        ));
                    }
                }
                BytesWellKnown::Ipv4 => {
                    if b.is_empty() {
                        violations.push(Violation::new(
                            "",
                            "bytes.ipv4_empty",
                            "value is empty, which is not a valid IPv4 address",
                        ));
                    } else if b.len() != 4 {
                        violations.push(Violation::new(
                            "",
                            "bytes.ipv4",
                            "value must be a valid IPv4 address",
                        ));
                    }
                }
                BytesWellKnown::Ipv6 => {
                    if b.is_empty() {
                        violations.push(Violation::new(
                            "",
                            "bytes.ipv6_empty",
                            "value is empty, which is not a valid IPv6 address",
                        ));
                    } else if b.len() != 16 {
                        violations.push(Violation::new(
                            "",
                            "bytes.ipv6",
                            "value must be a valid IPv6 address",
                        ));
                    }
                }
                BytesWellKnown::Uuid => {
                    if b.is_empty() {
                        violations.push(Violation::new(
                            "",
                            "bytes.uuid_empty",
                            "value is empty, which is not a valid UUID",
                        ));
                    } else if b.len() != 16 {
                        violations.push(Violation::new(
                            "",
                            "bytes.uuid",
                            "value must be a valid UUID",
                        ));
                    }
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BytesRuleEval;

    #[test]
    fn bytes_contains_empty_does_not_panic() {
        let rules = prost_protovalidate_types::BytesRules {
            contains: Some(Vec::new()),
            ..Default::default()
        };
        let eval = BytesRuleEval::new(&rules).expect("bytes rules should compile");
        let value = prost_reflect::Value::Bytes(vec![1, 2, 3].into());
        let cfg = crate::config::ValidationConfig::default();
        assert!(eval.evaluate(&value, &cfg).is_ok());
    }

    #[test]
    fn bytes_uuid_well_known_requires_non_empty_16_bytes() {
        let rules = prost_protovalidate_types::BytesRules {
            well_known: Some(prost_protovalidate_types::bytes_rules::WellKnown::Uuid(
                true,
            )),
            ..Default::default()
        };
        let eval = BytesRuleEval::new(&rules).expect("bytes rules should compile");
        let cfg = crate::config::ValidationConfig::default();

        let empty = prost_reflect::Value::Bytes(Vec::<u8>::new().into());
        assert!(eval.evaluate(&empty, &cfg).is_err());

        let bad_len = prost_reflect::Value::Bytes(vec![0_u8; 15].into());
        assert!(eval.evaluate(&bad_len, &cfg).is_err());

        let good = prost_reflect::Value::Bytes(vec![0_u8; 16].into());
        assert!(eval.evaluate(&good, &cfg).is_ok());
    }
}
