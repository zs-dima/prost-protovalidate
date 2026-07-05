use prost_protovalidate_types::rules_meta::duration as meta;
use prost_protovalidate_types::rules_meta::numeric::RangeRule;
use prost_reflect::ReflectMessage;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

/// Duration values are compared as `(seconds, nanos)` tuples: protobuf
/// requires the two fields to share a sign, so lexicographic tuple order is
/// duration order.
pub(crate) struct DurationRuleEval {
    r#const: Option<(i64, i32)>,
    /// The `gt`/`gte` bound, when set.
    gt_bound: Option<(i64, i32)>,
    /// The `lt`/`lte` bound, when set.
    lt_bound: Option<(i64, i32)>,
    /// Resolved range rule (kind + id + path + message), when any bound is
    /// set.
    range: Option<RangeRule>,
    r#in: Vec<(i64, i32)>,
    not_in: Vec<(i64, i32)>,
}

impl DurationRuleEval {
    pub fn new(rules: &prost_protovalidate_types::DurationRules) -> Self {
        use prost_protovalidate_types::duration_rules::{GreaterThan, LessThan};

        let as_tuple = |d: &prost_types::Duration| (d.seconds, d.nanos);
        let (gt, gte) = match rules.greater_than.as_ref() {
            Some(GreaterThan::Gt(d)) => (Some(as_tuple(d)), None),
            Some(GreaterThan::Gte(d)) => (None, Some(as_tuple(d))),
            None => (None, None),
        };
        let (lt, lte) = match rules.less_than.as_ref() {
            Some(LessThan::Lt(d)) => (Some(as_tuple(d)), None),
            Some(LessThan::Lte(d)) => (None, Some(as_tuple(d))),
            None => (None, None),
        };

        Self {
            r#const: rules.r#const.as_ref().map(as_tuple),
            gt_bound: gt.or(gte),
            lt_bound: lt.or(lte),
            range: meta::range_rule(gt, gte, lt, lte),
            r#in: rules.r#in.iter().map(as_tuple).collect(),
            not_in: rules.not_in.iter().map(as_tuple).collect(),
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
            && self.range.is_none()
            && self.r#in.is_empty()
            && self.not_in.is_empty()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let v = match val.as_message() {
            Some(msg) => {
                let desc = msg.descriptor();
                if desc.full_name() != "google.protobuf.Duration" {
                    return Ok(());
                }
                let seconds = msg
                    .get_field_by_name("seconds")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let nanos = msg
                    .get_field_by_name("nanos")
                    .and_then(|v| v.as_i32())
                    .unwrap_or(0);
                (seconds, nanos)
            }
            None => return Ok(()),
        };

        let mut violations = Vec::new();

        if let Some(c) = self.r#const {
            if v != c {
                violations.push(Violation::new(
                    "",
                    meta::CONST_ID,
                    meta::const_message(c.0, c.1),
                ));
            }
        }

        if let Some(range) = &self.range {
            if range.kind.violated(self.gt_bound, self.lt_bound, v) {
                violations.push(
                    Violation::new("", range.rule_id.clone(), range.message.clone())
                        .with_rule_path(range.rule_path.clone()),
                );
            }
        }

        if !self.r#in.is_empty() && !self.r#in.contains(&v) {
            violations.push(Violation::new(
                "",
                meta::IN_ID,
                meta::in_message(&self.r#in),
            ));
        }

        if self.not_in.contains(&v) {
            violations.push(Violation::new(
                "",
                meta::NOT_IN_ID,
                meta::not_in_message(&self.not_in),
            ));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}
