use prost_protovalidate_types::rules_meta::numeric::RangeRule;
use prost_protovalidate_types::rules_meta::timestamp as meta;
use prost_reflect::ReflectMessage;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

/// Timestamp values are compared as `(seconds, nanos)` tuples: protobuf
/// keeps `nanos` non-negative, so lexicographic tuple order is timestamp
/// order.
pub(crate) struct TimestampRuleEval {
    r#const: Option<(i64, i32)>,
    /// The `gt`/`gte` bound, when set.
    gt_bound: Option<(i64, i32)>,
    /// The `lt`/`lte` bound, when set.
    lt_bound: Option<(i64, i32)>,
    /// Resolved range rule (kind + id + path + message), when a static
    /// bound is set.
    range: Option<RangeRule>,
    lt_now: bool,
    gt_now: bool,
    within: Option<(i64, i32)>,
}

impl TimestampRuleEval {
    pub fn new(rules: &prost_protovalidate_types::TimestampRules) -> Self {
        use prost_protovalidate_types::timestamp_rules::{GreaterThan, LessThan};

        let as_tuple = |t: &prost_types::Timestamp| (t.seconds, t.nanos);
        let (gt, gte) = match rules.greater_than.as_ref() {
            Some(GreaterThan::Gt(t)) => (Some(as_tuple(t)), None),
            Some(GreaterThan::Gte(t)) => (None, Some(as_tuple(t))),
            Some(GreaterThan::GtNow(_)) | None => (None, None),
        };
        let (lt, lte) = match rules.less_than.as_ref() {
            Some(LessThan::Lt(t)) => (Some(as_tuple(t)), None),
            Some(LessThan::Lte(t)) => (None, Some(as_tuple(t))),
            Some(LessThan::LtNow(_)) | None => (None, None),
        };

        Self {
            r#const: rules.r#const.as_ref().map(as_tuple),
            gt_bound: gt.or(gte),
            lt_bound: lt.or(lte),
            range: meta::range_rule(gt, gte, lt, lte),
            lt_now: rules
                .less_than
                .as_ref()
                .is_some_and(|lt| matches!(lt, LessThan::LtNow(true))),
            gt_now: rules
                .greater_than
                .as_ref()
                .is_some_and(|gt| matches!(gt, GreaterThan::GtNow(true))),
            within: rules.within.as_ref().map(|d| (d.seconds, d.nanos)),
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
            && self.range.is_none()
            && !self.lt_now
            && !self.gt_now
            && self.within.is_none()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let v = match val.as_message() {
            Some(msg) => {
                let desc = msg.descriptor();
                if desc.full_name() != "google.protobuf.Timestamp" {
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
                violations.push(Violation::new("", meta::CONST_ID, meta::CONST_MESSAGE));
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

        if self.lt_now || self.gt_now || self.within.is_some() {
            let now = (cfg.now_fn)();
            let now = (now.seconds, now.nanos);

            if self.lt_now && v >= now {
                violations.push(Violation::new("", meta::LT_NOW_ID, meta::LT_NOW_MESSAGE));
            }

            if self.gt_now && v <= now {
                violations.push(Violation::new("", meta::GT_NOW_ID, meta::GT_NOW_MESSAGE));
            }

            if let Some(within) = self.within {
                if ts_abs_diff(v, now) > within {
                    violations.push(Violation::new("", meta::WITHIN_ID, meta::WITHIN_MESSAGE));
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

/// Compute the absolute difference between two timestamps as a
/// `(seconds, nanos)` duration tuple.
fn ts_abs_diff(a: (i64, i32), b: (i64, i32)) -> (i64, i32) {
    // Convert to total nanoseconds using i128 to avoid overflow.
    let a_nanos = i128::from(a.0) * 1_000_000_000 + i128::from(a.1);
    let b_nanos = i128::from(b.0) * 1_000_000_000 + i128::from(b.1);
    let diff = (a_nanos - b_nanos).unsigned_abs();

    // Safe: Duration seconds/nanos are bounded by proto spec.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    ((diff / 1_000_000_000) as i64, (diff % 1_000_000_000) as i32)
}
