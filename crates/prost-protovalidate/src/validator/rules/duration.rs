use prost_reflect::ReflectMessage;
use prost_types::Duration;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct DurationRuleEval {
    r#const: Option<Duration>,
    lt: Option<Duration>,
    lte: Option<Duration>,
    gt: Option<Duration>,
    gte: Option<Duration>,
    r#in: Vec<Duration>,
    not_in: Vec<Duration>,
}

impl DurationRuleEval {
    pub fn new(rules: &prost_protovalidate_types::DurationRules) -> Self {
        use prost_protovalidate_types::duration_rules::{GreaterThan, LessThan};

        Self {
            r#const: rules.r#const,
            lt: rules.less_than.as_ref().and_then(|lt| match lt {
                LessThan::Lt(v) => Some(*v),
                LessThan::Lte(_) => None,
            }),
            lte: rules.less_than.as_ref().and_then(|lt| match lt {
                LessThan::Lte(v) => Some(*v),
                LessThan::Lt(_) => None,
            }),
            gt: rules.greater_than.as_ref().and_then(|gt| match gt {
                GreaterThan::Gt(v) => Some(*v),
                GreaterThan::Gte(_) => None,
            }),
            gte: rules.greater_than.as_ref().and_then(|gt| match gt {
                GreaterThan::Gte(v) => Some(*v),
                GreaterThan::Gt(_) => None,
            }),
            r#in: rules.r#in.clone(),
            not_in: rules.not_in.clone(),
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
            && self.lt.is_none()
            && self.lte.is_none()
            && self.gt.is_none()
            && self.gte.is_none()
            && self.r#in.is_empty()
            && self.not_in.is_empty()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let dur = match val.as_message() {
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
                Duration { seconds, nanos }
            }
            None => return Ok(()),
        };

        let mut violations = Vec::new();

        if let Some(ref c) = self.r#const {
            if !dur_eq(&dur, c) {
                violations.push(Violation::new(
                    "",
                    "duration.const",
                    "must equal const duration",
                ));
            }
        }

        check_duration_range(
            &dur,
            self.gt.as_ref(),
            self.gte.as_ref(),
            self.lt.as_ref(),
            self.lte.as_ref(),
            &mut violations,
        );

        if !self.r#in.is_empty() && !self.r#in.iter().any(|d| dur_eq(&dur, d)) {
            violations.push(Violation::new("", "duration.in", "must be in list"));
        }

        if self.not_in.iter().any(|d| dur_eq(&dur, d)) {
            violations.push(Violation::new("", "duration.not_in", "must not be in list"));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

pub(crate) fn dur_eq(a: &Duration, b: &Duration) -> bool {
    a.seconds == b.seconds && a.nanos == b.nanos
}

pub(crate) fn dur_lt(a: &Duration, b: &Duration) -> bool {
    a.seconds < b.seconds || (a.seconds == b.seconds && a.nanos < b.nanos)
}

pub(crate) fn dur_gt(a: &Duration, b: &Duration) -> bool {
    a.seconds > b.seconds || (a.seconds == b.seconds && a.nanos > b.nanos)
}

fn dur_lte(a: &Duration, b: &Duration) -> bool {
    !dur_gt(a, b)
}

#[allow(clippy::too_many_lines)]
fn check_duration_range(
    v: &Duration,
    gt: Option<&Duration>,
    gte: Option<&Duration>,
    lt: Option<&Duration>,
    lte: Option<&Duration>,
    violations: &mut Vec<Violation>,
) {
    match (gt, gte, lt, lte) {
        // gt + lt
        (Some(gt), None, Some(lt), None) => {
            if dur_lt(gt, lt) {
                // normal range: value must be > gt AND < lt
                if dur_lte(v, gt) || !dur_lt(v, lt) {
                    violations.push(Violation::new(
                        "",
                        "duration.gt_lt",
                        "must be greater than and less than specified durations",
                    ));
                }
            } else {
                // exclusive range: value must be > gt OR < lt
                if !dur_lt(v, lt) && !dur_gt(v, gt) {
                    violations.push(Violation::new(
                        "",
                        "duration.gt_lt_exclusive",
                        "must be greater than or less than specified durations",
                    ));
                }
            }
        }
        // gt + lte
        (Some(gt), None, None, Some(lte)) => {
            if dur_lt(gt, lte) {
                if dur_lte(v, gt) || dur_gt(v, lte) {
                    violations.push(Violation::new(
                        "",
                        "duration.gt_lte",
                        "must be greater than and less than or equal to specified durations",
                    ));
                }
            } else if dur_gt(v, lte) && dur_lte(v, gt) {
                violations.push(Violation::new(
                    "",
                    "duration.gt_lte_exclusive",
                    "must be greater than or less than or equal to specified durations",
                ));
            }
        }
        // gte + lt
        (None, Some(gte), Some(lt), None) => {
            if dur_lt(gte, lt) {
                if dur_lt(v, gte) || !dur_lt(v, lt) {
                    violations.push(Violation::new(
                        "",
                        "duration.gte_lt",
                        "must be greater than or equal to and less than specified durations",
                    ));
                }
            } else if !dur_lt(v, lt) && dur_lt(v, gte) {
                violations.push(Violation::new(
                    "",
                    "duration.gte_lt_exclusive",
                    "must be greater than or equal to or less than specified durations",
                ));
            }
        }
        // gte + lte
        (None, Some(gte), None, Some(lte)) => {
            if dur_lte(gte, lte) {
                if dur_lt(v, gte) || dur_gt(v, lte) {
                    violations.push(Violation::new(
                        "",
                        "duration.gte_lte",
                        "must be between specified durations inclusive",
                    ));
                }
            } else if dur_gt(v, lte) && dur_lt(v, gte) {
                violations.push(Violation::new(
                    "",
                    "duration.gte_lte_exclusive",
                    "must be greater than or equal to or less than or equal to specified durations",
                ));
            }
        }
        // single bounds
        (Some(gt), None, None, None) => {
            if !dur_gt(v, gt) {
                violations.push(Violation::new(
                    "",
                    "duration.gt",
                    "must be greater than specified duration",
                ));
            }
        }
        (None, Some(gte), None, None) => {
            if dur_lt(v, gte) {
                violations.push(Violation::new(
                    "",
                    "duration.gte",
                    "must be greater than or equal to specified duration",
                ));
            }
        }
        (None, None, Some(lt), None) => {
            if !dur_lt(v, lt) {
                violations.push(Violation::new(
                    "",
                    "duration.lt",
                    "must be less than specified duration",
                ));
            }
        }
        (None, None, None, Some(lte)) => {
            if dur_gt(v, lte) {
                violations.push(Violation::new(
                    "",
                    "duration.lte",
                    "must be less than or equal to specified duration",
                ));
            }
        }
        _ => {}
    }
}
