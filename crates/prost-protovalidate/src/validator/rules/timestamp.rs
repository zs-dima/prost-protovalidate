use prost_reflect::ReflectMessage;
use prost_types::Timestamp;

use super::duration::dur_gt;
use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

pub(crate) struct TimestampRuleEval {
    r#const: Option<Timestamp>,
    lt: Option<Timestamp>,
    lte: Option<Timestamp>,
    gt: Option<Timestamp>,
    gte: Option<Timestamp>,
    lt_now: bool,
    gt_now: bool,
    within: Option<prost_types::Duration>,
}

impl TimestampRuleEval {
    pub fn new(rules: &prost_protovalidate_types::TimestampRules) -> Self {
        use prost_protovalidate_types::timestamp_rules::{GreaterThan, LessThan};

        Self {
            r#const: rules.r#const,
            lt: rules.less_than.as_ref().and_then(|lt| match lt {
                LessThan::Lt(v) => Some(*v),
                LessThan::Lte(_) | LessThan::LtNow(_) => None,
            }),
            lte: rules.less_than.as_ref().and_then(|lt| match lt {
                LessThan::Lte(v) => Some(*v),
                LessThan::Lt(_) | LessThan::LtNow(_) => None,
            }),
            gt: rules.greater_than.as_ref().and_then(|gt| match gt {
                GreaterThan::Gt(v) => Some(*v),
                GreaterThan::Gte(_) | GreaterThan::GtNow(_) => None,
            }),
            gte: rules.greater_than.as_ref().and_then(|gt| match gt {
                GreaterThan::Gte(v) => Some(*v),
                GreaterThan::Gt(_) | GreaterThan::GtNow(_) => None,
            }),
            lt_now: rules
                .less_than
                .as_ref()
                .is_some_and(|lt| matches!(lt, LessThan::LtNow(true))),
            gt_now: rules
                .greater_than
                .as_ref()
                .is_some_and(|gt| matches!(gt, GreaterThan::GtNow(true))),
            within: rules.within,
        }
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
            && self.lt.is_none()
            && self.lte.is_none()
            && self.gt.is_none()
            && self.gte.is_none()
            && !self.lt_now
            && !self.gt_now
            && self.within.is_none()
    }

    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let ts = match val.as_message() {
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
                Timestamp { seconds, nanos }
            }
            None => return Ok(()),
        };

        let mut violations = Vec::new();

        if let Some(ref c) = self.r#const {
            if !ts_eq(&ts, c) {
                violations.push(Violation::new(
                    "",
                    "timestamp.const",
                    "must equal const timestamp",
                ));
            }
        }

        check_timestamp_range(
            &ts,
            self.gt.as_ref(),
            self.gte.as_ref(),
            self.lt.as_ref(),
            self.lte.as_ref(),
            &mut violations,
        );

        let now = (cfg.now_fn)();

        if self.lt_now && !ts_lt(&ts, &now) {
            violations.push(Violation::new(
                "",
                "timestamp.lt_now",
                "must be less than now",
            ));
        }

        if self.gt_now && !ts_gt(&ts, &now) {
            violations.push(Violation::new(
                "",
                "timestamp.gt_now",
                "must be greater than now",
            ));
        }

        if let Some(ref within) = self.within {
            let diff = ts_abs_diff(&ts, &now);
            if dur_gt(
                &diff,
                &prost_types::Duration {
                    seconds: within.seconds,
                    nanos: within.nanos,
                },
            ) {
                violations.push(Violation::new(
                    "",
                    "timestamp.within",
                    "must be within specified duration of now",
                ));
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

fn ts_eq(a: &Timestamp, b: &Timestamp) -> bool {
    a.seconds == b.seconds && a.nanos == b.nanos
}

fn ts_lt(a: &Timestamp, b: &Timestamp) -> bool {
    a.seconds < b.seconds || (a.seconds == b.seconds && a.nanos < b.nanos)
}

fn ts_gt(a: &Timestamp, b: &Timestamp) -> bool {
    a.seconds > b.seconds || (a.seconds == b.seconds && a.nanos > b.nanos)
}

fn ts_lte(a: &Timestamp, b: &Timestamp) -> bool {
    !ts_gt(a, b)
}

/// Compute the absolute difference between two timestamps as a `Duration`.
fn ts_abs_diff(a: &Timestamp, b: &Timestamp) -> prost_types::Duration {
    // Convert to total nanoseconds using i128 to avoid overflow.
    let a_nanos = i128::from(a.seconds) * 1_000_000_000 + i128::from(a.nanos);
    let b_nanos = i128::from(b.seconds) * 1_000_000_000 + i128::from(b.nanos);
    let diff = (a_nanos - b_nanos).unsigned_abs();

    // Safe: Duration seconds/nanos are bounded by proto spec.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    prost_types::Duration {
        seconds: (diff / 1_000_000_000) as i64,
        nanos: (diff % 1_000_000_000) as i32,
    }
}

#[allow(clippy::too_many_lines)]
fn check_timestamp_range(
    v: &Timestamp,
    gt: Option<&Timestamp>,
    gte: Option<&Timestamp>,
    lt: Option<&Timestamp>,
    lte: Option<&Timestamp>,
    violations: &mut Vec<Violation>,
) {
    match (gt, gte, lt, lte) {
        // gt + lt
        (Some(gt), None, Some(lt), None) => {
            if ts_lt(gt, lt) {
                if ts_lte(v, gt) || !ts_lt(v, lt) {
                    violations.push(
                        Violation::new(
                            "",
                            "timestamp.gt_lt",
                            "must be greater than and less than specified timestamps",
                        )
                        .with_rule_path("timestamp.gt"),
                    );
                }
            } else if !ts_lt(v, lt) && !ts_gt(v, gt) {
                violations.push(
                    Violation::new(
                        "",
                        "timestamp.gt_lt_exclusive",
                        "must be greater than or less than specified timestamps",
                    )
                    .with_rule_path("timestamp.gt"),
                );
            }
        }
        // gt + lte
        (Some(gt), None, None, Some(lte)) => {
            if ts_lt(gt, lte) {
                if ts_lte(v, gt) || ts_gt(v, lte) {
                    violations.push(
                        Violation::new(
                            "",
                            "timestamp.gt_lte",
                            "must be greater than and less than or equal to specified timestamps",
                        )
                        .with_rule_path("timestamp.gt"),
                    );
                }
            } else if ts_gt(v, lte) && ts_lte(v, gt) {
                violations.push(
                    Violation::new(
                        "",
                        "timestamp.gt_lte_exclusive",
                        "must be greater than or less than or equal to specified timestamps",
                    )
                    .with_rule_path("timestamp.gt"),
                );
            }
        }
        // gte + lt
        (None, Some(gte), Some(lt), None) => {
            if ts_lt(gte, lt) {
                if ts_lt(v, gte) || !ts_lt(v, lt) {
                    violations.push(
                        Violation::new(
                            "",
                            "timestamp.gte_lt",
                            "must be greater than or equal to and less than specified timestamps",
                        )
                        .with_rule_path("timestamp.gte"),
                    );
                }
            } else if !ts_lt(v, lt) && ts_lt(v, gte) {
                violations.push(
                    Violation::new(
                        "",
                        "timestamp.gte_lt_exclusive",
                        "must be greater than or equal to or less than specified timestamps",
                    )
                    .with_rule_path("timestamp.gte"),
                );
            }
        }
        // gte + lte
        (None, Some(gte), None, Some(lte)) => {
            if ts_lte(gte, lte) {
                if ts_lt(v, gte) || ts_gt(v, lte) {
                    violations.push(
                        Violation::new(
                            "",
                            "timestamp.gte_lte",
                            "must be between specified timestamps inclusive",
                        )
                        .with_rule_path("timestamp.gte"),
                    );
                }
            } else if ts_gt(v, lte) && ts_lt(v, gte) {
                violations.push(
                    Violation::new(
                        "",
                        "timestamp.gte_lte_exclusive",
                        "must be greater than or equal to or less than or equal to specified timestamps",
                    )
                    .with_rule_path("timestamp.gte"),
                );
            }
        }
        // single bounds
        (Some(gt), None, None, None) => {
            if !ts_gt(v, gt) {
                violations.push(Violation::new(
                    "",
                    "timestamp.gt",
                    "must be greater than specified timestamp",
                ));
            }
        }
        (None, Some(gte), None, None) => {
            if ts_lt(v, gte) {
                violations.push(Violation::new(
                    "",
                    "timestamp.gte",
                    "must be greater than or equal to specified timestamp",
                ));
            }
        }
        (None, None, Some(lt), None) => {
            if !ts_lt(v, lt) {
                violations.push(Violation::new(
                    "",
                    "timestamp.lt",
                    "must be less than specified timestamp",
                ));
            }
        }
        (None, None, None, Some(lte)) => {
            if ts_gt(v, lte) {
                violations.push(Violation::new(
                    "",
                    "timestamp.lte",
                    "must be less than or equal to specified timestamp",
                ));
            }
        }
        _ => {}
    }
}
