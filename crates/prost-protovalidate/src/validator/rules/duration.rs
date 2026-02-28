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
                    format!("value must equal {}", fmt_dur(c)),
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
            let list: Vec<String> = self.r#in.iter().map(fmt_dur).collect();
            violations.push(Violation::new(
                "",
                "duration.in",
                format!("value must be in list [{}]", list.join(", ")),
            ));
        }

        if self.not_in.iter().any(|d| dur_eq(&dur, d)) {
            let list: Vec<String> = self.not_in.iter().map(fmt_dur).collect();
            violations.push(Violation::new(
                "",
                "duration.not_in",
                format!("value must not be in list [{}]", list.join(", ")),
            ));
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

/// Format a `Duration` as a Go-style string (e.g. `"3s"`, `"1.500s"`, `"-2s"`).
fn fmt_dur(d: &Duration) -> String {
    if d.nanos == 0 {
        format!("{}s", d.seconds)
    } else {
        let sign = if d.seconds < 0 || d.nanos < 0 {
            "-"
        } else {
            ""
        };
        let secs = d.seconds.unsigned_abs();
        let nanos = d.nanos.unsigned_abs();
        let frac = format!("{nanos:09}").trim_end_matches('0').to_string();
        format!("{sign}{secs}.{frac}s")
    }
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
                    violations.push(
                        Violation::new(
                            "",
                            "duration.gt_lt",
                            format!(
                                "value must be greater than {} and less than {}",
                                fmt_dur(gt),
                                fmt_dur(lt)
                            ),
                        )
                        .with_rule_path("duration.gt"),
                    );
                }
            } else {
                // exclusive range: value must be > gt OR < lt
                if !dur_lt(v, lt) && !dur_gt(v, gt) {
                    violations.push(
                        Violation::new(
                            "",
                            "duration.gt_lt_exclusive",
                            format!(
                                "value must be greater than {} or less than {}",
                                fmt_dur(gt),
                                fmt_dur(lt)
                            ),
                        )
                        .with_rule_path("duration.gt"),
                    );
                }
            }
        }
        // gt + lte
        (Some(gt), None, None, Some(lte)) => {
            if dur_lt(gt, lte) {
                if dur_lte(v, gt) || dur_gt(v, lte) {
                    violations.push(
                        Violation::new(
                            "",
                            "duration.gt_lte",
                            format!(
                                "value must be greater than {} and less than or equal to {}",
                                fmt_dur(gt),
                                fmt_dur(lte)
                            ),
                        )
                        .with_rule_path("duration.gt"),
                    );
                }
            } else if dur_gt(v, lte) && dur_lte(v, gt) {
                violations.push(
                    Violation::new(
                        "",
                        "duration.gt_lte_exclusive",
                        format!(
                            "value must be greater than {} or less than or equal to {}",
                            fmt_dur(gt),
                            fmt_dur(lte)
                        ),
                    )
                    .with_rule_path("duration.gt"),
                );
            }
        }
        // gte + lt
        (None, Some(gte), Some(lt), None) => {
            if dur_lt(gte, lt) {
                if dur_lt(v, gte) || !dur_lt(v, lt) {
                    violations.push(
                        Violation::new(
                            "",
                            "duration.gte_lt",
                            format!(
                                "value must be greater than or equal to {} and less than {}",
                                fmt_dur(gte),
                                fmt_dur(lt)
                            ),
                        )
                        .with_rule_path("duration.gte"),
                    );
                }
            } else if !dur_lt(v, lt) && dur_lt(v, gte) {
                violations.push(
                    Violation::new(
                        "",
                        "duration.gte_lt_exclusive",
                        format!(
                            "value must be greater than or equal to {} or less than {}",
                            fmt_dur(gte),
                            fmt_dur(lt)
                        ),
                    )
                    .with_rule_path("duration.gte"),
                );
            }
        }
        // gte + lte
        (None, Some(gte), None, Some(lte)) => {
            if dur_lte(gte, lte) {
                if dur_lt(v, gte) || dur_gt(v, lte) {
                    violations.push(
                        Violation::new(
                            "",
                            "duration.gte_lte",
                            format!(
                                "value must be greater than or equal to {} and less than or equal to {}",
                                fmt_dur(gte),
                                fmt_dur(lte)
                            ),
                        )
                        .with_rule_path("duration.gte"),
                    );
                }
            } else if dur_gt(v, lte) && dur_lt(v, gte) {
                violations.push(
                    Violation::new(
                        "",
                        "duration.gte_lte_exclusive",
                        format!(
                            "value must be greater than or equal to {} or less than or equal to {}",
                            fmt_dur(gte),
                            fmt_dur(lte)
                        ),
                    )
                    .with_rule_path("duration.gte"),
                );
            }
        }
        // single bounds
        (Some(gt), None, None, None) => {
            if !dur_gt(v, gt) {
                violations.push(Violation::new(
                    "",
                    "duration.gt",
                    format!("value must be greater than {}", fmt_dur(gt)),
                ));
            }
        }
        (None, Some(gte), None, None) => {
            if dur_lt(v, gte) {
                violations.push(Violation::new(
                    "",
                    "duration.gte",
                    format!("value must be greater than or equal to {}", fmt_dur(gte)),
                ));
            }
        }
        (None, None, Some(lt), None) => {
            if !dur_lt(v, lt) {
                violations.push(Violation::new(
                    "",
                    "duration.lt",
                    format!("value must be less than {}", fmt_dur(lt)),
                ));
            }
        }
        (None, None, None, Some(lte)) => {
            if dur_gt(v, lte) {
                violations.push(Violation::new(
                    "",
                    "duration.lte",
                    format!("value must be less than or equal to {}", fmt_dur(lte)),
                ));
            }
        }
        _ => {}
    }
}
