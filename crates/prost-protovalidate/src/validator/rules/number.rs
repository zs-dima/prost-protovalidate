use std::collections::HashSet;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

/// Macro for float types that need NaN handling and use `Vec`-based `in`/`not_in`.
macro_rules! float_rule_eval {
    ($name:ident, $rules_ty:ty, $value_ty:ty, $extract_method:ident, $rules_mod:ident, $prefix:literal) => {
        pub(crate) struct $name {
            inner: numeric_inner::NumericInner<$value_ty>,
            finite: bool,
        }

        impl $name {
            pub fn new(rules: &$rules_ty) -> Self {
                Self {
                    inner: numeric_inner::NumericInner {
                        r#const: rules.r#const,
                        lt: rules.less_than.as_ref().and_then(|lt| match lt {
                            prost_protovalidate_types::$rules_mod::LessThan::Lt(v) => Some(*v),
                            _ => None,
                        }),
                        lte: rules.less_than.as_ref().and_then(|lt| match lt {
                            prost_protovalidate_types::$rules_mod::LessThan::Lte(v) => Some(*v),
                            _ => None,
                        }),
                        gt: rules.greater_than.as_ref().and_then(|gt| match gt {
                            prost_protovalidate_types::$rules_mod::GreaterThan::Gt(v) => Some(*v),
                            _ => None,
                        }),
                        gte: rules.greater_than.as_ref().and_then(|gt| match gt {
                            prost_protovalidate_types::$rules_mod::GreaterThan::Gte(v) => Some(*v),
                            _ => None,
                        }),
                        r#in: rules.r#in.clone(),
                        not_in: rules.not_in.clone(),
                    },
                    finite: rules.finite.unwrap_or(false),
                }
            }

            pub fn tautology(&self) -> bool {
                !self.finite && self.inner.tautology()
            }

            pub fn evaluate(
                &self,
                val: &prost_reflect::Value,
                _cfg: &ValidationConfig,
            ) -> Result<(), Error> {
                let v = match val.$extract_method() {
                    Some(v) => v as $value_ty,
                    None => return Ok(()),
                };
                // Check finite constraint first
                if self.finite && (v.is_nan() || v.is_infinite()) {
                    return Err(ValidationError::new(vec![Violation::new(
                        "",
                        concat!($prefix, ".finite"),
                        "value must be finite",
                    )])
                    .into());
                }
                // NaN fails all range comparisons — reject explicitly
                if v.is_nan() && self.inner.has_range_constraint() {
                    return Err(ValidationError::new(vec![
                        self.inner.nan_range_violation($prefix),
                    ])
                    .into());
                }
                self.inner.evaluate(v, $prefix)
            }
        }
    };
}

/// Macro for integer types (no NaN, use `HashSet` directly).
macro_rules! int_rule_eval {
    ($name:ident, $rules_ty:ty, $value_ty:ty, $extract_method:ident, $rules_mod:ident, $prefix:literal) => {
        pub(crate) struct $name {
            r#const: Option<$value_ty>,
            lt: Option<$value_ty>,
            lte: Option<$value_ty>,
            gt: Option<$value_ty>,
            gte: Option<$value_ty>,
            r#in: HashSet<$value_ty>,
            not_in: HashSet<$value_ty>,
        }

        impl $name {
            pub fn new(rules: &$rules_ty) -> Self {
                Self {
                    r#const: rules.r#const,
                    lt: rules.less_than.as_ref().and_then(|lt| match lt {
                        prost_protovalidate_types::$rules_mod::LessThan::Lt(v) => Some(*v),
                        _ => None,
                    }),
                    lte: rules.less_than.as_ref().and_then(|lt| match lt {
                        prost_protovalidate_types::$rules_mod::LessThan::Lte(v) => Some(*v),
                        _ => None,
                    }),
                    gt: rules.greater_than.as_ref().and_then(|gt| match gt {
                        prost_protovalidate_types::$rules_mod::GreaterThan::Gt(v) => Some(*v),
                        _ => None,
                    }),
                    gte: rules.greater_than.as_ref().and_then(|gt| match gt {
                        prost_protovalidate_types::$rules_mod::GreaterThan::Gte(v) => Some(*v),
                        _ => None,
                    }),
                    r#in: rules.r#in.iter().copied().collect(),
                    not_in: rules.not_in.iter().copied().collect(),
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
                let v = match val.$extract_method() {
                    Some(v) => v as $value_ty,
                    None => return Ok(()),
                };

                let mut violations = Vec::new();

                if let Some(c) = self.r#const {
                    if v != c {
                        violations.push(Violation::new(
                            "",
                            concat!($prefix, ".const"),
                            format!("value must equal {c}"),
                        ));
                    }
                }

                check_range(
                    v,
                    self.gt,
                    self.gte,
                    self.lt,
                    self.lte,
                    $prefix,
                    &mut violations,
                );

                if !self.r#in.is_empty() && !self.r#in.contains(&v) {
                    violations.push(Violation::new(
                        "",
                        concat!($prefix, ".in"),
                        "value must be in list",
                    ));
                }

                if self.not_in.contains(&v) {
                    violations.push(Violation::new(
                        "",
                        concat!($prefix, ".not_in"),
                        "value must not be in list",
                    ));
                }

                if violations.is_empty() {
                    Ok(())
                } else {
                    Err(ValidationError::new(violations).into())
                }
            }
        }
    };
}

#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
fn check_range<T: PartialOrd + std::fmt::Display>(
    v: T,
    gt: Option<T>,
    gte: Option<T>,
    lt: Option<T>,
    lte: Option<T>,
    prefix: &str,
    violations: &mut Vec<Violation>,
) {
    match (&gt, &gte, &lt, &lte) {
        (Some(gt), None, Some(lt), None) => {
            if *gt < *lt {
                if v <= *gt || v >= *lt {
                    violations.push(
                        Violation::new(
                            "",
                            format!("{prefix}.gt_lt"),
                            format!("value must be greater than {gt} and less than {lt}"),
                        )
                        .with_rule_path(format!("{prefix}.gt")),
                    );
                }
            } else if v >= *lt && v <= *gt {
                violations.push(
                    Violation::new(
                        "",
                        format!("{prefix}.gt_lt_exclusive"),
                        format!("value must be greater than {gt} or less than {lt}"),
                    )
                    .with_rule_path(format!("{prefix}.gt")),
                );
            }
        }
        (Some(gt), None, None, Some(lte)) => {
            if *gt < *lte {
                if v <= *gt || v > *lte {
                    violations.push(
                        Violation::new(
                            "",
                            format!("{prefix}.gt_lte"),
                            format!(
                                "value must be greater than {gt} and less than or equal to {lte}"
                            ),
                        )
                        .with_rule_path(format!("{prefix}.gt")),
                    );
                }
            } else if v > *lte && v <= *gt {
                violations.push(
                    Violation::new(
                        "",
                        format!("{prefix}.gt_lte_exclusive"),
                        format!("value must be greater than {gt} or less than or equal to {lte}"),
                    )
                    .with_rule_path(format!("{prefix}.gt")),
                );
            }
        }
        (None, Some(gte), Some(lt), None) => {
            if *gte < *lt {
                if v < *gte || v >= *lt {
                    violations.push(
                        Violation::new(
                            "",
                            format!("{prefix}.gte_lt"),
                            format!(
                                "value must be greater than or equal to {gte} and less than {lt}"
                            ),
                        )
                        .with_rule_path(format!("{prefix}.gte")),
                    );
                }
            } else if v >= *lt && v < *gte {
                violations.push(
                    Violation::new(
                        "",
                        format!("{prefix}.gte_lt_exclusive"),
                        format!("value must be greater than or equal to {gte} or less than {lt}"),
                    )
                    .with_rule_path(format!("{prefix}.gte")),
                );
            }
        }
        (None, Some(gte), None, Some(lte)) => {
            if *gte <= *lte {
                if v < *gte || v > *lte {
                    violations.push(
                        Violation::new(
                            "",
                            format!("{prefix}.gte_lte"),
                            format!("value must be greater than or equal to {gte} and less than or equal to {lte}"),
                        )
                        .with_rule_path(format!("{prefix}.gte")),
                    );
                }
            } else if v > *lte && v < *gte {
                violations.push(
                    Violation::new(
                        "",
                        format!("{prefix}.gte_lte_exclusive"),
                        format!(
                            "value must be greater than or equal to {gte} or less than or equal to {lte}"
                        ),
                    )
                    .with_rule_path(format!("{prefix}.gte")),
                );
            }
        }
        (Some(gt), None, None, None) => {
            if v <= *gt {
                violations.push(Violation::new(
                    "",
                    format!("{prefix}.gt"),
                    format!("value must be greater than {gt}"),
                ));
            }
        }
        (None, Some(gte), None, None) => {
            if v < *gte {
                violations.push(Violation::new(
                    "",
                    format!("{prefix}.gte"),
                    format!("value must be greater than or equal to {gte}"),
                ));
            }
        }
        (None, None, Some(lt), None) => {
            if v >= *lt {
                violations.push(Violation::new(
                    "",
                    format!("{prefix}.lt"),
                    format!("value must be less than {lt}"),
                ));
            }
        }
        (None, None, None, Some(lte)) => {
            if v > *lte {
                violations.push(Violation::new(
                    "",
                    format!("{prefix}.lte"),
                    format!("value must be less than or equal to {lte}"),
                ));
            }
        }
        _ => {}
    }
}

mod numeric_inner {
    use super::{Error, ValidationError, Violation, check_range};

    pub(super) struct NumericInner<T> {
        pub r#const: Option<T>,
        pub lt: Option<T>,
        pub lte: Option<T>,
        pub gt: Option<T>,
        pub gte: Option<T>,
        pub r#in: Vec<T>,
        pub not_in: Vec<T>,
    }

    impl<T: PartialOrd + PartialEq + std::fmt::Display + Copy> NumericInner<T> {
        pub fn tautology(&self) -> bool {
            self.r#const.is_none()
                && self.lt.is_none()
                && self.lte.is_none()
                && self.gt.is_none()
                && self.gte.is_none()
                && self.r#in.is_empty()
                && self.not_in.is_empty()
        }

        /// Whether any range constraint (gt/gte/lt/lte) is set.
        pub fn has_range_constraint(&self) -> bool {
            self.gt.is_some() || self.gte.is_some() || self.lt.is_some() || self.lte.is_some()
        }

        /// Build the violation that NaN should produce for the first applicable range rule.
        pub fn nan_range_violation(&self, prefix: &str) -> Violation {
            // Determine the appropriate rule_id based on the combination of range constraints.
            // Exclusive ranges (gt >= lt or gte > lte) use the `_exclusive` suffix.
            let rule_id = match (&self.gt, &self.gte, &self.lt, &self.lte) {
                (Some(gt), _, Some(lt), _) if *gt < *lt => format!("{prefix}.gt_lt"),
                (Some(_), _, Some(_), _) => format!("{prefix}.gt_lt_exclusive"),
                (Some(gt), _, _, Some(lte)) if *gt < *lte => format!("{prefix}.gt_lte"),
                (Some(_), _, _, Some(_)) => format!("{prefix}.gt_lte_exclusive"),
                (_, Some(gte), Some(lt), _) if *gte < *lt => format!("{prefix}.gte_lt"),
                (_, Some(_), Some(_), _) => format!("{prefix}.gte_lt_exclusive"),
                (_, Some(gte), _, Some(lte)) if *gte <= *lte => format!("{prefix}.gte_lte"),
                (_, Some(_), _, Some(_)) => format!("{prefix}.gte_lte_exclusive"),
                (Some(_), _, _, _) => format!("{prefix}.gt"),
                (_, Some(_), _, _) => format!("{prefix}.gte"),
                (_, _, Some(_), _) => format!("{prefix}.lt"),
                (_, _, _, Some(_)) => format!("{prefix}.lte"),
                _ => unreachable!("has_range_constraint was true"),
            };
            let rule_path = match (&self.gt, &self.gte) {
                (Some(_), _) => format!("{prefix}.gt"),
                (_, Some(_)) => format!("{prefix}.gte"),
                _ => rule_id.clone(),
            };
            Violation::new("", &rule_id, "").with_rule_path(rule_path)
        }

        pub fn evaluate(&self, v: T, prefix: &str) -> Result<(), Error> {
            let mut violations = Vec::new();

            if let Some(c) = self.r#const {
                if v != c {
                    violations.push(Violation::new(
                        "",
                        format!("{prefix}.const"),
                        format!("value must equal {c}"),
                    ));
                }
            }

            check_range(
                v,
                self.gt,
                self.gte,
                self.lt,
                self.lte,
                prefix,
                &mut violations,
            );

            if !self.r#in.is_empty() && !self.r#in.contains(&v) {
                violations.push(Violation::new(
                    "",
                    format!("{prefix}.in"),
                    "value must be in list",
                ));
            }

            if self.not_in.contains(&v) {
                violations.push(Violation::new(
                    "",
                    format!("{prefix}.not_in"),
                    "value must not be in list",
                ));
            }

            if violations.is_empty() {
                Ok(())
            } else {
                Err(ValidationError::new(violations).into())
            }
        }
    }
}

// Float types
float_rule_eval!(
    FloatRuleEval,
    prost_protovalidate_types::FloatRules,
    f32,
    as_f32,
    float_rules,
    "float"
);
float_rule_eval!(
    DoubleRuleEval,
    prost_protovalidate_types::DoubleRules,
    f64,
    as_f64,
    double_rules,
    "double"
);

// Integer types
int_rule_eval!(
    Int32RuleEval,
    prost_protovalidate_types::Int32Rules,
    i32,
    as_i32,
    int32_rules,
    "int32"
);
int_rule_eval!(
    Int64RuleEval,
    prost_protovalidate_types::Int64Rules,
    i64,
    as_i64,
    int64_rules,
    "int64"
);
int_rule_eval!(
    UInt32RuleEval,
    prost_protovalidate_types::UInt32Rules,
    u32,
    as_u32,
    u_int32_rules,
    "uint32"
);
int_rule_eval!(
    UInt64RuleEval,
    prost_protovalidate_types::UInt64Rules,
    u64,
    as_u64,
    u_int64_rules,
    "uint64"
);
int_rule_eval!(
    SInt32RuleEval,
    prost_protovalidate_types::SInt32Rules,
    i32,
    as_i32,
    s_int32_rules,
    "sint32"
);
int_rule_eval!(
    SInt64RuleEval,
    prost_protovalidate_types::SInt64Rules,
    i64,
    as_i64,
    s_int64_rules,
    "sint64"
);
int_rule_eval!(
    Fixed32RuleEval,
    prost_protovalidate_types::Fixed32Rules,
    u32,
    as_u32,
    fixed32_rules,
    "fixed32"
);
int_rule_eval!(
    Fixed64RuleEval,
    prost_protovalidate_types::Fixed64Rules,
    u64,
    as_u64,
    fixed64_rules,
    "fixed64"
);
int_rule_eval!(
    SFixed32RuleEval,
    prost_protovalidate_types::SFixed32Rules,
    i32,
    as_i32,
    s_fixed32_rules,
    "sfixed32"
);
int_rule_eval!(
    SFixed64RuleEval,
    prost_protovalidate_types::SFixed64Rules,
    i64,
    as_i64,
    s_fixed64_rules,
    "sfixed64"
);
