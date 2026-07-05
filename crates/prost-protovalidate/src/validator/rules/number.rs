use prost_protovalidate_types::rules_meta::numeric;

use crate::config::ValidationConfig;
use crate::error::{Error, ValidationError};
use crate::violation::Violation;

/// Macro for float types: NaN/finite handling wrapped around the shared
/// numeric core.
macro_rules! float_rule_eval {
    ($name:ident, $rules_ty:ty, $value_ty:ty, $extract_method:ident, $rules_mod:ident, $prefix:literal) => {
        pub(crate) struct $name {
            inner: numeric_inner::NumericInner<$value_ty>,
            finite: bool,
        }

        impl $name {
            pub fn new(rules: &$rules_ty) -> Self {
                Self {
                    inner: numeric_inner::NumericInner::new(
                        $prefix,
                        rules.r#const,
                        extract_bounds!(rules, $rules_mod),
                        rules.r#in.clone(),
                        rules.not_in.clone(),
                    ),
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
                        numeric::finite_id($prefix),
                        numeric::FINITE_MESSAGE,
                    )])
                    .into());
                }
                // NaN fails all range comparisons — reject explicitly
                if v.is_nan() {
                    if let Some(violation) = self.inner.nan_range_violation() {
                        return Err(ValidationError::new(vec![violation]).into());
                    }
                }
                self.inner.evaluate(v)
            }
        }
    };
}

/// Macro for integer types: the shared numeric core without NaN handling.
macro_rules! int_rule_eval {
    ($name:ident, $rules_ty:ty, $value_ty:ty, $extract_method:ident, $rules_mod:ident, $prefix:literal) => {
        pub(crate) struct $name {
            inner: numeric_inner::NumericInner<$value_ty>,
        }

        impl $name {
            pub fn new(rules: &$rules_ty) -> Self {
                Self {
                    inner: numeric_inner::NumericInner::new(
                        $prefix,
                        rules.r#const,
                        extract_bounds!(rules, $rules_mod),
                        rules.r#in.clone(),
                        rules.not_in.clone(),
                    ),
                }
            }

            pub fn tautology(&self) -> bool {
                self.inner.tautology()
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
                self.inner.evaluate(v)
            }
        }
    };
}

/// Extract `(gt, gte, lt, lte)` from a numeric rules struct's bound oneofs.
macro_rules! extract_bounds {
    ($rules:expr, $rules_mod:ident) => {{
        use prost_protovalidate_types::$rules_mod::{GreaterThan, LessThan};
        let (gt, gte) = match $rules.greater_than.as_ref() {
            Some(GreaterThan::Gt(v)) => (Some(*v), None),
            Some(GreaterThan::Gte(v)) => (None, Some(*v)),
            None => (None, None),
        };
        let (lt, lte) = match $rules.less_than.as_ref() {
            Some(LessThan::Lt(v)) => (Some(*v), None),
            Some(LessThan::Lte(v)) => (None, Some(*v)),
            None => (None, None),
        };
        (gt, gte, lt, lte)
    }};
}

mod numeric_inner {
    use prost_protovalidate_types::rules_meta::numeric;

    use super::{Error, ValidationError, Violation};

    /// Shared `const`/range/`in`/`not_in` evaluation for every numeric type.
    ///
    /// Rule identifiers, messages, and the bound-combination selection are
    /// resolved once at construction through
    /// [`prost_protovalidate_types::rules_meta::numeric`] — the same source
    /// the build-time code generator embeds into generated validators.
    ///
    /// `in`/`not_in` use linear `Vec` scans: `f32`/`f64` are not
    /// `Hash`/`Eq`, rule lists are hand-written in protos and tiny, and for
    /// floats IEEE `==` is exactly the comparison `contains` performs
    /// (a NaN value never equals a list member).
    pub(super) struct NumericInner<T> {
        prefix: &'static str,
        r#const: Option<T>,
        /// The `gt`/`gte` bound value, when set.
        gt_bound: Option<T>,
        /// The `lt`/`lte` bound value, when set.
        lt_bound: Option<T>,
        /// Resolved range rule (kind + id + path + message), when any bound
        /// is set.
        range: Option<numeric::RangeRule>,
        /// Precomputed `(rule_id, rule_path)` a NaN value produces against
        /// the range bounds (float types only ever trigger it).
        nan_range: Option<(String, String)>,
        r#in: Vec<T>,
        not_in: Vec<T>,
    }

    impl<T: PartialOrd + PartialEq + std::fmt::Display + Copy> NumericInner<T> {
        pub fn new(
            prefix: &'static str,
            r#const: Option<T>,
            (gt, gte, lt, lte): (Option<T>, Option<T>, Option<T>, Option<T>),
            r#in: Vec<T>,
            not_in: Vec<T>,
        ) -> Self {
            Self {
                prefix,
                r#const,
                gt_bound: gt.or(gte),
                lt_bound: lt.or(lte),
                range: numeric::range_rule(prefix, gt, gte, lt, lte, T::to_string),
                nan_range: numeric::nan_range_rule(prefix, gt, gte, lt, lte),
                r#in,
                not_in,
            }
        }

        pub fn tautology(&self) -> bool {
            self.r#const.is_none()
                && self.range.is_none()
                && self.r#in.is_empty()
                && self.not_in.is_empty()
        }

        /// The violation a NaN value produces when a range constraint is
        /// set (empty message per the conformance corpus).
        pub fn nan_range_violation(&self) -> Option<Violation> {
            self.nan_range.as_ref().map(|(rule_id, rule_path)| {
                Violation::new("", rule_id.clone(), "").with_rule_path(rule_path.clone())
            })
        }

        pub fn evaluate(&self, v: T) -> Result<(), Error> {
            let mut violations = Vec::new();

            if let Some(c) = self.r#const {
                if v != c {
                    violations.push(Violation::new(
                        "",
                        numeric::const_id(self.prefix),
                        numeric::const_message(c),
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
                    numeric::in_id(self.prefix),
                    numeric::IN_MESSAGE,
                ));
            }

            if self.not_in.contains(&v) {
                violations.push(Violation::new(
                    "",
                    numeric::not_in_id(self.prefix),
                    numeric::NOT_IN_MESSAGE,
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
