//! Numeric rule code generation for all 12 proto numeric types.
//!
//! Rule identifiers, messages, and bound-combination selection come from
//! [`prost_protovalidate_types::rules_meta::numeric`] — the same source the
//! runtime evaluator consumes — and are embedded into the generated code as
//! literals. The emitted comparison for each [`RangeKind`] mirrors
//! [`RangeKind::violated`]; the parity suites pin the correspondence.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::rules_meta::numeric::{self, RangeKind, RangeRule};
use prost_protovalidate_types::{
    DoubleRules, Fixed32Rules, Fixed64Rules, FloatRules, Int32Rules, Int64Rules, SFixed32Rules,
    SFixed64Rules, SInt32Rules, SInt64Rules, UInt32Rules, UInt64Rules,
};

/// Wrap float/double `inner` checks in a labeled block with NaN/Inf guards
/// that match runtime's early-return semantics:
/// - `finite = true` + NaN/Inf → emit `<prefix>.finite`, skip remaining checks
/// - NaN + any range constraint → emit the runtime's NaN-range violation, skip
///   remaining checks
/// - Otherwise: run the standard checks (`const` / range / `in` / `not_in`).
///
/// When neither guard applies (no `finite`, no range bounds), the original
/// flat checks are returned unchanged.
fn wrap_with_float_guards(
    prefix: &str,
    finite_required: bool,
    nan_range: Option<(String, String)>,
    value_access: &TokenStream,
    proto_name: &str,
    inner: &[TokenStream],
) -> Vec<TokenStream> {
    if inner.is_empty() && !finite_required && nan_range.is_none() {
        return Vec::new();
    }

    // No NaN/Inf handling needed: still bind `_v` once so `inner` (which was
    // generated against `_v`) resolves cleanly. The single binding also avoids
    // re-evaluating `value_access` per check.
    if !finite_required && nan_range.is_none() {
        return vec![quote! {
            {
                let _v = #value_access;
                #(#inner)*
            }
        }];
    }

    let finite_check = if finite_required {
        let rule_id = numeric::finite_id(prefix);
        let message = numeric::FINITE_MESSAGE;
        quote! {
            if _v.is_nan() || _v.is_infinite() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #message,
                ));
                break 'numeric_check;
            }
        }
    } else {
        quote! {}
    };

    let nan_range_check = if let Some((rule_id, rule_path)) = nan_range {
        quote! {
            if _v.is_nan() {
                violations.push(::prost_protovalidate::Violation::new_constraint(
                    #proto_name, #rule_id, #rule_path,
                ));
                break 'numeric_check;
            }
        }
    } else {
        quote! {}
    };

    vec![quote! {
        {
            let _v = #value_access;
            'numeric_check: {
                #finite_check
                #nan_range_check
                #(#inner)*
            }
        }
    }]
}

/// Extracted numeric rule metadata ready for code generation.
struct NumericParts {
    prefix: &'static str,
    /// `(value literal, resolved message)` for `const`.
    const_part: Option<(TokenStream, String)>,
    /// Resolved range rule plus the bound literals it compares against.
    range: Option<(RangeRule, Option<TokenStream>, Option<TokenStream>)>,
    /// `(rule_id, rule_path)` a NaN value produces against the bounds
    /// (float/double only).
    nan_range: Option<(String, String)>,
    in_vals: Vec<TokenStream>,
    not_in_vals: Vec<TokenStream>,
}

impl NumericParts {
    fn generate(self, value_access: &TokenStream, proto_name: &str) -> Vec<TokenStream> {
        let mut checks = Vec::new();

        if let Some((literal, message)) = self.const_part {
            let rule_id = numeric::const_id(self.prefix);
            checks.push(quote! {
                if #value_access != #literal {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #message,
                    ));
                }
            });
        }

        if let Some((rule, gt, lt)) = &self.range {
            checks.extend(generate_range_check(
                rule,
                gt.as_ref(),
                lt.as_ref(),
                value_access,
                proto_name,
            ));
        }

        if !self.in_vals.is_empty() {
            let rule_id = numeric::in_id(self.prefix);
            let message = numeric::IN_MESSAGE;
            let vals = &self.in_vals;
            checks.push(quote! {
                if ![#(#vals),*].contains(&#value_access) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #message,
                    ));
                }
            });
        }

        if !self.not_in_vals.is_empty() {
            let rule_id = numeric::not_in_id(self.prefix);
            let message = numeric::NOT_IN_MESSAGE;
            let vals = &self.not_in_vals;
            checks.push(quote! {
                if [#(#vals),*].contains(&#value_access) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #message,
                    ));
                }
            });
        }

        checks
    }
}

/// Emit the violation check for a resolved range rule. The comparison is the
/// token-level mirror of [`RangeKind::violated`]. Also used by the duration
/// and timestamp generators, which compare `(seconds, nanos)` tuples.
pub(super) fn generate_range_check(
    rule: &RangeRule,
    gt: Option<&TokenStream>,
    lt: Option<&TokenStream>,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let Some(predicate) = range_predicate(rule.kind, value_access, gt, lt) else {
        return Vec::new();
    };
    let rule_id = &rule.rule_id;
    let rule_path = &rule.rule_path;
    let message = &rule.message;
    // `unused_comparisons`: unsigned types can produce always-false
    // comparisons like `v < 0u32` for a `gte: 0` bound.
    vec![quote! {
        #[allow(unused_comparisons)]
        if #predicate {
            let mut violation = ::prost_protovalidate::Violation::new_constraint(
                #proto_name, #rule_id, #rule_path,
            );
            violation.set_message(#message);
            violations.push(violation);
        }
    }]
}

/// The comparison tokens for a [`RangeKind`]; `None` when a bound the kind
/// requires is missing (unreachable for rules produced by `range_rule`).
fn range_predicate(
    kind: RangeKind,
    v: &TokenStream,
    gt: Option<&TokenStream>,
    lt: Option<&TokenStream>,
) -> Option<TokenStream> {
    Some(match kind {
        RangeKind::Gt => {
            let g = gt?;
            quote! { #v <= #g }
        }
        RangeKind::Gte => {
            let g = gt?;
            quote! { #v < #g }
        }
        RangeKind::Lt => {
            let l = lt?;
            quote! { #v >= #l }
        }
        RangeKind::Lte => {
            let l = lt?;
            quote! { #v > #l }
        }
        RangeKind::GtLt => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v <= #g || #v >= #l }
        }
        RangeKind::GtLtExclusive => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v >= #l && #v <= #g }
        }
        RangeKind::GtLte => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v <= #g || #v > #l }
        }
        RangeKind::GtLteExclusive => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v > #l && #v <= #g }
        }
        RangeKind::GteLt => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v < #g || #v >= #l }
        }
        RangeKind::GteLtExclusive => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v >= #l && #v < #g }
        }
        RangeKind::GteLte => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v < #g || #v > #l }
        }
        RangeKind::GteLteExclusive => {
            let (g, l) = gt.zip(lt)?;
            quote! { #v > #l && #v < #g }
        }
    })
}

/// Build [`NumericParts`] from a numeric rules struct: extracts the bound
/// oneofs, resolves the shared range/NaN metadata, and captures the value
/// literals.
macro_rules! numeric_parts {
    ($rules:expr, $prefix:literal, $mod:ident) => {{
        use prost_protovalidate_types::$mod::{GreaterThan, LessThan};
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
        let gt_tokens = gt.or(gte).map(|v| quote! { #v });
        let lt_tokens = lt.or(lte).map(|v| quote! { #v });
        NumericParts {
            prefix: $prefix,
            const_part: $rules
                .r#const
                .map(|c| (quote! { #c }, numeric::const_message(c))),
            range: numeric::range_rule($prefix, gt, gte, lt, lte, |v| v.to_string())
                .map(|rule| (rule, gt_tokens, lt_tokens)),
            nan_range: numeric::nan_range_rule($prefix, gt, gte, lt, lte),
            in_vals: $rules.r#in.iter().map(|v| quote! { #v }).collect(),
            not_in_vals: $rules.not_in.iter().map(|v| quote! { #v }).collect(),
        }
    }};
}

macro_rules! int_generator {
    ($fn_name:ident, $rules_ty:ty, $prefix:literal, $mod:ident) => {
        pub(crate) fn $fn_name(
            rules: &$rules_ty,
            value_access: &TokenStream,
            proto_name: &str,
        ) -> Vec<TokenStream> {
            numeric_parts!(rules, $prefix, $mod).generate(value_access, proto_name)
        }
    };
}

int_generator!(generate_int32, Int32Rules, "int32", int32_rules);
int_generator!(generate_int64, Int64Rules, "int64", int64_rules);
int_generator!(generate_uint32, UInt32Rules, "uint32", u_int32_rules);
int_generator!(generate_uint64, UInt64Rules, "uint64", u_int64_rules);
int_generator!(generate_sint32, SInt32Rules, "sint32", s_int32_rules);
int_generator!(generate_sint64, SInt64Rules, "sint64", s_int64_rules);
int_generator!(generate_fixed32, Fixed32Rules, "fixed32", fixed32_rules);
int_generator!(generate_fixed64, Fixed64Rules, "fixed64", fixed64_rules);
int_generator!(
    generate_sfixed32,
    SFixed32Rules,
    "sfixed32",
    s_fixed32_rules
);
int_generator!(
    generate_sfixed64,
    SFixed64Rules,
    "sfixed64",
    s_fixed64_rules
);

macro_rules! float_generator {
    ($fn_name:ident, $rules_ty:ty, $prefix:literal, $mod:ident) => {
        pub(crate) fn $fn_name(
            rules: &$rules_ty,
            value_access: &TokenStream,
            proto_name: &str,
        ) -> Vec<TokenStream> {
            let parts = numeric_parts!(rules, $prefix, $mod);
            let nan_range = parts.nan_range.clone();
            let inner_access = quote! { _v };
            let inner = parts.generate(&inner_access, proto_name);
            wrap_with_float_guards(
                $prefix,
                rules.finite == Some(true),
                nan_range,
                value_access,
                proto_name,
                &inner,
            )
        }
    };
}

float_generator!(generate_float, FloatRules, "float", float_rules);
float_generator!(generate_double, DoubleRules, "double", double_rules);
