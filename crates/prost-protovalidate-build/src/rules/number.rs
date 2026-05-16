//! Numeric rule code generation for all 12 proto numeric types.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::{
    DoubleRules, Fixed32Rules, Fixed64Rules, FloatRules, Int32Rules, Int64Rules, SFixed32Rules,
    SFixed64Rules, SInt32Rules, SInt64Rules, UInt32Rules, UInt64Rules, double_rules, fixed32_rules,
    fixed64_rules, float_rules, int32_rules, int64_rules, s_fixed32_rules, s_fixed64_rules,
    s_int32_rules, s_int64_rules, u_int32_rules, u_int64_rules,
};

/// Compute the `(rule_id, rule_path)` pair the runtime emits for a NaN value
/// hitting a range constraint, mirroring
/// `prost_protovalidate::validator::rules::number::numeric_inner::nan_range_violation`.
///
/// Returns `None` when no range constraint is set.
fn nan_range_rule_id_and_path(
    prefix: &str,
    gt: Option<f64>,
    gte: Option<f64>,
    lt: Option<f64>,
    lte: Option<f64>,
) -> Option<(String, String)> {
    let rule_id = match (gt, gte, lt, lte) {
        (Some(g), _, Some(l), _) if g < l => format!("{prefix}.gt_lt"),
        (Some(_), _, Some(_), _) => format!("{prefix}.gt_lt_exclusive"),
        (Some(g), _, _, Some(le)) if g < le => format!("{prefix}.gt_lte"),
        (Some(_), _, _, Some(_)) => format!("{prefix}.gt_lte_exclusive"),
        (_, Some(ge), Some(l), _) if ge < l => format!("{prefix}.gte_lt"),
        (_, Some(_), Some(_), _) => format!("{prefix}.gte_lt_exclusive"),
        (_, Some(ge), _, Some(le)) if ge <= le => format!("{prefix}.gte_lte"),
        (_, Some(_), _, Some(_)) => format!("{prefix}.gte_lte_exclusive"),
        (Some(_), _, _, _) => format!("{prefix}.gt"),
        (_, Some(_), _, _) => format!("{prefix}.gte"),
        (_, _, Some(_), _) => format!("{prefix}.lt"),
        (_, _, _, Some(_)) => format!("{prefix}.lte"),
        _ => return None,
    };
    let rule_path = match (gt, gte) {
        (Some(_), _) => format!("{prefix}.gt"),
        (_, Some(_)) => format!("{prefix}.gte"),
        _ => rule_id.clone(),
    };
    Some((rule_id, rule_path))
}

/// Wrap float/double `inner` checks in a labeled block with NaN/Inf guards
/// that match runtime's early-return semantics:
/// - `finite = true` + NaN/Inf → emit `<prefix>.finite`, skip remaining checks
/// - NaN + any range constraint → emit the runtime's NaN-range violation, skip
///   remaining checks
/// - Otherwise: run the standard checks (`const` / range / `in` / `not_in`).
///
/// When neither guard applies (no `finite`, no range bounds), the original
/// flat checks are returned unchanged.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn wrap_with_float_guards(
    prefix: &str,
    finite_required: bool,
    gt: Option<f64>,
    gte: Option<f64>,
    lt: Option<f64>,
    lte: Option<f64>,
    value_access: &TokenStream,
    proto_name: &str,
    inner: Vec<TokenStream>,
) -> Vec<TokenStream> {
    let nan_range = nan_range_rule_id_and_path(prefix, gt, gte, lt, lte);

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
        let rule_id = format!("{prefix}.finite");
        quote! {
            if _v.is_nan() || _v.is_infinite() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, "value must be finite",
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

/// Extracted numeric rule values ready for code generation.
struct NumericRuleValues {
    prefix: &'static str,
    const_val: Option<TokenStream>,
    lt: Option<(&'static str, TokenStream)>,
    gt: Option<(&'static str, TokenStream)>,
    in_vals: Vec<TokenStream>,
    not_in_vals: Vec<TokenStream>,
}

impl NumericRuleValues {
    fn generate(self, value_access: &TokenStream, proto_name: &str) -> Vec<TokenStream> {
        let mut checks = Vec::new();

        if let Some(const_tokens) = self.const_val {
            let rule_id = format!("{}.const", self.prefix);
            checks.push(quote! {
                if #value_access != #const_tokens {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, format!("value must equal {}", #const_tokens),
                    ));
                }
            });
        }

        checks.extend(generate_range_check(
            self.prefix,
            value_access,
            proto_name,
            self.lt,
            self.gt,
        ));

        if !self.in_vals.is_empty() {
            let rule_id = format!("{}.in", self.prefix);
            let vals = &self.in_vals;
            checks.push(quote! {
                if ![#(#vals),*].contains(&#value_access) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, "value must be in list",
                    ));
                }
            });
        }

        if !self.not_in_vals.is_empty() {
            let rule_id = format!("{}.not_in", self.prefix);
            let vals = &self.not_in_vals;
            checks.push(quote! {
                if [#(#vals),*].contains(&#value_access) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, "value must not be in list",
                    ));
                }
            });
        }

        checks
    }
}

/// Generate range check code for combined gt/gte + lt/lte bounds.
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn generate_range_check(
    prefix: &str,
    value_access: &TokenStream,
    proto_name: &str,
    lt: Option<(&str, TokenStream)>,
    gt: Option<(&str, TokenStream)>,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    match (gt, lt) {
        (Some((gt_op, gt_val)), Some((lt_op, lt_val))) => {
            let gt_eq = gt_op == "gte";
            let lt_eq = lt_op == "lte";

            let gt_label = if gt_eq { "gte" } else { "gt" };
            let lt_label = if lt_eq { "lte" } else { "lt" };

            let rule_id = format!("{prefix}.{gt_label}_{lt_label}");
            let rule_id_exclusive = format!("{prefix}.{gt_label}_{lt_label}_exclusive");
            let rule_path = format!("{prefix}.{gt_label}");

            let gt_desc = if gt_eq {
                "greater than or equal to"
            } else {
                "greater than"
            };
            let lt_desc = if lt_eq {
                "less than or equal to"
            } else {
                "less than"
            };

            let incl_msg = format!("value must be {gt_desc} {{gt}} and {lt_desc} {{lt}}");
            let excl_msg = format!("value must be {gt_desc} {{gt}} or {lt_desc} {{lt}}");

            let gt_check = if gt_eq {
                quote! { #value_access >= #gt_val }
            } else {
                quote! { #value_access > #gt_val }
            };

            let lt_check = if lt_eq {
                quote! { #value_access <= #lt_val }
            } else {
                quote! { #value_access < #lt_val }
            };

            let not_gt = if gt_eq {
                quote! { #value_access < #gt_val }
            } else {
                quote! { #value_access <= #gt_val }
            };

            let not_lt = if lt_eq {
                quote! { #value_access > #lt_val }
            } else {
                quote! { #value_access >= #lt_val }
            };

            checks.push(quote! {
                #[allow(unused_comparisons)]
                {
                    if #gt_val < #lt_val {
                        if !(#gt_check && #lt_check) {
                            let msg = format!(#incl_msg, gt = #gt_val, lt = #lt_val);
                            let mut violation = ::prost_protovalidate::Violation::new_constraint(
                                #proto_name, #rule_id, #rule_path,
                            );
                            violation.set_message(msg);
                            violations.push(violation);
                        }
                    } else if #not_lt && #not_gt {
                        let msg = format!(#excl_msg, gt = #gt_val, lt = #lt_val);
                        let mut violation = ::prost_protovalidate::Violation::new_constraint(
                            #proto_name, #rule_id_exclusive, #rule_path,
                        );
                        violation.set_message(msg);
                        violations.push(violation);
                    }
                }
            });
        }
        (Some((op, val)), None) => {
            let label = if op == "gte" { "gte" } else { "gt" };
            let rule_id = format!("{prefix}.{label}");
            let desc = if op == "gte" {
                "greater than or equal to"
            } else {
                "greater than"
            };
            let msg = format!("value must be {desc} {{v}}");
            let check = if op == "gte" {
                quote! { #value_access < #val }
            } else {
                quote! { #value_access <= #val }
            };
            checks.push(quote! {
                if #check {
                    let msg = format!(#msg, v = #val);
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, msg,
                    ));
                }
            });
        }
        (None, Some((op, val))) => {
            let label = if op == "lte" { "lte" } else { "lt" };
            let rule_id = format!("{prefix}.{label}");
            let desc = if op == "lte" {
                "less than or equal to"
            } else {
                "less than"
            };
            let msg = format!("value must be {desc} {{v}}");
            let check = if op == "lte" {
                quote! { #value_access > #val }
            } else {
                quote! { #value_access >= #val }
            };
            checks.push(quote! {
                if #check {
                    let msg = format!(#msg, v = #val);
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, msg,
                    ));
                }
            });
        }
        (None, None) => {}
    }

    checks
}

pub(crate) fn generate_int32(
    rules: &Int32Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "int32",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            int32_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            int32_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            int32_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            int32_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_int64(
    rules: &Int64Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "int64",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            int64_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            int64_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            int64_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            int64_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_uint32(
    rules: &UInt32Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "uint32",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            u_int32_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            u_int32_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            u_int32_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            u_int32_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_uint64(
    rules: &UInt64Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "uint64",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            u_int64_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            u_int64_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            u_int64_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            u_int64_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_sint32(
    rules: &SInt32Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "sint32",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            s_int32_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            s_int32_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            s_int32_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            s_int32_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_sint64(
    rules: &SInt64Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "sint64",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            s_int64_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            s_int64_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            s_int64_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            s_int64_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_fixed32(
    rules: &Fixed32Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "fixed32",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            fixed32_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            fixed32_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            fixed32_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            fixed32_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_fixed64(
    rules: &Fixed64Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "fixed64",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            fixed64_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            fixed64_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            fixed64_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            fixed64_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_sfixed32(
    rules: &SFixed32Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "sfixed32",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            s_fixed32_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            s_fixed32_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            s_fixed32_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            s_fixed32_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_sfixed64(
    rules: &SFixed64Rules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    NumericRuleValues {
        prefix: "sfixed64",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            s_fixed64_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            s_fixed64_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            s_fixed64_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            s_fixed64_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(value_access, proto_name)
}

pub(crate) fn generate_float(
    rules: &FloatRules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let (gt, gte) = match rules.greater_than.as_ref() {
        Some(float_rules::GreaterThan::Gt(v)) => (Some(f64::from(*v)), None),
        Some(float_rules::GreaterThan::Gte(v)) => (None, Some(f64::from(*v))),
        None => (None, None),
    };
    let (lt, lte) = match rules.less_than.as_ref() {
        Some(float_rules::LessThan::Lt(v)) => (Some(f64::from(*v)), None),
        Some(float_rules::LessThan::Lte(v)) => (None, Some(f64::from(*v))),
        None => (None, None),
    };

    let inner_access = quote! { _v };
    let inner = NumericRuleValues {
        prefix: "float",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            float_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            float_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            float_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            float_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(&inner_access, proto_name);

    wrap_with_float_guards(
        "float",
        rules.finite == Some(true),
        gt,
        gte,
        lt,
        lte,
        value_access,
        proto_name,
        inner,
    )
}

pub(crate) fn generate_double(
    rules: &DoubleRules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let (gt, gte) = match rules.greater_than.as_ref() {
        Some(double_rules::GreaterThan::Gt(v)) => (Some(*v), None),
        Some(double_rules::GreaterThan::Gte(v)) => (None, Some(*v)),
        None => (None, None),
    };
    let (lt, lte) = match rules.less_than.as_ref() {
        Some(double_rules::LessThan::Lt(v)) => (Some(*v), None),
        Some(double_rules::LessThan::Lte(v)) => (None, Some(*v)),
        None => (None, None),
    };

    let inner_access = quote! { _v };
    let inner = NumericRuleValues {
        prefix: "double",
        const_val: rules.r#const.map(|val| quote! { #val }),
        lt: rules.less_than.as_ref().map(|bound| match bound {
            double_rules::LessThan::Lt(val) => ("lt", quote! { #val }),
            double_rules::LessThan::Lte(val) => ("lte", quote! { #val }),
        }),
        gt: rules.greater_than.as_ref().map(|bound| match bound {
            double_rules::GreaterThan::Gt(val) => ("gt", quote! { #val }),
            double_rules::GreaterThan::Gte(val) => ("gte", quote! { #val }),
        }),
        in_vals: rules.r#in.iter().map(|val| quote! { #val }).collect(),
        not_in_vals: rules.not_in.iter().map(|val| quote! { #val }).collect(),
    }
    .generate(&inner_access, proto_name);

    wrap_with_float_guards(
        "double",
        rules.finite == Some(true),
        gt,
        gte,
        lt,
        lte,
        value_access,
        proto_name,
        inner,
    )
}
