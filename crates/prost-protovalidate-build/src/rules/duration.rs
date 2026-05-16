//! Duration rule code generation.
//!
//! Mirrors the runtime evaluator in
//! [`validator/rules/duration.rs`](../prost-protovalidate/src/validator/rules/duration.rs)
//! exactly — same `rule_id`, `rule_path`, and message text for every shape so
//! parity tests pass.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use prost_protovalidate_types::{DurationRules, duration_rules};

#[allow(clippy::too_many_lines)]
pub(crate) fn generate(
    rules: &DurationRules,
    field_ident: &Ident,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    // Const
    if let Some(ref c) = rules.r#const {
        let secs = c.seconds;
        let nanos = c.nanos;
        let msg = format!("value must equal {}", fmt_dur(c));
        checks.push(quote! {
            if let Some(ref _dur) = self.#field_ident {
                if _dur.seconds != #secs || _dur.nanos != #nanos {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "duration.const", #msg,
                    ));
                }
            }
        });
    }

    let lt = rules.less_than.as_ref().map(|v| match v {
        duration_rules::LessThan::Lt(d) => ("lt", d),
        duration_rules::LessThan::Lte(d) => ("lte", d),
    });
    let gt = rules.greater_than.as_ref().map(|v| match v {
        duration_rules::GreaterThan::Gt(d) => ("gt", d),
        duration_rules::GreaterThan::Gte(d) => ("gte", d),
    });

    match (gt, lt) {
        (Some((gt_op, gt_dur)), Some((lt_op, lt_dur))) => {
            checks.push(generate_combined_range(
                proto_name,
                field_ident,
                gt_op,
                gt_dur,
                lt_op,
                lt_dur,
            ));
        }
        (Some((gt_op, gt_dur)), None) => {
            checks.push(generate_single_bound(
                proto_name,
                field_ident,
                gt_op,
                gt_dur,
            ));
        }
        (None, Some((lt_op, lt_dur))) => {
            checks.push(generate_single_bound(
                proto_name,
                field_ident,
                lt_op,
                lt_dur,
            ));
        }
        (None, None) => {}
    }

    // `in`
    if !rules.r#in.is_empty() {
        let list_str = rules
            .r#in
            .iter()
            .map(fmt_dur)
            .collect::<Vec<_>>()
            .join(", ");
        let msg = format!("value must be in list [{list_str}]");
        let vals: Vec<_> = rules
            .r#in
            .iter()
            .map(|d| {
                let s = d.seconds;
                let n = d.nanos;
                quote! { (#s, #n) }
            })
            .collect();
        checks.push(quote! {
            if let Some(ref _dur) = self.#field_ident {
                if ![#(#vals),*].contains(&(_dur.seconds, _dur.nanos)) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "duration.in", #msg,
                    ));
                }
            }
        });
    }

    // `not_in`
    if !rules.not_in.is_empty() {
        let list_str = rules
            .not_in
            .iter()
            .map(fmt_dur)
            .collect::<Vec<_>>()
            .join(", ");
        let msg = format!("value must not be in list [{list_str}]");
        let vals: Vec<_> = rules
            .not_in
            .iter()
            .map(|d| {
                let s = d.seconds;
                let n = d.nanos;
                quote! { (#s, #n) }
            })
            .collect();
        checks.push(quote! {
            if let Some(ref _dur) = self.#field_ident {
                if [#(#vals),*].contains(&(_dur.seconds, _dur.nanos)) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "duration.not_in", #msg,
                    ));
                }
            }
        });
    }

    checks
}

fn generate_combined_range(
    proto_name: &str,
    field_ident: &Ident,
    gt_op: &str,
    gt_dur: &prost_types::Duration,
    lt_op: &str,
    lt_dur: &prost_types::Duration,
) -> TokenStream {
    let gt_eq = gt_op == "gte";
    let lt_eq = lt_op == "lte";
    let gt_label = if gt_eq { "gte" } else { "gt" };
    let lt_label = if lt_eq { "lte" } else { "lt" };

    let rule_id = format!("duration.{gt_label}_{lt_label}");
    let rule_id_exclusive = format!("{rule_id}_exclusive");
    let rule_path = format!("duration.{gt_label}");

    let gt_fmt = fmt_dur(gt_dur);
    let lt_fmt = fmt_dur(lt_dur);

    let (incl_msg, excl_msg) = combined_messages(gt_eq, lt_eq, &gt_fmt, &lt_fmt);

    let gt_secs = gt_dur.seconds;
    let gt_nanos = gt_dur.nanos;
    let lt_secs = lt_dur.seconds;
    let lt_nanos = lt_dur.nanos;

    // `gt < lt`: inclusive interpretation (the "normal" range).
    let gt_lt_compare = quote! {
        (#gt_secs < #lt_secs) || (#gt_secs == #lt_secs && #gt_nanos < #lt_nanos)
    };

    // Inclusive-range violation predicates: value lies outside `(gt, lt)`.
    let value_lte_gt = if gt_eq {
        quote! { _dur.seconds < #gt_secs || (_dur.seconds == #gt_secs && _dur.nanos < #gt_nanos) }
    } else {
        quote! { _dur.seconds < #gt_secs || (_dur.seconds == #gt_secs && _dur.nanos <= #gt_nanos) }
    };
    let value_gt_lt = if lt_eq {
        quote! { _dur.seconds > #lt_secs || (_dur.seconds == #lt_secs && _dur.nanos > #lt_nanos) }
    } else {
        quote! { _dur.seconds > #lt_secs || (_dur.seconds == #lt_secs && _dur.nanos >= #lt_nanos) }
    };

    // Exclusive-range violation: value lies inside the disallowed gap.
    let value_in_gap_below_gt = if gt_eq {
        quote! { _dur.seconds < #gt_secs || (_dur.seconds == #gt_secs && _dur.nanos < #gt_nanos) }
    } else {
        quote! { _dur.seconds < #gt_secs || (_dur.seconds == #gt_secs && _dur.nanos <= #gt_nanos) }
    };
    let value_in_gap_above_lt = if lt_eq {
        quote! { _dur.seconds > #lt_secs || (_dur.seconds == #lt_secs && _dur.nanos > #lt_nanos) }
    } else {
        quote! { _dur.seconds > #lt_secs || (_dur.seconds == #lt_secs && _dur.nanos >= #lt_nanos) }
    };

    quote! {
        if let Some(ref _dur) = self.#field_ident {
            if #gt_lt_compare {
                if #value_lte_gt || #value_gt_lt {
                    let mut _v = ::prost_protovalidate::Violation::new_constraint(
                        #proto_name, #rule_id, #rule_path,
                    );
                    _v.set_message(#incl_msg);
                    violations.push(_v);
                }
            } else if !(#value_in_gap_below_gt) && !(#value_in_gap_above_lt) {
                let mut _v = ::prost_protovalidate::Violation::new_constraint(
                    #proto_name, #rule_id_exclusive, #rule_path,
                );
                _v.set_message(#excl_msg);
                violations.push(_v);
            }
        }
    }
}

fn combined_messages(gt_eq: bool, lt_eq: bool, gt: &str, lt: &str) -> (String, String) {
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
    (
        format!("value must be {gt_desc} {gt} and {lt_desc} {lt}"),
        format!("value must be {gt_desc} {gt} or {lt_desc} {lt}"),
    )
}

fn generate_single_bound(
    proto_name: &str,
    field_ident: &Ident,
    op: &str,
    bound: &prost_types::Duration,
) -> TokenStream {
    let secs = bound.seconds;
    let nanos = bound.nanos;
    let rule_id = format!("duration.{op}");
    let bound_fmt = fmt_dur(bound);

    let (msg, cond) = match op {
        "gt" => (
            format!("value must be greater than {bound_fmt}"),
            quote! { !(_dur.seconds > #secs || (_dur.seconds == #secs && _dur.nanos > #nanos)) },
        ),
        "gte" => (
            format!("value must be greater than or equal to {bound_fmt}"),
            quote! { _dur.seconds < #secs || (_dur.seconds == #secs && _dur.nanos < #nanos) },
        ),
        "lt" => (
            format!("value must be less than {bound_fmt}"),
            quote! { !(_dur.seconds < #secs || (_dur.seconds == #secs && _dur.nanos < #nanos)) },
        ),
        "lte" => (
            format!("value must be less than or equal to {bound_fmt}"),
            quote! { _dur.seconds > #secs || (_dur.seconds == #secs && _dur.nanos > #nanos) },
        ),
        _ => unreachable!("op already validated by caller: {op}"),
    };

    quote! {
        if let Some(ref _dur) = self.#field_ident {
            if #cond {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        }
    }
}

/// Format a `Duration` as a Go-style string (e.g. `"3s"`, `"1.500s"`,
/// `"-2s"`) — mirrors the private runtime helper of the same name so
/// generated messages are byte-identical.
fn fmt_dur(d: &prost_types::Duration) -> String {
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
