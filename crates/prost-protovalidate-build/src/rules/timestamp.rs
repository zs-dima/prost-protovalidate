//! Timestamp rule code generation.
//!
//! Covers `const`, static `lt`/`lte`/`gt`/`gte` (single and combined), and
//! the time-relative rules `lt_now`, `gt_now`, `within`. The time-relative
//! branches read wall-clock time via
//! [`::prost_protovalidate::time::now_systemtime`] — same source as the
//! runtime `Validator`'s default `now_fn`, so behaviour parity holds. The
//! compile-time path cannot accept an injected `now`; tests that need a
//! deterministic clock must use the runtime `Validator` with a `now_fn`
//! override.
//!
//! `TimestampRules` does not declare `in`/`not_in` so no list coverage is
//! needed.
//!
//! Violation `rule_id`, `rule_path`, and message text must mirror the
//! runtime evaluator in [`validator/rules/timestamp.rs`](../prost-protovalidate/src/validator/rules/timestamp.rs)
//! so parity tests pass.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use prost_protovalidate_types::{TimestampRules, timestamp_rules};

#[allow(clippy::too_many_lines, clippy::similar_names)]
pub(crate) fn generate(
    rules: &TimestampRules,
    field_ident: &Ident,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    // Const — runtime emits a constant message; codegen must match.
    if let Some(ref c) = rules.r#const {
        let secs = c.seconds;
        let nanos = c.nanos;
        checks.push(quote! {
            if let Some(ref _ts) = self.#field_ident {
                if _ts.seconds != #secs || _ts.nanos != #nanos {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "timestamp.const", "must equal const timestamp",
                    ));
                }
            }
        });
    }

    let lt = rules.less_than.as_ref().and_then(|v| match v {
        timestamp_rules::LessThan::Lt(ts) => Some(("lt", ts)),
        timestamp_rules::LessThan::Lte(ts) => Some(("lte", ts)),
        timestamp_rules::LessThan::LtNow(_) => None,
    });
    let gt = rules.greater_than.as_ref().and_then(|v| match v {
        timestamp_rules::GreaterThan::Gt(ts) => Some(("gt", ts)),
        timestamp_rules::GreaterThan::Gte(ts) => Some(("gte", ts)),
        timestamp_rules::GreaterThan::GtNow(_) => None,
    });

    match (gt, lt) {
        (Some((gt_op, gt_ts)), Some((lt_op, lt_ts))) => {
            checks.push(generate_combined_range(
                proto_name,
                field_ident,
                gt_op,
                gt_ts,
                lt_op,
                lt_ts,
            ));
        }
        (Some((gt_op, gt_ts)), None) => {
            checks.push(generate_single_bound(
                proto_name,
                field_ident,
                gt_op,
                gt_ts,
                true,
            ));
        }
        (None, Some((lt_op, lt_ts))) => {
            checks.push(generate_single_bound(
                proto_name,
                field_ident,
                lt_op,
                lt_ts,
                false,
            ));
        }
        (None, None) => {}
    }

    // Time-relative rules: `lt_now`, `gt_now`, `within`. Reads wall-clock
    // time once at validation time via `time::now_systemtime()`, matching
    // the runtime evaluator's default `now_fn` source.
    let has_lt_now = rules
        .less_than
        .as_ref()
        .is_some_and(|lt| matches!(lt, timestamp_rules::LessThan::LtNow(true)));
    let has_gt_now = rules
        .greater_than
        .as_ref()
        .is_some_and(|gt| matches!(gt, timestamp_rules::GreaterThan::GtNow(true)));
    let within = rules.within;
    if has_lt_now || has_gt_now || within.is_some() {
        let within_check: Option<TokenStream> = within.map(|w| {
            let w_secs = w.seconds;
            let w_nanos = w.nanos;
            quote! {
                // |ts - now| as nanoseconds (i128 to avoid overflow). Both
                // bounds fit in i64 by proto spec, so the abs() of the
                // difference safely fits when split back into (secs, nanos).
                let _diff_nanos: i128 =
                    (i128::from(_ts.seconds) * 1_000_000_000 + i128::from(_ts.nanos))
                    - (i128::from(_now.seconds) * 1_000_000_000 + i128::from(_now.nanos));
                let _abs_nanos: u128 = _diff_nanos.unsigned_abs();
                // SAFETY: bounded by proto Duration spec; truncation is intentional.
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let _diff_secs: i64 = (_abs_nanos / 1_000_000_000) as i64;
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let _diff_subsec_nanos: i32 = (_abs_nanos % 1_000_000_000) as i32;
                // `dur_gt(diff, within)` — same lexicographic comparison
                // the runtime uses to flag "outside the window".
                let _outside = _diff_secs > #w_secs
                    || (_diff_secs == #w_secs && _diff_subsec_nanos > #w_nanos);
                if _outside {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name,
                        "timestamp.within",
                        "must be within specified duration of now",
                    ));
                }
            }
        });

        let lt_now_check: Option<TokenStream> = has_lt_now.then_some(quote! {
            // `!ts_lt(ts, now)` per runtime: violation when ts >= now.
            let _not_lt = _ts.seconds > _now.seconds
                || (_ts.seconds == _now.seconds && _ts.nanos >= _now.nanos);
            if _not_lt {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name,
                    "timestamp.lt_now",
                    "must be less than now",
                ));
            }
        });

        let gt_now_check: Option<TokenStream> = has_gt_now.then_some(quote! {
            let _not_gt = _ts.seconds < _now.seconds
                || (_ts.seconds == _now.seconds && _ts.nanos <= _now.nanos);
            if _not_gt {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name,
                    "timestamp.gt_now",
                    "must be greater than now",
                ));
            }
        });

        checks.push(quote! {
            if let Some(ref _ts) = self.#field_ident {
                let _now = ::prost_protovalidate::time::now_systemtime();
                #lt_now_check
                #gt_now_check
                #within_check
            }
        });
    }

    checks
}

/// Codegen for combined `gt(e)? + lt(e)?` bounds. Mirrors the runtime
/// `check_timestamp_range` match arms exactly: the `rule_id` distinguishes
/// inclusive vs exclusive interpretations, and `rule_path` always points to
/// the greater-than side of the range.
fn generate_combined_range(
    proto_name: &str,
    field_ident: &Ident,
    gt_op: &str,
    gt_ts: &prost_types::Timestamp,
    lt_op: &str,
    lt_ts: &prost_types::Timestamp,
) -> TokenStream {
    let gt_secs = gt_ts.seconds;
    let gt_nanos = gt_ts.nanos;
    let lt_secs = lt_ts.seconds;
    let lt_nanos = lt_ts.nanos;
    let gt_eq = gt_op == "gte";
    let lt_eq = lt_op == "lte";

    let rule_id = format!(
        "timestamp.{}_{}",
        if gt_eq { "gte" } else { "gt" },
        if lt_eq { "lte" } else { "lt" }
    );
    let rule_id_exclusive = format!("{rule_id}_exclusive");
    let rule_path = format!("timestamp.{}", if gt_eq { "gte" } else { "gt" });

    let (incl_msg, excl_msg) = combined_messages(gt_eq, lt_eq);

    // `gt < lt`: standard range — value must satisfy BOTH bounds.
    // `gt >= lt`: exclusive range — value must satisfy EITHER bound.
    let gt_lt_compare = quote! {
        (#gt_secs < #lt_secs) || (#gt_secs == #lt_secs && #gt_nanos < #lt_nanos)
    };

    // Inclusive-range violation: outside [gt, lt].
    let value_lte_gt = if gt_eq {
        quote! { _ts.seconds < #gt_secs || (_ts.seconds == #gt_secs && _ts.nanos < #gt_nanos) }
    } else {
        quote! { _ts.seconds < #gt_secs || (_ts.seconds == #gt_secs && _ts.nanos <= #gt_nanos) }
    };
    let value_gt_lt = if lt_eq {
        quote! { _ts.seconds > #lt_secs || (_ts.seconds == #lt_secs && _ts.nanos > #lt_nanos) }
    } else {
        quote! { _ts.seconds > #lt_secs || (_ts.seconds == #lt_secs && _ts.nanos >= #lt_nanos) }
    };

    // Exclusive-range violation: value lies inside the disallowed gap.
    let value_in_gap_below_gt = if gt_eq {
        quote! { _ts.seconds < #gt_secs || (_ts.seconds == #gt_secs && _ts.nanos < #gt_nanos) }
    } else {
        quote! { _ts.seconds < #gt_secs || (_ts.seconds == #gt_secs && _ts.nanos <= #gt_nanos) }
    };
    let value_in_gap_above_lt = if lt_eq {
        quote! { _ts.seconds > #lt_secs || (_ts.seconds == #lt_secs && _ts.nanos > #lt_nanos) }
    } else {
        quote! { _ts.seconds > #lt_secs || (_ts.seconds == #lt_secs && _ts.nanos >= #lt_nanos) }
    };

    quote! {
        if let Some(ref _ts) = self.#field_ident {
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

/// Standard message text for combined-range violations, copied verbatim
/// from the runtime so violation parity holds.
fn combined_messages(gt_eq: bool, lt_eq: bool) -> (&'static str, &'static str) {
    match (gt_eq, lt_eq) {
        (false, false) => (
            "must be greater than and less than specified timestamps",
            "must be greater than or less than specified timestamps",
        ),
        (false, true) => (
            "must be greater than and less than or equal to specified timestamps",
            "must be greater than or less than or equal to specified timestamps",
        ),
        (true, false) => (
            "must be greater than or equal to and less than specified timestamps",
            "must be greater than or equal to or less than specified timestamps",
        ),
        (true, true) => (
            "must be between specified timestamps inclusive",
            "must be greater than or equal to or less than or equal to specified timestamps",
        ),
    }
}

/// Codegen for a single `gt`/`gte`/`lt`/`lte` bound.
fn generate_single_bound(
    proto_name: &str,
    field_ident: &Ident,
    op: &str,
    ts: &prost_types::Timestamp,
    is_gt: bool,
) -> TokenStream {
    let secs = ts.seconds;
    let nanos = ts.nanos;
    let rule_id = format!("timestamp.{op}");
    let (msg, violation_cond) = match op {
        "gt" => (
            "must be greater than specified timestamp",
            quote! { !(_ts.seconds > #secs || (_ts.seconds == #secs && _ts.nanos > #nanos)) },
        ),
        "gte" => (
            "must be greater than or equal to specified timestamp",
            quote! { _ts.seconds < #secs || (_ts.seconds == #secs && _ts.nanos < #nanos) },
        ),
        "lt" => (
            "must be less than specified timestamp",
            quote! { !(_ts.seconds < #secs || (_ts.seconds == #secs && _ts.nanos < #nanos)) },
        ),
        "lte" => (
            "must be less than or equal to specified timestamp",
            quote! { _ts.seconds > #secs || (_ts.seconds == #secs && _ts.nanos > #nanos) },
        ),
        _ => unreachable!("op already validated by caller: {op}"),
    };

    // Touch `is_gt` so future maintenance retains the gt/lt-tagged dispatch
    // path; the current logic only depends on `op`.
    let _ = is_gt;

    quote! {
        if let Some(ref _ts) = self.#field_ident {
            if #violation_cond {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        }
    }
}
