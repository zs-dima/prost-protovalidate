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
//! Rule ids and messages come from
//! [`prost_protovalidate_types::rules_meta::timestamp`] — the same source
//! the runtime evaluator consumes. Timestamps are compared as
//! `(seconds, nanos)` tuples, which lets range emission reuse the shared
//! numeric range emitter.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use prost_protovalidate_types::rules_meta::timestamp as meta;
use prost_protovalidate_types::{TimestampRules, timestamp_rules};

use super::number::generate_range_check;

#[allow(clippy::too_many_lines, clippy::similar_names)]
pub(crate) fn generate(
    rules: &TimestampRules,
    field_ident: &Ident,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();
    let as_tuple = |t: &prost_types::Timestamp| (t.seconds, t.nanos);

    // Const — runtime emits a constant message; codegen must match.
    if let Some(ref c) = rules.r#const {
        let (secs, nanos) = as_tuple(c);
        let rule_id = meta::CONST_ID;
        let msg = meta::CONST_MESSAGE;
        checks.push(quote! {
            if let Some(ref _ts) = self.#field_ident {
                if (_ts.seconds, _ts.nanos) != (#secs, #nanos) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #msg,
                    ));
                }
            }
        });
    }

    // Static range bounds (`lt_now`/`gt_now` are handled separately below).
    let (gt, gte) = match rules.greater_than.as_ref() {
        Some(timestamp_rules::GreaterThan::Gt(t)) => (Some(as_tuple(t)), None),
        Some(timestamp_rules::GreaterThan::Gte(t)) => (None, Some(as_tuple(t))),
        Some(timestamp_rules::GreaterThan::GtNow(_)) | None => (None, None),
    };
    let (lt, lte) = match rules.less_than.as_ref() {
        Some(timestamp_rules::LessThan::Lt(t)) => (Some(as_tuple(t)), None),
        Some(timestamp_rules::LessThan::Lte(t)) => (None, Some(as_tuple(t))),
        Some(timestamp_rules::LessThan::LtNow(_)) | None => (None, None),
    };
    if let Some(rule) = meta::range_rule(gt, gte, lt, lte) {
        let tuple_tokens = |b: (i64, i32)| {
            let (s, n) = b;
            quote! { (#s, #n) }
        };
        let gt_tokens = gt.or(gte).map(tuple_tokens);
        let lt_tokens = lt.or(lte).map(tuple_tokens);
        let value_access = quote! { (_ts.seconds, _ts.nanos) };
        let range_checks = generate_range_check(
            &rule,
            gt_tokens.as_ref(),
            lt_tokens.as_ref(),
            &value_access,
            proto_name,
        );
        checks.push(quote! {
            if let Some(ref _ts) = self.#field_ident {
                #(#range_checks)*
            }
        });
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
            let rule_id = meta::WITHIN_ID;
            let msg = meta::WITHIN_MESSAGE;
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
                // Same lexicographic tuple comparison the runtime uses to
                // flag "outside the window".
                if (_diff_secs, _diff_subsec_nanos) > (#w_secs, #w_nanos) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #msg,
                    ));
                }
            }
        });

        let lt_now_check: Option<TokenStream> = has_lt_now.then(|| {
            let rule_id = meta::LT_NOW_ID;
            let msg = meta::LT_NOW_MESSAGE;
            quote! {
                // Violation when ts >= now, mirroring the runtime.
                if (_ts.seconds, _ts.nanos) >= (_now.seconds, _now.nanos) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #msg,
                    ));
                }
            }
        });

        let gt_now_check: Option<TokenStream> = has_gt_now.then(|| {
            let rule_id = meta::GT_NOW_ID;
            let msg = meta::GT_NOW_MESSAGE;
            quote! {
                if (_ts.seconds, _ts.nanos) <= (_now.seconds, _now.nanos) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #msg,
                    ));
                }
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
