//! Duration rule code generation.
//!
//! Rule ids and messages come from
//! [`prost_protovalidate_types::rules_meta::duration`] — the same source the
//! runtime evaluator consumes. Durations are compared as `(seconds, nanos)`
//! tuples (protobuf requires the fields to share a sign, so lexicographic
//! tuple order is duration order), which lets range emission reuse the
//! shared numeric range emitter.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use prost_protovalidate_types::rules_meta::duration as meta;
use prost_protovalidate_types::{DurationRules, duration_rules};

use super::number::generate_range_check;

pub(crate) fn generate(
    rules: &DurationRules,
    field_ident: &Ident,
    proto_name: &str,
    backend: crate::Backend,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();
    let as_tuple = |d: &prost_types::Duration| (d.seconds, d.nanos);
    let field = quote! { self.#field_ident };
    let bind = quote::format_ident!("_dur");

    // Const
    if let Some(ref c) = rules.r#const {
        let (secs, nanos) = as_tuple(c);
        let rule_id = meta::CONST_ID;
        let msg = meta::const_message(secs, nanos);
        let body = quote! {
            if (_dur.seconds, _dur.nanos) != (#secs, #nanos) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    // Range
    let (gt, gte) = match rules.greater_than.as_ref() {
        Some(duration_rules::GreaterThan::Gt(d)) => (Some(as_tuple(d)), None),
        Some(duration_rules::GreaterThan::Gte(d)) => (None, Some(as_tuple(d))),
        None => (None, None),
    };
    let (lt, lte) = match rules.less_than.as_ref() {
        Some(duration_rules::LessThan::Lt(d)) => (Some(as_tuple(d)), None),
        Some(duration_rules::LessThan::Lte(d)) => (None, Some(as_tuple(d))),
        None => (None, None),
    };
    if let Some(rule) = meta::range_rule(gt, gte, lt, lte) {
        let tuple_tokens = |b: (i64, i32)| {
            let (s, n) = b;
            quote! { (#s, #n) }
        };
        let gt_tokens = gt.or(gte).map(tuple_tokens);
        let lt_tokens = lt.or(lte).map(tuple_tokens);
        let value_access = quote! { (_dur.seconds, _dur.nanos) };
        let range_checks = generate_range_check(
            &rule,
            gt_tokens.as_ref(),
            lt_tokens.as_ref(),
            &value_access,
            proto_name,
        );
        let body = quote! { #(#range_checks)* };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    // `in`
    if !rules.r#in.is_empty() {
        let items: Vec<(i64, i32)> = rules.r#in.iter().map(as_tuple).collect();
        let rule_id = meta::IN_ID;
        let msg = meta::in_message(&items);
        let vals: Vec<TokenStream> = items.iter().map(|(s, n)| quote! { (#s, #n) }).collect();
        let body = quote! {
            if ![#(#vals),*].contains(&(_dur.seconds, _dur.nanos)) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    // `not_in`
    if !rules.not_in.is_empty() {
        let items: Vec<(i64, i32)> = rules.not_in.iter().map(as_tuple).collect();
        let rule_id = meta::NOT_IN_ID;
        let msg = meta::not_in_message(&items);
        let vals: Vec<TokenStream> = items.iter().map(|(s, n)| quote! { (#s, #n) }).collect();
        let body = quote! {
            if [#(#vals),*].contains(&(_dur.seconds, _dur.nanos)) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    checks
}
