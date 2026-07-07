//! `FieldMask` rule code generation.
//!
//! Covers `const`, `in`, `not_in`. Path matching uses the same semantics as
//! the runtime validator: a path in the `FieldMask` matches an allowed/blocked
//! entry when it equals the entry or starts with `"{entry}."`.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use prost_protovalidate_types::FieldMaskRules;
use prost_protovalidate_types::rules_meta::field_mask as meta;

pub(crate) fn generate(
    rules: &FieldMaskRules,
    field_ident: &Ident,
    proto_name: &str,
    backend: crate::Backend,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();
    let field = quote! { self.#field_ident };
    let bind = quote::format_ident!("_fm");

    // Const: exact paths equality.
    if let Some(ref expected) = rules.r#const {
        let const_id = meta::CONST_ID;
        let const_msg = meta::CONST_MESSAGE;
        let expected_paths = &expected.paths;
        let body = quote! {
            let _expected: &[&str] = &[#(#expected_paths),*];
            if _fm.paths.len() != _expected.len()
                || !_fm.paths.iter().zip(_expected.iter()).all(|(a, b)| a == b)
            {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #const_id, #const_msg,
                ));
            }
        };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    // In: every path must match at least one allowed entry (exact or prefix).
    if !rules.r#in.is_empty() {
        let in_id = meta::IN_ID;
        let in_msg = meta::IN_MESSAGE;
        let allowed = &rules.r#in;
        let body = quote! {
            let _allowed: &[&str] = &[#(#allowed),*];
            if !_fm.paths.iter().all(|_p| {
                _allowed.iter().any(|_a| {
                    ::prost_protovalidate::validators::fieldmask_covers(_a, _p)
                })
            }) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #in_id, #in_msg,
                ));
            }
        };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    // Not-in: no path may match any blocked entry (exact or prefix).
    if !rules.not_in.is_empty() {
        let not_in_id = meta::NOT_IN_ID;
        let not_in_msg = meta::NOT_IN_MESSAGE;
        let blocked = &rules.not_in;
        let body = quote! {
            let _blocked: &[&str] = &[#(#blocked),*];
            if _fm.paths.iter().any(|_p| {
                _blocked.iter().any(|_b| {
                    ::prost_protovalidate::validators::fieldmask_covers(_b, _p)
                })
            }) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #not_in_id, #not_in_msg,
                ));
            }
        };
        checks.push(backend.if_msg_field_set(&field, &bind, &body));
    }

    checks
}
