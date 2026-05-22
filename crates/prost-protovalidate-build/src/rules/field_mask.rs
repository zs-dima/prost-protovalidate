//! `FieldMask` rule code generation.
//!
//! Covers `const`, `in`, `not_in`. Path matching uses the same semantics as
//! the runtime validator: a path in the `FieldMask` matches an allowed/blocked
//! entry when it equals the entry or starts with `"{entry}."`.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use prost_protovalidate_types::FieldMaskRules;

pub(crate) fn generate(
    rules: &FieldMaskRules,
    field_ident: &Ident,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    // Const: exact paths equality.
    if let Some(ref expected) = rules.r#const {
        let expected_paths = &expected.paths;
        checks.push(quote! {
            if let ::core::option::Option::Some(ref _fm) = self.#field_ident {
                let _expected: &[&str] = &[#(#expected_paths),*];
                if _fm.paths.len() != _expected.len()
                    || !_fm.paths.iter().zip(_expected.iter()).all(|(a, b)| a == b)
                {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "field_mask.const", "must equal paths",
                    ));
                }
            }
        });
    }

    // In: every path must match at least one allowed entry (exact or prefix).
    if !rules.r#in.is_empty() {
        let allowed = &rules.r#in;
        checks.push(quote! {
            if let ::core::option::Option::Some(ref _fm) = self.#field_ident {
                let _allowed: &[&str] = &[#(#allowed),*];
                if !_fm.paths.iter().all(|_p| {
                    _allowed.iter().any(|_a| {
                        ::prost_protovalidate::validators::fieldmask_covers(_a, _p)
                    })
                }) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "field_mask.in", "must only contain allowed paths",
                    ));
                }
            }
        });
    }

    // Not-in: no path may match any blocked entry (exact or prefix).
    if !rules.not_in.is_empty() {
        let blocked = &rules.not_in;
        checks.push(quote! {
            if let ::core::option::Option::Some(ref _fm) = self.#field_ident {
                let _blocked: &[&str] = &[#(#blocked),*];
                if _fm.paths.iter().any(|_p| {
                    _blocked.iter().any(|_b| {
                        ::prost_protovalidate::validators::fieldmask_covers(_b, _p)
                    })
                }) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "field_mask.not_in", "must not contain forbidden paths",
                    ));
                }
            }
        });
    }

    checks
}
