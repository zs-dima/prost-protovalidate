//! Enum rule code generation.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::EnumRules;
use prost_protovalidate_types::rules_meta::enumeration as meta;

/// Generate enum validation checks.
///
/// `defined_values` contains the `i32` numbers of every value declared in
/// the enum descriptor. When `rules.defined_only` is true a membership
/// check against this set is emitted.
pub(crate) fn generate(
    rules: &EnumRules,
    value_access: &TokenStream,
    proto_name: &str,
    defined_values: &[i32],
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    // Const (prost represents enum fields as i32)
    if let Some(c) = rules.r#const {
        let rule_id = meta::CONST_ID;
        let msg = meta::const_message(c);
        checks.push(quote! {
            if #value_access != #c {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        });
    }

    // defined_only: value must be one of the declared enum numbers
    if rules.defined_only == Some(true) && !defined_values.is_empty() {
        let defined_only_id = meta::DEFINED_ONLY_ID;
        let defined_only_msg = meta::DEFINED_ONLY_MESSAGE;
        checks.push(quote! {
            if ![#(#defined_values),*].contains(&#value_access) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #defined_only_id, #defined_only_msg,
                ));
            }
        });
    }

    // In — sort to match the deterministic runtime format.
    if !rules.r#in.is_empty() {
        let rule_id = meta::IN_ID;
        let msg = meta::in_message(&rules.r#in);
        let mut sorted: Vec<i32> = rules.r#in.clone();
        sorted.sort_unstable();
        let vals = sorted;
        checks.push(quote! {
            if ![#(#vals),*].contains(&#value_access) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        });
    }

    // Not-in — same sorted format.
    if !rules.not_in.is_empty() {
        let rule_id = meta::NOT_IN_ID;
        let msg = meta::not_in_message(&rules.not_in);
        let mut sorted: Vec<i32> = rules.not_in.clone();
        sorted.sort_unstable();
        let vals = sorted;
        checks.push(quote! {
            if [#(#vals),*].contains(&#value_access) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        });
    }

    checks
}
