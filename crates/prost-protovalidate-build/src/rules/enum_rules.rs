//! Enum rule code generation.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::EnumRules;

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
        let msg = format!("must equal {c}");
        checks.push(quote! {
            if #value_access != #c {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "enum.const", #msg,
                ));
            }
        });
    }

    // defined_only: value must be one of the declared enum numbers
    if rules.defined_only == Some(true) && !defined_values.is_empty() {
        checks.push(quote! {
            if ![#(#defined_values),*].contains(&#value_access) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "enum.defined_only", "value must be one of the defined enum values",
                ));
            }
        });
    }

    // In — sort to match the deterministic runtime format.
    if !rules.r#in.is_empty() {
        let mut sorted: Vec<i32> = rules.r#in.clone();
        sorted.sort_unstable();
        let vals = sorted;
        checks.push(quote! {
            if ![#(#vals),*].contains(&#value_access) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "enum.in", format!("must be in list {:?}", &[#(#vals),*]),
                ));
            }
        });
    }

    // Not-in — same sorted format.
    if !rules.not_in.is_empty() {
        let mut sorted: Vec<i32> = rules.not_in.clone();
        sorted.sort_unstable();
        let vals = sorted;
        checks.push(quote! {
            if [#(#vals),*].contains(&#value_access) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "enum.not_in", format!("must not be in list {:?}", &[#(#vals),*]),
                ));
            }
        });
    }

    checks
}
