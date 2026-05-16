//! Bool rule code generation.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::BoolRules;

pub(crate) fn generate(
    rules: &BoolRules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    if let Some(c) = rules.r#const {
        let msg = format!("must equal {c}");
        checks.push(quote! {
            if #value_access != #c {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bool.const", #msg,
                ));
            }
        });
    }

    checks
}
