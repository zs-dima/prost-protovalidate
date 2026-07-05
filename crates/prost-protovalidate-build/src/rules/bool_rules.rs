//! Bool rule code generation.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::BoolRules;
use prost_protovalidate_types::rules_meta::boolean as meta;

pub(crate) fn generate(
    rules: &BoolRules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

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

    checks
}
