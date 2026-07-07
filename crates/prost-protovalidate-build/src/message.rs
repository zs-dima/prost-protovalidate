//! Message-level validation code generation.
//!
//! Handles virtual oneofs (from `MessageRules.oneof`) and real oneof
//! `required` checks.

use proc_macro2::TokenStream;
use prost_reflect::{DescriptorPool, MessageDescriptor};
use quote::quote;

use prost_protovalidate_types::MessageRules;

use crate::Error;
use crate::naming::NamingContext;

/// Generate message-level validation checks (virtual oneofs).
pub(crate) fn generate_message_checks(
    msg: &MessageDescriptor,
    msg_rules: Option<&MessageRules>,
    naming: &NamingContext,
) -> Vec<TokenStream> {
    let Some(rules) = msg_rules else {
        return Vec::new();
    };

    let mut checks = Vec::new();

    for oneof_rule in &rules.oneof {
        let fields = &oneof_rule.fields;
        if fields.is_empty() {
            continue;
        }

        let required = oneof_rule.required.unwrap_or(false);
        let field_names_str = fields.join(", ");

        // Generate field presence checks
        let mut count_stmts = Vec::new();
        for field_name in fields {
            let field_ident = naming.field_ident(field_name);

            // Pick the right presence test for the underlying storage:
            //   * lists/maps → `Vec`/`HashMap` → non-empty
            //   * message fields → backend presence (`Option<T>` /
            //     `MessageField<T>`)
            //   * presence-having scalars (proto3 `optional`,
            //     synthetic-oneof members) → `Option<T>` in both backends →
            //     `is_some()`
            //   * everything else is a bare proto3 scalar (`Cardinality::Optional`
            //     in the descriptor is implicit presence, NOT `Option<T>` in
            //     Rust) → fall back to a default-value check.
            if let Some(field_desc) = msg.get_field_by_name(field_name) {
                if field_desc.is_list() || field_desc.is_map() {
                    count_stmts.push(quote! {
                        if !self.#field_ident.is_empty() { _oneof_count += 1; }
                    });
                } else if field_desc.kind().as_message().is_some() {
                    let is_set = naming
                        .backend()
                        .msg_field_is_set(&quote! { self.#field_ident });
                    count_stmts.push(quote! {
                        if #is_set { _oneof_count += 1; }
                    });
                } else if field_desc.supports_presence() {
                    count_stmts.push(quote! {
                        if self.#field_ident.is_some() { _oneof_count += 1; }
                    });
                } else {
                    let default_check = crate::codegen::generate_default_check(
                        &field_desc,
                        &field_ident,
                        naming.backend(),
                    );
                    count_stmts.push(quote! {
                        if #default_check { _oneof_count += 1; }
                    });
                }
            }
        }

        let at_most_one_msg = format!("only one of {field_names_str} can be set");
        let exactly_one_msg = format!("one of {field_names_str} must be set");

        let mut oneof_checks = Vec::new();

        // At-most-one check (always)
        oneof_checks.push(quote! {
            if _oneof_count > 1 {
                violations.push(::prost_protovalidate::Violation::new(
                    "", "message.oneof", #at_most_one_msg,
                ).without_rule_path());
            }
        });

        // Exactly-one check (only if required)
        if required {
            oneof_checks.push(quote! {
                if _oneof_count == 0 {
                    violations.push(::prost_protovalidate::Violation::new(
                        "", "message.oneof", #exactly_one_msg,
                    ).without_rule_path());
                }
            });
        }

        checks.push(quote! {
            {
                let mut _oneof_count = 0u32;
                #(#count_stmts)*
                #(#oneof_checks)*
            }
        });
    }

    checks
}

/// Generate oneof required checks for real proto oneofs.
pub(crate) fn generate_oneof_checks(
    msg: &MessageDescriptor,
    pool: &DescriptorPool,
    naming: &NamingContext,
) -> Result<Vec<TokenStream>, Error> {
    let mut checks = Vec::new();

    for oneof in msg.oneofs() {
        // Skip synthetic oneofs (proto3 optional)
        if oneof.is_synthetic() {
            continue;
        }

        let required = crate::codegen::resolve_oneof_required(&oneof, pool)?;

        if !required {
            continue;
        }

        let oneof_name = oneof.name().to_string();
        let field_ident = naming.field_ident(&oneof_name);
        let msg_text = format!("{oneof_name} is required");

        // Real oneofs are `Option<OneofEnum>` in both prost and buffa.
        checks.push(quote! {
            if self.#field_ident.is_none() {
                violations.push(::prost_protovalidate::Violation::new(
                    #oneof_name, "required", #msg_text,
                ).without_rule_path());
            }
        });
    }

    Ok(checks)
}
