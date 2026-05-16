//! Repeated field rule code generation.

use proc_macro2::{Ident, TokenStream};
use prost_reflect::{DescriptorPool, FieldDescriptor};
use quote::quote;

use prost_protovalidate_types::{Ignore, RepeatedRules};

use crate::Error;
use crate::codegen;
use crate::naming::NamingContext;
use crate::rules;

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn generate(
    rules: &RepeatedRules,
    field: &FieldDescriptor,
    field_ident: &Ident,
    proto_name: &str,
    _pool: &DescriptorPool,
    _naming: &NamingContext,
) -> Result<Vec<TokenStream>, Error> {
    let mut checks = Vec::new();

    // Min items
    if let Some(min) = rules.min_items {
        let min_usize = min as usize;
        let msg = format!("must have at least {min} items");
        checks.push(quote! {
            if self.#field_ident.len() < #min_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "repeated.min_items", #msg,
                ));
            }
        });
    }

    // Max items
    if let Some(max) = rules.max_items {
        let max_usize = max as usize;
        let msg = format!("must have at most {max} items");
        checks.push(quote! {
            if self.#field_ident.len() > #max_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "repeated.max_items", #msg,
                ));
            }
        });
    }

    // Unique
    if rules.unique == Some(true) {
        checks.push(quote! {
            {
                let mut _seen = ::std::collections::HashSet::new();
                for item in &self.#field_ident {
                    if !_seen.insert(item) {
                        violations.push(::prost_protovalidate::Violation::new(
                            #proto_name, "repeated.unique", "repeated value must contain unique items",
                        ));
                        break;
                    }
                }
            }
        });
    }

    // Per-item scalar constraints.
    //
    // Each violation produced by the item's scalar generators is captured
    // into a local buffer, then prepended with `repeated.items` on the
    // rule path and the item's index subscript on the field path so the
    // final shape matches the runtime emission
    // (`field[idx]` / `repeated.items.<rule>`).
    if let Some(ref items) = rules.items {
        // Honor `repeated.items.ignore` to match the runtime semantics:
        // `IGNORE_ALWAYS` drops the per-item checks entirely;
        // `IGNORE_IF_ZERO_VALUE` wraps them in a default-value guard so
        // zero-valued items pass without violations.
        let items_ignore = codegen::ignore_mode_of(items.ignore);

        if items_ignore != Ignore::Always {
            if let Some(ref type_rules) = items.r#type {
                let item_access = quote!((*_item));
                let defined_values = rules::defined_enum_values(&field.kind());
                // Empty `proto_name` so inner violations have no field-path
                // segment of their own — the subscript prepend below sets it.
                let item_checks = rules::generate_scalar_type_checks(
                    type_rules,
                    &item_access,
                    "",
                    &defined_values,
                )?;

                if !item_checks.is_empty() {
                    let body = if items_ignore == Ignore::IfZeroValue {
                        if let Some(default_check) =
                            codegen::generate_element_default_check(&field.kind(), &item_access)
                        {
                            quote! {
                                if #default_check {
                                    let violations = &mut _local_violations;
                                    #(#item_checks)*
                                }
                            }
                        } else {
                            quote! {
                                let violations = &mut _local_violations;
                                #(#item_checks)*
                            }
                        }
                    } else {
                        quote! {
                            let violations = &mut _local_violations;
                            #(#item_checks)*
                        }
                    };

                    checks.push(quote! {
                        for (_idx, _item) in self.#field_ident.iter().enumerate() {
                            let mut _local_violations: ::std::vec::Vec<
                                ::prost_protovalidate::Violation,
                            > = ::std::vec::Vec::new();
                            {
                                #body
                            }
                            let _idx_u64: u64 = _idx as u64;
                            for mut _v in _local_violations {
                                _v.prepend_rule_path("repeated.items");
                                _v.prepend_index(#proto_name, _idx_u64);
                                violations.push(_v);
                            }
                        }
                    });
                }
            }
        }
    }

    Ok(checks)
}
