//! Repeated field rule code generation.

use proc_macro2::{Ident, TokenStream};
use prost_reflect::{DescriptorPool, FieldDescriptor, Kind};
use quote::quote;

use prost_protovalidate_types::rules_meta::repeated as meta;
use prost_protovalidate_types::{Ignore, RepeatedRules};

use crate::Error;
use crate::codegen;
use crate::naming::NamingContext;
use crate::rules;

/// Emit a `repeated.min_items` length check.
fn emit_min_items_check(field_ident: &Ident, proto_name: &str, min: u64) -> TokenStream {
    #[allow(clippy::cast_possible_truncation)]
    let min_usize = min as usize;
    let rule_id = meta::MIN_ITEMS_ID;
    let msg = meta::min_items_message(min);
    quote! {
        if self.#field_ident.len() < #min_usize {
            violations.push(::prost_protovalidate::Violation::new(
                #proto_name, #rule_id, #msg,
            ));
        }
    }
}

/// Emit a `repeated.max_items` length check.
fn emit_max_items_check(field_ident: &Ident, proto_name: &str, max: u64) -> TokenStream {
    #[allow(clippy::cast_possible_truncation)]
    let max_usize = max as usize;
    let rule_id = meta::MAX_ITEMS_ID;
    let msg = meta::max_items_message(max);
    quote! {
        if self.#field_ident.len() > #max_usize {
            violations.push(::prost_protovalidate::Violation::new(
                #proto_name, #rule_id, #msg,
            ));
        }
    }
}

/// Emit a `repeated.unique` check that hashes canonical IEEE-754 bits.
///
/// `bits_ty` is the `HashSet<T>` element type (`u32` for `f32`, `u64` for
/// `f64`); `zero_literal` is the typed zero used to canonicalise `±0.0`.
/// Mirrors the runtime's `canonical_f32_bits` / `canonical_f64_bits`
/// semantics in [validator/rules/repeated.rs](../../../../prost-protovalidate/src/validator/rules/repeated.rs):
/// `NaN` is skipped (multiple NaNs allowed), `+0.0` and `-0.0` collapse to
/// the same bit pattern.
fn emit_canonical_bits_unique_check(
    field_ident: &Ident,
    proto_name: &str,
    bits_ty: &TokenStream,
    canonical_fn: &TokenStream,
) -> TokenStream {
    let rule_id = meta::UNIQUE_ID;
    let msg = meta::UNIQUE_MESSAGE;
    quote! {
        {
            let mut _seen = ::std::collections::HashSet::<#bits_ty>::new();
            for item in &self.#field_ident {
                let Some(_bits) = #canonical_fn(*item) else {
                    continue;
                };
                if !_seen.insert(_bits) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #msg,
                    ));
                    break;
                }
            }
        }
    }
}

/// Emit a generic `repeated.unique` check for `HashSet<&T>`-compatible
/// scalar element kinds (bool, integer widths, string, bytes, enum).
fn emit_generic_unique_check(field_ident: &Ident, proto_name: &str) -> TokenStream {
    let rule_id = meta::UNIQUE_ID;
    let msg = meta::UNIQUE_MESSAGE;
    quote! {
        {
            let mut _seen = ::std::collections::HashSet::new();
            for item in &self.#field_ident {
                if !_seen.insert(item) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #rule_id, #msg,
                    ));
                    break;
                }
            }
        }
    }
}

pub(crate) fn generate(
    rules: &RepeatedRules,
    field: &FieldDescriptor,
    field_ident: &Ident,
    proto_name: &str,
    _pool: &DescriptorPool,
    naming: &NamingContext,
) -> Result<Vec<TokenStream>, Error> {
    let mut checks = Vec::new();

    if let Some(min) = rules.min_items {
        checks.push(emit_min_items_check(field_ident, proto_name, min));
    }

    if let Some(max) = rules.max_items {
        checks.push(emit_max_items_check(field_ident, proto_name, max));
    }

    // Unique. Float/double use canonical IEEE-754 bits via the helper;
    // other hashable scalar kinds (bool, integer widths, string, bytes,
    // enum) use the generic `HashSet<T>` path.
    if rules.unique == Some(true) {
        let unique_check = match field.kind() {
            Kind::Float => emit_canonical_bits_unique_check(
                field_ident,
                proto_name,
                &quote!(u32),
                &quote!(::prost_protovalidate::types::rules_meta::float::canonical_f32_bits),
            ),
            Kind::Double => emit_canonical_bits_unique_check(
                field_ident,
                proto_name,
                &quote!(u64),
                &quote!(::prost_protovalidate::types::rules_meta::float::canonical_f64_bits),
            ),
            _ => emit_generic_unique_check(field_ident, proto_name),
        };
        checks.push(unique_check);
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
                    naming.backend(),
                )?;

                if !item_checks.is_empty() {
                    let body = if items_ignore == Ignore::IfZeroValue {
                        if let Some(default_check) = codegen::generate_element_default_check(
                            &field.kind(),
                            &item_access,
                            naming.backend(),
                        ) {
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

                    let items_prefix = meta::ITEMS_RULE_PREFIX;
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
                                _v.prepend_rule_path(#items_prefix);
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
