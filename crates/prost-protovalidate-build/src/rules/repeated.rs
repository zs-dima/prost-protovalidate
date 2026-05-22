//! Repeated field rule code generation.

use proc_macro2::{Ident, TokenStream};
use prost_reflect::{DescriptorPool, FieldDescriptor, Kind};
use quote::quote;

use prost_protovalidate_types::{Ignore, RepeatedRules};

use crate::Error;
use crate::codegen;
use crate::naming::NamingContext;
use crate::rules;

/// Emit a `repeated.min_items` length check.
fn emit_min_items_check(field_ident: &Ident, proto_name: &str, min: u64) -> TokenStream {
    #[allow(clippy::cast_possible_truncation)]
    let min_usize = min as usize;
    let msg = format!("must have at least {min} items");
    quote! {
        if self.#field_ident.len() < #min_usize {
            violations.push(::prost_protovalidate::Violation::new(
                #proto_name, "repeated.min_items", #msg,
            ));
        }
    }
}

/// Emit a `repeated.max_items` length check.
fn emit_max_items_check(field_ident: &Ident, proto_name: &str, max: u64) -> TokenStream {
    #[allow(clippy::cast_possible_truncation)]
    let max_usize = max as usize;
    let msg = format!("must have at most {max} items");
    quote! {
        if self.#field_ident.len() > #max_usize {
            violations.push(::prost_protovalidate::Violation::new(
                #proto_name, "repeated.max_items", #msg,
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
    zero_literal: &TokenStream,
) -> TokenStream {
    quote! {
        {
            let mut _seen = ::std::collections::HashSet::<#bits_ty>::new();
            for item in &self.#field_ident {
                if item.is_nan() {
                    continue;
                }
                let _bits = if *item == #zero_literal {
                    #zero_literal.to_bits()
                } else {
                    item.to_bits()
                };
                if !_seen.insert(_bits) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "repeated.unique", "items must be unique",
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
    quote! {
        {
            let mut _seen = ::std::collections::HashSet::new();
            for item in &self.#field_ident {
                if !_seen.insert(item) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "repeated.unique", "items must be unique",
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
    _naming: &NamingContext,
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
                &quote!(0.0_f32),
            ),
            Kind::Double => emit_canonical_bits_unique_check(
                field_ident,
                proto_name,
                &quote!(u64),
                &quote!(0.0_f64),
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
