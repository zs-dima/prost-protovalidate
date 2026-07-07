//! Map field rule code generation.

use proc_macro2::{Ident, TokenStream};
use prost_reflect::{DescriptorPool, FieldDescriptor};
use quote::quote;

use prost_protovalidate_types::rules_meta::map as meta;
use prost_protovalidate_types::{Ignore, MapRules};

use crate::Error;
use crate::codegen;
use crate::naming::NamingContext;
use crate::rules;

#[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
pub(crate) fn generate(
    rules: &MapRules,
    field: &FieldDescriptor,
    field_ident: &Ident,
    proto_name: &str,
    _pool: &DescriptorPool,
    naming: &NamingContext,
) -> Result<Vec<TokenStream>, Error> {
    // Resolve the synthetic `value` field's kind once so we can propagate
    // `enum.defined_only` when the map value is an enum type.
    let value_kind = field
        .kind()
        .as_message()
        .and_then(|entry| entry.get_field_by_name("value"))
        .map(|v| v.kind());
    let mut checks = Vec::new();

    // Min pairs
    if let Some(min) = rules.min_pairs {
        let min_usize = min as usize;
        let rule_id = meta::MIN_PAIRS_ID;
        let msg = meta::min_pairs_message(min);
        checks.push(quote! {
            if self.#field_ident.len() < #min_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        });
    }

    // Max pairs
    if let Some(max) = rules.max_pairs {
        let max_usize = max as usize;
        let rule_id = meta::MAX_PAIRS_ID;
        let msg = meta::max_pairs_message(max);
        checks.push(quote! {
            if self.#field_ident.len() > #max_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, #rule_id, #msg,
                ));
            }
        });
    }

    // Per-entry key constraints.
    //
    // Each key-rule violation is captured locally, then marked with
    // `for_key = true` and prepended with `map.keys` on the rule path
    // and the entry's key subscript on the field path — matching the
    // runtime's [`MapEval`] key-violation post-processing exactly.
    //
    // Honors `map.keys.ignore`: `IGNORE_ALWAYS` skips the key checks
    // entirely; `IGNORE_IF_ZERO_VALUE` wraps them in a default-value
    // guard so zero-valued keys pass without violations (matching
    // runtime's `build_value(..., nested = true)` semantics).
    let key_kind = field
        .kind()
        .as_message()
        .and_then(|entry| entry.get_field_by_name("key"))
        .map(|k| k.kind());
    if let Some(ref keys) = rules.keys {
        let keys_ignore = codegen::ignore_mode_of(keys.ignore);

        if keys_ignore != Ignore::Always {
            if let Some(ref type_rules) = keys.r#type {
                let key_access = quote!((*_k));
                let key_checks = rules::generate_scalar_type_checks(
                    type_rules,
                    &key_access,
                    "",
                    &[],
                    naming.backend(),
                )?;

                if !key_checks.is_empty() {
                    let key_subscript =
                        map_key_subscript_prepend("_v_inner", proto_name, &field.kind());
                    let body = if keys_ignore == Ignore::IfZeroValue {
                        if let Some(default_check) = key_kind.as_ref().and_then(|k| {
                            codegen::generate_element_default_check(
                                k,
                                &key_access,
                                naming.backend(),
                            )
                        }) {
                            quote! {
                                if #default_check {
                                    let violations = &mut _local_violations;
                                    #(#key_checks)*
                                }
                            }
                        } else {
                            quote! {
                                let violations = &mut _local_violations;
                                #(#key_checks)*
                            }
                        }
                    } else {
                        quote! {
                            let violations = &mut _local_violations;
                            #(#key_checks)*
                        }
                    };

                    let keys_prefix = meta::KEYS_RULE_PREFIX;
                    checks.push(quote! {
                        for (_k, _) in &self.#field_ident {
                            let mut _local_violations: ::std::vec::Vec<
                                ::prost_protovalidate::Violation,
                            > = ::std::vec::Vec::new();
                            {
                                #body
                            }
                            for mut _v_inner in _local_violations {
                                _v_inner.mark_for_key();
                                _v_inner.prepend_rule_path(#keys_prefix);
                                #key_subscript
                                violations.push(_v_inner);
                            }
                        }
                    });
                }
            }
        }
    }

    // Per-entry value constraints — same pattern as keys, with
    // `map.values` as the rule-path prefix.
    if let Some(ref values) = rules.values {
        let values_ignore = codegen::ignore_mode_of(values.ignore);

        if values_ignore != Ignore::Always {
            if let Some(ref type_rules) = values.r#type {
                let val_access = quote!((*_v));
                let defined_values = value_kind
                    .as_ref()
                    .map(rules::defined_enum_values)
                    .unwrap_or_default();
                let val_checks = rules::generate_scalar_type_checks(
                    type_rules,
                    &val_access,
                    "",
                    &defined_values,
                    naming.backend(),
                )?;

                if !val_checks.is_empty() {
                    let key_subscript =
                        map_key_subscript_prepend("_v_inner", proto_name, &field.kind());
                    let body = if values_ignore == Ignore::IfZeroValue {
                        if let Some(default_check) = value_kind.as_ref().and_then(|k| {
                            codegen::generate_element_default_check(
                                k,
                                &val_access,
                                naming.backend(),
                            )
                        }) {
                            quote! {
                                if #default_check {
                                    let violations = &mut _local_violations;
                                    #(#val_checks)*
                                }
                            }
                        } else {
                            quote! {
                                let violations = &mut _local_violations;
                                #(#val_checks)*
                            }
                        }
                    } else {
                        quote! {
                            let violations = &mut _local_violations;
                            #(#val_checks)*
                        }
                    };

                    let values_prefix = meta::VALUES_RULE_PREFIX;
                    checks.push(quote! {
                        for (_k, _v) in &self.#field_ident {
                            let mut _local_violations: ::std::vec::Vec<
                                ::prost_protovalidate::Violation,
                            > = ::std::vec::Vec::new();
                            {
                                #body
                            }
                            for mut _v_inner in _local_violations {
                                _v_inner.prepend_rule_path(#values_prefix);
                                #key_subscript
                                violations.push(_v_inner);
                            }
                        }
                    });
                }
            }
        }
    }

    Ok(checks)
}

/// Emit a `prepend_*_key` call on `violation_ident` based on the map's
/// key kind, producing a subscripted field path like `field["key"]` /
/// `field[42]` / `field[true]` that matches the canonical runtime format.
fn map_key_subscript_prepend(
    violation_ident: &str,
    proto_name: &str,
    map_field_kind: &prost_reflect::Kind,
) -> TokenStream {
    use prost_reflect::Kind;
    let viol = quote::format_ident!("{}", violation_ident);
    // The kind we have is the map-entry message; drill in to the key field.
    let key_kind = map_field_kind
        .as_message()
        .and_then(|entry| entry.get_field_by_name("key"))
        .map(|k| k.kind());

    match key_kind {
        Some(Kind::String) => quote! {
            #viol.prepend_string_key(#proto_name, _k.as_str());
        },
        Some(Kind::Bool) => quote! {
            #viol.prepend_bool_key(#proto_name, *_k);
        },
        Some(Kind::Int32 | Kind::Sint32 | Kind::Sfixed32) => quote! {
            #viol.prepend_int_key(#proto_name, ::core::convert::From::from(*_k));
        },
        Some(Kind::Int64 | Kind::Sint64 | Kind::Sfixed64) => quote! {
            #viol.prepend_int_key(#proto_name, *_k);
        },
        Some(Kind::Uint32 | Kind::Fixed32) => quote! {
            #viol.prepend_uint_key(#proto_name, ::core::convert::From::from(*_k));
        },
        Some(Kind::Uint64 | Kind::Fixed64) => quote! {
            #viol.prepend_uint_key(#proto_name, *_k);
        },
        _ => quote! {
            #viol.prepend_field_path(#proto_name);
        },
    }
}
