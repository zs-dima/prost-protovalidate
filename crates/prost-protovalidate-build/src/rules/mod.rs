//! Rule type dispatch — routes `FieldRules.type` variants to specialized
//! code generators.

pub(crate) mod bool_rules;
pub(crate) mod bytes;
pub(crate) mod duration;
pub(crate) mod enum_rules;
pub(crate) mod field_mask;
pub(crate) mod map;
pub(crate) mod number;
pub(crate) mod repeated;
pub(crate) mod string;
pub(crate) mod timestamp;

use proc_macro2::{Ident, TokenStream};
use prost_reflect::{DescriptorPool, FieldDescriptor};
use quote::quote;

use prost_protovalidate_types::field_rules;
use prost_protovalidate_types::rules_meta::any as any_meta;

use crate::Error;
use crate::naming::NamingContext;

/// Generate validation checks for the type-specific portion of `FieldRules`.
pub(crate) fn generate_type_rules(
    type_rules: &field_rules::Type,
    field: &FieldDescriptor,
    field_ident: &Ident,
    proto_name: &str,
    pool: &DescriptorPool,
    naming: &NamingContext,
) -> Result<Vec<TokenStream>, Error> {
    // WKT wrappers: unwrap Option and apply scalar rules to inner `.value`.
    //
    // The wrapper unwrap path only applies to singular wrapper fields. For
    // repeated/map of wrapper, prost stores Vec/HashMap directly — the
    // capability analyzer routes those to runtime, so this branch is never
    // reached for them, but we gate defensively.
    if is_wkt_wrapper(field) && !field.is_list() && !field.is_map() {
        let inner_access = quote!(_wkt.value);
        let inner_checks = generate_scalar_type_checks(type_rules, &inner_access, proto_name, &[])?;
        if inner_checks.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(vec![quote! {
            if let ::core::option::Option::Some(ref _wkt) = self.#field_ident {
                #(#inner_checks)*
            }
        }]);
    }

    // Scalar/enum fields whose prost storage is `Option<T>`: unwrap here so
    // the rule code sees `*_val` instead of `self.field` (which would be
    // the `Option`). Storage shape per syntax:
    //
    // * proto2 `required` scalar — `supports_presence() == true`, but prost
    //   emits bare `T`. Excluded via `!is_required()`.
    // * proto2 `optional` scalar — `supports_presence() == true`, prost
    //   emits `Option<T>`.
    // * proto3 `optional` scalar — synthetic oneof, `supports_presence() ==
    //   true`, prost emits `Option<T>`.
    // * proto3 implicit scalar — `supports_presence() == false`, prost emits
    //   bare `T`.
    //
    // List, map, and message kinds have dedicated dispatchers below and are
    // excluded here.
    if field_storage_is_option_scalar(field) {
        // Parenthesise the deref so `(*_val).method()` parses as a method
        // call on the dereferenced value, not `*(_val.method())`.
        let inner_access = quote!((*_val));
        let defined_values = defined_enum_values(&field.kind());
        let inner_checks =
            generate_scalar_type_checks(type_rules, &inner_access, proto_name, &defined_values)?;
        if inner_checks.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(vec![quote! {
            if let ::core::option::Option::Some(ref _val) = self.#field_ident {
                #(#inner_checks)*
            }
        }]);
    }

    let value_access = quote!(self.#field_ident);
    match type_rules {
        field_rules::Type::Bool(r) => Ok(bool_rules::generate(r, &value_access, proto_name)),
        field_rules::Type::Float(r) => Ok(number::generate_float(r, &value_access, proto_name)),
        field_rules::Type::Double(r) => Ok(number::generate_double(r, &value_access, proto_name)),
        field_rules::Type::Int32(r) => Ok(number::generate_int32(r, &value_access, proto_name)),
        field_rules::Type::Int64(r) => Ok(number::generate_int64(r, &value_access, proto_name)),
        field_rules::Type::Uint32(r) => Ok(number::generate_uint32(r, &value_access, proto_name)),
        field_rules::Type::Uint64(r) => Ok(number::generate_uint64(r, &value_access, proto_name)),
        field_rules::Type::Sint32(r) => Ok(number::generate_sint32(r, &value_access, proto_name)),
        field_rules::Type::Sint64(r) => Ok(number::generate_sint64(r, &value_access, proto_name)),
        field_rules::Type::Fixed32(r) => Ok(number::generate_fixed32(r, &value_access, proto_name)),
        field_rules::Type::Fixed64(r) => Ok(number::generate_fixed64(r, &value_access, proto_name)),
        field_rules::Type::Sfixed32(r) => {
            Ok(number::generate_sfixed32(r, &value_access, proto_name))
        }
        field_rules::Type::Sfixed64(r) => {
            Ok(number::generate_sfixed64(r, &value_access, proto_name))
        }
        field_rules::Type::String(r) => Ok(string::generate(r, &value_access, proto_name)),
        field_rules::Type::Bytes(r) => Ok(bytes::generate(r, &value_access, proto_name)),
        field_rules::Type::Enum(r) => {
            let defined_values: Vec<i32> = field
                .kind()
                .as_enum()
                .map(|e| e.values().map(|v| v.number()).collect())
                .unwrap_or_default();
            Ok(enum_rules::generate(
                r,
                &value_access,
                proto_name,
                &defined_values,
            ))
        }
        field_rules::Type::Repeated(r) => {
            repeated::generate(r, field, field_ident, proto_name, pool, naming)
        }
        field_rules::Type::Map(r) => map::generate(r, field, field_ident, proto_name, pool, naming),
        field_rules::Type::Duration(r) => Ok(duration::generate(r, field_ident, proto_name)),
        field_rules::Type::Timestamp(r) => Ok(timestamp::generate(r, field_ident, proto_name)),
        field_rules::Type::FieldMask(r) => Ok(field_mask::generate(r, field_ident, proto_name)),
        field_rules::Type::Any(r) => Ok(generate_any_rules(r, field_ident, proto_name)),
    }
}

/// Generate scalar type checks for a given value access expression.
///
/// Used by `repeated` and `map` generators to validate individual items,
/// keys, or values. Only handles scalar types (bool, numerics, string,
/// bytes, enum). Duration, timestamp, and message types are not supported
/// in this path — message items get recursive `.validate()` calls instead.
///
/// `defined_values` carries the declared numbers for an enum item/value,
/// so `enum.defined_only` can be enforced. Callers without an enum
/// context pass `&[]`.
pub(crate) fn generate_scalar_type_checks(
    type_rules: &field_rules::Type,
    value_access: &TokenStream,
    proto_name: &str,
    defined_values: &[i32],
) -> Result<Vec<TokenStream>, Error> {
    match type_rules {
        field_rules::Type::Bool(r) => Ok(bool_rules::generate(r, value_access, proto_name)),
        field_rules::Type::Float(r) => Ok(number::generate_float(r, value_access, proto_name)),
        field_rules::Type::Double(r) => Ok(number::generate_double(r, value_access, proto_name)),
        field_rules::Type::Int32(r) => Ok(number::generate_int32(r, value_access, proto_name)),
        field_rules::Type::Int64(r) => Ok(number::generate_int64(r, value_access, proto_name)),
        field_rules::Type::Uint32(r) => Ok(number::generate_uint32(r, value_access, proto_name)),
        field_rules::Type::Uint64(r) => Ok(number::generate_uint64(r, value_access, proto_name)),
        field_rules::Type::Sint32(r) => Ok(number::generate_sint32(r, value_access, proto_name)),
        field_rules::Type::Sint64(r) => Ok(number::generate_sint64(r, value_access, proto_name)),
        field_rules::Type::Fixed32(r) => Ok(number::generate_fixed32(r, value_access, proto_name)),
        field_rules::Type::Fixed64(r) => Ok(number::generate_fixed64(r, value_access, proto_name)),
        field_rules::Type::Sfixed32(r) => {
            Ok(number::generate_sfixed32(r, value_access, proto_name))
        }
        field_rules::Type::Sfixed64(r) => {
            Ok(number::generate_sfixed64(r, value_access, proto_name))
        }
        field_rules::Type::String(r) => Ok(string::generate(r, value_access, proto_name)),
        field_rules::Type::Bytes(r) => Ok(bytes::generate(r, value_access, proto_name)),
        field_rules::Type::Enum(r) => Ok(enum_rules::generate(
            r,
            value_access,
            proto_name,
            defined_values,
        )),
        _ => Err(Error::Codegen(format!(
            "unsupported item/key/value rule type for field {proto_name}"
        ))),
    }
}

/// Extract the declared enum-value numbers for an item that is an enum kind,
/// or an empty `Vec` for any other kind. Used by `repeated`/`map` dispatchers
/// to propagate `defined_only` enforcement into nested scalar checks.
pub(crate) fn defined_enum_values(field_kind: &prost_reflect::Kind) -> Vec<i32> {
    field_kind
        .as_enum()
        .map(|e| e.values().map(|v| v.number()).collect())
        .unwrap_or_default()
}

/// Whether the field's prost storage is `Option<ScalarOrEnum>` (i.e., needs
/// `if let Some(ref _val)` unwrap before scalar rule checks).
///
/// Distinguishes proto2 `required` (`supports_presence == true` but prost
/// emits bare `T`) from other presence-having scalars.
pub(crate) fn field_storage_is_option_scalar(field: &FieldDescriptor) -> bool {
    field.supports_presence()
        && !field.is_required()
        && !field.is_list()
        && !field.is_map()
        && field.kind().as_message().is_none()
}

/// Returns `true` if the field's message type is a Google well-known wrapper type.
fn is_wkt_wrapper(field: &FieldDescriptor) -> bool {
    field.kind().as_message().is_some_and(|msg| {
        matches!(
            msg.full_name(),
            "google.protobuf.BoolValue"
                | "google.protobuf.BytesValue"
                | "google.protobuf.DoubleValue"
                | "google.protobuf.FloatValue"
                | "google.protobuf.Int32Value"
                | "google.protobuf.Int64Value"
                | "google.protobuf.StringValue"
                | "google.protobuf.UInt32Value"
                | "google.protobuf.UInt64Value"
        )
    })
}

/// Generate `Any` `type_url` `in`/`not_in` checks.
fn generate_any_rules(
    r: &prost_protovalidate_types::AnyRules,
    field_ident: &Ident,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();
    if !r.r#in.is_empty() {
        let in_id = any_meta::IN_ID;
        let in_msg = any_meta::IN_MESSAGE;
        let vals = &r.r#in;
        checks.push(quote! {
            if let ::core::option::Option::Some(ref _any) = self.#field_ident {
                if ![#(#vals),*].contains(&_any.type_url.as_str()) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #in_id, #in_msg,
                    ));
                }
            }
        });
    }
    if !r.not_in.is_empty() {
        let not_in_id = any_meta::NOT_IN_ID;
        let not_in_msg = any_meta::NOT_IN_MESSAGE;
        let vals = &r.not_in;
        checks.push(quote! {
            if let ::core::option::Option::Some(ref _any) = self.#field_ident {
                if [#(#vals),*].contains(&_any.type_url.as_str()) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, #not_in_id, #not_in_msg,
                    ));
                }
            }
        });
    }
    checks
}
