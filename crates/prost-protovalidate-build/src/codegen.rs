//! Code generation orchestration.
//!
//! Iterates all messages in a descriptor pool, determines which have
//! standard-only rules, and generates `impl Validate` blocks.

use std::collections::{HashMap, HashSet};

use proc_macro2::TokenStream;
use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DynamicMessage, ExtensionDescriptor, FieldDescriptor, MessageDescriptor,
    ReflectMessage,
};
use quote::quote;
use regex::Regex;

use prost_protovalidate_types::{FieldRules, Ignore, MessageRules, field_rules};

use crate::Error;
use crate::message;
use crate::naming::{self, NamingContext};
use crate::rules;

/// Decode a `buf.validate` extension from options using a pool-local descriptor.
///
/// Extension descriptors must come from the same [`DescriptorPool`] as the
/// options message. Using an extension from a different pool will silently
/// miss the extension data.
fn decode_pool_extension<T: prost::Message + Default>(
    options: &prost_reflect::DynamicMessage,
    extension_name: &str,
    pool: &DescriptorPool,
) -> Result<Option<T>, Error> {
    let Some(ext) = pool.get_extension_by_name(extension_name) else {
        return Ok(None);
    };
    if !options.has_extension(&ext) {
        return Ok(None);
    }
    match options.get_extension(&ext).as_message() {
        Some(msg) => msg
            .transcode_to::<T>()
            .map(Some)
            .map_err(|e| Error::ConstraintDecode(e.to_string())),
        None => Ok(None),
    }
}

fn resolve_field_constraints(
    field: &FieldDescriptor,
    pool: &DescriptorPool,
) -> Result<Option<FieldRules>, Error> {
    decode_pool_extension(&field.options(), "buf.validate.field", pool)
}

fn resolve_message_constraints(
    msg: &MessageDescriptor,
    pool: &DescriptorPool,
) -> Result<Option<MessageRules>, Error> {
    decode_pool_extension(&msg.options(), "buf.validate.message", pool)
}

pub(crate) fn resolve_oneof_required(
    oneof: &prost_reflect::OneofDescriptor,
    pool: &DescriptorPool,
) -> Result<bool, Error> {
    let rules: Option<prost_protovalidate_types::OneofRules> =
        decode_pool_extension(&oneof.options(), "buf.validate.oneof", pool)?;
    Ok(rules.is_some_and(|r| r.required.unwrap_or(false)))
}

/// Generate all `impl Validate` blocks for messages in the descriptor pool.
pub(crate) fn generate(pool: &DescriptorPool, naming: &NamingContext) -> TokenStream {
    let mut output = TokenStream::new();
    let mut analyzer = CapabilityAnalyzer::new(pool, naming);

    for message in pool.all_messages() {
        match generate_message(pool, &message, naming, &mut analyzer) {
            Ok(Some(tokens)) => output.extend(tokens),
            Ok(None) => {}
            Err(e) => {
                let name = message.full_name();
                println!("cargo:warning=prost-protovalidate-build: skipping {name}: {e:?}");
            }
        }
    }

    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InvalidRegex {
    rule_path: String,
    pattern: String,
    cause: String,
}

/// Analyze and optionally generate a Validate impl for a single message.
fn generate_message(
    pool: &DescriptorPool,
    msg: &MessageDescriptor,
    naming: &NamingContext,
    analyzer: &mut CapabilityAnalyzer<'_>,
) -> Result<Option<TokenStream>, Error> {
    match analyzer.capability_for(msg)? {
        MessageCapability::NoRules => return Ok(None),
        MessageCapability::RuntimeOnly(reason) => {
            println!(
                "cargo:warning=prost-protovalidate-build: {reason} ; use runtime Validator instead"
            );
            return Ok(None);
        }
        MessageCapability::Generated => {}
    }

    // Check message-level rules
    let msg_rules = resolve_message_constraints(msg, pool)?;

    // Check field-level rules
    let mut field_checks = Vec::new();
    let mut has_any_rules = msg_rules.is_some();

    for field in msg.fields() {
        let Some(fr) = resolve_field_constraints(&field, pool)? else {
            continue;
        };

        has_any_rules = true;

        let check = generate_field_check(&field, &fr, msg_rules.as_ref(), pool, naming)?;
        if let Some(tokens) = check {
            field_checks.push(tokens);
        }
    }

    // Generate message-level checks (virtual oneofs)
    let msg_level_checks = message::generate_message_checks(msg, msg_rules.as_ref());

    // Generate oneof checks
    let oneof_checks = message::generate_oneof_checks(msg, pool)?;

    // Nested message validation (recursive .validate() calls)
    for field in msg.fields() {
        let field_rules = resolve_field_constraints(&field, pool)?;
        if let Some(nested_check) =
            generate_nested_validation(&field, field_rules.as_ref(), analyzer)?
        {
            has_any_rules = true;
            field_checks.push(nested_check);
        }
    }

    if !has_any_rules && msg_level_checks.is_empty() && oneof_checks.is_empty() {
        return Ok(None);
    }

    let rust_type = naming.proto_to_rust_type(msg.full_name());

    Ok(Some(quote! {
        impl ::prost_protovalidate::Validate for #rust_type {
            fn validate(&self) -> ::core::result::Result<(), ::prost_protovalidate::ValidationError> {
                let mut violations = ::std::vec::Vec::new();

                #(#field_checks)*
                #(#msg_level_checks)*
                #(#oneof_checks)*

                if violations.is_empty() {
                    Ok(())
                } else {
                    Err(::prost_protovalidate::ValidationError::new(violations))
                }
            }
        }
    }))
}

/// Check if message-level rules contain CEL expressions.
fn has_cel_message_rules(rules: Option<&MessageRules>) -> bool {
    let Some(rules) = rules else {
        return false;
    };
    !rules.cel.is_empty() || !rules.cel_expression.is_empty()
}

/// Decode a `FieldRules.ignore` value (stored as `i32`) into the `Ignore`
/// enum, defaulting to `Ignore::Unspecified` on unknown values. Used by
/// the codegen ignore-routing paths in `generate_field_check`,
/// `rules::repeated`, and `rules::map`.
pub(crate) fn ignore_mode_of(ignore_field: Option<i32>) -> Ignore {
    ignore_field
        .and_then(|i| Ignore::try_from(i).ok())
        .unwrap_or(Ignore::Unspecified)
}

/// Whether the field is listed in any of the message's virtual oneof rules
/// (`MessageRules.oneof`). Mirrors runtime `is_part_of_message_oneof`.
fn is_part_of_message_oneof(msg_rules: Option<&MessageRules>, field: &FieldDescriptor) -> bool {
    let Some(rules) = msg_rules else {
        return false;
    };
    let field_name = field.name();
    rules
        .oneof
        .iter()
        .any(|oneof| oneof.fields.iter().any(|f| f == field_name))
}

/// Maps a `FieldRules.type` oneof variant to its canonical name, matching the
/// runtime helper `field_rule_variant_name` in
/// `crates/prost-protovalidate/src/validator/builder.rs`.
fn field_rule_variant_name(rules: &FieldRules) -> Option<&'static str> {
    use field_rules::Type;
    match &rules.r#type {
        Some(Type::Float(_)) => Some("float"),
        Some(Type::Double(_)) => Some("double"),
        Some(Type::Int32(_)) => Some("int32"),
        Some(Type::Int64(_)) => Some("int64"),
        Some(Type::Uint32(_)) => Some("uint32"),
        Some(Type::Uint64(_)) => Some("uint64"),
        Some(Type::Sint32(_)) => Some("sint32"),
        Some(Type::Sint64(_)) => Some("sint64"),
        Some(Type::Fixed32(_)) => Some("fixed32"),
        Some(Type::Fixed64(_)) => Some("fixed64"),
        Some(Type::Sfixed32(_)) => Some("sfixed32"),
        Some(Type::Sfixed64(_)) => Some("sfixed64"),
        Some(Type::Bool(_)) => Some("bool"),
        Some(Type::String(_)) => Some("string"),
        Some(Type::Bytes(_)) => Some("bytes"),
        Some(Type::Enum(_)) => Some("enum"),
        Some(Type::Repeated(_)) => Some("repeated"),
        Some(Type::Map(_)) => Some("map"),
        Some(Type::Any(_)) => Some("any"),
        Some(Type::Duration(_)) => Some("duration"),
        Some(Type::Timestamp(_)) => Some("timestamp"),
        Some(Type::FieldMask(_)) => Some("field_mask"),
        None => None,
    }
}

/// Expected `FieldRules.type` variant name for a given field, mirroring the
/// runtime helper `expected_rule_variant_name`. When `nested` is true the
/// field is treated as a repeated item or map key/value (its outer
/// list/map wrapping is ignored).
fn expected_rule_variant_name_for_kind(
    kind: &prost_reflect::Kind,
    is_list: bool,
    is_map: bool,
    nested: bool,
) -> Option<&'static str> {
    use prost_reflect::Kind;
    if is_map && !nested {
        return Some("map");
    }
    if is_list && !nested {
        return Some("repeated");
    }
    if let Some(msg) = kind.as_message() {
        return match msg.full_name() {
            "google.protobuf.BoolValue" => Some("bool"),
            "google.protobuf.BytesValue" => Some("bytes"),
            "google.protobuf.DoubleValue" => Some("double"),
            "google.protobuf.FloatValue" => Some("float"),
            "google.protobuf.Int32Value" => Some("int32"),
            "google.protobuf.Int64Value" => Some("int64"),
            "google.protobuf.StringValue" => Some("string"),
            "google.protobuf.UInt32Value" => Some("uint32"),
            "google.protobuf.UInt64Value" => Some("uint64"),
            "google.protobuf.Any" => Some("any"),
            "google.protobuf.Duration" => Some("duration"),
            "google.protobuf.Timestamp" => Some("timestamp"),
            "google.protobuf.FieldMask" => Some("field_mask"),
            _ => None,
        };
    }
    match kind {
        Kind::Float => Some("float"),
        Kind::Double => Some("double"),
        Kind::Int32 => Some("int32"),
        Kind::Int64 => Some("int64"),
        Kind::Uint32 => Some("uint32"),
        Kind::Uint64 => Some("uint64"),
        Kind::Sint32 => Some("sint32"),
        Kind::Sint64 => Some("sint64"),
        Kind::Fixed32 => Some("fixed32"),
        Kind::Fixed64 => Some("fixed64"),
        Kind::Sfixed32 => Some("sfixed32"),
        Kind::Sfixed64 => Some("sfixed64"),
        Kind::Bool => Some("bool"),
        Kind::String => Some("string"),
        Kind::Bytes => Some("bytes"),
        Kind::Enum(_) => Some("enum"),
        Kind::Message(_) => None,
    }
}

/// Find a rule-type vs field-kind mismatch (e.g. `string` rules on an int32),
/// recursively descending into `repeated.items`, `map.keys`, and `map.values`.
/// Returns a human-readable reason on the first mismatch encountered, mirroring
/// the runtime errors produced by `validate_rule_type_matches_field`.
fn rule_type_mismatch_reason(rules: &FieldRules, field: &FieldDescriptor) -> Option<String> {
    let actual = field_rule_variant_name(rules)?;
    let expected =
        expected_rule_variant_name_for_kind(&field.kind(), field.is_list(), field.is_map(), false);

    match expected {
        Some(exp) if exp == actual => {}
        Some(exp) => {
            return Some(format!(
                "expected rule `{exp}`, got `{actual}` on field `{}`",
                field.full_name()
            ));
        }
        None => {
            return Some(format!(
                "mismatched message rules, `{actual}` is not a valid rule for field `{}`",
                field.full_name()
            ));
        }
    }

    // Recurse into nested container rules. For `repeated.items`, the inner
    // descriptor kind is the field's element kind (not the list); for
    // `map.keys` / `map.values` we drill into the synthetic map-entry
    // descriptor and use its key/value field kinds.
    match &rules.r#type {
        Some(field_rules::Type::Repeated(r)) => {
            if let Some(items) = r.items.as_deref() {
                if let Some(actual_inner) = field_rule_variant_name(items) {
                    let expected_inner =
                        expected_rule_variant_name_for_kind(&field.kind(), false, false, true);
                    return match expected_inner {
                        Some(exp) if exp == actual_inner => None,
                        Some(exp) => Some(format!(
                            "expected rule `repeated.items.{exp}`, got `repeated.items.{actual_inner}` on field `{}`",
                            field.full_name()
                        )),
                        None => Some(format!(
                            "mismatched message rules, `repeated.items.{actual_inner}` is not a valid rule for field `{}`",
                            field.full_name()
                        )),
                    };
                }
            }
        }
        Some(field_rules::Type::Map(m)) => {
            let entry = field.kind();
            let entry_msg = entry.as_message();
            if let Some(keys) = m.keys.as_deref() {
                if let Some(actual_inner) = field_rule_variant_name(keys) {
                    let key_kind = entry_msg
                        .as_ref()
                        .and_then(|e| e.get_field_by_name("key"))
                        .map(|f| f.kind());
                    let expected_inner = key_kind
                        .as_ref()
                        .and_then(|k| expected_rule_variant_name_for_kind(k, false, false, true));
                    if expected_inner != Some(actual_inner) {
                        return Some(format!(
                            "expected rule `map.keys.{}`, got `map.keys.{actual_inner}` on field `{}`",
                            expected_inner.unwrap_or("<unknown>"),
                            field.full_name()
                        ));
                    }
                }
            }
            if let Some(values) = m.values.as_deref() {
                if let Some(actual_inner) = field_rule_variant_name(values) {
                    let val_kind = entry_msg
                        .as_ref()
                        .and_then(|e| e.get_field_by_name("value"))
                        .map(|f| f.kind());
                    let expected_inner = val_kind
                        .as_ref()
                        .and_then(|k| expected_rule_variant_name_for_kind(k, false, false, true));
                    if expected_inner != Some(actual_inner) {
                        return Some(format!(
                            "expected rule `map.values.{}`, got `map.values.{actual_inner}` on field `{}`",
                            expected_inner.unwrap_or("<unknown>"),
                            field.full_name()
                        ));
                    }
                }
            }
        }
        _ => {}
    }

    None
}

/// Check if field-level rules contain CEL expressions, recursively descending
/// into `repeated.items`, `map.keys`, and `map.values` so nested CEL rules
/// (`repeated.items.cel`, `map.values.cel_expression`, …) are detected at
/// capability time rather than being silently dropped by codegen.
fn has_cel_field_rules(rules: &FieldRules) -> bool {
    if !rules.cel.is_empty() || !rules.cel_expression.is_empty() {
        return true;
    }
    match rules.r#type.as_ref() {
        Some(field_rules::Type::Repeated(r)) => r.items.as_deref().is_some_and(has_cel_field_rules),
        Some(field_rules::Type::Map(r)) => {
            r.keys.as_deref().is_some_and(has_cel_field_rules)
                || r.values.as_deref().is_some_and(has_cel_field_rules)
        }
        _ => false,
    }
}

/// Check if a field has predefined CEL rules attached to any extension of
/// its active rule message (e.g., a user-declared
/// `extend buf.validate.StringRules { optional bool ascii_only = 1234
///   [(buf.validate.predefined).cel = ...]; }`).
///
/// Mirrors runtime `process_predefined_rules` so codegen routes any field
/// carrying user predefined CEL to the runtime validator. The walk is
/// recursive: `repeated.items` and `map.{keys, values}` are inspected too,
/// so nested-container predefined rules are not silently dropped.
fn has_predefined_cel(field: &FieldDescriptor, pool: &DescriptorPool) -> bool {
    let Some(field_ext) = pool.get_extension_by_name("buf.validate.field") else {
        return false;
    };
    let Some(predefined_ext) = pool.get_extension_by_name("buf.validate.predefined") else {
        return false;
    };
    let options = field.options();
    if !options.has_extension(&field_ext) {
        return false;
    }
    let field_rules_value = options.get_extension(&field_ext);
    let Some(field_rules_dyn) = field_rules_value.as_message() else {
        return false;
    };
    field_rules_have_predefined_cel(field_rules_dyn, &predefined_ext, pool)
}

/// Recursive helper: walks a `FieldRules` `DynamicMessage`, including the
/// inner `repeated.items` and `map.{keys, values}` `FieldRules`, looking
/// for any extension whose descriptor carries `buf.validate.predefined`
/// with a non-empty CEL expression.
fn field_rules_have_predefined_cel(
    rules: &DynamicMessage,
    predefined_ext: &ExtensionDescriptor,
    pool: &DescriptorPool,
) -> bool {
    let Some((rule_field, rule_message)) = active_rule_message(rules) else {
        return false;
    };
    let Ok(reparsed) = reparse_with_pool(&rule_message, pool) else {
        return false;
    };

    for (ext_desc, _value) in reparsed.extensions() {
        if extension_carries_predefined_cel(&ext_desc, predefined_ext) {
            return true;
        }
    }

    // Recurse into nested container rules so a `string.[ascii_only] = true`
    // attached via `repeated.items.string` still routes its parent message
    // to runtime.
    let nested = match rule_field.name() {
        "repeated" => extract_inner_rules(&reparsed, "items"),
        "map" => {
            // Either keys or values may carry predefined CEL.
            if let Some(keys) = extract_inner_rules(&reparsed, "keys") {
                if field_rules_have_predefined_cel(&keys, predefined_ext, pool) {
                    return true;
                }
            }
            extract_inner_rules(&reparsed, "values")
        }
        _ => None,
    };

    if let Some(inner) = nested {
        if field_rules_have_predefined_cel(&inner, predefined_ext, pool) {
            return true;
        }
    }

    false
}

/// Find the `type` oneof's active variant on a `FieldRules` dynamic message
/// and return its descriptor plus the inner `StringRules`/`Int32Rules`/etc.
fn active_rule_message(
    field_rules_dynamic: &DynamicMessage,
) -> Option<(FieldDescriptor, DynamicMessage)> {
    let descriptor = field_rules_dynamic.descriptor();
    let type_oneof = descriptor
        .oneofs()
        .find(|oneof: &prost_reflect::OneofDescriptor| oneof.name() == "type")?;
    for field in type_oneof.fields() {
        if !field_rules_dynamic.has_field(&field) {
            continue;
        }
        let value = field_rules_dynamic.get_field(&field);
        if let Some(message) = value.as_message() {
            return Some((field, message.clone()));
        }
    }
    None
}

/// Re-encode then decode a dynamic message using the supplied descriptor
/// pool so user-defined extensions on the message's type (e.g., an extension
/// of `StringRules`) become visible via `extensions()` rather than sitting
/// in unknown fields.
fn reparse_with_pool(
    message: &DynamicMessage,
    pool: &DescriptorPool,
) -> Result<DynamicMessage, Error> {
    let descriptor = message.descriptor();
    let full_name = descriptor.full_name();
    let Some(target) = pool.get_message_by_name(full_name) else {
        return Ok(message.clone());
    };
    let encoded = message.encode_to_vec();
    DynamicMessage::decode(target, encoded.as_slice())
        .map_err(|e| Error::ConstraintDecode(e.to_string()))
}

/// Pull an inner `FieldRules` (as a dynamic message) from a container rules
/// message — used to descend into `RepeatedRules.items` /
/// `MapRules.{keys, values}`.
fn extract_inner_rules(parent: &DynamicMessage, field_name: &str) -> Option<DynamicMessage> {
    let field_desc = parent.descriptor().get_field_by_name(field_name)?;
    if !parent.has_field(&field_desc) {
        return None;
    }
    let value = parent.get_field(&field_desc);
    value.as_message().cloned()
}

fn extension_carries_predefined_cel(
    extension: &ExtensionDescriptor,
    predefined_ext: &ExtensionDescriptor,
) -> bool {
    let options = extension.options();
    if !options.has_extension(predefined_ext) {
        return false;
    }
    let value = options.get_extension(predefined_ext);
    let Some(predefined_msg) = value.as_message() else {
        return false;
    };
    let Ok(predefined) =
        predefined_msg.transcode_to::<prost_protovalidate_types::PredefinedRules>()
    else {
        return false;
    };
    predefined.cel.iter().any(|r| {
        r.expression
            .as_ref()
            .is_some_and(|expr: &String| !expr.is_empty())
    })
}

/// Whether `repeated.unique = true` applies to an element kind that the
/// codegen cannot handle:
///
/// * `Message` / `Group` (prost message types don't derive `Hash`)
///
/// `Float` / `Double` (`f32`/`f64`) are handled via the canonical-bits
/// path in [`rules::repeated::generate`], matching the runtime's
/// `canonical_f32_bits` / `canonical_f64_bits` semantics. Other scalar
/// kinds (bool, all integer widths, string, bytes, enum) hash directly.
fn repeated_unique_unsupported(rules: &FieldRules, field: &FieldDescriptor) -> bool {
    use prost_reflect::Kind;
    let Some(field_rules::Type::Repeated(r)) = rules.r#type.as_ref() else {
        return false;
    };
    if r.unique != Some(true) {
        return false;
    }
    matches!(field.kind(), Kind::Message(_))
}

fn join_rule_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_string()
    } else {
        format!("{prefix}.{segment}")
    }
}

fn validate_pattern(pattern: &str, rule_path: &str) -> Option<InvalidRegex> {
    match Regex::new(pattern) {
        Ok(_) => None,
        Err(err) => Some(InvalidRegex {
            rule_path: rule_path.to_string(),
            pattern: pattern.to_string(),
            cause: err.to_string(),
        }),
    }
}

fn find_invalid_regex_with_prefix(rules: &FieldRules, prefix: &str) -> Option<InvalidRegex> {
    let Some(type_rules) = &rules.r#type else {
        return None;
    };

    match type_rules {
        field_rules::Type::String(string_rules) => string_rules
            .pattern
            .as_deref()
            .and_then(|p| validate_pattern(p, &join_rule_path(prefix, "string.pattern"))),
        field_rules::Type::Bytes(bytes_rules) => bytes_rules
            .pattern
            .as_deref()
            .and_then(|p| validate_pattern(p, &join_rule_path(prefix, "bytes.pattern"))),
        field_rules::Type::Repeated(repeated_rules) => {
            repeated_rules.items.as_deref().and_then(|items| {
                find_invalid_regex_with_prefix(items, &join_rule_path(prefix, "repeated.items"))
            })
        }
        field_rules::Type::Map(map_rules) => map_rules
            .keys
            .as_deref()
            .and_then(|keys| {
                find_invalid_regex_with_prefix(keys, &join_rule_path(prefix, "map.keys"))
            })
            .or_else(|| {
                map_rules.values.as_deref().and_then(|values| {
                    find_invalid_regex_with_prefix(values, &join_rule_path(prefix, "map.values"))
                })
            }),
        _ => None,
    }
}

fn find_invalid_regex(rules: &FieldRules) -> Option<InvalidRegex> {
    find_invalid_regex_with_prefix(rules, "")
}

/// Generate validation code for a single field.
fn generate_field_check(
    field: &FieldDescriptor,
    fr: &FieldRules,
    msg_rules: Option<&MessageRules>,
    pool: &DescriptorPool,
    naming: &NamingContext,
) -> Result<Option<TokenStream>, Error> {
    let proto_name = field.name().to_string();
    let rust_name = naming::field_to_rust_name(&proto_name);
    let field_ident = quote::format_ident!("{}", rust_name);

    let explicit_ignore = ignore_mode_of(fr.ignore);

    // Runtime treats two cases as implicitly `IGNORE_IF_ZERO_VALUE` when the
    // user has not set `ignore` explicitly:
    //
    // 1. Fields listed in a `MessageRules.oneof` virtual oneof — see
    //    `is_part_of_message_oneof` in
    //    `crates/prost-protovalidate/src/validator/builder.rs`.
    // 2. `required = true` on bare-`T` scalar storage (proto3 implicit
    //    scalars and proto2 `required` scalars). For these, runtime's
    //    `FieldEval::evaluate_message`
    //    (`crates/prost-protovalidate/src/validator/evaluator/field.rs`)
    //    returns the `required` violation early when the field is unset
    //    (i.e. equals its zero value), skipping any inner rules. Codegen
    //    has separate required-check and inner-rule blocks, so we mirror
    //    runtime by wrapping the inner block in an `IGNORE_IF_ZERO_VALUE`
    //    guard — non-default values still validate normally, default
    //    values skip the inner block while the required check fires.
    //
    // For presence fields (Option<T> storage) and lists/maps, the inner
    // rule generators already self-guard (`if let Some(...)` / iterate),
    // so the upgrade is not needed.
    let is_bare_t_scalar = !field.is_list()
        && !field.is_map()
        && field.kind().as_message().is_none()
        && (!field.supports_presence() || field.is_required());
    let needs_implicit_if_zero = explicit_ignore == Ignore::Unspecified
        && (is_part_of_message_oneof(msg_rules, field)
            || (fr.required == Some(true) && is_bare_t_scalar));
    let ignore = if needs_implicit_if_zero {
        Ignore::IfZeroValue
    } else {
        explicit_ignore
    };

    // IGNORE_ALWAYS: skip all validation
    if ignore == Ignore::Always {
        return Ok(None);
    }

    // Required check runs outside the ignore guard — a required field must
    // be present regardless of the ignore mode.
    let required_check = if fr.required == Some(true) {
        Some(generate_required_check(field, &field_ident, &proto_name))
    } else {
        None
    };

    // Type-specific rules are subject to the ignore guard.
    let mut type_checks = Vec::new();
    if let Some(type_rules) = &fr.r#type {
        type_checks =
            rules::generate_type_rules(type_rules, field, &field_ident, &proto_name, pool, naming)?;
    }

    if required_check.is_none() && type_checks.is_empty() {
        return Ok(None);
    }

    let mut output = Vec::new();
    if let Some(req) = required_check {
        output.push(req);
    }
    if !type_checks.is_empty() {
        let body = quote! { #(#type_checks)* };
        output.push(wrap_with_ignore_guard(field, &field_ident, ignore, body));
    }

    Ok(Some(quote! { #(#output)* }))
}

/// Generate a required field check.
fn generate_required_check(
    field: &FieldDescriptor,
    field_ident: &proc_macro2::Ident,
    proto_name: &str,
) -> TokenStream {
    if field.is_list() || field.is_map() {
        // Repeated/map fields: required means non-empty
        quote! {
            if self.#field_ident.is_empty() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "required", "value is required",
                ));
            }
        }
    } else if field.kind().as_message().is_some()
        || (field.supports_presence() && !field.is_required())
    {
        // prost stores `Option<T>`: message fields always (regardless of label),
        // and presence-having non-`required` scalars (proto3 `optional`, proto2
        // `optional`, synthetic-oneof members). `required = true` checks
        // `is_some()`.
        quote! {
            if self.#field_ident.is_none() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "required", "value is required",
                ));
            }
        }
    } else {
        // Bare `T` in prost storage — proto3 implicit scalars AND proto2
        // `required` scalars (the latter has `supports_presence() == true` but
        // `is_required() == true`, so prost still emits a bare field; see
        // `field_storage_is_option_scalar` in `rules/mod.rs`). Runtime emits a
        // `required` violation when the value equals its type's zero (the only
        // "absent" state for bare-T storage). Mirror that here using the same
        // default-value predicate as `IGNORE_IF_ZERO_VALUE`, negated so the
        // violation fires only for default-valued fields.
        let non_default = generate_default_check(field, field_ident);
        quote! {
            if !(#non_default) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "required", "value is required",
                ));
            }
        }
    }
}

/// Wrap field checks with an ignore-mode guard.
///
/// Mirrors runtime semantics in [`validator/evaluator/field.rs`](../prost-protovalidate/src/validator/evaluator/field.rs):
/// - `IGNORE_ALWAYS`: drop the checks entirely.
/// - `IGNORE_IF_ZERO_VALUE` without presence: validate iff the field is not
///   the zero value of its type (see [`generate_default_check`]).
/// - Otherwise (`IGNORE_UNSPECIFIED`, or `IGNORE_IF_ZERO_VALUE` on a presence
///   field): pass the body through. The body is always built by a generator
///   that already wraps presence types in `if let Some(ref _val) = self.<field>
///   { … }` (see [`rules::generate_type_rules`]), so an outer `is_some()`
///   check would be a redundant guard the compiler discards.
fn wrap_with_ignore_guard(
    field: &FieldDescriptor,
    field_ident: &proc_macro2::Ident,
    ignore: Ignore,
    body: TokenStream,
) -> TokenStream {
    match ignore {
        Ignore::Always => quote! {},
        Ignore::IfZeroValue if !field_has_presence(field) => {
            let default_check = generate_default_check(field, field_ident);
            quote! {
                if #default_check {
                    #body
                }
            }
        }
        _ => body,
    }
}

/// Generate an expression that is true when the field is NOT the default value.
pub(crate) fn generate_default_check(
    field: &FieldDescriptor,
    field_ident: &proc_macro2::Ident,
) -> TokenStream {
    if field.is_list() || field.is_map() {
        quote! { !self.#field_ident.is_empty() }
    } else {
        use prost_reflect::Kind;
        match field.kind() {
            Kind::Bool => quote! { self.#field_ident },
            Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => {
                quote! { self.#field_ident != 0i32 }
            }
            Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => {
                quote! { self.#field_ident != 0i64 }
            }
            Kind::Uint32 | Kind::Fixed32 => quote! { self.#field_ident != 0u32 },
            Kind::Uint64 | Kind::Fixed64 => quote! { self.#field_ident != 0u64 },
            Kind::Float => quote! { self.#field_ident != 0.0f32 },
            Kind::Double => quote! { self.#field_ident != 0.0f64 },
            Kind::String | Kind::Bytes => quote! { !self.#field_ident.is_empty() },
            Kind::Enum(_) => quote! { self.#field_ident != 0i32 },
            Kind::Message(_) => quote! { self.#field_ident.is_some() },
        }
    }
}

/// Element-level default check used by `repeated.items` / `map.{keys,values}`
/// when their nested `FieldRules.ignore` is `IGNORE_IF_ZERO_VALUE`. Mirrors
/// the singular path in [`generate_default_check`], but parameterised on an
/// arbitrary access expression (e.g. `_item`, `_k`, `_v`) instead of
/// `self.<field>`. Returns `None` for kinds whose zero check is the field's
/// outer presence, which never apply at the element level (lists, maps).
#[allow(clippy::match_same_arms)] // Enum and Int32 share `!= 0i32` semantically but logically distinct.
pub(crate) fn generate_element_default_check(
    kind: &prost_reflect::Kind,
    access: &TokenStream,
) -> Option<TokenStream> {
    use prost_reflect::Kind;
    Some(match kind {
        Kind::Bool => quote! { #access },
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => quote! { #access != 0i32 },
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => quote! { #access != 0i64 },
        Kind::Uint32 | Kind::Fixed32 => quote! { #access != 0u32 },
        Kind::Uint64 | Kind::Fixed64 => quote! { #access != 0u64 },
        Kind::Float => quote! { #access != 0.0f32 },
        Kind::Double => quote! { #access != 0.0f64 },
        Kind::String | Kind::Bytes => quote! { !#access.is_empty() },
        Kind::Enum(_) => quote! { #access != 0i32 },
        Kind::Message(_) => return None,
    })
}

/// Whether a field has presence semantics in prost-generated code.
///
/// Returns `true` for proto3 `optional` fields (synthetic oneof) and message
/// fields, which prost generates as `Option<T>`. Regular proto3 scalars do
/// NOT have presence — prost generates them as bare `T`.
fn field_has_presence(field: &FieldDescriptor) -> bool {
    field.supports_presence()
}

/// Whether the element kind of a repeated or map field is a Google
/// well-known wrapper type (e.g. `Int32Value`). Singular wrapper fields
/// get the dedicated unwrap path in `rules::generate_type_rules`; the
/// repeated/map variants are not yet supported and must be routed to
/// runtime to avoid emitting code that doesn't compile.
fn repeated_or_map_element_is_wkt_wrapper(field: &FieldDescriptor) -> bool {
    let element_msg = if field.is_map() {
        field
            .kind()
            .as_message()
            .and_then(|entry| entry.get_field_by_name("value"))
            .and_then(|v| v.kind().as_message().cloned())
    } else if field.is_list() {
        field.kind().as_message().cloned()
    } else {
        None
    };

    element_msg.is_some_and(|msg| {
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum MessageCapability {
    NoRules,
    Generated,
    RuntimeOnly(String),
}

struct CapabilityAnalyzer<'a> {
    pool: &'a DescriptorPool,
    naming: &'a NamingContext,
    cache: HashMap<String, MessageCapability>,
    visiting: HashSet<String>,
}

impl<'a> CapabilityAnalyzer<'a> {
    fn new(pool: &'a DescriptorPool, naming: &'a NamingContext) -> Self {
        Self {
            pool,
            naming,
            cache: HashMap::new(),
            visiting: HashSet::new(),
        }
    }

    fn capability_for(&mut self, msg: &MessageDescriptor) -> Result<MessageCapability, Error> {
        let full_name = msg.full_name().to_string();

        if let Some(capability) = self.cache.get(&full_name) {
            return Ok(capability.clone());
        }

        // Break recursive cycles optimistically; concrete unsupported rules
        // are still discovered while unwinding the recursion.
        //
        // Invariant: each node in the cycle still runs its own
        // `compute_capability` to completion before its cache entry is
        // written. If any node in the cycle has a `RuntimeOnly` rule, that
        // node's own ascent caches `RuntimeOnly`, and the parent observes
        // the cached value on its second descent (the cache lookup above)
        // — not this optimistic `Generated`. So the only path where this
        // return is the final answer is a cycle in which every participant
        // is genuinely standard-rules-only, which is the correct outcome.
        if self.visiting.contains(&full_name) {
            return Ok(MessageCapability::Generated);
        }

        self.visiting.insert(full_name.clone());
        let capability = self.compute_capability(msg)?;
        self.visiting.remove(&full_name);
        self.cache.insert(full_name, capability.clone());

        Ok(capability)
    }

    #[allow(clippy::too_many_lines)]
    fn compute_capability(&mut self, msg: &MessageDescriptor) -> Result<MessageCapability, Error> {
        // Skip schema/support message namespaces that are not user payload
        // types for generated validation impls.
        if msg.full_name().starts_with("google.protobuf.")
            || msg.full_name().starts_with("buf.validate.")
        {
            return Ok(MessageCapability::NoRules);
        }

        // Messages owned by another crate (via `Builder::extern_path`) live
        // outside this user's crate, so we cannot legally emit `impl
        // prost_protovalidate::Validate for ::other_crate::…` — the trait
        // and the type would both be foreign and Rust's orphan rule rejects
        // the impl. Their owning crate is responsible for validation.
        if self.naming.is_extern(msg.full_name()) {
            return Ok(MessageCapability::NoRules);
        }

        // Synthetic map-entry messages (`<Field>Entry` nested under the
        // parent) don't have a corresponding public Rust type — prost
        // exposes the map as `HashMap<K, V>` instead. Generating an
        // `impl Validate` for them would reference a non-existent type.
        if msg.is_map_entry() {
            return Ok(MessageCapability::NoRules);
        }

        let msg_rules = resolve_message_constraints(msg, self.pool)?;
        if has_cel_message_rules(msg_rules.as_ref()) {
            return Ok(MessageCapability::RuntimeOnly(format!(
                "{} has CEL message rules (cel/cel_expression)",
                msg.full_name()
            )));
        }

        // Virtual oneof (MessageRules.oneof) may list fields that live inside
        // a real proto `oneof` — prost stores those as an enum variant under
        // a single Option<Enum>, not as a struct member named after the field,
        // so the generated `self.field_ident` access wouldn't compile. Route
        // such messages to runtime.
        if let Some(rules) = msg_rules.as_ref() {
            for oneof_rule in &rules.oneof {
                for field_name in &oneof_rule.fields {
                    let Some(fdesc) = msg.get_field_by_name(field_name) else {
                        continue;
                    };
                    if fdesc.containing_oneof().is_some_and(|o| !o.is_synthetic()) {
                        return Ok(MessageCapability::RuntimeOnly(format!(
                            "{}.{} is referenced by a virtual oneof but lives inside a real \
                             proto oneof (codegen cannot synthesise variant access)",
                            msg.full_name(),
                            field_name,
                        )));
                    }
                }
            }
        }

        let mut has_any_rules = msg_rules.is_some() || has_required_oneof_rules(msg, self.pool)?;

        for field in msg.fields() {
            let field_rules = resolve_field_constraints(&field, self.pool)?;
            let ignore = effective_ignore_mode(field_rules.as_ref());

            // Fields inside a real proto `oneof` are stored as enum variants
            // under a single `Option<Enum>` member — there is no struct field
            // named after the variant. Direct field-level rules on such a
            // field cannot be expressed by codegen (we'd emit `self.<name>`
            // accesses that don't exist) so route the parent to runtime.
            if field_rules.is_some() && field.containing_oneof().is_some_and(|o| !o.is_synthetic())
            {
                return Ok(MessageCapability::RuntimeOnly(format!(
                    "{}.{} has direct field rules but lives inside a real proto oneof \
                     (codegen cannot synthesise variant access)",
                    msg.full_name(),
                    field.name()
                )));
            }

            if let Some(rules) = field_rules.as_ref() {
                has_any_rules = true;

                if let Some(reason) = rule_type_mismatch_reason(rules, &field) {
                    return Ok(MessageCapability::RuntimeOnly(reason));
                }

                if has_cel_field_rules(rules) {
                    return Ok(MessageCapability::RuntimeOnly(format!(
                        "{}.{} has CEL rules (cel/cel_expression)",
                        msg.full_name(),
                        field.name()
                    )));
                }

                if has_predefined_cel(&field, self.pool) {
                    return Ok(MessageCapability::RuntimeOnly(format!(
                        "{}.{} has predefined CEL rules",
                        msg.full_name(),
                        field.name()
                    )));
                }

                if let Some(invalid) = find_invalid_regex(rules) {
                    return Ok(MessageCapability::RuntimeOnly(format!(
                        "{}.{} has invalid regex at `{}`: pattern `{}` ({})",
                        msg.full_name(),
                        field.name(),
                        invalid.rule_path,
                        invalid.pattern,
                        invalid.cause
                    )));
                }

                // `repeated.unique = true` on float/double/message element
                // kinds can't use a plain `HashSet` (no `Eq`/`Hash`). The
                // runtime applies a canonical-bits encoding for floats and
                // treats messages as unsupported (always-not-unique). Route
                // those shapes to runtime for parity.
                if repeated_unique_unsupported(rules, &field) {
                    return Ok(MessageCapability::RuntimeOnly(format!(
                        "{}.{} uses `repeated.unique` on a non-hashable element \
                         (float/double/message); codegen routes to runtime",
                        msg.full_name(),
                        field.name()
                    )));
                }
            }

            // Repeated/map of a WKT wrapper type (Int32Value, StringValue, …)
            // would need bespoke per-element unwrap; the singular WKT path in
            // `rules::generate_type_rules` isn't applicable to `Vec<T>` /
            // `HashMap<_, T>`. Route those to runtime.
            if (field.is_list() || field.is_map()) && repeated_or_map_element_is_wkt_wrapper(&field)
            {
                return Ok(MessageCapability::RuntimeOnly(format!(
                    "{}.{} is a {} of a Google well-known wrapper type \
                     (per-element wrapper unwrap is not supported in codegen)",
                    msg.full_name(),
                    field.name(),
                    if field.is_map() { "map" } else { "repeated" },
                )));
            }

            if ignore == Ignore::Always {
                continue;
            }

            let Some(info) = nested_validation_info(&field)? else {
                continue;
            };

            let nested_capability = self.capability_for(&info.message)?;
            match nested_capability {
                MessageCapability::NoRules => {}
                MessageCapability::Generated => {
                    if field.containing_oneof().is_some_and(|o| !o.is_synthetic()) {
                        return Ok(MessageCapability::RuntimeOnly(format!(
                            "{}.{} is a nested message field inside a real oneof \
                             (nested codegen for oneof variants is not supported)",
                            msg.full_name(),
                            field.name()
                        )));
                    }
                    has_any_rules = true;
                }
                MessageCapability::RuntimeOnly(reason) => {
                    return Ok(MessageCapability::RuntimeOnly(format!(
                        "{}.{} depends on nested message `{}` that requires runtime validation: {}",
                        msg.full_name(),
                        field.name(),
                        info.message.full_name(),
                        reason
                    )));
                }
            }
        }

        Ok(if has_any_rules {
            MessageCapability::Generated
        } else {
            MessageCapability::NoRules
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NestedValidationKind {
    Singular,
    Repeated,
    /// Map value, parameterised by the map's key kind so codegen can emit
    /// the type-correct `Violation::prepend_*_key` call.
    MapValue(prost_reflect::Kind),
}

#[derive(Debug, Clone)]
struct NestedValidationInfo {
    kind: NestedValidationKind,
    message: MessageDescriptor,
}

fn nested_validation_info(field: &FieldDescriptor) -> Result<Option<NestedValidationInfo>, Error> {
    if field.is_map() {
        let field_kind = field.kind();
        let Some(entry) = field_kind.as_message() else {
            return Ok(None);
        };
        let Some(key_field) = entry.get_field_by_name("key") else {
            return Err(Error::Codegen(format!(
                "map field {} is missing synthetic `key` descriptor",
                field.full_name()
            )));
        };
        let Some(value_field) = entry.get_field_by_name("value") else {
            return Err(Error::Codegen(format!(
                "map field {} is missing synthetic `value` descriptor",
                field.full_name()
            )));
        };
        let value_kind = value_field.kind();
        let Some(message) = value_kind.as_message() else {
            return Ok(None);
        };
        return Ok(Some(NestedValidationInfo {
            kind: NestedValidationKind::MapValue(key_field.kind()),
            message: message.clone(),
        }));
    }

    let field_kind = field.kind();
    let Some(message) = field_kind.as_message() else {
        return Ok(None);
    };

    let kind = if field.is_list() {
        NestedValidationKind::Repeated
    } else {
        NestedValidationKind::Singular
    };

    Ok(Some(NestedValidationInfo {
        kind,
        message: message.clone(),
    }))
}

/// Emit the `Violation::prepend_*` call appropriate for a map key kind.
///
/// Map keys are restricted to scalar types in protobuf; this dispatch
/// produces a typed `prepend_string_key` / `prepend_int_key` /
/// `prepend_uint_key` / `prepend_bool_key` so paths match runtime
/// formatting exactly (including JSON-escaped string keys).
fn map_key_prepend_call(
    proto_name: &str,
    violation_ident: &proc_macro2::Ident,
    key_kind: &prost_reflect::Kind,
) -> TokenStream {
    use prost_reflect::Kind;
    match *key_kind {
        Kind::String => quote! {
            #violation_ident.prepend_string_key(#proto_name, _k.as_str());
        },
        Kind::Bool => quote! {
            #violation_ident.prepend_bool_key(#proto_name, *_k);
        },
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => quote! {
            #violation_ident.prepend_int_key(#proto_name, ::core::convert::From::from(*_k));
        },
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => quote! {
            #violation_ident.prepend_int_key(#proto_name, *_k);
        },
        Kind::Uint32 | Kind::Fixed32 => quote! {
            #violation_ident.prepend_uint_key(#proto_name, ::core::convert::From::from(*_k));
        },
        Kind::Uint64 | Kind::Fixed64 => quote! {
            #violation_ident.prepend_uint_key(#proto_name, *_k);
        },
        // Float/Double/Bytes/Message/Enum/Group are not valid proto map
        // key types; fall back to the generic string prepend to keep
        // codegen from refusing the message outright.
        _ => quote! {
            #violation_ident.prepend_field_path(#proto_name);
        },
    }
}

fn has_required_oneof_rules(msg: &MessageDescriptor, pool: &DescriptorPool) -> Result<bool, Error> {
    for oneof in msg.oneofs() {
        if oneof.is_synthetic() {
            continue;
        }
        if resolve_oneof_required(&oneof, pool)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn effective_ignore_mode(rules: Option<&FieldRules>) -> Ignore {
    ignore_mode_of(rules.and_then(|r| r.ignore))
}

/// Generate recursive validation for a message-typed field.
///
/// Produces a `.validate()` call on nested messages that have their own
/// `Validate` impl, prepending the field path to any violations.
fn generate_nested_validation(
    field: &FieldDescriptor,
    field_rules: Option<&FieldRules>,
    analyzer: &mut CapabilityAnalyzer<'_>,
) -> Result<Option<TokenStream>, Error> {
    if effective_ignore_mode(field_rules) == Ignore::Always {
        return Ok(None);
    }

    // Skip fields in real oneofs (handled by oneof checks)
    if field.containing_oneof().is_some_and(|o| !o.is_synthetic()) {
        return Ok(None);
    }

    let Some(info) = nested_validation_info(field)? else {
        return Ok(None);
    };

    match analyzer.capability_for(&info.message)? {
        MessageCapability::NoRules => return Ok(None),
        MessageCapability::RuntimeOnly(reason) => {
            return Err(Error::Codegen(format!(
                "nested field {} depends on runtime-only message {}: {}",
                field.full_name(),
                info.message.full_name(),
                reason
            )));
        }
        MessageCapability::Generated => {}
    }

    let proto_name = field.name().to_string();
    let rust_name = naming::field_to_rust_name(&proto_name);
    let field_ident = quote::format_ident!("{}", rust_name);

    match info.kind {
        NestedValidationKind::Repeated => Ok(Some(quote! {
            for (_idx, _item) in self.#field_ident.iter().enumerate() {
                if let ::core::result::Result::Err(_e) =
                    ::prost_protovalidate::Validate::validate(_item)
                {
                    let _idx_u64: u64 = _idx as u64;
                    for mut _viol in _e.into_violations() {
                        _viol.prepend_index(#proto_name, _idx_u64);
                        violations.push(_viol);
                    }
                }
            }
        })),
        NestedValidationKind::Singular => Ok(Some(quote! {
            if let ::core::option::Option::Some(ref _nested) = self.#field_ident {
                if let ::core::result::Result::Err(_e) =
                    ::prost_protovalidate::Validate::validate(_nested)
                {
                    for mut _viol in _e.into_violations() {
                        _viol.prepend_field_path(#proto_name);
                        violations.push(_viol);
                    }
                }
            }
        })),
        NestedValidationKind::MapValue(key_kind) => {
            let viol_ident = quote::format_ident!("_viol");
            let prepend = map_key_prepend_call(&proto_name, &viol_ident, &key_kind);
            Ok(Some(quote! {
                for (_k, _v) in &self.#field_ident {
                    if let ::core::result::Result::Err(_e) =
                        ::prost_protovalidate::Validate::validate(_v)
                    {
                        for mut _viol in _e.into_violations() {
                            #prepend
                            violations.push(_viol);
                        }
                    }
                }
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_protovalidate_types::{
        BytesRules, MapRules, RepeatedRules, Rule, StringRules, field_rules,
    };

    #[test]
    fn cel_field_rules_empty_is_false() {
        let rules = FieldRules::default();
        assert!(!has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_field_rules_with_cel_is_true() {
        let rules = FieldRules {
            cel: vec![Rule {
                id: Some("test".to_string()),
                expression: Some("this > 0".to_string()),
                message: None,
            }],
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_field_rules_with_cel_expression_is_true() {
        let rules = FieldRules {
            cel_expression: vec!["this > 0".to_string()],
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    fn cel_rule() -> Rule {
        Rule {
            id: Some("nested".to_string()),
            expression: Some("this > 0".to_string()),
            message: None,
        }
    }

    #[test]
    fn cel_in_repeated_items_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Repeated(Box::new(RepeatedRules {
                items: Some(Box::new(FieldRules {
                    cel: vec![cel_rule()],
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_expression_in_repeated_items_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Repeated(Box::new(RepeatedRules {
                items: Some(Box::new(FieldRules {
                    cel_expression: vec!["this > 0".to_string()],
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_in_map_keys_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Map(Box::new(MapRules {
                keys: Some(Box::new(FieldRules {
                    cel: vec![cel_rule()],
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_in_map_values_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Map(Box::new(MapRules {
                values: Some(Box::new(FieldRules {
                    cel: vec![cel_rule()],
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_expression_in_map_values_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Map(Box::new(MapRules {
                values: Some(Box::new(FieldRules {
                    cel_expression: vec!["this != ''".to_string()],
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };
        assert!(has_cel_field_rules(&rules));
    }

    #[test]
    fn no_cel_in_repeated_items_with_only_standard_rules() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Repeated(Box::new(RepeatedRules {
                items: Some(Box::new(FieldRules {
                    r#type: Some(field_rules::Type::String(StringRules {
                        min_len: Some(1),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };
        assert!(!has_cel_field_rules(&rules));
    }

    #[test]
    fn cel_message_rules_empty_is_false() {
        assert!(!has_cel_message_rules(None));
        let rules = MessageRules::default();
        assert!(!has_cel_message_rules(Some(&rules)));
    }

    #[test]
    fn cel_message_rules_with_cel_is_true() {
        let rules = MessageRules {
            cel: vec![Rule {
                id: Some("test".to_string()),
                expression: Some("this.a > this.b".to_string()),
                message: None,
            }],
            ..Default::default()
        };
        assert!(has_cel_message_rules(Some(&rules)));
    }

    #[test]
    fn cel_message_rules_with_cel_expression_is_true() {
        let rules = MessageRules {
            cel_expression: vec!["this.a > this.b".to_string()],
            ..Default::default()
        };
        assert!(has_cel_message_rules(Some(&rules)));
    }

    #[test]
    fn invalid_regex_in_string_rules_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::String(StringRules {
                pattern: Some("[".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let invalid = find_invalid_regex(&rules).expect("expected invalid regex");
        assert_eq!(invalid.rule_path, "string.pattern");
    }

    #[test]
    fn invalid_regex_in_bytes_rules_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Bytes(BytesRules {
                pattern: Some("*".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let invalid = find_invalid_regex(&rules).expect("expected invalid regex");
        assert_eq!(invalid.rule_path, "bytes.pattern");
    }

    #[test]
    fn invalid_regex_in_repeated_item_rules_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Repeated(Box::new(RepeatedRules {
                items: Some(Box::new(FieldRules {
                    r#type: Some(field_rules::Type::String(StringRules {
                        pattern: Some("[".to_string()),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };

        let invalid = find_invalid_regex(&rules).expect("expected invalid regex");
        assert_eq!(invalid.rule_path, "repeated.items.string.pattern");
    }

    #[test]
    fn invalid_regex_in_map_value_rules_detected() {
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Map(Box::new(MapRules {
                values: Some(Box::new(FieldRules {
                    r#type: Some(field_rules::Type::String(StringRules {
                        pattern: Some("[".to_string()),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            }))),
            ..Default::default()
        };

        let invalid = find_invalid_regex(&rules).expect("expected invalid regex");
        assert_eq!(invalid.rule_path, "map.values.string.pattern");
    }
}
