//! Normalize protobuf Edition 2023 descriptors to proto3 format.
//!
//! `prost-reflect` 0.16 does not support `syntax = "editions"` and panics
//! when decoding such descriptors. This module rewrites Edition 2023
//! descriptors at the wire level so that they are valid proto3, preserving
//! all extension and option bytes.

use std::collections::HashMap;

use prost::encoding::{WireType, decode_key, decode_varint, encode_key, encode_varint};

/// `FeatureSet.field_presence` values.
const FIELD_PRESENCE_EXPLICIT: i32 = 1;
const FIELD_PRESENCE_LEGACY_REQUIRED: i32 = 3;

/// `FeatureSet.message_encoding` values.
const MESSAGE_ENCODING_DELIMITED: i32 = 2;

/// FieldDescriptorProto.Label values.
const LABEL_OPTIONAL: i32 = 1;
const LABEL_REQUIRED: i32 = 2;
const LABEL_REPEATED: i32 = 3;

/// FieldDescriptorProto.Type values.
const TYPE_MESSAGE: i32 = 11;
const TYPE_GROUP: i32 = 10;

// Wire format tag numbers for FileDescriptorProto.
mod file_tags {
    pub const MESSAGE_TYPE: u32 = 4;
    pub const EXTENSION: u32 = 7;
    pub const OPTIONS: u32 = 8;
    pub const SYNTAX: u32 = 12;
    pub const EDITION: u32 = 14;
}

// Wire format tag numbers for DescriptorProto.
mod message_tags {
    pub const FIELD: u32 = 2;
    pub const NESTED_TYPE: u32 = 3;
    pub const EXTENSION: u32 = 6;
    pub const ONEOF_DECL: u32 = 8;
}

// Wire format tag numbers for FieldDescriptorProto.
mod field_tags {
    pub const NAME: u32 = 1;
    pub const LABEL: u32 = 4;
    pub const TYPE: u32 = 5;
    pub const OPTIONS: u32 = 8;
    pub const ONEOF_INDEX: u32 = 9;
    pub const PROTO3_OPTIONAL: u32 = 17;
}

// Wire format tag numbers for FieldOptions.
mod field_option_tags {
    pub const FEATURES: u32 = 21;
}

// Wire format tag numbers for FeatureSet.
mod feature_tags {
    pub const FIELD_PRESENCE: u32 = 1;
    pub const MESSAGE_ENCODING: u32 = 5;
}

// Wire format tag numbers for FileOptions / MessageOptions.
mod option_tags {
    pub const FEATURES: u32 = 50;
}

/// Normalize a `FileDescriptorSet` so that any Edition 2023 files are
/// rewritten as `proto3`. Returns the original bytes unchanged if no
/// edition files are detected.
#[must_use]
pub fn normalize_edition_descriptor_set(bytes: &[u8]) -> Vec<u8> {
    let mut cursor = bytes;
    let mut has_editions = false;

    // Quick scan: do any entries use editions?
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return bytes.to_vec();
        };
        match (tag, wire_type) {
            (1, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                if file_has_editions_syntax(&cursor[..len]) {
                    has_editions = true;
                    break;
                }
                cursor = &cursor[len..];
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    return bytes.to_vec();
                }
            }
        }
    }

    if !has_editions {
        return bytes.to_vec();
    }

    // Full rewrite pass.
    let mut cursor = bytes;
    let mut out = Vec::with_capacity(bytes.len());

    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return bytes.to_vec();
        };
        if let (1, WireType::LengthDelimited) = (tag, wire_type) {
            let Ok(len) = decode_len(&mut cursor) else {
                return bytes.to_vec();
            };
            if cursor.len() < len {
                return bytes.to_vec();
            }
            let file_bytes = &cursor[..len];
            cursor = &cursor[len..];

            let normalized = normalize_file_descriptor(file_bytes);
            encode_key(1, WireType::LengthDelimited, &mut out);
            encode_varint(normalized.len() as u64, &mut out);
            out.extend_from_slice(&normalized);
        } else {
            let start = cursor;
            if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                return bytes.to_vec();
            }
            // Re-encode the tag + data.
            encode_key(tag, wire_type, &mut out);
            out.extend_from_slice(&start[..start.len() - cursor.len()]);
        }
    }

    out
}

/// Check whether a `FileDescriptorProto` has `syntax = "editions"`.
fn file_has_editions_syntax(bytes: &[u8]) -> bool {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return false;
        };
        match (tag, wire_type) {
            (file_tags::SYNTAX, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return false;
                };
                if cursor.len() < len {
                    return false;
                }
                return &cursor[..len] == b"editions";
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    return false;
                }
            }
        }
    }
    false
}

/// Extract a varint field from a `FeatureSet` message by tag number.
#[allow(clippy::cast_possible_truncation)] // Protobuf enum values fit in i32.
fn extract_feature_set_varint(bytes: &[u8], field_tag: u32) -> i32 {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            break;
        };
        match (tag, wire_type) {
            (t, WireType::Varint) if t == field_tag => {
                let Ok(v) = decode_varint(&mut cursor) else {
                    break;
                };
                return v as i32;
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    break;
                }
            }
        }
    }
    0
}

/// Extract a feature varint from an options message (`FileOptions` / `MessageOptions` / `FieldOptions`).
///
/// Scans for the `features` submessage at `features_tag`, then reads
/// the specified `field_tag` varint from the `FeatureSet` inside.
fn extract_feature_varint(options_bytes: &[u8], features_tag: u32, field_tag: u32) -> i32 {
    let mut cursor = options_bytes;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            break;
        };
        match (tag, wire_type) {
            (t, WireType::LengthDelimited) if t == features_tag => {
                let Ok(len) = decode_len(&mut cursor) else {
                    break;
                };
                if cursor.len() < len {
                    break;
                }
                let feature_set = &cursor[..len];
                let val = extract_feature_set_varint(feature_set, field_tag);
                if val != 0 {
                    return val;
                }
                cursor = &cursor[len..];
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    break;
                }
            }
        }
    }
    0
}

/// Extract a `FeatureSet` field value from file-level options.
///
/// Scans `FileDescriptorProto` bytes for the options submessage (tag 8),
/// then reads the specified feature field. Returns `0` if not found.
fn extract_file_level_feature(bytes: &[u8], feature_field_tag: u32) -> i32 {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            break;
        };
        match (tag, wire_type) {
            (file_tags::OPTIONS, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    break;
                };
                if cursor.len() < len {
                    break;
                }
                let options_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let val =
                    extract_feature_varint(options_bytes, option_tags::FEATURES, feature_field_tag);
                if val != 0 {
                    return val;
                }
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    break;
                }
            }
        }
    }
    0
}

/// Normalize a single `FileDescriptorProto`.
/// If `syntax != "editions"`, returns the bytes unchanged.
fn normalize_file_descriptor(bytes: &[u8]) -> Vec<u8> {
    if !file_has_editions_syntax(bytes) {
        return bytes.to_vec();
    }

    let presence = extract_file_level_feature(bytes, feature_tags::FIELD_PRESENCE);
    let file_default_presence = if presence != 0 {
        presence
    } else {
        FIELD_PRESENCE_EXPLICIT
    };
    let file_default_encoding = extract_file_level_feature(bytes, feature_tags::MESSAGE_ENCODING);

    let mut cursor = bytes;
    let mut out = Vec::with_capacity(bytes.len());

    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return bytes.to_vec();
        };

        match (tag, wire_type) {
            // Rewrite syntax.
            (file_tags::SYNTAX, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                cursor = &cursor[len..];
                // Write "proto3" instead.
                encode_key(file_tags::SYNTAX, WireType::LengthDelimited, &mut out);
                encode_varint(6, &mut out); // len("proto3")
                out.extend_from_slice(b"proto3");
            }
            // Strip edition field (tag 14).
            (file_tags::EDITION, WireType::Varint) => {
                let Ok(_) = decode_varint(&mut cursor) else {
                    return bytes.to_vec();
                };
                // Drop this field.
            }
            // Normalize message_type.
            (file_tags::MESSAGE_TYPE, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                let msg_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let normalized = normalize_message_descriptor(
                    msg_bytes,
                    file_default_presence,
                    file_default_encoding,
                );
                encode_key(file_tags::MESSAGE_TYPE, WireType::LengthDelimited, &mut out);
                encode_varint(normalized.len() as u64, &mut out);
                out.extend_from_slice(&normalized);
            }
            // Normalize top-level extension fields.
            (file_tags::EXTENSION, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                let field_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let normalized = normalize_field_descriptor(
                    field_bytes,
                    file_default_presence,
                    file_default_encoding,
                );
                encode_key(file_tags::EXTENSION, WireType::LengthDelimited, &mut out);
                encode_varint(normalized.len() as u64, &mut out);
                out.extend_from_slice(&normalized);
            }
            // Pass through all other fields unchanged.
            _ => {
                let pre = cursor;
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    return bytes.to_vec();
                }
                encode_key(tag, wire_type, &mut out);
                out.extend_from_slice(&pre[..pre.len() - cursor.len()]);
            }
        }
    }

    out
}

/// Normalize a `DescriptorProto` (message type).
#[allow(clippy::too_many_lines)] // Wire-level rewriting requires sequential field processing.
fn normalize_message_descriptor(
    bytes: &[u8],
    parent_presence: i32,
    parent_encoding: i32,
) -> Vec<u8> {
    // Extract message-level feature overrides.
    let msg_presence = extract_message_level_feature(bytes, feature_tags::FIELD_PRESENCE)
        .unwrap_or(parent_presence);
    let msg_encoding = extract_message_level_feature(bytes, feature_tags::MESSAGE_ENCODING)
        .unwrap_or(parent_encoding);

    let mut cursor = bytes;
    let mut out = Vec::with_capacity(bytes.len());
    let mut oneof_count = 0u32;

    // First pass: count existing oneofs.
    {
        let mut scan = bytes;
        while !scan.is_empty() {
            let Ok((tag, wire_type)) = decode_key(&mut scan) else {
                break;
            };
            if tag == message_tags::ONEOF_DECL && wire_type == WireType::LengthDelimited {
                oneof_count += 1;
            }
            if skip_wire_value_simple(&mut scan, wire_type).is_err() {
                break;
            }
        }
    }

    // We need to collect fields that need synthetic oneofs.
    let mut fields_needing_synthetic_oneof = Vec::new();
    let mut field_index = 0u32;

    // Collect field info in a first pass.
    {
        let mut scan = bytes;
        while !scan.is_empty() {
            let Ok((tag, wire_type)) = decode_key(&mut scan) else {
                break;
            };
            if tag == message_tags::FIELD && wire_type == WireType::LengthDelimited {
                let Ok(len) = decode_len(&mut scan) else {
                    break;
                };
                if scan.len() < len {
                    break;
                }
                let field_bytes = &scan[..len];
                scan = &scan[len..];
                let info = analyze_field(field_bytes, msg_presence, msg_encoding);
                if info.needs_proto3_optional && !info.has_oneof_index {
                    fields_needing_synthetic_oneof.push((field_index, info.name.clone()));
                }
                field_index += 1;
            } else if skip_wire_value_simple(&mut scan, wire_type).is_err() {
                break;
            }
        }
    }

    // Build a map of field_index → synthetic oneof index.
    let mut synthetic_oneof_map: HashMap<u32, u32> = HashMap::new();
    for (i, (fi, _)) in fields_needing_synthetic_oneof.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)] // Oneof index fits in u32.
        let idx = i as u32;
        synthetic_oneof_map.insert(*fi, oneof_count + idx);
    }

    // Second pass: rewrite.
    field_index = 0;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return bytes.to_vec();
        };

        match (tag, wire_type) {
            (message_tags::FIELD, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                let field_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let synthetic_oneof = synthetic_oneof_map.get(&field_index).copied();
                let normalized = normalize_field_descriptor_with_oneof(
                    field_bytes,
                    msg_presence,
                    msg_encoding,
                    synthetic_oneof,
                );
                encode_key(message_tags::FIELD, WireType::LengthDelimited, &mut out);
                encode_varint(normalized.len() as u64, &mut out);
                out.extend_from_slice(&normalized);
                field_index += 1;
            }
            (message_tags::NESTED_TYPE, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                let nested_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let normalized =
                    normalize_message_descriptor(nested_bytes, msg_presence, msg_encoding);
                encode_key(
                    message_tags::NESTED_TYPE,
                    WireType::LengthDelimited,
                    &mut out,
                );
                encode_varint(normalized.len() as u64, &mut out);
                out.extend_from_slice(&normalized);
            }
            (message_tags::EXTENSION, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    return bytes.to_vec();
                };
                if cursor.len() < len {
                    return bytes.to_vec();
                }
                let ext_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let normalized = normalize_field_descriptor(ext_bytes, msg_presence, msg_encoding);
                encode_key(message_tags::EXTENSION, WireType::LengthDelimited, &mut out);
                encode_varint(normalized.len() as u64, &mut out);
                out.extend_from_slice(&normalized);
            }
            _ => {
                let pre = cursor;
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    return bytes.to_vec();
                }
                encode_key(tag, wire_type, &mut out);
                out.extend_from_slice(&pre[..pre.len() - cursor.len()]);
            }
        }
    }

    // Append synthetic OneofDescriptorProto entries for proto3_optional fields.
    for (_, name) in &fields_needing_synthetic_oneof {
        let oneof_name = format!("_{name}");
        let mut oneof_bytes = Vec::new();
        // OneofDescriptorProto.name (tag 1)
        encode_key(1, WireType::LengthDelimited, &mut oneof_bytes);
        encode_varint(oneof_name.len() as u64, &mut oneof_bytes);
        oneof_bytes.extend_from_slice(oneof_name.as_bytes());

        encode_key(
            message_tags::ONEOF_DECL,
            WireType::LengthDelimited,
            &mut out,
        );
        encode_varint(oneof_bytes.len() as u64, &mut out);
        out.extend_from_slice(&oneof_bytes);
    }

    out
}

/// Extract a `FeatureSet` field value from message-level options.
///
/// Scans `DescriptorProto` bytes for the `MessageOptions` submessage (tag 7),
/// then reads the specified feature field. Returns `None` if not found.
fn extract_message_level_feature(bytes: &[u8], feature_field_tag: u32) -> Option<i32> {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            break;
        };
        match (tag, wire_type) {
            // MessageOptions is tag 7 in DescriptorProto.
            (7, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    break;
                };
                if cursor.len() < len {
                    break;
                }
                let options_bytes = &cursor[..len];
                cursor = &cursor[len..];
                let val =
                    extract_feature_varint(options_bytes, option_tags::FEATURES, feature_field_tag);
                if val != 0 {
                    return Some(val);
                }
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    break;
                }
            }
        }
    }
    None
}

#[allow(clippy::struct_excessive_bools)] // Wire-format analysis produces independent boolean flags.
struct FieldInfo {
    name: String,
    needs_proto3_optional: bool,
    has_oneof_index: bool,
    is_delimited: bool,
    is_legacy_required: bool,
}

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
// Protobuf field metadata values fit in i32.
fn analyze_field(bytes: &[u8], parent_presence: i32, parent_encoding: i32) -> FieldInfo {
    let mut cursor = bytes;
    let mut name = String::new();
    let mut label = 0i32;
    let mut field_type = 0i32;
    let mut has_oneof_index = false;
    let mut field_presence = 0i32;
    let mut field_encoding = 0i32;
    let mut has_proto3_optional = false;

    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            break;
        };
        match (tag, wire_type) {
            (field_tags::NAME, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    break;
                };
                if cursor.len() < len {
                    break;
                }
                name = String::from_utf8_lossy(&cursor[..len]).to_string();
                cursor = &cursor[len..];
            }
            (field_tags::LABEL, WireType::Varint) => {
                let Ok(v) = decode_varint(&mut cursor) else {
                    break;
                };
                label = v as i32;
            }
            (field_tags::TYPE, WireType::Varint) => {
                let Ok(v) = decode_varint(&mut cursor) else {
                    break;
                };
                field_type = v as i32;
            }
            (field_tags::ONEOF_INDEX, WireType::Varint) => {
                let Ok(_) = decode_varint(&mut cursor) else {
                    break;
                };
                has_oneof_index = true;
            }
            (field_tags::PROTO3_OPTIONAL, WireType::Varint) => {
                let Ok(v) = decode_varint(&mut cursor) else {
                    break;
                };
                has_proto3_optional = v != 0;
            }
            (field_tags::OPTIONS, WireType::LengthDelimited) => {
                let Ok(len) = decode_len(&mut cursor) else {
                    break;
                };
                if cursor.len() < len {
                    break;
                }
                let options = &cursor[..len];
                field_presence = extract_feature_varint(
                    options,
                    field_option_tags::FEATURES,
                    feature_tags::FIELD_PRESENCE,
                );
                field_encoding = extract_feature_varint(
                    options,
                    field_option_tags::FEATURES,
                    feature_tags::MESSAGE_ENCODING,
                );
                cursor = &cursor[len..];
            }
            _ => {
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    break;
                }
            }
        }
    }

    let effective_presence = if field_presence != 0 {
        field_presence
    } else {
        parent_presence
    };

    // Determine if this field needs proto3_optional.
    let is_repeated = label == LABEL_REPEATED;
    let is_message = field_type == TYPE_MESSAGE || field_type == TYPE_GROUP;
    let needs_proto3_optional = !has_proto3_optional
        && !is_repeated
        && !has_oneof_index
        && effective_presence == FIELD_PRESENCE_EXPLICIT
        && !is_message;

    // Determine if this message field uses DELIMITED (group) encoding.
    let effective_encoding = if field_encoding != 0 {
        field_encoding
    } else {
        parent_encoding
    };
    let is_delimited =
        field_type == TYPE_MESSAGE && effective_encoding == MESSAGE_ENCODING_DELIMITED;
    let is_legacy_required = effective_presence == FIELD_PRESENCE_LEGACY_REQUIRED;

    FieldInfo {
        name,
        needs_proto3_optional,
        has_oneof_index,
        is_delimited,
        is_legacy_required,
    }
}

/// Normalize a `FieldDescriptorProto` (simple version, no synthetic oneof).
fn normalize_field_descriptor(bytes: &[u8], parent_presence: i32, parent_encoding: i32) -> Vec<u8> {
    normalize_field_descriptor_with_oneof(bytes, parent_presence, parent_encoding, None)
}

#[allow(clippy::cast_possible_truncation)] // Protobuf field metadata values fit in i32.
fn normalize_field_descriptor_with_oneof(
    bytes: &[u8],
    parent_presence: i32,
    parent_encoding: i32,
    synthetic_oneof_index: Option<u32>,
) -> Vec<u8> {
    let info = analyze_field(bytes, parent_presence, parent_encoding);

    let mut cursor = bytes;
    let mut out = Vec::with_capacity(bytes.len() + 8);

    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return bytes.to_vec();
        };

        match (tag, wire_type) {
            // Rewrite label for LEGACY_REQUIRED.
            (field_tags::LABEL, WireType::Varint) => {
                let Ok(v) = decode_varint(&mut cursor) else {
                    return bytes.to_vec();
                };
                encode_key(field_tags::LABEL, WireType::Varint, &mut out);
                if info.is_legacy_required && v as i32 == LABEL_OPTIONAL {
                    encode_varint(LABEL_REQUIRED as u64, &mut out);
                } else {
                    encode_varint(v, &mut out);
                }
            }
            // Rewrite TYPE_MESSAGE → TYPE_GROUP for DELIMITED encoding.
            (field_tags::TYPE, WireType::Varint) => {
                let Ok(v) = decode_varint(&mut cursor) else {
                    return bytes.to_vec();
                };
                encode_key(field_tags::TYPE, WireType::Varint, &mut out);
                if info.is_delimited && v as i32 == TYPE_MESSAGE {
                    encode_varint(TYPE_GROUP as u64, &mut out);
                } else {
                    encode_varint(v, &mut out);
                }
            }
            // Pass through other fields.
            _ => {
                let pre = cursor;
                if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
                    return bytes.to_vec();
                }
                encode_key(tag, wire_type, &mut out);
                out.extend_from_slice(&pre[..pre.len() - cursor.len()]);
            }
        }
    }

    // Add proto3_optional if needed.
    if (info.needs_proto3_optional || synthetic_oneof_index.is_some())
        && !has_field_tag(bytes, field_tags::PROTO3_OPTIONAL)
    {
        encode_key(field_tags::PROTO3_OPTIONAL, WireType::Varint, &mut out);
        encode_varint(1, &mut out);
    }

    // Add synthetic oneof_index if needed.
    if let Some(idx) = synthetic_oneof_index {
        if !info.has_oneof_index {
            encode_key(field_tags::ONEOF_INDEX, WireType::Varint, &mut out);
            encode_varint(u64::from(idx), &mut out);
        }
    }

    out
}

/// Check if a message has a specific tag.
fn has_field_tag(bytes: &[u8], target_tag: u32) -> bool {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let Ok((tag, wire_type)) = decode_key(&mut cursor) else {
            return false;
        };
        if tag == target_tag {
            return true;
        }
        if skip_wire_value_simple(&mut cursor, wire_type).is_err() {
            return false;
        }
    }
    false
}

fn decode_len(cursor: &mut &[u8]) -> Result<usize, ()> {
    let v = decode_varint(cursor).map_err(|_| ())?;
    usize::try_from(v).map_err(|_| ())
}

fn skip_wire_value_simple(cursor: &mut &[u8], wire_type: WireType) -> Result<(), ()> {
    match wire_type {
        WireType::Varint => {
            decode_varint(cursor).map_err(|_| ())?;
            Ok(())
        }
        WireType::LengthDelimited => {
            let len = decode_len(cursor)?;
            if cursor.len() < len {
                return Err(());
            }
            *cursor = &cursor[len..];
            Ok(())
        }
        WireType::ThirtyTwoBit => {
            if cursor.len() < 4 {
                return Err(());
            }
            *cursor = &cursor[4..];
            Ok(())
        }
        WireType::SixtyFourBit => {
            if cursor.len() < 8 {
                return Err(());
            }
            *cursor = &cursor[8..];
            Ok(())
        }
        WireType::StartGroup => {
            // Skip group contents until EndGroup.
            loop {
                let (inner_tag, inner_wt) = decode_key(cursor).map_err(|_| ())?;
                if inner_wt == WireType::EndGroup {
                    let _ = inner_tag;
                    break;
                }
                skip_wire_value_simple(cursor, inner_wt)?;
            }
            Ok(())
        }
        WireType::EndGroup => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_edition_descriptor_set;
    use proptest::collection::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn normalization_is_idempotent_for_arbitrary_bytes(input in vec(any::<u8>(), 0..2048)) {
            let once = normalize_edition_descriptor_set(&input);
            let twice = normalize_edition_descriptor_set(&once);
            prop_assert_eq!(twice, once);
        }
    }
}
