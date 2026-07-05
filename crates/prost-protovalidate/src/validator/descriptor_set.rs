//! Descriptor-pool assembly from raw `FileDescriptorSet` bytes.
//!
//! Combines the built-in `buf.validate` descriptors with caller-provided
//! descriptor sets at the wire level. Working on raw bytes (instead of
//! decoding through `prost_types::FileDescriptorSet`) preserves extension
//! data — such as `buf.validate.*` options — that a typed decode would drop.

use std::any::Any;
use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use prost::encoding::{WireType, decode_key, encode_key, encode_varint};
use prost_reflect::DescriptorPool;

use crate::error::CompilationError;

use super::wire;

/// Build the pool backing rule-extension resolution: the built-in
/// `buf.validate` descriptors plus `additional_descriptor_sets`, deduplicated
/// by file name and normalized for Edition 2023 support.
///
/// Never fails outright: on invalid input the built-in pool is returned
/// together with a [`CompilationError`] to surface at validation time.
pub(crate) fn build_descriptor_pool(
    additional_descriptor_sets: &[Vec<u8>],
) -> (DescriptorPool, Option<CompilationError>) {
    let base_bytes = prost_protovalidate_types::DESCRIPTOR_POOL.encode_to_vec();
    let base_entries = match parse_file_descriptor_set_entries(base_bytes.as_slice()) {
        Ok(entries) => entries,
        Err(err) => {
            return (
                prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                Some(CompilationError {
                    cause: format!("failed to decode built-in descriptor set: {err}"),
                }),
            );
        }
    };

    let mut seen_names: HashSet<String> =
        base_entries.iter().map(|(name, _)| name.clone()).collect();
    let mut combined_files: Vec<Vec<u8>> =
        base_entries.into_iter().map(|(_, bytes)| bytes).collect();
    let mut parsed_additional: Vec<Vec<(String, Vec<u8>)>> =
        Vec::with_capacity(additional_descriptor_sets.len());

    for (idx, bytes) in additional_descriptor_sets.iter().enumerate() {
        let entries = match parse_file_descriptor_set_entries(bytes.as_slice()) {
            Ok(entries) => entries,
            Err(err) => {
                return (
                    prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                    Some(CompilationError {
                        cause: format!(
                            "failed to decode additional descriptor set at index {idx}: {err}"
                        ),
                    }),
                );
            }
        };

        for (name, file_bytes) in &entries {
            if seen_names.insert(name.clone()) {
                combined_files.push(file_bytes.clone());
            }
        }
        parsed_additional.push(entries);
    }

    let combined_bytes = encode_file_descriptor_set(&combined_files);
    let combined_bytes = super::editions::normalize_edition_descriptor_set(&combined_bytes);
    match decode_pool_from_bytes(combined_bytes.as_slice()) {
        Ok(pool) => (pool, None),
        Err(err) => {
            // Keep index-oriented diagnostics without decoding into a non-empty pool.
            let mut prefix_seen: HashSet<String> = HashSet::new();
            let mut prefix_files = Vec::new();
            for (name, file_bytes) in
                parse_file_descriptor_set_entries(base_bytes.as_slice()).unwrap_or_default()
            {
                if prefix_seen.insert(name) {
                    prefix_files.push(file_bytes);
                }
            }

            for (idx, entries) in parsed_additional.iter().enumerate() {
                for (name, file_bytes) in entries {
                    if prefix_seen.insert(name.clone()) {
                        prefix_files.push(file_bytes.clone());
                    }
                }
                let prefix_bytes = encode_file_descriptor_set(&prefix_files);
                if let Err(prefix_err) = decode_pool_from_bytes(prefix_bytes.as_slice()) {
                    return (
                        prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                        Some(CompilationError {
                            cause: format!(
                                "failed to decode additional descriptor set at index {idx}: {prefix_err}"
                            ),
                        }),
                    );
                }
            }

            (
                prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                Some(CompilationError {
                    cause: format!(
                        "failed to decode additional descriptor sets (indices 0..{}): {err}",
                        additional_descriptor_sets.len()
                    ),
                }),
            )
        }
    }
}

fn decode_pool_from_bytes(bytes: &[u8]) -> Result<DescriptorPool, String> {
    let mut pool = DescriptorPool::new();
    match catch_unwind(AssertUnwindSafe(|| pool.decode_file_descriptor_set(bytes))) {
        Ok(Ok(())) => Ok(pool),
        Ok(Err(err)) => Err(err.to_string()),
        Err(panic) => Err(format!(
            "panic during descriptor pool decode: {}",
            panic_message(&panic)
        )),
    }
}

fn parse_file_descriptor_set_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut cursor = bytes;
    let mut entries = Vec::new();

    while !cursor.is_empty() {
        let (tag, wire_type) = decode_key(&mut cursor).map_err(|err| err.to_string())?;
        match (tag, wire_type) {
            (1, WireType::LengthDelimited) => {
                let len = wire::decode_len(&mut cursor)?;
                if cursor.len() < len {
                    return Err("truncated file descriptor entry".to_string());
                }

                let entry = cursor[..len].to_vec();
                cursor = &cursor[len..];
                let name = parse_file_descriptor_name(entry.as_slice())?;
                entries.push((name, entry));
            }
            _ => wire::skip_wire_value(&mut cursor, wire_type)?,
        }
    }

    Ok(entries)
}

fn parse_file_descriptor_name(bytes: &[u8]) -> Result<String, String> {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let (tag, wire_type) = decode_key(&mut cursor).map_err(|err| err.to_string())?;
        match (tag, wire_type) {
            (1, WireType::LengthDelimited) => {
                let len = wire::decode_len(&mut cursor)?;
                if cursor.len() < len {
                    return Err("truncated file descriptor name".to_string());
                }

                let name = std::str::from_utf8(&cursor[..len])
                    .map_err(|err| format!("invalid UTF-8 in file descriptor name: {err}"))?;
                return Ok(name.to_string());
            }
            _ => wire::skip_wire_value(&mut cursor, wire_type)?,
        }
    }

    Err("missing file name in file descriptor".to_string())
}

fn encode_file_descriptor_set(files: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for file in files {
        encode_key(1, WireType::LengthDelimited, &mut out);
        encode_varint(file.len() as u64, &mut out);
        out.extend_from_slice(file);
    }
    out
}

fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}
