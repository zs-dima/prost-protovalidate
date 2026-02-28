use std::any::Any;
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};

use prost::Message;
use prost_protovalidate::{Error, Validator, ValidatorOption, normalize_edition_descriptor_set};
use prost_reflect::{DescriptorPool, DynamicMessage};

#[allow(clippy::doc_markdown)]
mod harness {
    include!(concat!(
        env!("OUT_DIR"),
        "/buf.validate.conformance.harness.rs"
    ));
}

fn main() {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .expect("failed to read stdin");

    // Extract the raw fdset bytes (field 2) from the wire format BEFORE prost
    // decodes the request. prost_types::FileDescriptorSet drops extension data
    // (unknown fields) when decoding nested FieldOptions, so we must avoid
    // round-tripping the fdset through prost.
    let fdset_bytes = extract_fdset_bytes(&input);

    let request = harness::TestConformanceRequest::decode(input.as_slice())
        .expect("failed to decode TestConformanceRequest");

    let response = process_request(&request, fdset_bytes);

    io::stdout()
        .write_all(&response.encode_to_vec())
        .expect("failed to write stdout");
}

/// Extract raw bytes of the `fdset` field (field number 2, wire type LEN)
/// from a protobuf-encoded `TestConformanceRequest` without decoding nested
/// messages. This preserves extension data that `prost_types` would drop.
fn extract_fdset_bytes(buf: &[u8]) -> Option<Vec<u8>> {
    use prost::encoding::{WireType, decode_key, decode_varint};
    let mut cursor = buf;
    while !cursor.is_empty() {
        let (tag, wire_type) = decode_key(&mut cursor).ok()?;
        match (tag, wire_type) {
            (2, WireType::LengthDelimited) => {
                let len = usize::try_from(decode_varint(&mut cursor).ok()?).ok()?;
                if cursor.len() < len {
                    return None;
                }
                return Some(cursor[..len].to_vec());
            }
            (_, WireType::Varint) => {
                decode_varint(&mut cursor).ok()?;
            }
            (_, WireType::LengthDelimited) => {
                let len = usize::try_from(decode_varint(&mut cursor).ok()?).ok()?;
                if cursor.len() < len {
                    return None;
                }
                cursor = &cursor[len..];
            }
            (_, WireType::ThirtyTwoBit) => {
                if cursor.len() < 4 {
                    return None;
                }
                cursor = &cursor[4..];
            }
            (_, WireType::SixtyFourBit) => {
                if cursor.len() < 8 {
                    return None;
                }
                cursor = &cursor[8..];
            }
            _ => return None,
        }
    }
    None
}

fn process_request(
    request: &harness::TestConformanceRequest,
    fdset_bytes: Option<Vec<u8>>,
) -> harness::TestConformanceResponse {
    let Some(fdset_bytes) = fdset_bytes else {
        return all_unexpected(&request.cases, "missing fdset in request");
    };

    let (pool, validator) = match build_suite(fdset_bytes) {
        Ok(pair) => pair,
        Err(msg) => return all_unexpected(&request.cases, &msg),
    };

    let results = request
        .cases
        .iter()
        .map(|(name, any)| (name.clone(), run_test_case(&pool, &validator, any)))
        .collect();

    harness::TestConformanceResponse { results }
}

fn build_suite(fdset_bytes: Vec<u8>) -> Result<(DescriptorPool, Validator), String> {
    catch_unwind_silent(move || {
        // Normalize Edition 2023 descriptors to proto3 for prost-reflect compatibility.
        let normalized = normalize_edition_descriptor_set(&fdset_bytes);

        // Build a fresh dynamic decode pool from the suite descriptor set only.
        // Validator extension resolution uses AdditionalDescriptorSetBytes.
        let mut pool = DescriptorPool::new();
        pool.decode_file_descriptor_set(normalized.as_slice())
            .map_err(|e| format!("failed to decode descriptor pool: {e}"))?;
        let validator =
            Validator::with_options(&[ValidatorOption::AdditionalDescriptorSetBytes(normalized)]);
        Ok((pool, validator))
    })
    .unwrap_or_else(|p| Err(format!("panic during suite setup: {}", panic_message(&p))))
}

fn run_test_case(
    pool: &DescriptorPool,
    validator: &Validator,
    any_value: &prost_types::Any,
) -> harness::TestResult {
    let type_name = any_value
        .type_url
        .rsplit('/')
        .next()
        .unwrap_or(&any_value.type_url);

    let Some(descriptor) = pool.get_message_by_name(type_name) else {
        return compilation_error(format!("unknown message type: {type_name}"));
    };

    let dynamic = match DynamicMessage::decode(descriptor, any_value.value.as_slice()) {
        Ok(msg) => msg,
        Err(err) => return runtime_error(format!("failed to decode message: {err}")),
    };

    match catch_unwind_silent(|| validator.validate(&dynamic)) {
        Ok(Ok(())) => success(),
        Ok(Err(Error::Validation(err))) => validation_error(err.to_proto()),
        Ok(Err(Error::Compilation(err))) => compilation_error(err.cause),
        Ok(Err(Error::Runtime(err))) => runtime_error(err.cause),
        Ok(Err(err)) => unexpected_error(err.to_string()),
        Err(p) => runtime_error(panic_message(&p)),
    }
}

// --- TestResult constructors ---

fn success() -> harness::TestResult {
    harness::TestResult {
        result: Some(harness::test_result::Result::Success(true)),
    }
}

fn validation_error(v: prost_protovalidate_types::Violations) -> harness::TestResult {
    harness::TestResult {
        result: Some(harness::test_result::Result::ValidationError(v)),
    }
}

fn compilation_error(msg: String) -> harness::TestResult {
    harness::TestResult {
        result: Some(harness::test_result::Result::CompilationError(msg)),
    }
}

fn runtime_error(msg: String) -> harness::TestResult {
    harness::TestResult {
        result: Some(harness::test_result::Result::RuntimeError(msg)),
    }
}

fn unexpected_error(msg: String) -> harness::TestResult {
    harness::TestResult {
        result: Some(harness::test_result::Result::UnexpectedError(msg)),
    }
}

fn all_unexpected(
    cases: &std::collections::HashMap<String, prost_types::Any>,
    message: &str,
) -> harness::TestConformanceResponse {
    let results = cases
        .keys()
        .map(|name| (name.clone(), unexpected_error(message.to_string())))
        .collect();

    harness::TestConformanceResponse { results }
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

fn catch_unwind_silent<F, T>(f: F) -> Result<T, Box<dyn Any + Send>>
where
    F: FnOnce() -> T,
{
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(hook);
    result
}
