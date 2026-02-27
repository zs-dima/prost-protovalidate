use std::any::Any;
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};

use prost::Message;
use prost_protovalidate::{Error, Validator, ValidatorOption};
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

    let request = harness::TestConformanceRequest::decode(input.as_slice())
        .expect("failed to decode TestConformanceRequest");

    let response = process_request(&request);

    io::stdout()
        .write_all(&response.encode_to_vec())
        .expect("failed to write stdout");
}

fn process_request(request: &harness::TestConformanceRequest) -> harness::TestConformanceResponse {
    let Some(fdset) = request.fdset.as_ref() else {
        return all_unexpected(&request.cases, "missing fdset in request");
    };

    let fdset_bytes = fdset.encode_to_vec();

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
    panic::catch_unwind(move || {
        let pool = DescriptorPool::decode(fdset_bytes.as_slice())
            .map_err(|e| format!("failed to decode descriptor pool: {e}"))?;
        let validator =
            Validator::with_options(&[ValidatorOption::AdditionalDescriptorSetBytes(fdset_bytes)]);
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

    match panic::catch_unwind(AssertUnwindSafe(|| validator.validate(&dynamic))) {
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
