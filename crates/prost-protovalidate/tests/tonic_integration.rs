#![cfg(feature = "tonic")]

//! Integration tests for the optional `tonic` feature on `prost-protovalidate`.
//!
//! Covers:
//! - `From<ValidationError> for tonic::Status` maps to `Code::InvalidArgument`
//!   with the expected message.
//! - `ValidateRequest::validate_inner` returns `Ok(())` for valid messages and
//!   the same `InvalidArgument` status for invalid ones.
//! - With `tonic-types` on, the resulting status carries a `BadRequest`
//!   detail with one `FieldViolation` per violation.

use pretty_assertions::assert_eq;
use prost_protovalidate::tonic::ValidateRequest;
use prost_protovalidate::{
    CompilationError, Error, RuntimeError, Validate, ValidationError, Violation,
};

/// Minimal message type whose validity is governed by a runtime field.
/// Implements `Validate` directly so the test does not need a generated
/// validator — we are exercising the tonic bridge, not the validator engine.
struct Greet {
    valid: bool,
}

impl Validate for Greet {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.valid {
            Ok(())
        } else {
            Err(ValidationError::new(vec![
                Violation::new("name", "string.min_len", "value length must be at least 1"),
                Violation::new(
                    "email",
                    "string.email",
                    "value must be a valid email address",
                ),
            ]))
        }
    }
}

#[test]
fn validate_inner_returns_ok_for_valid_request() {
    let req = tonic::Request::new(Greet { valid: true });
    let result = req.validate_inner();
    assert!(result.is_ok(), "expected Ok, got {result:?}");
}

#[test]
fn validate_inner_returns_invalid_argument_status_for_invalid_request() {
    let req = tonic::Request::new(Greet { valid: false });
    let status = req
        .validate_inner()
        .expect_err("expected an invalid_argument status");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    let msg = status.message();
    // `ValidationError` Display prints `{field}: {message}` when message is
    // non-empty, falling back to `{field}: [{rule_id}]` for empty messages.
    // Our violations carry messages, so look for the field-path + message pair.
    assert!(
        msg.contains("name") && msg.contains("value length must be at least 1"),
        "status message missing expected field/message text: {msg:?}"
    );
    assert!(
        msg.contains("email") && msg.contains("value must be a valid email address"),
        "status message missing second violation: {msg:?}"
    );
}

#[test]
fn validation_error_converts_directly_via_into() {
    let err = ValidationError::new(vec![Violation::new(
        "field",
        "string.const",
        "value must equal 'expected'",
    )]);
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[cfg(feature = "tonic-types")]
#[test]
fn invalid_argument_status_carries_bad_request_details() {
    use tonic_types::StatusExt;

    let req = tonic::Request::new(Greet { valid: false });
    let status = req.validate_inner().expect_err("expected error");

    let details = status
        .get_error_details_vec()
        .into_iter()
        .find_map(|d| match d {
            tonic_types::ErrorDetail::BadRequest(br) => Some(br),
            _ => None,
        })
        .expect("BadRequest detail must be present");

    let fields: Vec<&str> = details
        .field_violations
        .iter()
        .map(|fv| fv.field.as_str())
        .collect();
    assert!(
        fields.contains(&"name") && fields.contains(&"email"),
        "expected both field violations; got {fields:?}"
    );

    // With messages present on each Violation, the BadRequest detail's
    // description must equal the message — no rule_id suffix, no leading
    // space (the canonical Violation::Display shape).
    let name_description = details
        .field_violations
        .iter()
        .find(|fv| fv.field == "name")
        .map(|fv| fv.description.as_str())
        .expect("name violation must be present");
    assert_eq!(name_description, "value length must be at least 1");
}

#[cfg(feature = "tonic-types")]
#[test]
fn empty_message_violation_falls_back_to_rule_id_in_brackets() {
    use tonic_types::StatusExt;

    // A violation with empty `message` should yield `"[{rule_id}]"` per
    // the canonical Violation::Display rules, not a leading-space string
    // or a trimmed format.
    let err = ValidationError::new(vec![Violation::new("field", "string.const", "")]);
    let status: tonic::Status = err.into();

    let details = status
        .get_error_details_vec()
        .into_iter()
        .find_map(|d| match d {
            tonic_types::ErrorDetail::BadRequest(br) => Some(br),
            _ => None,
        })
        .expect("BadRequest detail must be present");
    let description = details
        .field_violations
        .first()
        .map(|fv| fv.description.as_str())
        .expect("at least one field violation");
    assert_eq!(description, "[string.const]");
}

#[test]
fn compilation_error_maps_to_internal_with_generic_message() {
    // Cause must NOT leak into the gRPC client-facing status message.
    let err = CompilationError {
        cause: "secret detail referencing internal field xyz".to_string(),
    };
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::Internal);
    assert_eq!(status.message(), "validation rule compilation failed");
    assert!(
        !status.message().contains("secret detail"),
        "internal cause leaked into client-facing message: {:?}",
        status.message()
    );
}

#[test]
fn runtime_error_maps_to_internal_with_generic_message() {
    let err = RuntimeError {
        cause: "implementation-specific cause string".to_string(),
    };
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::Internal);
    assert_eq!(status.message(), "validation rule evaluation failed");
    assert!(
        !status.message().contains("implementation-specific"),
        "internal cause leaked into client-facing message: {:?}",
        status.message()
    );
}

#[test]
fn error_enum_maps_each_variant_to_expected_code() {
    let validation: tonic::Status = Error::Validation(ValidationError::new(vec![Violation::new(
        "f",
        "string.min_len",
        "must be >= 1",
    )]))
    .into();
    assert_eq!(validation.code(), tonic::Code::InvalidArgument);

    let compilation: tonic::Status = Error::Compilation(CompilationError {
        cause: "x".to_string(),
    })
    .into();
    assert_eq!(compilation.code(), tonic::Code::Internal);

    let runtime: tonic::Status = Error::Runtime(RuntimeError {
        cause: "x".to_string(),
    })
    .into();
    assert_eq!(runtime.code(), tonic::Code::Internal);
}
