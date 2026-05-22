//! Optional integration with [`tonic`] (gRPC).
//!
//! Enabled by the `tonic` cargo feature. Provides a typed bridge between
//! [`ValidationError`] / [`Error`] and [`tonic::Status`], plus a
//! [`ValidateRequest`] extension trait for one-line per-handler validation:
//!
//! ```ignore
//! use prost_protovalidate::{Validate, tonic::ValidateRequest};
//!
//! #[tonic::async_trait]
//! impl my_proto::greeter_server::Greeter for GreeterImpl {
//!     async fn say_hello(
//!         &self,
//!         req: tonic::Request<my_proto::HelloRequest>,
//!     ) -> Result<tonic::Response<my_proto::HelloReply>, tonic::Status> {
//!         req.validate_inner()?;
//!         // ... handler body ...
//! #       unimplemented!()
//!     }
//! }
//! ```
//!
//! With the additional `tonic-types` feature on, the resulting
//! [`tonic::Status`] carries a `google.rpc.BadRequest` detail with one
//! `FieldViolation` per [`Violation`](crate::Violation), so clients can
//! parse field-level errors without scraping the message string.
//!
//! # Mapping to gRPC codes
//!
//! - [`ValidationError`] → [`tonic::Code::InvalidArgument`]. The status
//!   message is the [`Display`](std::fmt::Display) form of the error
//!   (a list of `{field}: {message}` lines), which is safe to expose to
//!   clients since it derives from rules the client violated.
//! - [`CompilationError`] / [`RuntimeError`] → [`tonic::Code::Internal`]
//!   with a **fixed, generic message**. The underlying `cause` strings can
//!   contain proto field names, CEL parse output, or type-mismatch details
//!   that should not be exposed to untrusted clients. Callers who need the
//!   full cause for server-side logging must inspect/log the error
//!   **before** invoking the `Into` conversion.
//!
//! # Streaming requests
//!
//! [`ValidateRequest`] applies to handlers whose request shape is
//! `tonic::Request<T>` (unary and server-streaming). For client-streaming
//! and bidirectional handlers, where the request is
//! `tonic::Request<tonic::Streaming<T>>`, validate each message inside the
//! per-message loop:
//!
//! ```ignore
//! use prost_protovalidate::Validate;
//! while let Some(msg) = stream.message().await? {
//!     msg.validate().map_err(tonic::Status::from)?;
//!     // ... process msg ...
//! }
//! ```

use crate::Validate;
use crate::error::{CompilationError, Error, RuntimeError, ValidationError};

impl From<ValidationError> for tonic::Status {
    fn from(err: ValidationError) -> Self {
        #[cfg(feature = "tonic-types")]
        {
            use tonic_types::{ErrorDetails, StatusExt};
            let mut error_details = ErrorDetails::new();
            for v in err.violations() {
                let description = if !v.message().is_empty() {
                    v.message().to_string()
                } else if !v.rule_id().is_empty() {
                    format!("[{}]", v.rule_id())
                } else {
                    "[unknown]".to_string()
                };
                error_details.add_bad_request_violation(v.field_path(), description);
            }
            tonic::Status::with_error_details(
                tonic::Code::InvalidArgument,
                err.to_string(),
                error_details,
            )
        }
        #[cfg(not(feature = "tonic-types"))]
        {
            tonic::Status::invalid_argument(err.to_string())
        }
    }
}

impl From<CompilationError> for tonic::Status {
    /// Maps to [`tonic::Code::Internal`] with a fixed, generic message.
    ///
    /// The original `cause` is **not** forwarded — it can contain proto field
    /// names or CEL internals that should not be exposed to untrusted clients.
    /// Log the underlying error server-side before converting.
    fn from(_err: CompilationError) -> Self {
        tonic::Status::internal("validation rule compilation failed")
    }
}

impl From<RuntimeError> for tonic::Status {
    /// Maps to [`tonic::Code::Internal`] with a fixed, generic message.
    ///
    /// The original `cause` is **not** forwarded — it can contain proto field
    /// names, type-mismatch details, or CEL evaluation internals that should
    /// not be exposed to untrusted clients. Log the underlying error
    /// server-side before converting.
    fn from(_err: RuntimeError) -> Self {
        tonic::Status::internal("validation rule evaluation failed")
    }
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::Validation(e) => e.into(),
            Error::Compilation(e) => e.into(),
            Error::Runtime(e) => e.into(),
        }
    }
}

/// Extension trait that calls [`Validate::validate`] on the inner message of
/// a [`tonic::Request`] and maps any [`ValidationError`] to a
/// [`tonic::Status`] with `Code::InvalidArgument`.
///
/// Applies to handlers whose request shape is `tonic::Request<T>` — unary
/// and server-streaming RPCs. For client-streaming and bidirectional RPCs
/// where the request is `tonic::Request<tonic::Streaming<T>>`, see the
/// per-message pattern in the module-level docs.
pub trait ValidateRequest {
    /// Validate the inner message of this gRPC request.
    ///
    /// # Errors
    /// Returns a [`tonic::Status`] with `Code::InvalidArgument` if any
    /// validation rule failed. With the `tonic-types` feature on, the
    /// status carries a `google.rpc.BadRequest` detail with one
    /// `FieldViolation` per [`Violation`](crate::Violation).
    #[must_use = "discarding a validation result allows invalid requests through"]
    fn validate_inner(&self) -> Result<(), tonic::Status>;
}

impl<T: Validate> ValidateRequest for tonic::Request<T> {
    fn validate_inner(&self) -> Result<(), tonic::Status> {
        self.get_ref().validate().map_err(Into::into)
    }
}
