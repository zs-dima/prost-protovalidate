//! Runtime validation for Protocol Buffer messages using
//! [`buf.validate`](https://github.com/bufbuild/protovalidate) rules.
//!
//! This crate dynamically inspects `prost-reflect` message descriptors at runtime,
//! compiles `buf.validate` constraint annotations (including CEL expressions),
//! and evaluates them against concrete message instances.
//!
//! # Quick start
//!
//! For one-off validation, use the [`validate`] convenience function:
//!
//! ```rust,no_run
//! use prost_protovalidate::validate;
//! # fn example(msg: impl prost_reflect::ReflectMessage) {
//! match validate(&msg) {
//!     Ok(()) => { /* message is valid */ }
//!     Err(e) => eprintln!("validation failed: {e}"),
//! }
//! # }
//! ```
//!
//! For repeated validations, construct a [`Validator`] once to cache compiled
//! rules across calls:
//!
//! ```rust,no_run
//! use prost_protovalidate::Validator;
//! # fn example(msg: impl prost_reflect::ReflectMessage) {
//! let validator = Validator::new();
//! validator.validate(&msg).expect("message should be valid");
//! # }
//! ```
//!
//! # Feature flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `cel`   | Yes     | CEL expression evaluation and `chrono` time support. Disable for a lighter dependency footprint when only standard rules are used. |
//!
//! Without the `cel` feature, any message or field annotated with CEL
//! expressions (via both `cel` and legacy `cel_expression`, including
//! `buf.validate.predefined` rules) will produce a [`CompilationError`] at
//! validation time. Standard rules (range checks, string constraints, format
//! validators, etc.) work without `cel`.
//!
//! # Error types
//!
//! | Type | When |
//! |------|------|
//! | [`ValidationError`] | One or more constraint violations detected |
//! | [`CompilationError`] | A CEL expression or constraint definition failed to parse |
//! | [`RuntimeError`] | An unexpected failure during evaluation |
//!
//! All three are unified under [`Error`].
//!
//! # Re-exported types
//!
//! The [`types`] module re-exports [`prost-protovalidate-types`](https://crates.io/crates/prost-protovalidate-types)
//! so consumers do not need to depend on it directly.

#![warn(missing_docs)]

mod config;
mod error;
mod validator;
pub mod validators;
mod violation;

/// Re-export of [`prost-protovalidate-types`](https://crates.io/crates/prost-protovalidate-types)
/// for accessing generated `buf.validate` proto types and descriptor pool.
pub use prost_protovalidate_types as types;

/// Re-export of [`regex`](https://crates.io/crates/regex) so generated validators
/// from `prost-protovalidate-build` can construct compiled patterns without the
/// consumer's `Cargo.toml` needing a direct `regex` dependency.
pub use regex;

pub use config::{Filter, ValidationOption, ValidatorOption};
pub use error::{CompilationError, Error, RuntimeError, ValidationError};
pub use validator::{Validator, validate};
pub use violation::Violation;

/// Compile-time validation for Protocol Buffer messages with generated validators.
///
/// This trait is implemented by `prost-protovalidate-build` for messages that
/// have **only** standard `buf.validate` rules (no CEL expressions). Validators
/// run through monomorphized direct field access at runtime — no
/// `prost-reflect` transcoding, no CEL interpreter on the hot path. For
/// messages using CEL expressions or a mix of standard + CEL rules, use the
/// runtime [`Validator`] instead.
///
/// # Generated violations
///
/// Violations produced by generated validators have identical [`Violation::field_path()`],
/// [`Violation::rule_id()`], [`Violation::rule_path()`], and [`Violation::message()`]
/// as the runtime validator. The enrichment accessors
/// ([`Violation::field_descriptor()`], [`Violation::field_value()`],
/// [`Violation::rule_descriptor()`], [`Violation::rule_value()`]) return `None` —
/// these require runtime reflection data not available in generated code.
///
/// # Errors
///
/// Returns [`ValidationError`] containing all constraint violations found.
pub trait Validate {
    /// Validate this message against its `buf.validate` rules.
    ///
    /// # Errors
    /// Returns [`ValidationError`] containing all constraint violations found.
    fn validate(&self) -> Result<(), ValidationError>;
}

/// Normalize protobuf Edition 2023 descriptors to proto3 format for
/// compatibility with `prost-reflect` 0.16 which does not support editions.
pub use validator::editions::normalize_edition_descriptor_set;
