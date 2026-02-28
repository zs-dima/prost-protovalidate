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
mod violation;

/// Re-export of [`prost-protovalidate-types`](https://crates.io/crates/prost-protovalidate-types)
/// for accessing generated `buf.validate` proto types and descriptor pool.
pub use prost_protovalidate_types as types;

pub use config::{Filter, ValidationOption, ValidatorOption};
pub use error::{CompilationError, Error, RuntimeError, ValidationError};
pub use validator::{Validator, validate};
pub use violation::Violation;

/// Normalize protobuf Edition 2023 descriptors to proto3 format for
/// compatibility with `prost-reflect` 0.16 which does not support editions.
pub use validator::editions::normalize_edition_descriptor_set;
