#![allow(clippy::all, warnings)]

//! Buffa `runtime_bridge` parity fixtures.
//!
//! Includes the buffa-generated message types for `bridge.proto` and the
//! `impl Validate` blocks generated in `runtime_bridge` mode (inline for
//! standard-only messages, bridge-delegating for CEL messages). The `tests/`
//! sweep drives these against the runtime `Validator`.
//!
//! # Why this establishes full buffa conformance
//!
//! There is no separate buffa conformance executor (the protovalidate suite is
//! reflection-driven and ships no vendored case protos). Instead the buffa path
//! reaches the runtime's conformance level **by construction**:
//!
//! 1. The runtime `Validator` passes the full protovalidate v1.2.2 suite
//!    (2872/2872, verified by `make conformance`).
//! 2. `prost-protovalidate-tests-buffa` proves buffa-generated `Validate`
//!    equals the runtime `Validator` for every **standard**-rule vector.
//! 3. This crate proves the `runtime_bridge` path (CEL / routed messages)
//!    delegates to that same engine and agrees with it.
//!
//! Standard rules inline + everything else through the bridge ⇒ the buffa path
//! validates the entire rule surface exactly as the runtime does.

// buffa-generated module tree (`pub mod bridge { ... }`).
include!(concat!(env!("OUT_DIR"), "/_buffa_include.rs"));

// Generated `impl Validate` blocks (inline + bridge) against the buffa types
// above, plus the shared runtime-bridge accessor.
include!(concat!(env!("OUT_DIR"), "/validate_impl.rs"));

/// Embedded file descriptor set for `bridge.proto` (with `buf.validate`
/// extensions), used by the parity sweep to build dynamic messages and the
/// runtime `Validator` oracle.
pub static FILE_DESCRIPTOR_SET_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
