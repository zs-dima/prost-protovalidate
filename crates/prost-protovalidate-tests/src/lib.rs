#![allow(clippy::all, warnings)]

pub mod parity {
    include!(concat!(env!("OUT_DIR"), "/parity.rs"));
}

// Generated `impl Validate` blocks (references `parity::*` types).
include!(concat!(env!("OUT_DIR"), "/validate_impl.rs"));

/// Embedded file descriptor set for the test protos.
pub static FILE_DESCRIPTOR_SET_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
