//! Descriptor-driven parity sweep (buffa backend).
//!
//! Reuses the shared boundary-vector generator from
//! `prost_protovalidate_tests::sweep`; every vector is encoded to bytes,
//! decoded into the **buffa**-generated type, validated through the
//! generated `Validate` impl, and compared against the runtime `Validator`
//! verdict on the dynamic form. Agreement is the oracle.

use std::sync::LazyLock;

use prost::Message;
use prost_protovalidate::{Error, Validator};
use prost_protovalidate_tests::sweep::generate_vectors;
use prost_protovalidate_tests_buffa::{
    FILE_DESCRIPTOR_SET_BYTES, PARITY_REGISTRY, ValidateFn, sorted_violations,
};
use prost_reflect::{DescriptorPool, DynamicMessage};

static POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(FILE_DESCRIPTOR_SET_BYTES).expect("embedded descriptor set decodes")
});

static VALIDATOR: LazyLock<Validator> = LazyLock::new(Validator::new);

#[test]
fn descriptor_driven_boundary_sweep_buffa() {
    let mut total_vectors = 0usize;
    for (full_name, validate_fn) in PARITY_REGISTRY {
        let desc = POOL
            .get_message_by_name(full_name)
            .unwrap_or_else(|| panic!("`{full_name}` missing from descriptor pool"));

        for (label, vector) in generate_vectors(&desc) {
            assert_paths_agree(full_name, *validate_fn, &label, &vector);
            total_vectors += 1;
        }
    }
    // Guard against the generator silently degenerating.
    assert!(
        total_vectors > 200,
        "sweep generated suspiciously few vectors: {total_vectors}"
    );
}

/// Validate one vector through both paths and require identical outcomes.
fn assert_paths_agree(
    full_name: &str,
    validate_fn: ValidateFn,
    label: &str,
    vector: &DynamicMessage,
) {
    let bytes = vector.encode_to_vec();
    let build = validate_fn(&bytes);
    let runtime = VALIDATOR.validate(vector);

    match (&build, &runtime) {
        (Ok(()), Ok(())) => {}
        (Err(build_err), Err(Error::Validation(runtime_err))) => {
            pretty_assertions::assert_eq!(
                sorted_violations(build_err),
                sorted_violations(runtime_err),
                "violation mismatch for {full_name} [{label}]"
            );
        }
        _ => panic!(
            "parity mismatch for {full_name} [{label}]:\n  build   = {build:?}\n  runtime = {runtime:?}"
        ),
    }
}
