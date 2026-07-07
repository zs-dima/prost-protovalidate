//! Completeness gate (buffa backend): every message defined in the test
//! protos must be wired into `PARITY_REGISTRY` (has a generated `Validate`
//! impl against buffa types and is swept) or explicitly listed in
//! `ROUTED_TO_RUNTIME`. Adding a rule-bearing message to `parity.proto`
//! without wiring it into the buffa parity infrastructure fails the build.

use prost_protovalidate_tests_buffa::{
    FILE_DESCRIPTOR_SET_BYTES, PARITY_REGISTRY, ROUTED_TO_RUNTIME,
};
use prost_reflect::DescriptorPool;

fn parity_pool() -> DescriptorPool {
    DescriptorPool::decode(FILE_DESCRIPTOR_SET_BYTES).expect("embedded descriptor set decodes")
}

#[test]
fn every_parity_message_is_wired() {
    let pool = parity_pool();
    let mut missing = Vec::new();

    for message in pool.all_messages() {
        if message.package_name() != "parity" || message.is_map_entry() {
            continue;
        }
        let name = message.full_name();
        let in_registry = PARITY_REGISTRY.iter().any(|(n, _)| *n == name);
        let routed = ROUTED_TO_RUNTIME.contains(&name);
        assert!(
            !(in_registry && routed),
            "{name} is in both PARITY_REGISTRY and ROUTED_TO_RUNTIME"
        );
        if !in_registry && !routed {
            missing.push(name.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "messages defined in the test protos but wired into neither \
         PARITY_REGISTRY nor ROUTED_TO_RUNTIME: {missing:?}"
    );
}

#[test]
fn registry_names_resolve_and_are_unique() {
    let pool = parity_pool();
    for (i, (name, _)) in PARITY_REGISTRY.iter().enumerate() {
        assert!(
            pool.get_message_by_name(name).is_some(),
            "PARITY_REGISTRY entry `{name}` does not exist in the descriptor set"
        );
        assert!(
            !PARITY_REGISTRY[..i].iter().any(|(n, _)| n == name),
            "duplicate PARITY_REGISTRY entry `{name}`"
        );
    }
    for name in ROUTED_TO_RUNTIME {
        assert!(
            pool.get_message_by_name(name).is_some(),
            "ROUTED_TO_RUNTIME entry `{name}` does not exist in the descriptor set"
        );
    }
}
