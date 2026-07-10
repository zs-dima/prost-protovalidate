//! Parity for the buffa `runtime_bridge` mode.
//!
//! `bridge.proto` mixes CEL messages (routed to the runtime bridge) with a
//! standard-only message (inline generated validator). Each vector is encoded
//! to wire bytes, validated through the buffa-generated `Validate` impl, and
//! checked against the runtime `Validator` on the dynamic form. The bridge
//! delegates to the same engine, so agreement proves the generated wiring
//! (encode → bridge accessor → `validate_wire` → runtime) compiles and behaves
//! identically — including for the mixed inline-plus-bridge file.

use std::sync::LazyLock;

use buffa::Message as _;
use prost::Message as _;
use prost_protovalidate::{Error, Validate as _, ValidationError, Validator};
use prost_reflect::{DescriptorPool, DynamicMessage, Value};

use prost_protovalidate_tests_buffa_bridge::{FILE_DESCRIPTOR_SET_BYTES, bridge};

static POOL: LazyLock<DescriptorPool> =
    LazyLock::new(|| DescriptorPool::decode(FILE_DESCRIPTOR_SET_BYTES).expect("fds decodes"));
static VALIDATOR: LazyLock<Validator> = LazyLock::new(Validator::new);

type ViolationKey = (String, String, String, String, Option<bool>);

fn sorted(ve: &ValidationError) -> Vec<ViolationKey> {
    let mut v: Vec<ViolationKey> = ve
        .violations()
        .iter()
        .map(|x| {
            (
                x.field_path(),
                x.rule_id().to_string(),
                x.rule_path(),
                x.message().to_string(),
                x.for_key(),
            )
        })
        .collect();
    v.sort();
    v
}

/// Build a dynamic message of `full_name`, apply `set`, and return it.
fn dynamic(full_name: &str, set: impl FnOnce(&mut DynamicMessage)) -> DynamicMessage {
    let desc = POOL
        .get_message_by_name(full_name)
        .unwrap_or_else(|| panic!("`{full_name}` missing from pool"));
    let mut dm = DynamicMessage::new(desc);
    set(&mut dm);
    dm
}

/// Require the buffa `Validate` verdict to match the runtime `Validator`.
fn assert_agree(label: &str, buffa: &Result<(), ValidationError>, runtime: &Result<(), Error>) {
    match (buffa, runtime) {
        (Ok(()), Ok(())) => {}
        (Err(b), Err(Error::Validation(r))) => {
            pretty_assertions::assert_eq!(sorted(b), sorted(r), "violation mismatch for {label}");
        }
        _ => panic!("parity mismatch for {label}:\n  buffa   = {buffa:?}\n  runtime = {runtime:?}"),
    }
}

#[test]
fn bridged_field_level_cel_matches_runtime() {
    for (label, value) in [("positive", 1_i32), ("zero", 0), ("negative", -5)] {
        let dm = dynamic("bridge.CelField", |m| {
            m.set_field_by_name("value", Value::I32(value));
        });
        let bytes = dm.encode_to_vec();
        let buffa = bridge::CelField::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("CelField/{label}"), &buffa, &runtime);
    }
}

#[test]
fn bridged_message_level_cel_matches_runtime() {
    for (label, a, b) in [("ok", 1_i32, 2_i32), ("equal", 1, 1), ("reversed", 5, 2)] {
        let dm = dynamic("bridge.CelMessage", |m| {
            m.set_field_by_name("a", Value::I32(a));
            m.set_field_by_name("b", Value::I32(b));
        });
        let bytes = dm.encode_to_vec();
        let buffa = bridge::CelMessage::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("CelMessage/{label}"), &buffa, &runtime);
    }
}

#[test]
fn bridged_mixed_standard_and_cel_matches_runtime() {
    for (label, code) in [("ok", "ok"), ("empty", ""), ("has_space", "a b")] {
        let dm = dynamic("bridge.MixedRules", |m| {
            m.set_field_by_name("code", Value::String(code.to_string()));
        });
        let bytes = dm.encode_to_vec();
        let buffa = bridge::MixedRules::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("MixedRules/{label}"), &buffa, &runtime);
    }
}

#[test]
fn inline_standard_only_matches_runtime() {
    for (label, name, count) in [
        ("ok", "abc", 1_i32),
        ("short_name", "a", 0),
        ("negative", "ab", -1),
    ] {
        let dm = dynamic("bridge.StandardOnly", |m| {
            m.set_field_by_name("name", Value::String(name.to_string()));
            m.set_field_by_name("count", Value::I32(count));
        });
        let bytes = dm.encode_to_vec();
        let buffa = bridge::StandardOnly::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("StandardOnly/{label}"), &buffa, &runtime);
    }
}

#[test]
fn inline_protobuf_fqn_matches_runtime() {
    // (label, fqn, dot_fqn) — vary one field, keep the other valid so the
    // case under test is isolated. `protobuf_fqn` / `protobuf_dot_fqn` are
    // standard rules, so these validate through the inline generated path.
    let cases = [
        ("both_valid", "foo.bar.Baz", ".foo.bar"),
        ("fqn_underscore", "_x", ".x"),
        ("fqn_leading_digit", "1bad", ".x"),
        ("fqn_double_dot", "a..b", ".x"),
        ("fqn_empty", "", ".x"),
        ("fqn_bad_char", "no$", ".x"),
        ("dot_missing_dot", "x", "no_dot"),
        ("dot_trailing_dot", "x", ".a."),
        ("dot_leading_digit", "x", ".1bad"),
        ("dot_empty", "x", ""),
    ];
    for (label, fqn, dot) in cases {
        let dm = dynamic("bridge.ProtoName", |m| {
            m.set_field_by_name("fqn", Value::String(fqn.to_string()));
            m.set_field_by_name("dot_fqn", Value::String(dot.to_string()));
        });
        let bytes = dm.encode_to_vec();
        let buffa = bridge::ProtoName::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("ProtoName/{label}"), &buffa, &runtime);
    }
}

#[test]
fn bridged_real_oneof_field_rule_matches_runtime() {
    // `a` carries a standard rule but lives in a *real* proto oneof, so codegen
    // routes the message to the runtime (no CEL involved). It only has a
    // `Validate` impl at all because it is bridged — so this exercises the
    // bridge for a non-CEL runtime-only shape.
    let vectors = [
        (
            "a_valid",
            dynamic("bridge.OneofRuntimeOnly", |m| {
                m.set_field_by_name("a", Value::String("abc".to_string()));
            }),
        ),
        (
            "a_too_short",
            dynamic("bridge.OneofRuntimeOnly", |m| {
                m.set_field_by_name("a", Value::String("ab".to_string()));
            }),
        ),
        (
            "variant_b",
            dynamic("bridge.OneofRuntimeOnly", |m| {
                m.set_field_by_name("b", Value::I32(7));
            }),
        ),
        ("unset", dynamic("bridge.OneofRuntimeOnly", |_| {})),
    ];
    for (label, dm) in vectors {
        let bytes = dm.encode_to_vec();
        let buffa = bridge::OneofRuntimeOnly::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("OneofRuntimeOnly/{label}"), &buffa, &runtime);
    }
}

#[test]
fn bridged_nested_runtime_only_child_matches_runtime() {
    // `HasRuntimeChild.child` is a runtime-only type, so the parent is routed
    // to the runtime as a whole and bridged wholesale — the child's rules must
    // still surface (with the `child.*` path) identically to the runtime.
    let child_desc = POOL
        .get_message_by_name("bridge.OneofRuntimeOnly")
        .expect("child descriptor present");

    let mut child_valid = DynamicMessage::new(child_desc.clone());
    child_valid.set_field_by_name("a", Value::String("abc".to_string()));
    let mut child_invalid = DynamicMessage::new(child_desc);
    child_invalid.set_field_by_name("a", Value::String("x".to_string()));

    let vectors = [
        (
            "child_valid",
            dynamic("bridge.HasRuntimeChild", |m| {
                m.set_field_by_name("child", Value::Message(child_valid));
            }),
        ),
        (
            "child_invalid",
            dynamic("bridge.HasRuntimeChild", |m| {
                m.set_field_by_name("child", Value::Message(child_invalid));
            }),
        ),
        ("child_missing", dynamic("bridge.HasRuntimeChild", |_| {})),
    ];
    for (label, dm) in vectors {
        let bytes = dm.encode_to_vec();
        let buffa = bridge::HasRuntimeChild::decode_from_slice(&bytes)
            .expect("decodes into buffa type")
            .validate();
        let runtime = VALIDATOR.validate(&dm);
        assert_agree(&format!("HasRuntimeChild/{label}"), &buffa, &runtime);
    }
}
