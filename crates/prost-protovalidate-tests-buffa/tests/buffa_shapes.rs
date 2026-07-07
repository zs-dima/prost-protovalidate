//! Hand-written buffa-shape tests.
//!
//! The descriptor-driven sweep covers rule breadth; these tests pin the
//! buffa-specific storage semantics readably: `MessageField` presence,
//! `EnumValue::Unknown` normalization, `Option<T>` optional scalars,
//! raw-identifier keyword fields, and foldhash map iteration — all through
//! the generated `Validate` impls.

use buffa::{EnumValue, MessageField};
use prost_protovalidate::Validate;
use prost_protovalidate_tests_buffa::parity;

fn valid_parity_test() -> parity::ParityTest {
    parity::ParityTest {
        name: "alice".to_string(),
        email: "alice@example.com".to_string(),
        code: "ABC".to_string(),
        age: 25,
        score: 100,
        accepted: true,
        status: parity::Status::STATUS_ACTIVE.into(),
        tags: vec!["tag1".to_string()],
        inner: MessageField::some(parity::Inner {
            value: "hello".to_string(),
            ..Default::default()
        }),
        ignored: String::new(),
        ..Default::default()
    }
}

#[test]
fn valid_message_passes() {
    assert!(valid_parity_test().validate().is_ok());
}

#[test]
fn unset_message_field_fails_required() {
    let msg = parity::ParityTest {
        inner: MessageField::none(),
        ..valid_parity_test()
    };
    let err = msg.validate().expect_err("unset required MessageField");
    let v = &err.violations()[0];
    assert_eq!(v.field_path(), "inner");
    assert_eq!(v.rule_id(), "required");
    assert_eq!(v.message(), "value is required");
}

#[test]
fn nested_violations_surface_through_message_field_unwrap() {
    let msg = parity::ParityTest {
        inner: MessageField::some(parity::Inner {
            value: String::new(),
            ..Default::default()
        }),
        ..valid_parity_test()
    };
    let err = msg.validate().expect_err("empty nested value");
    let v = &err.violations()[0];
    assert_eq!(v.field_path(), "inner.value");
    assert_eq!(v.rule_id(), "string.min_len");
}

#[test]
fn unknown_enum_value_fails_defined_only() {
    let msg = parity::ParityTest {
        status: EnumValue::Unknown(99),
        ..valid_parity_test()
    };
    let err = msg.validate().expect_err("undefined enum number");
    let v = &err.violations()[0];
    assert_eq!(v.field_path(), "status");
    assert_eq!(v.rule_id(), "enum.defined_only");
}

#[test]
fn unknown_enum_inside_repeated_and_map_normalizes_via_to_i32() {
    let msg = parity::EnumDefinedOnlyContainers {
        statuses: vec![parity::Status::STATUS_ACTIVE.into(), EnumValue::Unknown(7)],
        by_key: [("k".to_string(), EnumValue::Unknown(7))]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let err = msg.validate().expect_err("undefined enum in containers");
    let mut paths: Vec<String> = err
        .violations()
        .iter()
        .map(prost_protovalidate::Violation::field_path)
        .collect();
    paths.sort();
    assert_eq!(paths, vec!["by_key[\"k\"]", "statuses[1]"]);
}

#[test]
fn optional_scalars_skip_when_unset_and_validate_when_set() {
    let unset = parity::OptionalScalars {
        name: None,
        score: None,
        data: None,
        ..Default::default()
    };
    assert!(unset.validate().is_ok(), "unset optional scalars must pass");

    let set = parity::OptionalScalars {
        name: Some("ab".to_string()), // min_len 3
        score: Some(1),
        data: Some(vec![1, 2]),
        ..Default::default()
    };
    let err = set.validate().expect_err("short optional string");
    assert_eq!(err.violations().len(), 1);
    assert_eq!(err.violations()[0].field_path(), "name");
    assert_eq!(err.violations()[0].rule_id(), "string.min_len");
}

#[test]
fn keyword_fields_compile_as_raw_identifiers() {
    let msg = parity::KeywordFields {
        r#type: "a".to_string(),
        r#mod: "b".to_string(),
        r#match: String::new(), // min_len 1 → violation
        ..Default::default()
    };
    let err = msg.validate().expect_err("empty keyword-named field");
    assert_eq!(err.violations().len(), 1);
    assert_eq!(err.violations()[0].field_path(), "match");
}

#[test]
fn map_key_rules_mark_for_key_over_foldhash_maps() {
    let msg = parity::MapKeyRules {
        by_name: [(String::new(), "v".to_string())].into_iter().collect(),
        by_id: [(1i32, "v".to_string())].into_iter().collect(),
        ..Default::default()
    };
    let err = msg.validate().expect_err("empty map key");
    assert_eq!(err.violations().len(), 1);
    let v = &err.violations()[0];
    assert_eq!(v.field_path(), "by_name[\"\"]");
    assert_eq!(v.for_key(), Some(true));
}
