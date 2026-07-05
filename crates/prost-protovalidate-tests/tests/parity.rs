use std::sync::LazyLock;

use pretty_assertions::assert_eq;
use prost::Message;
use prost_protovalidate::{Error, Validate, Validator, Violation};
use prost_protovalidate_tests::parity::{
    self, AllNumericTypes, BytesContainsEmpty, BytesPatternRaw, BytesRuleMatrix, ConstInTest,
    DurationTimestampRules, EnumDefinedOnlyContainers, FieldMaskTest, FloatFiniteRules, Inner,
    KeywordFields, MapKeyRules, MapScalarValues, MapStringInner, NestedIgnore, OptionalScalars,
    ParityTest, PresenceMix, RepeatedFloatUnique, RepeatedScalarItems, RequiredImplicitScalar,
    StringRuleMatrix, StringWellKnown, TimestampRelative, VirtualOneof, VirtualOneofImplicitIgnore,
};
use prost_protovalidate_tests::sorted_violations;
use prost_reflect::{DescriptorPool, DynamicMessage};

static POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(prost_protovalidate_tests::FILE_DESCRIPTOR_SET_BYTES).unwrap()
});

static VALIDATOR: LazyLock<Validator> = LazyLock::new(Validator::new);

/// Validate a prost message via the runtime `Validator` by encoding to bytes,
/// decoding as `DynamicMessage`, then running runtime evaluation.
fn validate_runtime(msg: &impl Message, type_name: &str) -> Result<(), Error> {
    let bytes = msg.encode_to_vec();
    let desc = POOL
        .get_message_by_name(type_name)
        .unwrap_or_else(|| panic!("message `{type_name}` not found in descriptor pool"));
    let dynamic = DynamicMessage::decode(desc, bytes.as_slice()).unwrap();
    VALIDATOR.validate(&dynamic)
}

/// Assert both build-time `Validate` and runtime `Validator` succeed.
fn assert_both_ok(msg: &(impl Validate + Message), type_name: &str) {
    let build = msg.validate();
    assert!(build.is_ok(), "build-time validation failed: {build:?}");

    let runtime = validate_runtime(msg, type_name);
    assert!(runtime.is_ok(), "runtime validation failed: {runtime:?}");
}

/// Assert both paths produce identical violations (sorted).
fn assert_violations_match(msg: &(impl Validate + Message), type_name: &str) {
    let build_err = msg.validate().expect_err("build-time should fail");
    let runtime_err = match validate_runtime(msg, type_name) {
        Err(Error::Validation(ve)) => ve,
        Ok(()) => panic!("runtime validation should have failed"),
        Err(other) => panic!("expected ValidationError from runtime, got: {other}"),
    };
    assert_eq!(
        sorted_violations(&build_err),
        sorted_violations(&runtime_err),
    );
}

fn valid_parity_test() -> ParityTest {
    ParityTest {
        name: "alice".to_string(),
        email: "alice@example.com".to_string(),
        code: "ABC".to_string(),
        age: 25,
        score: 100,
        accepted: true,
        status: parity::Status::Active.into(),
        tags: vec!["tag1".to_string()],
        inner: Some(Inner {
            value: "hello".to_string(),
        }),
        ignored: String::new(),
    }
}

// --- ParityTest: OK ---

#[test]
fn valid_message_both_pass() {
    assert_both_ok(&valid_parity_test(), "parity.ParityTest");
}

// --- ParityTest: single-field violations ---

#[test]
fn string_min_len_violation() {
    let msg = ParityTest {
        name: "a".to_string(),
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn email_violation() {
    let msg = ParityTest {
        email: "not-an-email".to_string(),
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn pattern_violation() {
    let msg = ParityTest {
        code: "abc".to_string(),
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn number_range_violation() {
    let msg = ParityTest {
        age: -1,
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn number_gt_violation() {
    let msg = ParityTest {
        score: 0,
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn bool_const_violation() {
    let msg = ParityTest {
        accepted: false,
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn enum_defined_only_violation() {
    let msg = ParityTest {
        status: 99,
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn repeated_min_items_violation() {
    let msg = ParityTest {
        tags: vec![],
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn required_message_violation() {
    let msg = ParityTest {
        inner: None,
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

// --- ParityTest: edge cases ---

#[test]
fn ignore_always_skips_validation() {
    let msg = ParityTest {
        ignored: String::new(), // violates min_len:100, but IGNORE_ALWAYS
        ..valid_parity_test()
    };
    assert_both_ok(&msg, "parity.ParityTest");
}

#[test]
fn nested_message_violation() {
    let msg = ParityTest {
        inner: Some(Inner {
            value: String::new(), // violates min_len:1
        }),
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

#[test]
fn multiple_violations() {
    let msg = ParityTest {
        name: "a".to_string(),
        score: 0,
        tags: vec![],
        ..valid_parity_test()
    };
    assert_violations_match(&msg, "parity.ParityTest");
}

// --- ConstInTest ---

#[test]
fn const_in_valid() {
    let msg = ConstInTest {
        exact: "fixed".to_string(),
        pick: 2,
        avoid: 5,
    };
    assert_both_ok(&msg, "parity.ConstInTest");
}

#[test]
fn const_in_violations() {
    let msg = ConstInTest {
        exact: "wrong".to_string(),
        pick: 99,
        avoid: 0,
    };
    assert_violations_match(&msg, "parity.ConstInTest");
}

// --- FieldMaskTest ---

fn valid_field_mask_test() -> FieldMaskTest {
    FieldMaskTest {
        exact_mask: Some(prost_types::FieldMask {
            paths: vec!["a".to_string(), "b".to_string()],
        }),
        allowed_mask: Some(prost_types::FieldMask {
            paths: vec!["x".to_string(), "y".to_string()],
        }),
        blocked_mask: Some(prost_types::FieldMask {
            paths: vec!["public".to_string()],
        }),
    }
}

#[test]
fn field_mask_valid() {
    assert_both_ok(&valid_field_mask_test(), "parity.FieldMaskTest");
}

#[test]
fn field_mask_const_violation() {
    let msg = FieldMaskTest {
        exact_mask: Some(prost_types::FieldMask {
            paths: vec!["wrong".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_violations_match(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_in_violation() {
    let msg = FieldMaskTest {
        allowed_mask: Some(prost_types::FieldMask {
            paths: vec!["not_allowed".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_violations_match(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_not_in_violation() {
    let msg = FieldMaskTest {
        blocked_mask: Some(prost_types::FieldMask {
            paths: vec!["secret".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_violations_match(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_in_subpath_valid() {
    // z.a is allowed, so z.a.b should also be allowed (prefix match)
    let msg = FieldMaskTest {
        allowed_mask: Some(prost_types::FieldMask {
            paths: vec!["z.a.b".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_both_ok(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_not_in_subpath_violation() {
    // internal is blocked, so internal.data should also be blocked (prefix match)
    let msg = FieldMaskTest {
        blocked_mask: Some(prost_types::FieldMask {
            paths: vec!["internal.data".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_violations_match(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_in_rejects_partial_segment_prefix() {
    // Allowed entries: ["x", "y", "z.a"]. A path that *starts with* an
    // allowed entry but does NOT end at a path-segment boundary must be
    // rejected — the coverage check is on segment boundaries (a literal
    // `.`), not on raw string prefixes. Without the boundary check, the
    // old `format!("{prefix}.")` and the new allocation-free
    // `fieldmask_covers` would both have to reject this case.
    let msg = FieldMaskTest {
        allowed_mask: Some(prost_types::FieldMask {
            // "xy" starts with allowed "x" but the next char is `y`, not `.`.
            paths: vec!["xy".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_violations_match(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_in_rejects_partial_multisegment_prefix() {
    // Allowed entries include "z.a". "z.ab" shares the literal `z.a`
    // prefix but the next char is `b`, not `.`.
    let msg = FieldMaskTest {
        allowed_mask: Some(prost_types::FieldMask {
            paths: vec!["z.ab".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_violations_match(&msg, "parity.FieldMaskTest");
}

#[test]
fn field_mask_not_in_allows_partial_segment_prefix() {
    // Blocked entries: ["secret", "internal"]. "secrets" starts with
    // "secret" but the next char is `s`, not `.` — so it must NOT be
    // treated as a sub-path of `secret` and must be allowed through.
    let msg = FieldMaskTest {
        blocked_mask: Some(prost_types::FieldMask {
            paths: vec!["secrets".to_string()],
        }),
        ..valid_field_mask_test()
    };
    assert_both_ok(&msg, "parity.FieldMaskTest");
}

// --- RepeatedFloatUnique: canonical-bits codegen path for float/double ---

#[test]
fn repeated_float_unique_empty_and_distinct_pass() {
    let msg = RepeatedFloatUnique {
        floats: vec![1.0, 2.0, 3.5],
        doubles: vec![1.0, 2.0, 3.5],
    };
    assert_both_ok(&msg, "parity.RepeatedFloatUnique");
}

#[test]
fn repeated_float_unique_duplicate_values_violate() {
    let msg = RepeatedFloatUnique {
        floats: vec![1.0, 2.0, 1.0],
        doubles: vec![3.5, 3.5],
    };
    assert_violations_match(&msg, "parity.RepeatedFloatUnique");
}

#[test]
fn repeated_float_unique_positive_and_negative_zero_collide() {
    // +0.0 and -0.0 share canonical bits → must violate uniqueness on both
    // engines.
    let msg = RepeatedFloatUnique {
        floats: vec![0.0_f32, -0.0_f32],
        doubles: vec![0.0_f64, -0.0_f64],
    };
    assert_violations_match(&msg, "parity.RepeatedFloatUnique");
}

#[test]
fn repeated_float_unique_multiple_nans_are_allowed() {
    // IEEE-754: NaN != NaN. Both engines treat each NaN as never-seen, so
    // multiple NaNs do NOT violate the unique constraint.
    let msg = RepeatedFloatUnique {
        floats: vec![f32::NAN, f32::NAN, 1.0, f32::NAN],
        doubles: vec![f64::NAN, f64::NAN, 1.0],
    };
    assert_both_ok(&msg, "parity.RepeatedFloatUnique");
}

// --- TimestampRelative: lt_now / gt_now / within (1d codegen) ---
//
// Both engines call `SystemTime::now()` at validation time. To make the
// expected outcome deterministic we use timestamps far enough from "now"
// that wall-clock skew between the two paths' clock reads can't flip the
// result: deep past (year ~2001) for must_be_past + within_minute, and
// far future (year ~33658) for must_be_future. The within_minute check
// also uses a far-past value, so its `|ts - now| > 60s` outcome is
// stable.

const PAST_SECONDS: i64 = 1_000_000_000; // 2001-09-09 — comfortably past
const FUTURE_SECONDS: i64 = 1_000_000_000_000; // year ~33658 — comfortably future

fn ts(secs: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: secs,
        nanos: 0,
    }
}

#[test]
fn timestamp_relative_all_satisfied_passes() {
    let msg = TimestampRelative {
        must_be_past: Some(ts(PAST_SECONDS)),
        must_be_future: Some(ts(FUTURE_SECONDS)),
        within_minute: None, // optional; skipping makes the within check inapplicable
    };
    assert_both_ok(&msg, "parity.TimestampRelative");
}

#[test]
fn timestamp_relative_future_value_violates_lt_now() {
    let msg = TimestampRelative {
        must_be_past: Some(ts(FUTURE_SECONDS)), // wrongly in the future
        must_be_future: Some(ts(FUTURE_SECONDS)),
        within_minute: None,
    };
    assert_violations_match(&msg, "parity.TimestampRelative");
}

#[test]
fn timestamp_relative_past_value_violates_gt_now() {
    let msg = TimestampRelative {
        must_be_past: Some(ts(PAST_SECONDS)),
        must_be_future: Some(ts(PAST_SECONDS)), // wrongly in the past
        within_minute: None,
    };
    assert_violations_match(&msg, "parity.TimestampRelative");
}

#[test]
fn timestamp_relative_far_past_violates_within_minute() {
    let msg = TimestampRelative {
        must_be_past: Some(ts(PAST_SECONDS)),
        must_be_future: Some(ts(FUTURE_SECONDS)),
        within_minute: Some(ts(PAST_SECONDS)), // |now - PAST| >> 60s
    };
    assert_violations_match(&msg, "parity.TimestampRelative");
}

#[test]
fn timestamp_relative_all_fields_unset_passes() {
    // None for all timestamp fields. The codegen wraps every check in
    // `if let Some(ref _ts) = self.#field_ident`, so an unset field must
    // skip validation entirely — same as the runtime which only validates
    // present fields. Confirms both engines short-circuit identically.
    let msg = TimestampRelative {
        must_be_past: None,
        must_be_future: None,
        within_minute: None,
    };
    assert_both_ok(&msg, "parity.TimestampRelative");
}

#[test]
fn timestamp_relative_multiple_violations_collected_identically() {
    // Three rules, all violated by the same message. Both engines must
    // accumulate the same three violations in the same order:
    //   - must_be_past in the future (lt_now)
    //   - must_be_future in the past (gt_now)
    //   - within_minute deep in the past (within)
    let msg = TimestampRelative {
        must_be_past: Some(ts(FUTURE_SECONDS)),
        must_be_future: Some(ts(PAST_SECONDS)),
        within_minute: Some(ts(PAST_SECONDS)),
    };
    assert_violations_match(&msg, "parity.TimestampRelative");
}

#[test]
fn timestamp_relative_within_close_to_now_passes() {
    // A timestamp constructed from `now_systemtime()` reads the wall clock
    // at message-construction time; both engines read their own clock at
    // validation time. The diff `|construct - validate|` is microseconds,
    // well within the 60-second window — both engines must pass. This
    // exercises the `within` predicate's happy path (without a fragile
    // exact-boundary test that's not portable across two separate clock
    // reads).
    let now_ish = prost_protovalidate::time::now_systemtime();
    let msg = TimestampRelative {
        must_be_past: Some(ts(PAST_SECONDS)),
        must_be_future: Some(ts(FUTURE_SECONDS)),
        within_minute: Some(now_ish),
    };
    assert_both_ok(&msg, "parity.TimestampRelative");
}

// --- OptionalScalars: proto3 `optional` + IGNORE_IF_ZERO_VALUE (covers A.1) ---

#[test]
fn optional_unset_skips_validation() {
    // All fields unset (None). Runtime treats unset presence fields as the
    // default and skips. Codegen must do the same — and the generated code
    // must type-check against `Option<T>` storage.
    let msg = OptionalScalars::default();
    assert_both_ok(&msg, "parity.OptionalScalars");
}

#[test]
fn optional_zero_matches_runtime_under_ignore_if_zero() {
    // Explicit `Some(zero)` for proto3 optional fields with
    // `IGNORE_IF_ZERO_VALUE`. The two paths must agree on whether the
    // zero value is validated — the parity contract is "match runtime,"
    // not "match a particular interpretation of the spec."
    let msg = OptionalScalars {
        name: Some(String::new()),
        score: Some(0),
        data: Some(Vec::new()),
    };
    let build = msg.validate();
    let runtime = validate_runtime(&msg, "parity.OptionalScalars");
    match (build, runtime) {
        (Ok(()), Ok(())) => {}
        (Err(b), Err(Error::Validation(r))) => {
            assert_eq!(sorted_violations(&b), sorted_violations(&r));
        }
        (build, runtime) => {
            panic!("build-time/runtime disagree:\n  build = {build:?}\n  runtime = {runtime:?}")
        }
    }
}

#[test]
fn optional_set_violates_inner_rules() {
    let msg = OptionalScalars {
        name: Some("a".to_string()), // violates string.min_len = 3
        score: Some(-1),             // violates int32.gte = 1
        data: Some(b"x".to_vec()),   // violates bytes.min_len = 2
    };
    assert_violations_match(&msg, "parity.OptionalScalars");
}

#[test]
fn optional_set_satisfies_inner_rules() {
    let msg = OptionalScalars {
        name: Some("alice".to_string()),
        score: Some(10),
        data: Some(b"data".to_vec()),
    };
    assert_both_ok(&msg, "parity.OptionalScalars");
}

// --- KeywordFields: proto fields named after Rust keywords (covers A.3) ---

#[test]
fn keyword_named_fields_validate() {
    // Empty fields violate string.min_len = 1 — but the point of the test
    // is that the generated `self.r#type` / `self.r#mod` / `self.r#match`
    // accesses even compile.
    let msg = KeywordFields::default();
    assert_violations_match(&msg, "parity.KeywordFields");

    let ok = KeywordFields {
        r#type: "T".to_string(),
        r#mod: "M".to_string(),
        r#match: "X".to_string(),
    };
    assert_both_ok(&ok, "parity.KeywordFields");
}

// --- BytesContainsEmpty: empty `contains` literal must not panic (covers A.2) ---

#[test]
fn bytes_contains_empty_is_a_noop() {
    let msg = BytesContainsEmpty {
        payload: Vec::new(),
    };
    assert_both_ok(&msg, "parity.BytesContainsEmpty");

    let msg2 = BytesContainsEmpty {
        payload: b"non-empty".to_vec(),
    };
    assert_both_ok(&msg2, "parity.BytesContainsEmpty");
}

// --- EnumDefinedOnlyContainers: enum.defined_only in repeated/map (covers A.4) ---

#[test]
fn enum_defined_only_repeated_rejects_undeclared() {
    let msg = EnumDefinedOnlyContainers {
        statuses: vec![parity::Status::Active.into(), 99],
        by_key: std::collections::HashMap::default(),
    };
    assert_violations_match(&msg, "parity.EnumDefinedOnlyContainers");
}

#[test]
fn enum_defined_only_map_value_rejects_undeclared() {
    let mut by_key = std::collections::HashMap::new();
    by_key.insert("alpha".to_string(), parity::Status::Active.into());
    by_key.insert("beta".to_string(), 99);

    let msg = EnumDefinedOnlyContainers {
        statuses: Vec::new(),
        by_key,
    };
    assert_violations_match(&msg, "parity.EnumDefinedOnlyContainers");
}

#[test]
fn enum_defined_only_containers_accept_declared_values() {
    let mut by_key = std::collections::HashMap::new();
    by_key.insert("alpha".to_string(), parity::Status::Active.into());

    let msg = EnumDefinedOnlyContainers {
        statuses: vec![parity::Status::Inactive.into()],
        by_key,
    };
    assert_both_ok(&msg, "parity.EnumDefinedOnlyContainers");
}

// --- MapStringInner: map subscript path parity (covers A.5) ---

#[test]
fn map_string_key_path_parity_for_ascii_key() {
    let mut items = std::collections::HashMap::new();
    items.insert(
        "alpha".to_string(),
        Inner {
            value: String::new(),
        },
    ); // violates string.min_len = 1

    let msg = MapStringInner { items };
    assert_violations_match(&msg, "parity.MapStringInner");
}

#[test]
fn map_string_key_path_parity_for_json_sensitive_keys() {
    // Keys with chars whose `{:?}` Rust debug format diverges from
    // `serde_json` JSON escaping — the parity guard exposes any
    // divergence in the codegen subscript renderer.
    let mut items = std::collections::HashMap::new();
    items.insert(
        "héllo".to_string(),
        Inner {
            value: String::new(),
        },
    );
    items.insert(
        "line\nvalue".to_string(),
        Inner {
            value: String::new(),
        },
    );
    items.insert(
        "\"quoted\"".to_string(),
        Inner {
            value: String::new(),
        },
    );

    let msg = MapStringInner { items };
    assert_violations_match(&msg, "parity.MapStringInner");
}

#[test]
fn map_string_inner_empty_passes() {
    let msg = MapStringInner::default();
    assert_both_ok(&msg, "parity.MapStringInner");
}

// --- MapKeyRules: per-key constraints with `for_key=true` (locks A.1) ---

#[test]
fn map_string_key_min_len_violation_marks_for_key() {
    let mut by_name = std::collections::HashMap::new();
    by_name.insert(String::new(), "irrelevant".to_string()); // key violates min_len=1
    by_name.insert("ok".to_string(), "irrelevant".to_string());

    let msg = MapKeyRules {
        by_name,
        by_id: std::collections::HashMap::default(),
    };
    assert_violations_match(&msg, "parity.MapKeyRules");

    // Belt-and-braces: assert at least one for_key=Some(true) is present on
    // the build-time side so a future drop of `mark_for_key` from codegen
    // would fail loudly even if the runtime were also broken.
    let err = msg.validate().expect_err("build-time should fail");
    assert!(
        err.violations().iter().any(|v| v.for_key() == Some(true)),
        "expected at least one for_key=true violation, got {:?}",
        sorted_violations(&err),
    );
}

#[test]
fn map_int_key_gt_violation_uses_int_subscript() {
    let mut by_id = std::collections::HashMap::new();
    by_id.insert(0, "zero".to_string()); // key violates int32.gt = 0
    by_id.insert(-1, "neg".to_string()); // key violates int32.gt = 0
    by_id.insert(5, "ok".to_string());

    let msg = MapKeyRules {
        by_name: std::collections::HashMap::default(),
        by_id,
    };
    assert_violations_match(&msg, "parity.MapKeyRules");

    let err = msg.validate().expect_err("build-time should fail");
    let for_key_count = err
        .violations()
        .iter()
        .filter(|v| v.for_key() == Some(true))
        .count();
    assert_eq!(
        for_key_count,
        2,
        "expected two for_key violations (keys 0 and -1), got {:?}",
        sorted_violations(&err),
    );
}

#[test]
fn map_key_rules_valid_passes_both_paths() {
    let mut by_name = std::collections::HashMap::new();
    by_name.insert("alpha".to_string(), "v".to_string());
    let mut by_id = std::collections::HashMap::new();
    by_id.insert(1, "v".to_string());

    let msg = MapKeyRules { by_name, by_id };
    assert_both_ok(&msg, "parity.MapKeyRules");
}

// --- Repeated: multi-violation index rendering (locks C.2) ---

#[test]
fn repeated_string_items_emit_indexed_paths() {
    // `tags` has `repeated.min_items: 1, max_items: 5` but no per-item
    // rule. Use `name` for that — wait, `name` is singular. Need a
    // dedicated `repeated string` with `string.min_len` on items. Use the
    // existing `EnumDefinedOnlyContainers.statuses` repeated semantics as
    // a template: assert two failing items produce two violations with
    // distinct `path[idx]` subscripts and the `repeated.items.*` prefix.
    let msg = EnumDefinedOnlyContainers {
        statuses: vec![99, 100, parity::Status::Active.into()],
        by_key: std::collections::HashMap::default(),
    };
    let err = msg.validate().expect_err("build-time should fail");

    let runtime = match validate_runtime(&msg, "parity.EnumDefinedOnlyContainers") {
        Err(Error::Validation(r)) => r,
        other => panic!("runtime should also fail; got {other:?}"),
    };
    assert_eq!(sorted_violations(&err), sorted_violations(&runtime));

    // Plus a direct shape check on what the build-time path emitted.
    let paths: Vec<String> = err.violations().iter().map(Violation::field_path).collect();
    assert!(
        paths.iter().any(|p| p == "statuses[0]"),
        "expected statuses[0] in {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p == "statuses[1]"),
        "expected statuses[1] in {paths:?}"
    );
    assert!(
        err.violations()
            .iter()
            .all(|v| v.rule_path() == "repeated.items.enum.defined_only"),
        "every emitted violation should carry the repeated.items prefix",
    );
}

// --- AllNumericTypes: every prost numeric primitive ---

fn valid_all_numeric_types() -> AllNumericTypes {
    AllNumericTypes {
        a_int64: 50,
        a_uint32: 1,
        a_sint32: 0,
        a_sint64: 0,
        a_fixed32: 7,
        a_fixed64: 5,
        a_sfixed32: 49,
        a_sfixed64: 0,
        a_float: 0.5,
        a_double: 1.0,
    }
}

#[test]
fn all_numeric_types_valid() {
    assert_both_ok(&valid_all_numeric_types(), "parity.AllNumericTypes");
}

#[test]
fn all_numeric_types_all_violate() {
    let msg = AllNumericTypes {
        a_int64: -1,     // gte: 0
        a_uint32: 0,     // gt: 0
        a_sint32: -20,   // gte: -10
        a_sint64: 99,    // in [-1, 0, 1]
        a_fixed32: 8,    // const: 7
        a_fixed64: 1,    // not_in [0, 1]
        a_sfixed32: 100, // lt: 50
        a_sfixed64: -10, // gte: -5
        a_float: 2.0,    // <= 1.0
        a_double: 0.0,   // gt: 0.0
    };
    assert_violations_match(&msg, "parity.AllNumericTypes");
}

// --- StringRuleMatrix: every string rule the smoke test didn't hit ---

fn valid_string_rule_matrix() -> StringRuleMatrix {
    StringRuleMatrix {
        exact_len: "abcd".to_string(),
        with_prefix: "pre-thing".to_string(),
        with_suffix: "thing-end".to_string(),
        with_sub: "the-needle-here".to_string(),
        without_sub: "harmless".to_string(),
        from_list: "a".to_string(),
        not_in_list: "fine".to_string(),
        min_bytes: "abc".to_string(),
        max_bytes: "abcde".to_string(),
    }
}

#[test]
fn string_rule_matrix_valid() {
    assert_both_ok(&valid_string_rule_matrix(), "parity.StringRuleMatrix");
}

#[test]
fn string_rule_matrix_all_violate() {
    let msg = StringRuleMatrix {
        exact_len: "abc".to_string(),         // len != 4
        with_prefix: "no-prefix".to_string(), // missing prefix
        with_suffix: "no-suffix".to_string(), // missing suffix
        with_sub: "haystack".to_string(),     // missing "needle"
        without_sub: "has-secret".to_string(),
        from_list: "z".to_string(),
        not_in_list: "bad".to_string(),
        min_bytes: "a".to_string(),
        max_bytes: "abcdef".to_string(),
    };
    assert_violations_match(&msg, "parity.StringRuleMatrix");
}

// --- StringWellKnown: format validators (delegated to `validators::*`) ---

fn valid_string_well_known() -> StringWellKnown {
    StringWellKnown {
        hostname: "example.com".to_string(),
        ipv4: "192.0.2.1".to_string(),
        ipv6: "2001:db8::1".to_string(),
        uri: "https://example.com/path".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        ulid: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
    }
}

#[test]
fn string_well_known_valid() {
    assert_both_ok(&valid_string_well_known(), "parity.StringWellKnown");
}

#[test]
fn string_well_known_invalid() {
    let msg = StringWellKnown {
        hostname: "not a hostname".to_string(),
        ipv4: "999.999.999.999".to_string(),
        ipv6: "not-an-ipv6".to_string(),
        uri: "not a uri".to_string(),
        uuid: "not-a-uuid".to_string(),
        ulid: "not-a-ulid".to_string(),
    };
    assert_violations_match(&msg, "parity.StringWellKnown");
}

// --- BytesRuleMatrix: every bytes rule the smoke test didn't hit ---

fn valid_bytes_rule_matrix() -> BytesRuleMatrix {
    BytesRuleMatrix {
        exact_len: b"abc".to_vec(),
        min_len: b"ab".to_vec(),
        max_len: b"abc".to_vec(),
        with_prefix: vec![0x01, 0x02, 0x10],
        with_suffix: vec![0x10, 0xff, 0xfe],
        with_sub: b"xabcy".to_vec(),
        pattern: b"12345".to_vec(),
        from_list: b"yes".to_vec(),
        not_in_list: b"fine".to_vec(),
    }
}

#[test]
fn bytes_rule_matrix_valid() {
    assert_both_ok(&valid_bytes_rule_matrix(), "parity.BytesRuleMatrix");
}

#[test]
fn bytes_rule_matrix_all_violate() {
    let msg = BytesRuleMatrix {
        exact_len: b"ab".to_vec(),  // len != 3
        min_len: b"a".to_vec(),     // < 2
        max_len: b"abcde".to_vec(), // > 4
        with_prefix: vec![0x99],    // bad prefix
        with_suffix: vec![0x99],    // bad suffix
        with_sub: b"xyz".to_vec(),  // no "ab"
        pattern: b"abc".to_vec(),   // not [0-9]+
        from_list: b"maybe".to_vec(),
        not_in_list: b"nope".to_vec(),
    };
    assert_violations_match(&msg, "parity.BytesRuleMatrix");
}

// --- DurationTimestampRules: static range rules on both temporal types ---

fn valid_duration_timestamp_rules() -> DurationTimestampRules {
    DurationTimestampRules {
        dur_const: Some(prost_types::Duration {
            seconds: 5,
            nanos: 0,
        }),
        dur_range: Some(prost_types::Duration {
            seconds: 30,
            nanos: 0,
        }),
        ts_const: Some(prost_types::Timestamp {
            seconds: 1000,
            nanos: 0,
        }),
        ts_range: Some(prost_types::Timestamp {
            seconds: 150,
            nanos: 0,
        }),
        // Nanos-tiebreaker bounds: gt {5s, 100n} / lt {100s, 500n}.
        dur_nanos: Some(prost_types::Duration {
            seconds: 5,
            nanos: 200,
        }),
        ts_nanos: Some(prost_types::Timestamp {
            seconds: 100,
            nanos: 400,
        }),
    }
}

#[test]
fn duration_timestamp_valid() {
    assert_both_ok(
        &valid_duration_timestamp_rules(),
        "parity.DurationTimestampRules",
    );
}

#[test]
fn duration_const_violation() {
    let msg = DurationTimestampRules {
        dur_const: Some(prost_types::Duration {
            seconds: 7,
            nanos: 0,
        }),
        ..valid_duration_timestamp_rules()
    };
    assert_violations_match(&msg, "parity.DurationTimestampRules");
}

#[test]
fn duration_range_violation() {
    let msg = DurationTimestampRules {
        dur_range: Some(prost_types::Duration {
            seconds: 90,
            nanos: 0,
        }),
        ..valid_duration_timestamp_rules()
    };
    assert_violations_match(&msg, "parity.DurationTimestampRules");
}

#[test]
fn timestamp_const_violation() {
    let msg = DurationTimestampRules {
        ts_const: Some(prost_types::Timestamp {
            seconds: 999,
            nanos: 0,
        }),
        ..valid_duration_timestamp_rules()
    };
    assert_violations_match(&msg, "parity.DurationTimestampRules");
}

#[test]
fn timestamp_range_violation() {
    let msg = DurationTimestampRules {
        ts_range: Some(prost_types::Timestamp {
            seconds: 50,
            nanos: 0,
        }),
        ..valid_duration_timestamp_rules()
    };
    assert_violations_match(&msg, "parity.DurationTimestampRules");
}

// --- MapScalarValues: per-value scalar rules ---

#[test]
fn map_scalar_values_valid() {
    let mut scores = std::collections::HashMap::new();
    scores.insert("alice".to_string(), 50);
    let mut by_id = std::collections::HashMap::new();
    by_id.insert(1i64, "ok".to_string());

    let msg = MapScalarValues { scores, by_id };
    assert_both_ok(&msg, "parity.MapScalarValues");
}

#[test]
fn map_scalar_values_violation() {
    let mut scores = std::collections::HashMap::new();
    scores.insert("alice".to_string(), 0); // value violates gt: 0
    let mut by_id = std::collections::HashMap::new();
    by_id.insert(0i64, String::new()); // key violates gt:0 AND value violates min_len:1

    let msg = MapScalarValues { scores, by_id };
    assert_violations_match(&msg, "parity.MapScalarValues");
}

// --- RepeatedScalarItems: non-enum item rules ---

#[test]
fn repeated_scalar_items_valid() {
    let msg = RepeatedScalarItems {
        names: vec!["alice".to_string(), "bob".to_string()],
        payloads: vec![b"ABC".to_vec(), b"XYZ".to_vec()],
    };
    assert_both_ok(&msg, "parity.RepeatedScalarItems");
}

#[test]
fn repeated_scalar_items_violations() {
    let msg = RepeatedScalarItems {
        names: vec!["alice".to_string(), "a".to_string()], // [1] violates min_len:2
        payloads: vec![b"ABC".to_vec(), b"abc".to_vec()],  // [1] violates pattern
    };
    assert_violations_match(&msg, "parity.RepeatedScalarItems");
}

// --- VirtualOneof: MessageRules.oneof happy path ---

#[test]
fn virtual_oneof_exactly_one_set() {
    let msg = VirtualOneof {
        a: "value".to_string(),
        b: String::new(),
    };
    assert_both_ok(&msg, "parity.VirtualOneof");
}

#[test]
fn virtual_oneof_none_set_violates_required() {
    let msg = VirtualOneof::default();
    assert_violations_match(&msg, "parity.VirtualOneof");
}

#[test]
fn virtual_oneof_both_set_violates_at_most_one() {
    let msg = VirtualOneof {
        a: "one".to_string(),
        b: "two".to_string(),
    };
    assert_violations_match(&msg, "parity.VirtualOneof");
}

// --- PresenceMix: regression guard for `field_storage_is_option_scalar` ---

#[test]
fn presence_mix_valid() {
    // `maybe_n` is `Option<i32>` (proto3 `optional`); `plain_n` is bare
    // `i32` (proto3 implicit). Both ≥ 0 should pass.
    let msg = PresenceMix {
        maybe_n: Some(5),
        plain_n: 5,
    };
    assert_both_ok(&msg, "parity.PresenceMix");
}

#[test]
fn presence_mix_optional_unset_is_skipped() {
    // Implicit scalars apply the rule unconditionally — `plain_n = -1`
    // violates `int32.gte = 0`. Optional unset (`maybe_n = None`) is
    // skipped (no Option to unwrap).
    let msg = PresenceMix {
        maybe_n: None,
        plain_n: -1,
    };
    assert_violations_match(&msg, "parity.PresenceMix");
}

#[test]
fn presence_mix_optional_set_violates_inner() {
    let msg = PresenceMix {
        maybe_n: Some(-1),
        plain_n: 0,
    };
    assert_violations_match(&msg, "parity.PresenceMix");
}

// --- BytesPatternRaw: F8 regression guard ---

#[test]
fn bytes_pattern_raw_valid_match() {
    // Plain ASCII that matches the regex — both paths OK.
    let msg = BytesPatternRaw {
        value: b"HELLO".to_vec(),
    };
    assert_both_ok(&msg, "parity.BytesPatternRaw");
}

#[test]
fn bytes_pattern_raw_invalid_utf8_paths_diverge_by_design() {
    // Canonical buf protovalidate refuses to apply a regex to non-UTF-8
    // input — the runtime surfaces this as `RuntimeError`. The codegen
    // `Validate` impl can only return `ValidationError`, so it emits a
    // `bytes.pattern` violation instead. The two paths intentionally
    // diverge for this one input shape and we lock that contract here
    // instead of asserting parity.
    let msg = BytesPatternRaw {
        value: vec![0xFF, 0xFE, 0xFD],
    };

    let build_err = msg.validate().expect_err("codegen should emit a violation");
    assert!(
        build_err
            .violations()
            .iter()
            .any(|v| v.rule_id() == "bytes.pattern"),
        "expected a `bytes.pattern` violation, got {build_err:?}",
    );

    match validate_runtime(&msg, "parity.BytesPatternRaw") {
        Err(Error::Runtime(_)) => {}
        other => panic!("runtime should raise RuntimeError on invalid UTF-8, got: {other:?}"),
    }
}

#[test]
fn bytes_pattern_raw_lowercase_violates_both_paths() {
    // Valid UTF-8 but doesn't match `^[A-Z]+$`. Sanity check that the
    // F8 migration did not change behavior for ordinary text input.
    let msg = BytesPatternRaw {
        value: b"hello".to_vec(),
    };
    assert_violations_match(&msg, "parity.BytesPatternRaw");
}

// --- FloatFiniteRules: C1 regression guards (NaN / Infinity / finite) ---

fn valid_float_finite_rules() -> FloatFiniteRules {
    FloatFiniteRules {
        range_f: 50.0,
        gt_only_d: 1.0,
        finite_f: 0.0,
        finite_range: 0.5,
        gt_lt_f: 50.0,
        // `gt_lt_excl_f`: gt=100, lt=0 — exclusive range. Any value outside
        // [0, 100] satisfies (both conditions). Pick 200.0 so the "valid"
        // fixture passes; NaN tests will short-circuit before this check
        // anyway via the NaN range guard.
        gt_lt_excl_f: 200.0,
        gt_lte_d: 50.0,
        // `gte_lt_excl_d`: gte=100, lt=0 — exclusive. Pick 200.0.
        gte_lt_excl_d: 200.0,
        gte_only_f: 0.0,
        lt_only_d: 50.0,
        lte_only_f: 100.0,
    }
}

#[test]
fn float_finite_valid_both_pass() {
    assert_both_ok(&valid_float_finite_rules(), "parity.FloatFiniteRules");
}

#[test]
fn float_range_nan_emits_runtime_rule_id() {
    let msg = FloatFiniteRules {
        range_f: f32::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn double_gt_nan_emits_runtime_rule_id() {
    let msg = FloatFiniteRules {
        gt_only_d: f64::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn float_finite_rule_rejects_nan() {
    let msg = FloatFiniteRules {
        finite_f: f32::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn float_finite_rule_rejects_infinity() {
    let msg = FloatFiniteRules {
        finite_f: f32::INFINITY,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn double_finite_plus_range_emits_only_finite_on_nan() {
    // Runtime returns Err with ONLY the `double.finite` violation for NaN
    // when both `finite=true` and a range bound are set — the range check
    // is short-circuited. Codegen must mirror or parity breaks.
    let msg = FloatFiniteRules {
        finite_range: f64::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn float_plus_infinity_passes_range_when_not_finite_required() {
    // +Inf > 0.0 is true and +Inf compares sensibly against finite range
    // bounds (Inf <= 100.0 → false → violates `lte`). With finite NOT
    // required, runtime emits whatever the comparisons yield; codegen
    // must match.
    let msg = FloatFiniteRules {
        range_f: f32::INFINITY,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

// --- T1: NaN coverage for every distinct nan_range_rule_id branch ---

#[test]
fn nan_gt_lt_inclusive_emits_runtime_rule_id() {
    // gt=0, lt=100, gt < lt → `float.gt_lt`.
    let msg = FloatFiniteRules {
        gt_lt_f: f32::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn nan_gt_lt_exclusive_emits_runtime_rule_id() {
    // gt=100, lt=0, gt > lt → `float.gt_lt_exclusive`.
    let msg = FloatFiniteRules {
        gt_lt_excl_f: f32::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn nan_gt_lte_inclusive_emits_runtime_rule_id() {
    // gt=0, lte=100 → `double.gt_lte`.
    let msg = FloatFiniteRules {
        gt_lte_d: f64::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn nan_gte_lt_exclusive_emits_runtime_rule_id() {
    // gte=100, lt=0, gte >= lt → `double.gte_lt_exclusive`.
    let msg = FloatFiniteRules {
        gte_lt_excl_d: f64::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn nan_gte_only_emits_runtime_rule_id() {
    let msg = FloatFiniteRules {
        gte_only_f: f32::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn nan_lt_only_emits_runtime_rule_id() {
    let msg = FloatFiniteRules {
        lt_only_d: f64::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

#[test]
fn nan_lte_only_emits_runtime_rule_id() {
    let msg = FloatFiniteRules {
        lte_only_f: f32::NAN,
        ..valid_float_finite_rules()
    };
    assert_violations_match(&msg, "parity.FloatFiniteRules");
}

// --- VirtualOneofImplicitIgnore: C2 regression guard ---

fn valid_virtual_oneof_implicit_ignore() -> VirtualOneofImplicitIgnore {
    VirtualOneofImplicitIgnore {
        alpha: String::new(),
        beta: "selected".to_string(),
        gamma: 0,
        delta: Vec::<String>::new(),
        // `epsilon` has explicit IGNORE_ALWAYS — value never validated.
        epsilon: String::new(),
    }
}

#[test]
fn virtual_oneof_unset_member_does_not_emit_inner_rule() {
    // `alpha = ""` is the zero value of a virtual-oneof member without an
    // explicit ignore — runtime applies the implicit `IGNORE_IF_ZERO_VALUE`
    // upgrade. The `string.min_len: 5` rule should NOT fire on `alpha`
    // when `beta` is the set member. Pre-fix codegen emitted a
    // `string.min_len` violation here; both paths now match.
    //
    // Also covers `gamma = 0` (int implicit upgrade) and `delta = []`
    // (repeated implicit upgrade) — all virtual-oneof members at their
    // zero value must skip their inner rules.
    assert_both_ok(
        &valid_virtual_oneof_implicit_ignore(),
        "parity.VirtualOneofImplicitIgnore",
    );
}

#[test]
fn virtual_oneof_set_member_still_validates_inner_rule() {
    // When alpha IS set (non-zero), its own `min_len: 5` rule still applies.
    let msg = VirtualOneofImplicitIgnore {
        alpha: "hi".to_string(),
        beta: String::new(),
        ..valid_virtual_oneof_implicit_ignore()
    };
    assert_violations_match(&msg, "parity.VirtualOneofImplicitIgnore");
}

#[test]
fn virtual_oneof_int_member_zero_does_not_emit_inner_rule() {
    // Numeric storage shape: `gamma = 0` is the zero value; the implicit
    // `IGNORE_IF_ZERO_VALUE` upgrade must skip `int32.gt = 0`.
    let msg = VirtualOneofImplicitIgnore {
        beta: "set".to_string(),
        gamma: 0,
        ..valid_virtual_oneof_implicit_ignore()
    };
    assert_both_ok(&msg, "parity.VirtualOneofImplicitIgnore");
}

#[test]
fn virtual_oneof_int_member_nonzero_validates_inner_rule() {
    // `gamma = -1` is non-zero, so its `int32.gt = 0` rule still applies.
    let msg = VirtualOneofImplicitIgnore {
        beta: String::new(),
        gamma: -1,
        ..valid_virtual_oneof_implicit_ignore()
    };
    assert_violations_match(&msg, "parity.VirtualOneofImplicitIgnore");
}

#[test]
fn virtual_oneof_repeated_member_empty_does_not_emit_inner_rule() {
    // Repeated storage shape: empty `delta` is the zero value; the
    // implicit upgrade must skip `repeated.min_items = 1`.
    let msg = VirtualOneofImplicitIgnore {
        beta: "set".to_string(),
        delta: Vec::<String>::new(),
        ..valid_virtual_oneof_implicit_ignore()
    };
    assert_both_ok(&msg, "parity.VirtualOneofImplicitIgnore");
}

#[test]
fn virtual_oneof_explicit_ignore_always_preserved() {
    // `epsilon` has explicit `IGNORE_ALWAYS` and `string.min_len = 100`.
    // The implicit-upgrade logic must only fire when the explicit ignore
    // is `Unspecified`; an `IGNORE_ALWAYS` must be preserved exactly so
    // the inner rule never fires regardless of value.
    //
    // Set ONLY epsilon to a non-empty string. The virtual oneof's
    // at-most-one constraint is satisfied (count == 1). epsilon's inner
    // `string.min_len = 100` rule must NOT fire because `IGNORE_ALWAYS`
    // takes precedence. Other members at their zero value are implicitly
    // upgraded to `IGNORE_IF_ZERO_VALUE` and skip their own inner rules.
    let msg = VirtualOneofImplicitIgnore {
        alpha: String::new(),
        beta: String::new(),
        gamma: 0,
        delta: Vec::<String>::new(),
        // Would violate `min_len: 100` if the rule were active.
        epsilon: "short".to_string(),
    };
    assert_both_ok(&msg, "parity.VirtualOneofImplicitIgnore");
}

// --- NestedIgnore: C3 regression guards ---

fn valid_nested_ignore() -> NestedIgnore {
    NestedIgnore {
        // `IGNORE_ALWAYS` on items — even invalid items must not produce
        // violations.
        items_skipped: vec!["short".to_string()],
        items_zero_ok: vec![String::new(), "ok".to_string()],
        map_skipped: std::collections::HashMap::from([("any".to_string(), 0_i32)]),
        map_zero_ok: std::collections::HashMap::from([
            ("empty".to_string(), String::new()),
            ("filled".to_string(), "abc".to_string()),
        ]),
        keys_zero_ok: std::collections::HashMap::from([
            // Zero key (0) is skipped by `IGNORE_IF_ZERO_VALUE` on the keys
            // rule. Non-zero key (200) satisfies `int32.gt = 100`.
            (0_i32, "zero-key-skipped".to_string()),
            (200_i32, "non-zero-key-ok".to_string()),
        ]),
    }
}

#[test]
fn nested_ignore_always_skips_invalid_items_both_paths() {
    let msg = valid_nested_ignore();
    assert_both_ok(&msg, "parity.NestedIgnore");
}

#[test]
fn nested_ignore_if_zero_skips_zero_items_validates_others() {
    // Non-zero item below min_len → violation on that item, zero item passes.
    let msg = NestedIgnore {
        items_zero_ok: vec![String::new(), "a".to_string()],
        ..valid_nested_ignore()
    };
    assert_violations_match(&msg, "parity.NestedIgnore");
}

#[test]
fn nested_ignore_if_zero_map_value_skips_empty_validates_others() {
    let msg = NestedIgnore {
        map_zero_ok: std::collections::HashMap::from([
            ("zero".to_string(), String::new()),
            ("short".to_string(), "x".to_string()),
        ]),
        ..valid_nested_ignore()
    };
    assert_violations_match(&msg, "parity.NestedIgnore");
}

#[test]
fn nested_ignore_if_zero_map_key_skips_zero_validates_others() {
    // Key 0 must skip (IGNORE_IF_ZERO_VALUE), key 50 must violate gt=100.
    let msg = NestedIgnore {
        keys_zero_ok: std::collections::HashMap::from([
            (0_i32, "zero-key-skipped".to_string()),
            (50_i32, "non-zero-but-below-100".to_string()),
        ]),
        ..valid_nested_ignore()
    };
    assert_violations_match(&msg, "parity.NestedIgnore");
}

// --- RequiredImplicitScalar: H6 regression guard ---

fn valid_required_implicit_scalar() -> RequiredImplicitScalar {
    RequiredImplicitScalar {
        forced_n: 1,
        forced_s: "x".to_string(),
        forced_b: true,
        forced_by: b"x".to_vec(),
        forced_e: parity::Status::Active.into(),
    }
}

#[test]
fn required_implicit_scalar_non_default_passes_both_paths() {
    // proto3 implicit scalars satisfy `required` when they hold a non-zero
    // value. Critically, the build must compile — pre-fix codegen emitted
    // `self.forced_n.is_none()` against a bare `i32`, which won't compile.
    assert_both_ok(
        &valid_required_implicit_scalar(),
        "parity.RequiredImplicitScalar",
    );
}

#[test]
fn required_implicit_scalar_default_emits_required_violation() {
    // Runtime treats the zero value of a proto3 implicit scalar as "unset"
    // for `required = true` purposes and emits a `required` violation.
    // Codegen must mirror — generating no check at all would make the
    // generated `Validate` impl silently accept invalid messages. Every
    // kind handled by `generate_default_check` is exercised here.
    let msg = RequiredImplicitScalar {
        forced_n: 0,
        forced_s: String::new(),
        forced_b: false,
        forced_by: Vec::<u8>::new(),
        forced_e: 0, // Status::Unspecified
    };
    assert_violations_match(&msg, "parity.RequiredImplicitScalar");
}

#[test]
fn required_implicit_scalar_negative_violates_inner_rule() {
    // The inner `int32.gte = 0` rule still fires on negative values; both
    // paths must agree.
    let msg = RequiredImplicitScalar {
        forced_n: -1,
        ..valid_required_implicit_scalar()
    };
    assert_violations_match(&msg, "parity.RequiredImplicitScalar");
}

#[test]
fn required_implicit_scalar_inner_string_rule_meaningful() {
    // `forced_s` previously had `min_len: 0` (a no-op). It now has
    // `min_len: 1` — a non-empty string passes, an empty string violates
    // both `required` AND `string.min_len`. Both paths must agree.
    let msg = RequiredImplicitScalar {
        forced_s: String::new(),
        ..valid_required_implicit_scalar()
    };
    assert_violations_match(&msg, "parity.RequiredImplicitScalar");
}

#[test]
fn required_implicit_scalar_bool_false_emits_required_only() {
    // Only `forced_b` at its zero (`false`); other fields are valid.
    let msg = RequiredImplicitScalar {
        forced_b: false,
        ..valid_required_implicit_scalar()
    };
    assert_violations_match(&msg, "parity.RequiredImplicitScalar");
}

#[test]
fn required_implicit_scalar_bytes_empty_emits_required_only() {
    let msg = RequiredImplicitScalar {
        forced_by: Vec::<u8>::new(),
        ..valid_required_implicit_scalar()
    };
    assert_violations_match(&msg, "parity.RequiredImplicitScalar");
}

#[test]
fn required_implicit_scalar_enum_zero_emits_required_only() {
    // `Status::Unspecified == 0` — the implicit zero for enums.
    let msg = RequiredImplicitScalar {
        forced_e: 0,
        ..valid_required_implicit_scalar()
    };
    assert_violations_match(&msg, "parity.RequiredImplicitScalar");
}
