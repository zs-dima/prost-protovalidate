//! Descriptor-driven boundary-vector generation for parity sweeps.
//!
//! For every rule found on a message descriptor, emits labeled probe
//! vectors (bounds ±1, lengths n−1/n/n+1, const equal/different, `in`/`not_in`
//! members and outsiders, NaN and infinities for floats). Shared by the
//! prost parity sweep and the buffa parity sweep — the vectors are plain
//! `DynamicMessage`s, so each consumer encodes them to bytes and decodes
//! into its own generated types.
//!
//! One deliberate exception: probes for `bytes.pattern` fields are kept
//! valid-UTF-8. Non-UTF-8 input to `bytes.pattern` is the documented,
//! hand-pinned divergence between the engines (see `tests/parity.rs`).

use std::collections::HashMap;

use prost::Message;
use prost_protovalidate_types::{
    BytesRules, DurationRules, EnumRules, FieldConstraintsExt, FieldMaskRules, FieldRules,
    MapRules, MessageConstraintsExt, RepeatedRules, StringRules, TimestampRules, duration_rules,
    field_rules, timestamp_rules,
};
use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor, Value,
};

/// A timestamp far enough from `now` that time-relative rules (`lt_now`,
/// `gt_now`, `within`) evaluate identically across back-to-back validation
/// calls: 2100-01-01T00:00:00Z.
const FAR_FUTURE_SECONDS: i64 = 4_102_444_800;

/// Generate labeled boundary vectors for a message from its own rules.
///
/// Vectors come back as `DynamicMessage`s built against `desc`; encode them
/// to bytes to drive any generated-`Validate` backend (prost or buffa) and
/// compare against the runtime `Validator` verdict.
pub fn generate_vectors(desc: &MessageDescriptor) -> Vec<(String, DynamicMessage)> {
    let mut vectors = vec![("default".to_string(), DynamicMessage::new(desc.clone()))];

    for field in desc.fields() {
        let Ok(Some(rules)) = field.field_constraints() else {
            continue;
        };
        for (label, value) in field_probes(&field, &rules) {
            let mut msg = DynamicMessage::new(desc.clone());
            msg.set_field(&field, value);
            vectors.push((format!("{}={label}", field.name()), msg));
        }
    }

    // Virtual oneofs: exercise zero (default vector), one, and two members set.
    if let Ok(Some(msg_rules)) = desc.message_constraints() {
        for rule in &msg_rules.oneof {
            let members: Vec<FieldDescriptor> = rule
                .fields
                .iter()
                .filter_map(|name| desc.get_field_by_name(name))
                .collect();
            for member in &members {
                let mut msg = DynamicMessage::new(desc.clone());
                msg.set_field(member, nonzero_value(&member.kind(), member.is_list()));
                vectors.push((format!("oneof:{}", member.name()), msg));
            }
            if let [first, second, ..] = members.as_slice() {
                let mut msg = DynamicMessage::new(desc.clone());
                msg.set_field(first, nonzero_value(&first.kind(), first.is_list()));
                msg.set_field(second, nonzero_value(&second.kind(), second.is_list()));
                vectors.push((format!("oneof:{}+{}", first.name(), second.name()), msg));
            }
        }
    }

    vectors
}

/// Boundary probes for one field, derived from its rules.
fn field_probes(field: &FieldDescriptor, rules: &FieldRules) -> Vec<(String, Value)> {
    let mut probes = Vec::new();

    match &rules.r#type {
        Some(field_rules::Type::Repeated(repeated)) => {
            probes.extend(repeated_probes(field, repeated));
        }
        Some(field_rules::Type::Map(map)) => {
            probes.extend(map_probes(field, map));
        }
        Some(other) => {
            for (label, value) in scalar_probes(field, &field.kind(), other) {
                probes.push((label, value));
            }
        }
        None => {}
    }

    // `required` message fields: an empty-but-present nested message drives
    // nested validation and the presence check on both paths.
    if let Kind::Message(nested) = field.kind() {
        if !field.is_list() && !field.is_map() && !is_well_known(&nested) {
            probes.push((
                "empty_message".to_string(),
                Value::Message(DynamicMessage::new(nested)),
            ));
        }
    }

    probes
}

/// Extract combined numeric bounds and dispatch to the shared probe builder.
macro_rules! numeric_case {
    ($r:expr, $mod:ident, $to:expr) => {{
        use prost_protovalidate_types::$mod::{GreaterThan, LessThan};
        int_probes(
            $r.r#const,
            $r.less_than.as_ref().map(|b| match b {
                LessThan::Lt(v) | LessThan::Lte(v) => *v,
            }),
            $r.greater_than.as_ref().map(|b| match b {
                GreaterThan::Gt(v) | GreaterThan::Gte(v) => *v,
            }),
            &$r.r#in,
            &$r.not_in,
            $to,
        )
    }};
}

/// Probes for scalar-shaped rules (everything except repeated/map wrappers).
fn scalar_probes(
    field: &FieldDescriptor,
    kind: &Kind,
    rule: &field_rules::Type,
) -> Vec<(String, Value)> {
    use field_rules::Type;

    match rule {
        Type::Int32(r) => numeric_case!(r, int32_rules, Value::I32),
        Type::Int64(r) => numeric_case!(r, int64_rules, Value::I64),
        Type::Sint32(r) => numeric_case!(r, s_int32_rules, Value::I32),
        Type::Sint64(r) => numeric_case!(r, s_int64_rules, Value::I64),
        Type::Sfixed32(r) => numeric_case!(r, s_fixed32_rules, Value::I32),
        Type::Sfixed64(r) => numeric_case!(r, s_fixed64_rules, Value::I64),
        Type::Uint32(r) => numeric_case!(r, u_int32_rules, Value::U32),
        Type::Uint64(r) => numeric_case!(r, u_int64_rules, Value::U64),
        Type::Fixed32(r) => numeric_case!(r, fixed32_rules, Value::U32),
        Type::Fixed64(r) => numeric_case!(r, fixed64_rules, Value::U64),
        Type::Float(r) => {
            use prost_protovalidate_types::float_rules::{GreaterThan, LessThan};
            float_probes(
                r.r#const.map(f64::from),
                r.less_than.as_ref().map(|b| match b {
                    LessThan::Lt(v) | LessThan::Lte(v) => f64::from(*v),
                }),
                r.greater_than.as_ref().map(|b| match b {
                    GreaterThan::Gt(v) | GreaterThan::Gte(v) => f64::from(*v),
                }),
                |v| {
                    #[allow(clippy::cast_possible_truncation)]
                    Value::F32(v as f32)
                },
            )
        }
        Type::Double(r) => {
            use prost_protovalidate_types::double_rules::{GreaterThan, LessThan};
            float_probes(
                r.r#const,
                r.less_than.as_ref().map(|b| match b {
                    LessThan::Lt(v) | LessThan::Lte(v) => *v,
                }),
                r.greater_than.as_ref().map(|b| match b {
                    GreaterThan::Gt(v) | GreaterThan::Gte(v) => *v,
                }),
                Value::F64,
            )
        }
        Type::Bool(_) => vec![
            ("true".to_string(), Value::Bool(true)),
            ("false".to_string(), Value::Bool(false)),
        ],
        Type::String(r) => string_probes(r),
        Type::Bytes(r) => bytes_probes(r),
        Type::Enum(r) => enum_probes(r),
        Type::Any(r) => any_probes(field, r),
        Type::Duration(r) => duration_probes(field, r),
        Type::Timestamp(r) => timestamp_probes(field, r),
        Type::FieldMask(r) => field_mask_probes(field, r),
        // Any / repeated / map are handled elsewhere; kinds without probe
        // support fall back to a presence probe so the vector set is never
        // empty for a rule-bearing field.
        _ => vec![("nonzero".to_string(), nonzero_value(kind, false))],
    }
}

fn int_probes<T>(
    r#const: Option<T>,
    lt_or_lte: Option<T>,
    gt_or_gte: Option<T>,
    in_list: &[T],
    not_in: &[T],
    to_value: impl Fn(T) -> Value,
) -> Vec<(String, Value)>
where
    T: Copy + std::fmt::Display + num_ops::CheckedStep + Ord,
{
    let mut out = Vec::new();
    for b in [r#const, lt_or_lte, gt_or_gte].into_iter().flatten() {
        for v in [b.step_down(), Some(b), b.step_up()].into_iter().flatten() {
            out.push((format!("{v}"), to_value(v)));
        }
    }
    if let Some(first) = in_list.first() {
        out.push((format!("in:{first}"), to_value(*first)));
        if let Some(outsider) = in_list
            .iter()
            .max()
            .copied()
            .and_then(num_ops::CheckedStep::step_up)
        {
            out.push((format!("in_outsider:{outsider}"), to_value(outsider)));
        }
    }
    if let Some(first) = not_in.first() {
        out.push((format!("not_in:{first}"), to_value(*first)));
    }
    out
}

/// Checked ±1 stepping for integer boundary probes.
mod num_ops {
    pub trait CheckedStep: Sized {
        fn step_up(self) -> Option<Self>;
        fn step_down(self) -> Option<Self>;
    }

    macro_rules! impl_checked_step {
        ($($t:ty),*) => {$(
            impl CheckedStep for $t {
                fn step_up(self) -> Option<Self> {
                    self.checked_add(1)
                }
                fn step_down(self) -> Option<Self> {
                    self.checked_sub(1)
                }
            }
        )*};
    }

    impl_checked_step!(i32, i64, u32, u64);
}

fn float_probes(
    r#const: Option<f64>,
    lt_or_lte: Option<f64>,
    gt_or_gte: Option<f64>,
    to_value: impl Fn(f64) -> Value,
) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for b in [r#const, lt_or_lte, gt_or_gte].into_iter().flatten() {
        for v in [b.next_down(), b, b.next_up(), b - 1.0, b + 1.0] {
            out.push((format!("{v}"), to_value(v)));
        }
    }
    // Non-finite probes exercise NaN range semantics and the `finite` rule
    // regardless of which rules are present.
    out.push(("NaN".to_string(), to_value(f64::NAN)));
    out.push(("+Inf".to_string(), to_value(f64::INFINITY)));
    out.push(("-Inf".to_string(), to_value(f64::NEG_INFINITY)));
    out
}

fn string_probes(r: &StringRules) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut push = |label: String, s: String| out.push((label, Value::String(s)));

    for (name, len) in [
        ("len", r.len),
        ("min_len", r.min_len),
        ("max_len", r.max_len),
        ("len_bytes", r.len_bytes),
        ("min_bytes", r.min_bytes),
        ("max_bytes", r.max_bytes),
    ] {
        if let Some(n) = len {
            #[allow(clippy::cast_possible_truncation)]
            let n = n as usize;
            for k in [n.saturating_sub(1), n, n + 1] {
                push(format!("{name}:{k}"), "a".repeat(k));
                push(format!("{name}:{k}:multibyte"), "\u{e9}".repeat(k));
            }
        }
    }
    if let Some(c) = &r.r#const {
        push("const_eq".to_string(), c.clone());
        push("const_ne".to_string(), format!("{c}x"));
    }
    if r.pattern.is_some() {
        push("pattern_probe_a".to_string(), "a".to_string());
        push("pattern_probe_upper".to_string(), "ABC".to_string());
    }
    if let Some(p) = &r.prefix {
        push("prefix_hit".to_string(), format!("{p}tail"));
        push("prefix_miss".to_string(), "zzz".to_string());
    }
    if let Some(s) = &r.suffix {
        push("suffix_hit".to_string(), format!("head{s}"));
        push("suffix_miss".to_string(), "zzz".to_string());
    }
    if let Some(c) = &r.contains {
        push("contains_hit".to_string(), format!("<{c}>"));
        push("contains_miss".to_string(), "zzz".to_string());
    }
    if let Some(c) = &r.not_contains {
        push("not_contains_hit".to_string(), format!("<{c}>"));
        push("not_contains_miss".to_string(), "ok".to_string());
    }
    if let Some(first) = r.r#in.first() {
        push("in_member".to_string(), first.clone());
        push(
            "in_outsider".to_string(),
            "certainly-not-in-list".to_string(),
        );
    }
    if let Some(first) = r.not_in.first() {
        push("not_in_member".to_string(), first.clone());
    }
    if r.well_known.is_some() {
        for (label, probe) in [
            ("wk_empty", ""),
            ("wk_junk", "definitely not valid ~~"),
            ("wk_hostname", "example.com"),
            ("wk_email", "a@b.io"),
            ("wk_ipv4", "127.0.0.1"),
            ("wk_ipv6", "::1"),
            ("wk_uri", "https://example.com/p?q=1"),
            ("wk_uuid", "550e8400-e29b-41d4-a716-446655440000"),
            ("wk_ulid", "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        ] {
            push(label.to_string(), probe.to_string());
        }
    }
    out
}

fn bytes_probes(r: &BytesRules) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut push = |label: String, b: Vec<u8>| {
        out.push((label, Value::Bytes(prost::bytes::Bytes::from(b))));
    };

    for (name, len) in [
        ("len", r.len),
        ("min_len", r.min_len),
        ("max_len", r.max_len),
    ] {
        if let Some(n) = len {
            #[allow(clippy::cast_possible_truncation)]
            let n = n as usize;
            for k in [n.saturating_sub(1), n, n + 1] {
                push(format!("{name}:{k}"), vec![b'a'; k]);
            }
        }
    }
    if let Some(c) = &r.r#const {
        push("const_eq".to_string(), c.clone());
        let mut ne = c.clone();
        ne.push(b'x');
        push("const_ne".to_string(), ne);
    }
    if r.pattern.is_some() {
        // Valid-UTF-8 only: non-UTF-8 + pattern is the pinned divergence.
        push("pattern_digits".to_string(), b"123".to_vec());
        push("pattern_alpha".to_string(), b"abc".to_vec());
    }
    if let Some(p) = &r.prefix {
        let mut hit = p.clone();
        hit.extend_from_slice(b"tail");
        push("prefix_hit".to_string(), hit);
        push("prefix_miss".to_string(), b"zzz".to_vec());
    }
    if let Some(s) = &r.suffix {
        let mut hit = b"head".to_vec();
        hit.extend_from_slice(s);
        push("suffix_hit".to_string(), hit);
        push("suffix_miss".to_string(), b"zzz".to_vec());
    }
    if let Some(c) = &r.contains {
        let mut hit = b"<".to_vec();
        hit.extend_from_slice(c);
        hit.push(b'>');
        push("contains_hit".to_string(), hit);
        push("contains_miss".to_string(), b"zzz".to_vec());
    }
    if let Some(first) = r.r#in.first() {
        push("in_member".to_string(), first.clone());
        push("in_outsider".to_string(), b"certainly-not-in".to_vec());
    }
    if let Some(first) = r.not_in.first() {
        push("not_in_member".to_string(), first.clone());
    }
    if r.well_known.is_some() {
        push("wk_4bytes".to_string(), vec![127, 0, 0, 1]);
        push("wk_junk".to_string(), b"xy".to_vec());
    }
    out
}

fn enum_probes(r: &EnumRules) -> Vec<(String, Value)> {
    let mut out = vec![
        ("zero".to_string(), Value::EnumNumber(0)),
        ("one".to_string(), Value::EnumNumber(1)),
        ("undefined".to_string(), Value::EnumNumber(99)),
    ];
    if let Some(c) = r.r#const {
        out.push((format!("const:{c}"), Value::EnumNumber(c)));
    }
    if let Some(first) = r.r#in.first() {
        out.push((format!("in:{first}"), Value::EnumNumber(*first)));
    }
    if let Some(first) = r.not_in.first() {
        out.push((format!("not_in:{first}"), Value::EnumNumber(*first)));
    }
    out
}

fn around(probes: &mut Vec<(i64, i32)>, s: i64, n: i32) {
    probes.extend([(s - 1, n), (s, n), (s + 1, n), (s, n + 1)]);
    if n > 0 {
        probes.push((s, n - 1));
    }
}

fn duration_probes(field: &FieldDescriptor, r: &DurationRules) -> Vec<(String, Value)> {
    let mut probes: Vec<(i64, i32)> = Vec::new();
    if let Some(d) = &r.r#const {
        around(&mut probes, d.seconds, d.nanos);
    }
    match &r.less_than {
        Some(duration_rules::LessThan::Lt(d) | duration_rules::LessThan::Lte(d)) => {
            around(&mut probes, d.seconds, d.nanos);
        }
        None => {}
    }
    match &r.greater_than {
        Some(duration_rules::GreaterThan::Gt(d) | duration_rules::GreaterThan::Gte(d)) => {
            around(&mut probes, d.seconds, d.nanos);
        }
        None => {}
    }
    for d in r.r#in.iter().chain(r.not_in.iter()).take(1) {
        probes.extend([(d.seconds, d.nanos), (d.seconds + 9999, 0)]);
    }

    probes
        .into_iter()
        .map(|(s, n)| {
            (
                format!("{s}s{n}n"),
                wkt_value(
                    field,
                    &prost_types::Duration {
                        seconds: s,
                        nanos: n,
                    },
                ),
            )
        })
        .collect()
}

fn timestamp_probes(field: &FieldDescriptor, r: &TimestampRules) -> Vec<(String, Value)> {
    let mut probes: Vec<(i64, i32)> = Vec::new();
    if let Some(t) = &r.r#const {
        around(&mut probes, t.seconds, t.nanos);
    }
    match &r.less_than {
        Some(timestamp_rules::LessThan::Lt(t) | timestamp_rules::LessThan::Lte(t)) => {
            around(&mut probes, t.seconds, t.nanos);
        }
        // `lt_now`: deterministic probes far from the moving boundary.
        Some(timestamp_rules::LessThan::LtNow(_)) => {
            probes.extend([(0, 0), (FAR_FUTURE_SECONDS, 0)]);
        }
        None => {}
    }
    match &r.greater_than {
        Some(timestamp_rules::GreaterThan::Gt(t) | timestamp_rules::GreaterThan::Gte(t)) => {
            around(&mut probes, t.seconds, t.nanos);
        }
        Some(timestamp_rules::GreaterThan::GtNow(_)) => {
            probes.extend([(0, 0), (FAR_FUTURE_SECONDS, 0)]);
        }
        None => {}
    }
    if r.within.is_some() {
        probes.extend([(0, 0), (FAR_FUTURE_SECONDS, 0)]);
    }

    probes
        .into_iter()
        .map(|(s, n)| {
            (
                format!("{s}s{n}n"),
                wkt_value(
                    field,
                    &prost_types::Timestamp {
                        seconds: s,
                        nanos: n,
                    },
                ),
            )
        })
        .collect()
}

fn field_mask_probes(field: &FieldDescriptor, r: &FieldMaskRules) -> Vec<(String, Value)> {
    let mut masks: Vec<(String, Vec<String>)> = vec![
        ("mask_nope".to_string(), vec!["nope".to_string()]),
        ("mask_empty_path".to_string(), vec![]),
    ];
    if let Some(c) = &r.r#const {
        masks.push(("mask_const_eq".to_string(), c.paths.clone()));
    }
    if let Some(first) = r.r#in.first() {
        masks.push(("mask_in_member".to_string(), vec![first.clone()]));
    }
    if let Some(first) = r.not_in.first() {
        masks.push(("mask_not_in_member".to_string(), vec![first.clone()]));
    }

    masks
        .into_iter()
        .map(|(label, paths)| (label, wkt_value(field, &prost_types::FieldMask { paths })))
        .collect()
}

fn repeated_probes(field: &FieldDescriptor, r: &RepeatedRules) -> Vec<(String, Value)> {
    let item_kind = field.kind();
    let mut out = Vec::new();

    for (name, bound) in [("min_items", r.min_items), ("max_items", r.max_items)] {
        if let Some(n) = bound {
            #[allow(clippy::cast_possible_truncation)]
            let n = n as usize;
            for k in [n.saturating_sub(1), n, n + 1] {
                let items = vec![nonzero_value(&item_kind, false); k];
                out.push((format!("{name}:{k}"), Value::List(items)));
            }
        }
    }
    if r.unique == Some(true) {
        let dup = nonzero_value(&item_kind, false);
        out.push((
            "unique_dup".to_string(),
            Value::List(vec![dup.clone(), dup]),
        ));
        match item_kind {
            Kind::Float => {
                out.push((
                    "unique_signed_zero".to_string(),
                    Value::List(vec![Value::F32(0.0), Value::F32(-0.0)]),
                ));
                out.push((
                    "unique_nan_pair".to_string(),
                    Value::List(vec![Value::F32(f32::NAN), Value::F32(f32::NAN)]),
                ));
            }
            Kind::Double => {
                out.push((
                    "unique_signed_zero".to_string(),
                    Value::List(vec![Value::F64(0.0), Value::F64(-0.0)]),
                ));
                out.push((
                    "unique_nan_pair".to_string(),
                    Value::List(vec![Value::F64(f64::NAN), Value::F64(f64::NAN)]),
                ));
            }
            _ => {}
        }
    }
    if let Some(items) = &r.items {
        if let Some(rule) = &items.r#type {
            for (label, value) in scalar_probes(field, &item_kind, rule) {
                out.push((format!("item[{label}]"), Value::List(vec![value])));
            }
        }
    }
    out
}

fn map_probes(field: &FieldDescriptor, r: &MapRules) -> Vec<(String, Value)> {
    let Kind::Message(entry) = field.kind() else {
        return Vec::new();
    };
    let key_field = entry.map_entry_key_field();
    let value_field = entry.map_entry_value_field();
    let key_kind = key_field.kind();
    let value_kind = value_field.kind();

    let mut out = Vec::new();

    for (name, bound) in [("min_pairs", r.min_pairs), ("max_pairs", r.max_pairs)] {
        if let Some(n) = bound {
            #[allow(clippy::cast_possible_truncation)]
            let n = n as usize;
            for k in [n.saturating_sub(1), n, n + 1] {
                let mut map = HashMap::new();
                for i in 1..=k {
                    map.insert(
                        indexed_map_key(&key_kind, i),
                        nonzero_value(&value_kind, false),
                    );
                }
                out.push((format!("{name}:{k}"), Value::Map(map)));
            }
        }
    }

    if let Some(keys) = &r.keys {
        if let Some(rule) = &keys.r#type {
            for (label, value) in scalar_probes(field, &key_kind, rule) {
                if let Some(key) = value_to_map_key(&value) {
                    let mut map = HashMap::new();
                    map.insert(key, nonzero_value(&value_kind, false));
                    out.push((format!("key[{label}]"), Value::Map(map)));
                }
            }
        }
    }
    if let Some(values) = &r.values {
        if let Some(rule) = &values.r#type {
            for (label, value) in scalar_probes(field, &value_kind, rule) {
                let mut map = HashMap::new();
                map.insert(indexed_map_key(&key_kind, 1), value);
                out.push((format!("value[{label}]"), Value::Map(map)));
            }
        }
    }
    // Message-valued maps without explicit rules: one empty nested message
    // drives nested validation (e.g. `map<string, Inner>`).
    if let Kind::Message(nested) = &value_kind {
        if !is_well_known(nested) {
            let mut map = HashMap::new();
            map.insert(
                indexed_map_key(&key_kind, 1),
                Value::Message(DynamicMessage::new(nested.clone())),
            );
            out.push(("value_empty_message".to_string(), Value::Map(map)));
        }
    }

    out
}

/// Probes for `google.protobuf.Any` rules: an empty `Any`, plus the first
/// `in` entry (pass case) and the first `not_in` entry (block-list
/// violation) as `type_url` values — asserting both `any.in` and
/// `any.not_in` message text on both engines.
fn any_probes(
    field: &FieldDescriptor,
    r: &prost_protovalidate_types::AnyRules,
) -> Vec<(String, Value)> {
    let Kind::Message(desc) = field.kind() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut push = |label: &str, type_url: Option<&str>| {
        let mut msg = DynamicMessage::new(desc.clone());
        if let Some(url) = type_url {
            msg.set_field_by_name("type_url", Value::String(url.to_string()));
        }
        out.push((label.to_string(), Value::Message(msg)));
    };
    push("any_empty", None);
    if let Some(first) = r.r#in.first() {
        push("any_in_member", Some(first));
    }
    if let Some(first) = r.not_in.first() {
        push("any_not_in_member", Some(first));
    }
    out
}

/// Build the i-th synthetic map key for a key kind (1-based, non-zero).
fn indexed_map_key(kind: &Kind, i: usize) -> MapKey {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    match kind {
        Kind::String => MapKey::String(format!("k{i}")),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => MapKey::I32(i as i32),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => MapKey::I64(i as i64),
        Kind::Uint32 | Kind::Fixed32 => MapKey::U32(i as u32),
        Kind::Uint64 | Kind::Fixed64 => MapKey::U64(i as u64),
        Kind::Bool => MapKey::Bool(i % 2 == 1),
        other => panic!("unsupported map key kind: {other:?}"),
    }
}

fn value_to_map_key(value: &Value) -> Option<MapKey> {
    match value {
        Value::String(s) => Some(MapKey::String(s.clone())),
        Value::I32(v) => Some(MapKey::I32(*v)),
        Value::I64(v) => Some(MapKey::I64(*v)),
        Value::U32(v) => Some(MapKey::U32(*v)),
        Value::U64(v) => Some(MapKey::U64(*v)),
        Value::Bool(v) => Some(MapKey::Bool(*v)),
        _ => None,
    }
}

/// A non-default value for a field kind (used for oneof members, list items,
/// and map values where the concrete value is irrelevant).
fn nonzero_value(kind: &Kind, is_list: bool) -> Value {
    if is_list {
        return Value::List(vec![nonzero_value(kind, false)]);
    }
    match kind {
        Kind::String => Value::String("x".to_string()),
        Kind::Bytes => Value::Bytes(prost::bytes::Bytes::from_static(b"x")),
        Kind::Bool => Value::Bool(true),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Value::I32(1),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Value::I64(1),
        Kind::Uint32 | Kind::Fixed32 => Value::U32(1),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(1),
        Kind::Float => Value::F32(1.0),
        Kind::Double => Value::F64(1.0),
        Kind::Enum(_) => Value::EnumNumber(1),
        Kind::Message(desc) => Value::Message(DynamicMessage::new(desc.clone())),
    }
}

/// Encode a well-known-type prost struct into a dynamic field value.
fn wkt_value<M: Message>(field: &FieldDescriptor, message: &M) -> Value {
    let Kind::Message(desc) = field.kind() else {
        panic!("expected message kind for {}", field.full_name());
    };
    let dynamic = DynamicMessage::decode(desc, message.encode_to_vec().as_slice())
        .expect("well-known type transcodes");
    Value::Message(dynamic)
}

fn is_well_known(desc: &MessageDescriptor) -> bool {
    desc.full_name().starts_with("google.protobuf.")
}
