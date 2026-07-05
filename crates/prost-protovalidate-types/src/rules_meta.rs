//! Canonical rule metadata shared by the runtime validator and the
//! build-time code generator.
//!
//! This module is the single source of truth for `buf.validate` rule
//! identifiers, violation message text, and rule-combination tables that
//! both validation engines must agree on byte-for-byte. The runtime crate
//! (`prost-protovalidate`) consumes it while compiling evaluators; the build
//! crate (`prost-protovalidate-build`) consumes it while emitting generated
//! validators, embedding the results as literals.
//!
//! Message text tracks the upstream protovalidate conformance corpus and may
//! change in minor releases; it is not a stability surface of its own.

/// Metadata shared by all twelve proto numeric types
/// (`int32`…`sfixed64`, `float`, `double`).
pub mod numeric {
    use std::fmt::Display;

    /// The violation message for `<numeric>.in`.
    pub const IN_MESSAGE: &str = "value must be in list";
    /// The violation message for `<numeric>.not_in`.
    pub const NOT_IN_MESSAGE: &str = "value must not be in list";
    /// The violation message for `float.finite` / `double.finite`.
    pub const FINITE_MESSAGE: &str = "value must be finite";

    /// Rule id for `const`, e.g. `int32.const`.
    #[must_use]
    pub fn const_id(prefix: &str) -> String {
        format!("{prefix}.const")
    }

    /// Rule id for `in`, e.g. `int32.in`.
    #[must_use]
    pub fn in_id(prefix: &str) -> String {
        format!("{prefix}.in")
    }

    /// Rule id for `not_in`, e.g. `int32.not_in`.
    #[must_use]
    pub fn not_in_id(prefix: &str) -> String {
        format!("{prefix}.not_in")
    }

    /// Rule id for `finite`, e.g. `float.finite`.
    #[must_use]
    pub fn finite_id(prefix: &str) -> String {
        format!("{prefix}.finite")
    }

    /// The violation message for `const`.
    #[must_use]
    pub fn const_message<T: Display>(want: T) -> String {
        format!("value must equal {want}")
    }

    /// How the `gt`/`gte` and `lt`/`lte` bounds combine.
    ///
    /// When both sides are present and the lower bound lies below the upper
    /// bound, the range is inclusive (value must satisfy both, message joins
    /// with "and"); when inverted, the range is exclusive (value must
    /// satisfy either, message joins with "or"). [`range_rule`] selects the
    /// variant from the bounds; evaluation applies the matching predicate
    /// through [`RangeKind::violated`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RangeKind {
        /// `gt < lt`: value must be `> gt` and `< lt`.
        GtLt,
        /// `gt >= lt`: value must be `> gt` or `< lt`.
        GtLtExclusive,
        /// `gt < lte`: value must be `> gt` and `<= lte`.
        GtLte,
        /// `gt >= lte`: value must be `> gt` or `<= lte`.
        GtLteExclusive,
        /// `gte < lt`: value must be `>= gte` and `< lt`.
        GteLt,
        /// `gte >= lt`: value must be `>= gte` or `< lt`.
        GteLtExclusive,
        /// `gte <= lte`: value must be `>= gte` and `<= lte`.
        GteLte,
        /// `gte > lte`: value must be `>= gte` or `<= lte`.
        GteLteExclusive,
        /// Only `gt` is set.
        Gt,
        /// Only `gte` is set.
        Gte,
        /// Only `lt` is set.
        Lt,
        /// Only `lte` is set.
        Lte,
    }

    impl RangeKind {
        /// Whether `v` violates this range. `gt` carries the `gt`/`gte`
        /// bound, `lt` the `lt`/`lte` bound; a variant ignores bounds it
        /// does not use and reports no violation when a bound it needs is
        /// missing.
        ///
        /// The build-time code generator emits the token-level equivalent of
        /// this predicate; the parity suites pin the correspondence.
        #[must_use]
        pub fn violated<T: PartialOrd + Copy>(self, gt: Option<T>, lt: Option<T>, v: T) -> bool {
            match self {
                Self::Gt => gt.is_some_and(|g| v <= g),
                Self::Gte => gt.is_some_and(|g| v < g),
                Self::Lt => lt.is_some_and(|l| v >= l),
                Self::Lte => lt.is_some_and(|l| v > l),
                Self::GtLt => gt.zip(lt).is_some_and(|(g, l)| v <= g || v >= l),
                Self::GtLtExclusive => gt.zip(lt).is_some_and(|(g, l)| v >= l && v <= g),
                Self::GtLte => gt.zip(lt).is_some_and(|(g, l)| v <= g || v > l),
                Self::GtLteExclusive => gt.zip(lt).is_some_and(|(g, l)| v > l && v <= g),
                Self::GteLt => gt.zip(lt).is_some_and(|(g, l)| v < g || v >= l),
                Self::GteLtExclusive => gt.zip(lt).is_some_and(|(g, l)| v >= l && v < g),
                Self::GteLte => gt.zip(lt).is_some_and(|(g, l)| v < g || v > l),
                Self::GteLteExclusive => gt.zip(lt).is_some_and(|(g, l)| v > l && v < g),
            }
        }
    }

    /// A fully resolved range rule: the combination variant plus the exact
    /// identifier, rule path, and message text both engines must emit.
    #[derive(Debug, Clone)]
    pub struct RangeRule {
        /// Selected bound combination.
        pub kind: RangeKind,
        /// e.g. `int32.gte_lte` or `float.gt`.
        pub rule_id: String,
        /// For combined bounds, the `greater_than` side (`<prefix>.gt` /
        /// `<prefix>.gte`); equals `rule_id` for single bounds.
        pub rule_path: String,
        /// Human-readable violation message with the bounds rendered in.
        pub message: String,
    }

    /// Resolve the range rule for a set of bounds, or `None` when no bound
    /// is set.
    ///
    /// `fmt` renders a bound into the message; pass a formatter over the
    /// exact wire scalar (`f32` for `float` rules — widening to `f64` first
    /// changes the rendered digits).
    #[must_use]
    pub fn range_rule<T: PartialOrd + Copy>(
        prefix: &str,
        gt: Option<T>,
        gte: Option<T>,
        lt: Option<T>,
        lte: Option<T>,
        fmt: impl Fn(&T) -> String,
    ) -> Option<RangeRule> {
        let (g_label, g_desc, g_bound, g_is_eq) = match (&gt, &gte) {
            (Some(g), None) => ("gt", "greater than", Some(g), false),
            (None, Some(g)) => ("gte", "greater than or equal to", Some(g), true),
            _ => ("", "", None, false),
        };
        let (l_label, l_desc, l_bound, l_is_eq) = match (&lt, &lte) {
            (Some(l), None) => ("lt", "less than", Some(l), false),
            (None, Some(l)) => ("lte", "less than or equal to", Some(l), true),
            _ => ("", "", None, false),
        };

        match (g_bound, l_bound) {
            (Some(g), Some(l)) => {
                // `gte`+`lte` treats equal bounds as inclusive; other
                // combinations require strict ordering.
                let inclusive = if g_is_eq && l_is_eq { g <= l } else { g < l };
                let kind = match (g_is_eq, l_is_eq, inclusive) {
                    (false, false, true) => RangeKind::GtLt,
                    (false, false, false) => RangeKind::GtLtExclusive,
                    (false, true, true) => RangeKind::GtLte,
                    (false, true, false) => RangeKind::GtLteExclusive,
                    (true, false, true) => RangeKind::GteLt,
                    (true, false, false) => RangeKind::GteLtExclusive,
                    (true, true, true) => RangeKind::GteLte,
                    (true, true, false) => RangeKind::GteLteExclusive,
                };
                let (suffix, joiner) = if inclusive {
                    ("", "and")
                } else {
                    ("_exclusive", "or")
                };
                Some(RangeRule {
                    kind,
                    rule_id: format!("{prefix}.{g_label}_{l_label}{suffix}"),
                    rule_path: format!("{prefix}.{g_label}"),
                    message: format!(
                        "value must be {g_desc} {} {joiner} {l_desc} {}",
                        fmt(g),
                        fmt(l)
                    ),
                })
            }
            (Some(g), None) => Some(RangeRule {
                kind: if g_is_eq {
                    RangeKind::Gte
                } else {
                    RangeKind::Gt
                },
                rule_id: format!("{prefix}.{g_label}"),
                rule_path: format!("{prefix}.{g_label}"),
                message: format!("value must be {g_desc} {}", fmt(g)),
            }),
            (None, Some(l)) => Some(RangeRule {
                kind: if l_is_eq {
                    RangeKind::Lte
                } else {
                    RangeKind::Lt
                },
                rule_id: format!("{prefix}.{l_label}"),
                rule_path: format!("{prefix}.{l_label}"),
                message: format!("value must be {l_desc} {}", fmt(l)),
            }),
            (None, None) => None,
        }
    }

    /// The `(rule_id, rule_path)` pair a NaN value produces when it hits a
    /// range constraint (the message is intentionally empty). `None` when no
    /// bound is set.
    #[must_use]
    pub fn nan_range_rule<T: PartialOrd + Copy>(
        prefix: &str,
        gt: Option<T>,
        gte: Option<T>,
        lt: Option<T>,
        lte: Option<T>,
    ) -> Option<(String, String)> {
        let rule = range_rule(prefix, gt, gte, lt, lte, |_| String::new())?;
        Some((rule.rule_id, rule.rule_path))
    }

    #[cfg(test)]
    mod tests {
        use super::{RangeKind, nan_range_rule, range_rule};

        #[test]
        fn combined_bounds_select_inclusive_and_exclusive_variants() {
            let incl = range_rule("int32", Some(1), None, Some(10), None, i32::to_string)
                .expect("bounds set");
            assert_eq!(incl.kind, RangeKind::GtLt);
            assert_eq!(incl.rule_id, "int32.gt_lt");
            assert_eq!(incl.rule_path, "int32.gt");
            assert_eq!(
                incl.message,
                "value must be greater than 1 and less than 10"
            );

            let excl = range_rule("int32", Some(10), None, Some(1), None, i32::to_string)
                .expect("bounds set");
            assert_eq!(excl.kind, RangeKind::GtLtExclusive);
            assert_eq!(excl.rule_id, "int32.gt_lt_exclusive");
            assert_eq!(excl.message, "value must be greater than 10 or less than 1");
        }

        #[test]
        fn gte_lte_equal_bounds_are_inclusive() {
            let rule = range_rule("uint32", None, Some(5u32), None, Some(5), u32::to_string)
                .expect("bounds set");
            assert_eq!(rule.kind, RangeKind::GteLte);
            assert_eq!(rule.rule_id, "uint32.gte_lte");
            assert_eq!(
                rule.message,
                "value must be greater than or equal to 5 and less than or equal to 5"
            );
        }

        #[test]
        fn single_bounds_use_their_own_id_as_rule_path() {
            let rule = range_rule("double", None, None, None, Some(1.5f64), f64::to_string)
                .expect("bound set");
            assert_eq!(rule.kind, RangeKind::Lte);
            assert_eq!(rule.rule_id, "double.lte");
            assert_eq!(rule.rule_path, "double.lte");
            assert_eq!(rule.message, "value must be less than or equal to 1.5");
        }

        #[test]
        fn float_bounds_format_from_the_wire_scalar() {
            // 0.1f32 renders as "0.1"; widening to f64 first would render
            // the f64-widened value instead — the trap this API prevents.
            let rule = range_rule("float", Some(0.1f32), None, None, None, f32::to_string)
                .expect("bound set");
            assert_eq!(rule.message, "value must be greater than 0.1");
        }

        #[test]
        fn violated_matches_bound_semantics() {
            assert!(RangeKind::Gt.violated(Some(5), None, 5));
            assert!(!RangeKind::Gt.violated(Some(5), None, 6));
            assert!(RangeKind::Gte.violated(Some(5), None, 4));
            assert!(!RangeKind::Gte.violated(Some(5), None, 5));
            assert!(RangeKind::Lt.violated(None, Some(5), 5));
            assert!(RangeKind::Lte.violated(None, Some(5), 6));

            // Inclusive 1..10 (gt/lt): 1 and 10 violate, 5 passes.
            assert!(RangeKind::GtLt.violated(Some(1), Some(10), 1));
            assert!(RangeKind::GtLt.violated(Some(1), Some(10), 10));
            assert!(!RangeKind::GtLt.violated(Some(1), Some(10), 5));

            // Exclusive gt 10 / lt 1: 5 violates, 0 and 11 pass.
            assert!(RangeKind::GtLtExclusive.violated(Some(10), Some(1), 5));
            assert!(!RangeKind::GtLtExclusive.violated(Some(10), Some(1), 0));
            assert!(!RangeKind::GtLtExclusive.violated(Some(10), Some(1), 11));

            // gte 0 / lte 1 inclusive.
            assert!(RangeKind::GteLte.violated(Some(0.0), Some(1.0), -0.5));
            assert!(RangeKind::GteLte.violated(Some(0.0), Some(1.0), 1.5));
            assert!(!RangeKind::GteLte.violated(Some(0.0), Some(1.0), 0.0));
        }

        #[test]
        fn nan_rule_reuses_the_range_table() {
            let (id, path) =
                nan_range_rule("float", None, Some(0.0f32), None, Some(100.0)).expect("bounds");
            assert_eq!(id, "float.gte_lte");
            assert_eq!(path, "float.gte");

            let (id, path) =
                nan_range_rule("double", Some(0.0f64), None, None, None).expect("bound");
            assert_eq!(id, "double.gt");
            assert_eq!(path, "double.gt");

            assert!(nan_range_rule::<f32>("float", None, None, None, None).is_none());
        }
    }
}

/// Metadata for `google.protobuf.Duration` rules.
pub mod duration {
    use super::numeric;

    /// Rule id for `duration.const`.
    pub const CONST_ID: &str = "duration.const";
    /// Rule id for `duration.in`.
    pub const IN_ID: &str = "duration.in";
    /// Rule id for `duration.not_in`.
    pub const NOT_IN_ID: &str = "duration.not_in";

    /// Render a duration Go-style, as used in every duration message
    /// (`"3s"`, `"1.5s"`, `"-2s"`).
    #[must_use]
    pub fn fmt(seconds: i64, nanos: i32) -> String {
        if nanos == 0 {
            format!("{seconds}s")
        } else {
            let sign = if seconds < 0 || nanos < 0 { "-" } else { "" };
            let secs = seconds.unsigned_abs();
            let nanos = nanos.unsigned_abs();
            let frac = format!("{nanos:09}");
            let frac = frac.trim_end_matches('0');
            format!("{sign}{secs}.{frac}s")
        }
    }

    /// The violation message for `duration.const`.
    #[must_use]
    pub fn const_message(seconds: i64, nanos: i32) -> String {
        format!("value must equal {}", fmt(seconds, nanos))
    }

    /// The violation message for `duration.in`.
    #[must_use]
    pub fn in_message(items: &[(i64, i32)]) -> String {
        format!("value must be in list [{}]", join(items))
    }

    /// The violation message for `duration.not_in`.
    #[must_use]
    pub fn not_in_message(items: &[(i64, i32)]) -> String {
        format!("value must not be in list [{}]", join(items))
    }

    fn join(items: &[(i64, i32)]) -> String {
        items
            .iter()
            .map(|(s, n)| fmt(*s, *n))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Resolve the range rule for `(seconds, nanos)` bounds.
    ///
    /// Duration ordering is lexicographic on the tuple (protobuf requires
    /// `seconds` and `nanos` to share a sign), so the shared
    /// [`numeric::RangeKind::violated`] predicate applies to the tuples
    /// directly.
    #[must_use]
    pub fn range_rule(
        gt: Option<(i64, i32)>,
        gte: Option<(i64, i32)>,
        lt: Option<(i64, i32)>,
        lte: Option<(i64, i32)>,
    ) -> Option<numeric::RangeRule> {
        numeric::range_rule("duration", gt, gte, lt, lte, |(s, n)| fmt(*s, *n))
    }

    #[cfg(test)]
    mod tests {
        use super::{fmt, in_message, range_rule};

        #[test]
        fn fmt_matches_go_style() {
            assert_eq!(fmt(3, 0), "3s");
            assert_eq!(fmt(1, 500_000_000), "1.5s");
            assert_eq!(fmt(-2, 0), "-2s");
            assert_eq!(fmt(0, -500_000_000), "-0.5s");
            assert_eq!(fmt(0, 1), "0.000000001s");
        }

        #[test]
        fn range_messages_render_bounds_go_style() {
            let rule = range_rule(Some((0, 0)), None, Some((60, 0)), None).expect("bounds");
            assert_eq!(rule.rule_id, "duration.gt_lt");
            assert_eq!(
                rule.message,
                "value must be greater than 0s and less than 60s"
            );
        }

        #[test]
        fn list_messages_join_with_brackets() {
            assert_eq!(
                in_message(&[(1, 0), (2, 500_000_000)]),
                "value must be in list [1s, 2.5s]"
            );
        }
    }
}

/// Metadata for `google.protobuf.Timestamp` rules.
pub mod timestamp {
    use super::numeric;

    /// Rule id for `timestamp.const`.
    pub const CONST_ID: &str = "timestamp.const";
    /// The violation message for `timestamp.const` (timestamp messages do
    /// not render the bound).
    pub const CONST_MESSAGE: &str = "must equal const timestamp";
    /// Rule id for `timestamp.lt_now`.
    pub const LT_NOW_ID: &str = "timestamp.lt_now";
    /// The violation message for `timestamp.lt_now`.
    pub const LT_NOW_MESSAGE: &str = "must be less than now";
    /// Rule id for `timestamp.gt_now`.
    pub const GT_NOW_ID: &str = "timestamp.gt_now";
    /// The violation message for `timestamp.gt_now`.
    pub const GT_NOW_MESSAGE: &str = "must be greater than now";
    /// Rule id for `timestamp.within`.
    pub const WITHIN_ID: &str = "timestamp.within";
    /// The violation message for `timestamp.within`.
    pub const WITHIN_MESSAGE: &str = "must be within specified duration of now";

    /// The fixed violation message for each bound combination.
    #[must_use]
    pub fn range_message(kind: numeric::RangeKind) -> &'static str {
        match kind {
            numeric::RangeKind::GtLt => "must be greater than and less than specified timestamps",
            numeric::RangeKind::GtLtExclusive => {
                "must be greater than or less than specified timestamps"
            }
            numeric::RangeKind::GtLte => {
                "must be greater than and less than or equal to specified timestamps"
            }
            numeric::RangeKind::GtLteExclusive => {
                "must be greater than or less than or equal to specified timestamps"
            }
            numeric::RangeKind::GteLt => {
                "must be greater than or equal to and less than specified timestamps"
            }
            numeric::RangeKind::GteLtExclusive => {
                "must be greater than or equal to or less than specified timestamps"
            }
            numeric::RangeKind::GteLte => "must be between specified timestamps inclusive",
            numeric::RangeKind::GteLteExclusive => {
                "must be greater than or equal to or less than or equal to specified timestamps"
            }
            numeric::RangeKind::Gt => "must be greater than specified timestamp",
            numeric::RangeKind::Gte => "must be greater than or equal to specified timestamp",
            numeric::RangeKind::Lt => "must be less than specified timestamp",
            numeric::RangeKind::Lte => "must be less than or equal to specified timestamp",
        }
    }

    /// Resolve the range rule for `(seconds, nanos)` bounds with timestamp's
    /// constant messages. Timestamp ordering is lexicographic on the tuple,
    /// so [`numeric::RangeKind::violated`] applies to the tuples directly.
    #[must_use]
    pub fn range_rule(
        gt: Option<(i64, i32)>,
        gte: Option<(i64, i32)>,
        lt: Option<(i64, i32)>,
        lte: Option<(i64, i32)>,
    ) -> Option<numeric::RangeRule> {
        let mut rule = numeric::range_rule("timestamp", gt, gte, lt, lte, |_| String::new())?;
        rule.message = range_message(rule.kind).to_string();
        Some(rule)
    }

    #[cfg(test)]
    mod tests {
        use super::range_rule;

        #[test]
        fn range_rule_uses_constant_messages() {
            let rule = range_rule(None, Some((100, 0)), None, Some((200, 0))).expect("bounds");
            assert_eq!(rule.rule_id, "timestamp.gte_lte");
            assert_eq!(rule.rule_path, "timestamp.gte");
            assert_eq!(
                rule.message,
                "must be between specified timestamps inclusive"
            );

            let single = range_rule(Some((5, 0)), None, None, None).expect("bound");
            assert_eq!(single.rule_id, "timestamp.gt");
            assert_eq!(single.message, "must be greater than specified timestamp");
        }
    }
}

/// Metadata for string rules.
pub mod string {
    /// Rule id for `string.const`.
    pub const CONST_ID: &str = "string.const";
    /// Rule id for `string.len`.
    pub const LEN_ID: &str = "string.len";
    /// Rule id for `string.min_len`.
    pub const MIN_LEN_ID: &str = "string.min_len";
    /// Rule id for `string.max_len`.
    pub const MAX_LEN_ID: &str = "string.max_len";
    /// Rule id for `string.len_bytes`.
    pub const LEN_BYTES_ID: &str = "string.len_bytes";
    /// Rule id for `string.min_bytes`.
    pub const MIN_BYTES_ID: &str = "string.min_bytes";
    /// Rule id for `string.max_bytes`.
    pub const MAX_BYTES_ID: &str = "string.max_bytes";
    /// Rule id for `string.pattern`.
    pub const PATTERN_ID: &str = "string.pattern";
    /// Rule id for `string.prefix`.
    pub const PREFIX_ID: &str = "string.prefix";
    /// Rule id for `string.suffix`.
    pub const SUFFIX_ID: &str = "string.suffix";
    /// Rule id for `string.contains`.
    pub const CONTAINS_ID: &str = "string.contains";
    /// Rule id for `string.not_contains`.
    pub const NOT_CONTAINS_ID: &str = "string.not_contains";
    /// Rule id for `string.in`.
    pub const IN_ID: &str = "string.in";
    /// Rule id for `string.not_in`.
    pub const NOT_IN_ID: &str = "string.not_in";

    /// Rule path shared by both HTTP-header well-known checks.
    pub const WELL_KNOWN_REGEX_PATH: &str = "string.well_known_regex";
    /// Rule id for an invalid HTTP header name.
    pub const HEADER_NAME_ID: &str = "string.well_known_regex.header_name";
    /// Rule id for an empty HTTP header name.
    pub const HEADER_NAME_EMPTY_ID: &str = "string.well_known_regex.header_name_empty";
    /// Rule id for an invalid HTTP header value (no empty variant exists).
    pub const HEADER_VALUE_ID: &str = "string.well_known_regex.header_value";

    /// The violation message for `string.const`.
    #[must_use]
    pub fn const_message(want: &str) -> String {
        format!("must equal `{want}`")
    }

    /// The violation message for `string.len`.
    #[must_use]
    pub fn len_message(len: u64) -> String {
        format!("must be {len} characters")
    }

    /// The violation message for `string.min_len`.
    #[must_use]
    pub fn min_len_message(min: u64) -> String {
        format!("value length must be at least {min} characters")
    }

    /// The violation message for `string.max_len`.
    #[must_use]
    pub fn max_len_message(max: u64) -> String {
        format!("value length must be at most {max} characters")
    }

    /// The violation message for `string.len_bytes`.
    #[must_use]
    pub fn len_bytes_message(len: u64) -> String {
        format!("must be {len} bytes")
    }

    /// The violation message for `string.min_bytes`.
    #[must_use]
    pub fn min_bytes_message(min: u64) -> String {
        format!("must be at least {min} bytes")
    }

    /// The violation message for `string.max_bytes`.
    #[must_use]
    pub fn max_bytes_message(max: u64) -> String {
        format!("must be at most {max} bytes")
    }

    /// The violation message for `string.pattern`.
    #[must_use]
    pub fn pattern_message(pattern: &str) -> String {
        format!("does not match regex pattern `{pattern}`")
    }

    /// The violation message for `string.prefix`.
    #[must_use]
    pub fn prefix_message(prefix: &str) -> String {
        format!("does not have prefix `{prefix}`")
    }

    /// The violation message for `string.suffix`.
    #[must_use]
    pub fn suffix_message(suffix: &str) -> String {
        format!("does not have suffix `{suffix}`")
    }

    /// The violation message for `string.contains`.
    #[must_use]
    pub fn contains_message(substring: &str) -> String {
        format!("does not contain substring `{substring}`")
    }

    /// The violation message for `string.not_contains`.
    #[must_use]
    pub fn not_contains_message(substring: &str) -> String {
        format!("contains substring `{substring}`")
    }

    /// The violation message for `string.in`. Items are sorted so the
    /// rendering is deterministic regardless of source order.
    #[must_use]
    pub fn in_message(items: &[String]) -> String {
        format!("must be in list {:?}", sorted(items))
    }

    /// The violation message for `string.not_in`.
    #[must_use]
    pub fn not_in_message(items: &[String]) -> String {
        format!("must not be in list {:?}", sorted(items))
    }

    fn sorted(items: &[String]) -> Vec<&String> {
        let mut v: Vec<&String> = items.iter().collect();
        v.sort();
        v
    }

    /// Rule id (and rule path) for a well-known format, e.g. `string.email`.
    #[must_use]
    pub fn well_known_id(name: &str) -> String {
        format!("string.{name}")
    }

    /// Rule id for an empty value against a well-known format,
    /// e.g. `string.email_empty`.
    #[must_use]
    pub fn well_known_empty_id(name: &str) -> String {
        format!("string.{name}_empty")
    }

    #[cfg(test)]
    mod tests {
        use super::{in_message, well_known_empty_id, well_known_id};

        #[test]
        fn list_messages_sort_and_debug_format() {
            let items = vec!["b".to_string(), "a".to_string()];
            assert_eq!(in_message(&items), r#"must be in list ["a", "b"]"#);
        }

        #[test]
        fn well_known_ids_compose() {
            assert_eq!(well_known_id("uri_ref"), "string.uri_ref");
            assert_eq!(
                well_known_empty_id("ip_with_prefixlen"),
                "string.ip_with_prefixlen_empty"
            );
        }
    }
}

/// Metadata for bytes rules.
pub mod bytes {
    /// Rule id for `bytes.const`.
    pub const CONST_ID: &str = "bytes.const";
    /// Rule id for `bytes.len`.
    pub const LEN_ID: &str = "bytes.len";
    /// Rule id for `bytes.min_len`.
    pub const MIN_LEN_ID: &str = "bytes.min_len";
    /// Rule id for `bytes.max_len`.
    pub const MAX_LEN_ID: &str = "bytes.max_len";
    /// Rule id for `bytes.pattern`.
    pub const PATTERN_ID: &str = "bytes.pattern";
    /// Rule id for `bytes.prefix`.
    pub const PREFIX_ID: &str = "bytes.prefix";
    /// Rule id for `bytes.suffix`.
    pub const SUFFIX_ID: &str = "bytes.suffix";
    /// Rule id for `bytes.contains`.
    pub const CONTAINS_ID: &str = "bytes.contains";
    /// Rule id for `bytes.in`.
    pub const IN_ID: &str = "bytes.in";
    /// Rule id for `bytes.not_in`.
    pub const NOT_IN_ID: &str = "bytes.not_in";

    /// The violation message for `bytes.in`.
    pub const IN_MESSAGE: &str = "value must be in list";
    /// The violation message for `bytes.not_in`.
    pub const NOT_IN_MESSAGE: &str = "value must not be in list";

    /// Rule id for an empty value against `bytes.ip`.
    pub const IP_EMPTY_ID: &str = "bytes.ip_empty";
    /// The violation message for an empty value against `bytes.ip`.
    pub const IP_EMPTY_MESSAGE: &str = "value is empty, which is not a valid IP address";
    /// Rule id for `bytes.ip`.
    pub const IP_ID: &str = "bytes.ip";
    /// The violation message for `bytes.ip`.
    pub const IP_MESSAGE: &str = "value must be a valid IP address";
    /// Rule id for an empty value against `bytes.ipv4`.
    pub const IPV4_EMPTY_ID: &str = "bytes.ipv4_empty";
    /// The violation message for an empty value against `bytes.ipv4`.
    pub const IPV4_EMPTY_MESSAGE: &str = "value is empty, which is not a valid IPv4 address";
    /// Rule id for `bytes.ipv4`.
    pub const IPV4_ID: &str = "bytes.ipv4";
    /// The violation message for `bytes.ipv4`.
    pub const IPV4_MESSAGE: &str = "value must be a valid IPv4 address";
    /// Rule id for an empty value against `bytes.ipv6`.
    pub const IPV6_EMPTY_ID: &str = "bytes.ipv6_empty";
    /// The violation message for an empty value against `bytes.ipv6`.
    pub const IPV6_EMPTY_MESSAGE: &str = "value is empty, which is not a valid IPv6 address";
    /// Rule id for `bytes.ipv6`.
    pub const IPV6_ID: &str = "bytes.ipv6";
    /// The violation message for `bytes.ipv6`.
    pub const IPV6_MESSAGE: &str = "value must be a valid IPv6 address";
    /// Rule id for an empty value against `bytes.uuid`. Unlike the other
    /// bytes formats this violation carries no message and uses `bytes.uuid`
    /// as its rule path, matching the conformance corpus.
    pub const UUID_EMPTY_ID: &str = "bytes.uuid_empty";
    /// Rule id for `bytes.uuid`; also the rule path of the empty variant.
    pub const UUID_ID: &str = "bytes.uuid";
    /// The violation message for `bytes.uuid`.
    pub const UUID_MESSAGE: &str = "value must be a valid UUID";

    /// The violation message for `bytes.const` (`Vec<u8>` Debug rendering,
    /// e.g. `[1, 2, 3]`).
    #[must_use]
    pub fn const_message(value: &[u8]) -> String {
        format!("value must be {value:?}")
    }

    /// The violation message for `bytes.len`.
    #[must_use]
    pub fn len_message(len: u64) -> String {
        format!("value length must be {len} bytes")
    }

    /// The violation message for `bytes.min_len`.
    #[must_use]
    pub fn min_len_message(min: u64) -> String {
        format!("value length must be at least {min} bytes")
    }

    /// The violation message for `bytes.max_len`.
    #[must_use]
    pub fn max_len_message(max: u64) -> String {
        format!("value length must be at most {max} bytes")
    }

    /// The violation message for `bytes.pattern`.
    #[must_use]
    pub fn pattern_message(pattern: &str) -> String {
        format!("value must match regex pattern `{pattern}`")
    }

    /// The violation message for `bytes.prefix`.
    #[must_use]
    pub fn prefix_message(prefix: &[u8]) -> String {
        format!("value does not have prefix {prefix:?}")
    }

    /// The violation message for `bytes.suffix`.
    #[must_use]
    pub fn suffix_message(suffix: &[u8]) -> String {
        format!("value does not have suffix {suffix:?}")
    }

    /// The violation message for `bytes.contains`.
    #[must_use]
    pub fn contains_message(substring: &[u8]) -> String {
        format!("value does not contain {substring:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::const_message;

        #[test]
        fn byte_messages_use_debug_rendering() {
            assert_eq!(const_message(&[1, 2, 255]), "value must be [1, 2, 255]");
        }
    }
}

/// Metadata for repeated rules.
pub mod repeated {
    /// Rule id for `repeated.min_items`.
    pub const MIN_ITEMS_ID: &str = "repeated.min_items";
    /// Rule id for `repeated.max_items`.
    pub const MAX_ITEMS_ID: &str = "repeated.max_items";
    /// Rule id for `repeated.unique`.
    pub const UNIQUE_ID: &str = "repeated.unique";
    /// The violation message for `repeated.unique`.
    pub const UNIQUE_MESSAGE: &str = "items must be unique";
    /// Rule-path prefix prepended to per-item violations.
    pub const ITEMS_RULE_PREFIX: &str = "repeated.items";

    /// The violation message for `repeated.min_items`.
    #[must_use]
    pub fn min_items_message(min: u64) -> String {
        format!("must have at least {min} items")
    }

    /// The violation message for `repeated.max_items`.
    #[must_use]
    pub fn max_items_message(max: u64) -> String {
        format!("must have at most {max} items")
    }
}

/// Metadata for map rules.
pub mod map {
    /// Rule id for `map.min_pairs`.
    pub const MIN_PAIRS_ID: &str = "map.min_pairs";
    /// Rule id for `map.max_pairs`.
    pub const MAX_PAIRS_ID: &str = "map.max_pairs";
    /// Rule-path prefix prepended to per-key violations.
    pub const KEYS_RULE_PREFIX: &str = "map.keys";
    /// Rule-path prefix prepended to per-value violations.
    pub const VALUES_RULE_PREFIX: &str = "map.values";

    /// The violation message for `map.min_pairs`.
    #[must_use]
    pub fn min_pairs_message(min: u64) -> String {
        format!("must have at least {min} entries")
    }

    /// The violation message for `map.max_pairs`.
    #[must_use]
    pub fn max_pairs_message(max: u64) -> String {
        format!("must have at most {max} entries")
    }
}

/// Metadata for enum rules.
pub mod enumeration {
    /// Rule id for `enum.const`.
    pub const CONST_ID: &str = "enum.const";
    /// Rule id for `enum.defined_only`.
    pub const DEFINED_ONLY_ID: &str = "enum.defined_only";
    /// The violation message for `enum.defined_only`.
    pub const DEFINED_ONLY_MESSAGE: &str = "value must be one of the defined enum values";
    /// Rule id for `enum.in`.
    pub const IN_ID: &str = "enum.in";
    /// Rule id for `enum.not_in`.
    pub const NOT_IN_ID: &str = "enum.not_in";

    /// The violation message for `enum.const`.
    #[must_use]
    pub fn const_message(value: i32) -> String {
        format!("must equal {value}")
    }

    /// The violation message for `enum.in`. Values are sorted so the
    /// rendering is deterministic regardless of source order.
    #[must_use]
    pub fn in_message(values: &[i32]) -> String {
        format!("must be in list {:?}", sorted(values))
    }

    /// The violation message for `enum.not_in`.
    #[must_use]
    pub fn not_in_message(values: &[i32]) -> String {
        format!("must not be in list {:?}", sorted(values))
    }

    fn sorted(values: &[i32]) -> Vec<i32> {
        let mut v = values.to_vec();
        v.sort_unstable();
        v
    }
}

/// Metadata for `google.protobuf.FieldMask` rules.
pub mod field_mask {
    /// Rule id for `field_mask.const`.
    pub const CONST_ID: &str = "field_mask.const";
    /// The violation message for `field_mask.const`.
    pub const CONST_MESSAGE: &str = "must equal paths";
    /// Rule id for `field_mask.in`.
    pub const IN_ID: &str = "field_mask.in";
    /// The violation message for `field_mask.in`.
    pub const IN_MESSAGE: &str = "must only contain allowed paths";
    /// Rule id for `field_mask.not_in`.
    pub const NOT_IN_ID: &str = "field_mask.not_in";
    /// The violation message for `field_mask.not_in`.
    pub const NOT_IN_MESSAGE: &str = "must not contain forbidden paths";
}

/// Metadata for bool rules.
pub mod boolean {
    /// Rule id for `bool.const`.
    pub const CONST_ID: &str = "bool.const";

    /// The violation message for `bool.const`.
    #[must_use]
    pub fn const_message(value: bool) -> String {
        format!("must equal {value}")
    }
}

/// Metadata for `google.protobuf.Any` rules.
pub mod any {
    /// Rule id for `any.in`.
    pub const IN_ID: &str = "any.in";
    /// The violation message for `any.in`.
    pub const IN_MESSAGE: &str = "type URL must be in the allow list";
    /// Rule id for `any.not_in`.
    pub const NOT_IN_ID: &str = "any.not_in";
    /// The violation message for `any.not_in`.
    pub const NOT_IN_MESSAGE: &str = "type URL must not be in the block list";
}

/// Canonical IEEE-754 handling shared by `repeated.unique` on float/double
/// fields, in both the runtime evaluator and generated validators.
pub mod float {
    /// The uniqueness key for an `f32`: `None` for NaN (NaN never equals
    /// itself, so multiple NaNs do not violate uniqueness); `+0.0` and
    /// `-0.0` collapse to the same bit pattern.
    #[must_use]
    pub fn canonical_f32_bits(value: f32) -> Option<u32> {
        if value.is_nan() {
            return None;
        }
        Some(if value == 0.0 {
            0.0_f32.to_bits()
        } else {
            value.to_bits()
        })
    }

    /// The uniqueness key for an `f64`; see [`canonical_f32_bits`].
    #[must_use]
    pub fn canonical_f64_bits(value: f64) -> Option<u64> {
        if value.is_nan() {
            return None;
        }
        Some(if value == 0.0 {
            0.0_f64.to_bits()
        } else {
            value.to_bits()
        })
    }

    #[cfg(test)]
    mod tests {
        use super::{canonical_f32_bits, canonical_f64_bits};

        #[test]
        fn nan_has_no_key_and_zeros_collapse() {
            assert_eq!(canonical_f32_bits(f32::NAN), None);
            assert_eq!(canonical_f64_bits(f64::NAN), None);
            assert_eq!(canonical_f32_bits(0.0), canonical_f32_bits(-0.0));
            assert_eq!(canonical_f64_bits(0.0), canonical_f64_bits(-0.0));
            assert_ne!(canonical_f32_bits(1.0), canonical_f32_bits(2.0));
        }
    }
}
