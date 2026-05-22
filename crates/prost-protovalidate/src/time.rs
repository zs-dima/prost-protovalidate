//! Time helpers shared between the runtime validator and code generated
//! by `prost-protovalidate-build`.
//!
//! The single public entry point [`now_systemtime`] returns the current
//! wall-clock time as a `prost_types::Timestamp`. Generated `Validate`
//! impls for messages with `lt_now` / `gt_now` / `within` timestamp rules
//! call this directly — the trait signature `fn validate(&self) -> …` has
//! no place to inject a `now_fn`, so the compile-time path always reads
//! `SystemTime::now()`. This matches the runtime `Validator`'s default
//! configuration, which uses the same `SystemTime::now()` source via
//! `ValidationConfig::now_fn`.
//!
//! **Test determinism**: for tests that need a deterministic `now`, use
//! the runtime [`Validator`](crate::Validator) with a `now_fn` override.
//! The compile-time `Validate::validate(&self)` path cannot accept an
//! injected `now`.

use prost_types::Timestamp;

/// Current wall-clock time as a protobuf `Timestamp`.
///
/// Reads `std::time::SystemTime::now()` once per call.
///
/// # Pre-epoch fallback
///
/// When the system clock is before the Unix epoch (extremely rare,
/// typically indicating a misconfigured system), `duration_since(UNIX_EPOCH)`
/// returns an error and this function falls back to the Unix epoch
/// (`seconds = 0, nanos = 0`) rather than panicking. Validation results
/// for `timestamp.lt_now` / `timestamp.gt_now` against pre-epoch timestamps
/// on such systems will be inverted — a pre-epoch `Timestamp` (negative
/// `seconds`) will compare as "before the (epoch-treated-as) now", which
/// matches reality only by accident. Use the runtime
/// [`Validator`](crate::Validator) with a `NowFn` override
/// ([`ValidatorOption::NowFn`](crate::ValidatorOption) or
/// [`ValidationOption::NowFn`](crate::ValidationOption)) if you need
/// defined behaviour on anomalous clocks.
#[must_use]
pub fn now_systemtime() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Both casts are semantically safe:
    // - `as_secs()` since UNIX_EPOCH fits in `i64` for billions of years.
    // - `subsec_nanos()` is always `< 1_000_000_000` which fits in `i32`.
    #[allow(clippy::cast_possible_wrap)]
    Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_systemtime_returns_non_zero_after_epoch() {
        let ts = now_systemtime();
        // Any plausible wall-clock since 1970 has seconds well above zero.
        assert!(ts.seconds > 1_000_000_000, "ts.seconds = {}", ts.seconds);
        assert!(
            (0..1_000_000_000).contains(&ts.nanos),
            "ts.nanos = {} out of [0, 1e9)",
            ts.nanos
        );
    }
}
