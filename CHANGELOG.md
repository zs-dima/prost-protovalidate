# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-07-07

### Added

- **`prost-protovalidate-build` — buffa codegen backend.** New `Backend` enum
  (`Prost` default, `Buffa`) selected via `Builder::backend`. In `Buffa` mode the
  generated `impl Validate` blocks target
  [`buffa`](https://crates.io/crates/buffa)-generated message types (`buffa-build`,
  or a wrapper such as `connectrpc-build`): message-field presence goes through
  `MessageField` (`is_set` / `is_unset` / `as_option`) instead of `Option`, enum
  accesses are normalized with `EnumValue::to_i32` (singular, repeated, and map
  elements), type idents stay verbatim (proto `UUID` stays Rust `UUID` — prost
  renames it to `Uuid`), and field/module names follow buffa-codegen's snake-casing
  and keyword escaping. Type paths are resolved from a descriptor-pool-derived map
  with sub-package / nested-module deconfliction rather than guessed from name
  shape. Pairing the buffa backend with `default-features = false` on
  `prost-protovalidate` gives build-time validation with no `prost-reflect` and no
  CEL anywhere in the runtime dependency graph.
- **`prost-protovalidate-build` — `Builder::fail_on_runtime_only`.** Opt-in flag
  that turns "route to the runtime `Validator`" outcomes (messages with CEL rules,
  or shapes the generator cannot cover) into a hard build error (new
  `Error::RuntimeOnly` variant) instead of a `cargo:warning` skip. For consumers
  that ship no runtime validation path, so a rule can never be silently dropped.
- **Optional `reflect` feature on `prost-protovalidate`** (default on, implied by
  `cel`). Gates runtime reflection: the descriptor-driven `Validator`, validation
  filters (`Filter`, `ValidationOption`, `ValidatorOption`), edition normalization
  (`normalize_edition_descriptor_set`), and `Violation` rule-path hydration.
  Disabling it yields a slim, `prost-reflect`-free build carrying only the
  `Validate` trait, `Violation` / `ValidationError`, the `validators` format
  helpers, and `time` — the exact surface `prost-protovalidate-build` generated
  code depends on. With the feature off, `Violation::to_proto` emits rule-path
  elements with names only (no `field_number` / `field_type`); the string accessors
  (`field_path`, `rule_path`, `rule_id`, `message`) are unaffected.
- **Optional `reflect` feature on `prost-protovalidate-types`** (default on). Gates
  the `DESCRIPTOR_POOL` static, the `buf.validate` extension-descriptor statics, and
  the constraint-extraction traits and typed helpers (`FieldConstraintsExt`,
  `MessageConstraintsExt`, …), now housed in a new `constraints` module. Disabling
  it leaves a reflection-free build of just the generated prost types and
  `rules_meta`.

### Changed

- **`default-features = false` now selects the slim build.** In 0.4.x, disabling
  default features produced a CEL-free build that still included the runtime
  `Validator` (`prost-reflect` was a hard dependency). In 0.5.0 the `Validator`,
  validation filters, and edition normalization are gated behind the new `reflect`
  feature, and `cel` implies `reflect`. Consumers that disabled `cel` for a lighter
  build but still use `Validator` / `validate` must switch to
  `default-features = false, features = ["reflect"]`. Default builds (with `cel`)
  are unaffected. The resulting three-tier footprint is `cel` ⊃ `reflect` ⊃ slim.
- Format validators moved from the reflection-gated `validator/formats` module to a
  top-level `formats` module so the public `validators::*` helpers compile without
  `reflect`. No change to the `validators` public API.
- `prost-protovalidate` now declares its `prost-protovalidate-types` dependency
  explicitly (not through `workspace = true`) so `default-features` can be toggled
  and re-enabled through the `reflect` feature; Cargo forbids overriding
  `default-features` through workspace inheritance.
- Internal parity infrastructure: new `prost-protovalidate-tests-buffa` crate
  (`publish = false`) generates `impl Validate` against buffa types for the shared
  `parity.proto` corpus and asserts identical `Violation` output against the runtime
  `Validator`; the descriptor-driven boundary-vector generator was extracted to
  `prost-protovalidate-tests::sweep` and now drives both the prost and buffa parity
  sweeps. `make lint` / `make test-no-cel` gained `--features reflect` jobs; the
  benchmark suite now requires the `cel` feature.

## [0.4.3] - 2026-07-06

### Added

- **`prost_protovalidate_types::rules_meta`** — new public module centralizing
  the canonical `buf.validate` rule ids, violation-message templates, and
  range-combination tables. Single source of truth consumed by both the runtime
  `Validator` and the `prost-protovalidate-build` code generator, so the two
  engines can no longer drift on rule ids or messages.

### Changed

- Runtime validator internals now source rule ids/messages from `rules_meta`
  instead of hardcoding them across `validator/rules/*`; format validators were
  extracted into `validator/formats` and descriptor/wire helpers into
  `validator/descriptor_set` + `validator/wire`. No public API or behavior
  change — full conformance retained (2854/2854).
- `prost-protovalidate-build` codegen now emits rule ids/messages from the same
  `rules_meta` tables the runtime uses, guaranteeing parity by construction.
- `prost-protovalidate-build` dependency footprint trimmed: `prost-build` and
  `prost-reflect-build` moved from `[dependencies]` to `[dev-dependencies]`
  (used only by the crate's own tests). Downstream `build.rs` consumers no
  longer pull them transitively.

## [0.4.2] - 2026-05-22

### Fixed

- **docs.rs build.** Removed a stray `#[cfg_attr(docsrs, doc(cfg(feature = "cel")))]` on a `pub(crate)` module in `validator/evaluator/mod.rs`. The attribute required the unstable `feature(doc_cfg)` (gated under the `docsrs` cfg that docs.rs sets via `rustdoc-args = ["--cfg", "docsrs"]`) and rendered no visible docs anyway — rustdoc only emits feature-gate badges for `pub` items. The 0.4.1 release builds locally but fails on docs.rs.

## [0.4.1] - 2026-05-22

### Added

- **`prost-protovalidate-build` — compile-time validators for messages with standard-only rules.** New build-time code generator that emits `impl prost_protovalidate::Validate` for messages whose `buf.validate` rules are all standard, evaluated through monomorphized direct field access at runtime — no `prost-reflect` transcoding, no CEL interpreter on the hot path. Combined with `default-features = false` on `prost-protovalidate`, the entire `cel` / `chrono` / `paste` / `thiserror` 1.x subtree drops out of consumer builds. Messages with any CEL rule, predefined CEL rule, time-relative timestamp rule (`lt_now` / `gt_now` / `within`), invalid regex, `repeated.unique` on non-hashable elements, real-oneof field with direct field rules, WKT-wrappers inside repeated/maps, or a nested runtime-only dependency are routed to the runtime `Validator` with a `cargo:warning=` diagnostic — never silently skipped. The capability analyzer also rejects rule-type / field-kind mismatches (e.g. `string` rules on an `int32` field) with the runtime's wording, so codegen never emits Rust that fails to compile.
- **Optional `cel` feature flag on `prost-protovalidate`** (default on) — opt out of the CEL interpreter for a lighter dependency tree. Disabling it removes `cel`, `chrono`, `paste`, and `thiserror` 1.x from the transitive dependency tree. With the feature off, any message annotated with CEL rules or predefined CEL rules produces an actionable `CompilationError` mentioning the feature flag — never silently skipped.
- **`prost_protovalidate::Validate` trait** — the public contract implemented by generated validators. Signature: `fn validate(&self) -> Result<(), ValidationError>`. Documented that enrichment accessors (`field_descriptor()`, `field_value()`, `rule_descriptor()`, `rule_value()`) return `None` for violations produced by generated code.
- **`prost_protovalidate::validators` module** — public re-exports of the format validators (`is_email`, `is_hostname`, `is_ip`, `is_ipv4`, `is_ipv6`, `is_uri`, `is_uri_ref`, `is_uuid`, `is_tuuid`, `is_ulid`, `is_ip_prefix`, `is_ipv4_prefix`, `is_ipv6_prefix`, `is_host_and_port`, `is_http_header_name`, `is_http_header_value`) so generated validators can call them without reimplementation.
- **`validators::fieldmask_covers`** — allocation-free public helper exposing the `FieldMask` path-coverage check shared by the runtime evaluator and the generated `field_mask.in` / `field_mask.not_in` validators. The generated code formerly inlined `_p.starts_with(&format!("{_a}."))` and allocated one `String` per path comparison; the helper compares via `as_bytes()[candidate.len()] == b'.'` and allocates nothing.
- **Optional `tonic` feature on `prost-protovalidate`** (default off) — gRPC integration. Adds `impl From<ValidationError> for tonic::Status` mapping to `Code::InvalidArgument`, plus a `ValidateRequest` extension trait so unary and server-streaming handlers can write `req.validate_inner()?`. `CompilationError` / `RuntimeError` / `Error::Compilation` / `Error::Runtime` map to `Code::Internal` with a fixed generic message; the underlying `cause` strings are not forwarded to the client. Callers needing the original cause must log it before invoking the `Into` conversion.
- **Optional `tonic-types` feature on `prost-protovalidate`** (default off, implies `tonic`) — attaches a `google.rpc.BadRequest` detail to validation-failure statuses, with one `FieldViolation` per `Violation`. Lets gRPC clients parse field-level errors programmatically without scraping the message string.
- **`prost_protovalidate::time::now_systemtime`** — public helper returning `prost_types::Timestamp` from `SystemTime::now()`. Same source the runtime `Validator` uses by default, exposed so generated `Validate` impls can read wall-clock time without a context parameter on the trait. See the time-relative timestamp codegen entry below.
- **`prost-protovalidate-build` — compile-time validators for time-relative timestamp rules.** `timestamp.lt_now`, `timestamp.gt_now`, and `timestamp.within` now generate inline checks that call `::prost_protovalidate::time::now_systemtime()` once per validation. Reads the same `SystemTime::now()` source the runtime's default `now_fn` uses. Tests that need a deterministic clock must use the runtime `Validator` with a `now_fn` override — the `Validate::validate(&self)` trait signature cannot accept an injected `now`.
- **`prost-protovalidate-build` — compile-time `repeated.unique` for `float` / `double`.** Generated code now hashes the canonical IEEE-754 bit pattern of each element (via `to_bits()`), normalising `+0.0` and `-0.0` to the same bit pattern and skipping `NaN` so multiple `NaN` values are allowed (mirrors `NaN != NaN`). Removes the runtime fallback for these element kinds. The runtime evaluator's existing `canonical_f32_bits` / `canonical_f64_bits` logic is the reference implementation; parity tests assert identical violation sets across both paths.

### Changed

- **CEL evaluator — skip the `now` binding when the program does not reference it.** The CEL evaluator now walks each compiled program's AST once at compile time, sets a `references_now` flag on the cached `CelRuleProgram`, and at evaluation skips both `(cfg.now_fn)()` (a `SystemTime::now()` syscall in the default config) and the `add_variable("now", …)` call when the flag is `false`. Saves one syscall per CEL rule evaluation on any message whose CEL rules don't use `now`.
- **`Violation::new` / `Violation::new_constraint`** are now `pub` (were `pub(crate)`). Their enrichment fields (`field_descriptor`, `field_value`, `rule_descriptor`, `rule_value`) remain `None` when constructed by generated code, which is documented on the `Validate` trait.
- **`Violation` helper methods** are now `pub`: `prepend_field_path`, `prepend_index`, `prepend_string_key`, `prepend_int_key`, `prepend_uint_key`, `prepend_bool_key`, `prepend_rule_path`, `without_rule_path`, `mark_for_key`, `for_key`. Generated code uses these to compose the same `field_path` / `rule_path` shapes the runtime evaluator produces.
- **`pub use regex;`** re-export on `prost-protovalidate` so generated code can reference `::prost_protovalidate::regex::Regex` for `string.pattern` / `bytes.pattern` rules without consumers adding a direct `regex` dependency.
- **Criterion benchmark suite** (`crates/prost-protovalidate/benches/validate.rs`): 38 benchmarks across `transcode_to_dynamic`, `format_validators` (every public validator on valid and invalid input), `validate_end_to_end` (cached and cold), and `validate_convenience` groups. Baseline numbers in `BENCHMARKS.md`. New `make bench` target. `[profile.bench]` with debug info enabled for profiler-friendly samples.
- **Parity test crate** (`crates/prost-protovalidate-tests`, internal, `publish = false`): exercises both the runtime `Validator` and generated `Validate` against the same proto fixtures, asserting identical `Violation` output for standard rules. Covers numerics (NaN / Inf / finite + range), strings (incl. well-known formats), bytes, enums, repeated, maps (key + value, ignore modes), durations, timestamps, field masks, oneofs (real + virtual, including the implicit `IGNORE_IF_ZERO_VALUE` upgrade for virtual-oneof members), and presence/`required` semantics across proto3 implicit and `optional` storage shapes.
- **CI**: new `--no-default-features` test and clippy jobs for `prost-protovalidate`; `cargo-semver-checks` job covering all three publishable crates.

### Changed

- **BREAKING (workspace)**: bumped to `v0.4.0`.
- Bumped `cel` 0.12 → 0.13. CEL evaluation now uses error-resilient `&&` / `||` operators (matches CEL spec semantics), overflow-safe integer math, and stricter map / string indexing (no implicit type coercion; `NoSuchOverload` returned when indexing into strings). Full conformance retained: 2854/2854 tests pass.
- Bumped `criterion` 0.5 → 0.8.2 (dev-dependency only). The benchmark file migrated from the deprecated `criterion::black_box` to `std::hint::black_box`, and every benchmark group now carries a `Throughput::Bytes` (format validators report MiB/s of input bytes; transcode reports MiB/s of `prost::Message::encoded_len`) or `Throughput::Elements` (end-to-end and convenience report Melem/s) annotation. `bench_validate_convenience` is now `validate_convenience/bool_rules` (grouped) for consistency. The bench suite was expanded from 14 to 38 benchmarks — every public format validator (16 total) is now benched on both valid and invalid inputs, surfacing early-exit performance characteristics.
- Removed obsolete `RUSTSEC-2024-0436` advisory ignore from `deny.toml`; `paste` is no longer a transitive dependency after the cel 0.13 upgrade (replaced upstream with `pastey`).

### Fixed

- CEL `has()` now correctly returns `false` for absent presence-tracked fields (proto2/proto3 messages, proto3 `optional`, oneof members) when reflecting messages for user-written `cel:` rules. Previously every field key was inserted into the reflected map, so `has(this.field)` always returned `true` and guarded selectors like `!has(this.x) || this.x.min_len == 1` did not short-circuit. Repeated and map fields remain visible to preserve existing collection-default behaviour. Regression introduced in 0.2.0 (`2853074`).
- **Codegen parity bugs** caught before any release of `prost-protovalidate-build`:
  - Float / double `finite` rule is now generated; range checks short-circuit on `NaN` with the runtime's exact `<prefix>.<bound>` rule id and rule path. Previously NaN passed every `gt` / `gte` / `lt` / `lte` comparison silently (IEEE-754 returns false for any NaN comparison) and `finite` was silently dropped.
  - Fields listed in a `MessageRules.oneof` virtual oneof now receive the implicit `IGNORE_IF_ZERO_VALUE` upgrade when no explicit ignore is set, matching runtime's `is_part_of_message_oneof` short-circuit. Previously a zero-valued virtual-oneof member could emit violations the runtime suppresses.
  - `repeated.items.ignore`, `map.keys.ignore`, and `map.values.ignore` are now honored at the per-element level (`IGNORE_ALWAYS` skips nested checks; `IGNORE_IF_ZERO_VALUE` wraps them in a default-value guard).
  - `required = true` on a proto3 implicit scalar no longer emits `self.x.is_none()` against a bare `T`; presence detection now uses `FieldDescriptor::supports_presence()` so only fields whose prost storage is actually `Option<T>` get the `is_some()` check.

### Known limitations

- **`bytes.pattern` on invalid UTF-8 (compile-time path)**: when a `bytes` field carries a `pattern` rule and the value is not valid UTF-8, the generated `Validate` impl produces a `bytes.pattern` violation. The runtime `Validator` returns a `RuntimeError` for the same input instead — the `Validate` trait's `Result<(), ValidationError>` signature cannot carry a runtime error. This is the only intentional behavioural divergence between the compile-time and runtime paths; valid-UTF-8 input is unaffected. Route bytes-pattern fields that need the runtime error surface through `Validator::validate` rather than the compile-time path.

## [0.3.0] - 2026-02-28

### Changed

- **BREAKING** (`prost-protovalidate-types`): Synced `validate.proto` to upstream `buf.build/bufbuild/protovalidate` v1.1.1 — `string.protobuf_fqn` / `string.protobuf_dot_fqn` rules removed upstream, removing `string_rules::WellKnown::ProtobufFqn` and `::ProtobufDotFqn` enum variants from the generated types.
- CEL error messages now use `"value must …"` prefix (upstream change in protovalidate v1.1.1).
- Removed internal `WellKnownStringRule::ProtobufFqn` and `WellKnownStringRule::ProtobufDotFqn` variants.

## [0.2.0] - 2026-02-28

### Added

- Edition 2023 `DELIMITED` (group) encoding support via `TYPE_MESSAGE` to `TYPE_GROUP` normalization in `editions.rs`.
- Full conformance: 2854/2854 protovalidate tests pass (0 expected failures).
- Typed helper functions for extension extraction with concrete error types (`field_constraints_typed`, `message_constraints_typed`, `oneof_constraints_typed`, `predefined_constraints_typed`).
- `ConstraintDecodeError` enum with granular error variants for descriptor pool initialization, missing extensions, and decode failures.
- `Violation` accessor methods: `field_path()`, `rule_path()`, `rule_id()`, `message()`, `field_descriptor()`, `field_value()`, `rule_descriptor()`, `rule_value()`.
- `Violation` setter methods: `set_field_path()`, `set_rule_path()`, `set_rule_id()`, `set_message()`.
- `ValidationError` accessor methods: `violations()`, `into_violations()`, `len()`, `is_empty()`.
- `ValidationError::new()` and `ValidationError::single()` are now public constructors.
- Property-based tests for path round-tripping and edition normalization idempotency.
- `validate_repeated_unique_rule_type` compilation check: `repeated.unique` is now rejected for message item types.

### Changed

- **BREAKING**: `Violation` struct fields are now private. Use the new accessor and setter methods instead.
- **BREAKING**: `ValidationError.violations` field is now private. Use `violations()`, `into_violations()`, `len()`, `is_empty()` instead.
- **BREAKING** (`prost-protovalidate-types`): Replaced `anyhow` errors with `thiserror`-based `ConstraintDecodeError`. Extension trait methods now return `ConstraintDecodeResult<T>` instead of `anyhow::Result<Option<T>>`.
- **BREAKING** (`prost-protovalidate-types`): `OneofConstraintsExt::is_required()` replaced by fallible `try_is_required()`.
- **BREAKING** (`prost-protovalidate-types`): `DESCRIPTOR_POOL` initialization is now fallible — panics on decode failure replaced with graceful error propagation via `descriptor_pool_decode_error()`.
- Upgraded `fluent-uri` from 0.3 to 0.4.
- Removed direct `serde` dependency (unused; `serde_json` retained).
- Removed direct `anyhow` dependency.
- Deduplicated `prepend_rule_prefix` into `evaluator::mod.rs`.
- Deduplicated `kind_to_descriptor_type` between `violation.rs` and `builder.rs`.
- Conformance executor: extracted `run()` from `main()`, replaced `expect()` with `Result` propagation.
- Conformance executor: `catch_unwind_silent` renamed to `catch_unwind_safe`, panic hook suppression removed.
- Import ordering normalized to `std → external → workspace → local` across all modules.

### Fixed

- `Violation::to_proto()` no longer double-applies field descriptor to the first path element, fixing corrupted nested field paths.

## [0.1.0] - 2026-02-21

### Added

- Runtime validation engine with CEL expression support (`prost-protovalidate`).
- Generated `buf.validate` proto types with `prost` and `prost-reflect` (`prost-protovalidate-types`).
- Dynamic field inspection via `prost-reflect` descriptors.
- Evaluator caching for repeated validations (`Validator`).
- Global convenience function (`validate`) for one-off checks.
- Extension traits for extracting constraints from descriptors (`FieldConstraintsExt`, `MessageConstraintsExt`, `OneofConstraintsExt`, `PredefinedConstraintsExt`).
- Support for standard scalar rules, enum, map, repeated, any, duration, timestamp, and field mask rules.
- Predefined rule evaluation via `buf.validate.predefined` extensions.
- Per-call validation options (`FailFast`, `Filter`, `NowFn`).
- Validator construction options (`DisableLazy`, `AdditionalDescriptorSetBytes`, `MessageDescriptors`).

[Unreleased]: https://github.com/zs-dima/prost-protovalidate/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/zs-dima/prost-protovalidate/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/zs-dima/prost-protovalidate/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/zs-dima/prost-protovalidate/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/zs-dima/prost-protovalidate/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/zs-dima/prost-protovalidate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zs-dima/prost-protovalidate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zs-dima/prost-protovalidate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zs-dima/prost-protovalidate/releases/tag/v0.1.0
