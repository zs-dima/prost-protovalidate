# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Removed `WellKnownStringRule::ProtobufFqn` and `WellKnownStringRule::ProtobufDotFqn` variants — dropped upstream in protovalidate v1.1.1.
- Synced `validate.proto` to upstream `buf.build/bufbuild/protovalidate` v1.1.1 (CEL error messages now use `"value must …"` prefix; `string.protobuf_fqn` / `string.protobuf_dot_fqn` rules removed).
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

[0.2.0]: https://github.com/zs-dima/prost-protovalidate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zs-dima/prost-protovalidate/releases/tag/v0.1.0
