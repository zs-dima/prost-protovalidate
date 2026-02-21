# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/zs-dima/prost-protovalidate/releases/tag/v0.1.0
