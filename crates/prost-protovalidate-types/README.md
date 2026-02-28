# prost-protovalidate-types

[![Crates.io](https://img.shields.io/crates/v/prost-protovalidate-types.svg)](https://crates.io/crates/prost-protovalidate-types)
[![docs.rs](https://img.shields.io/docsrs/prost-protovalidate-types)](https://docs.rs/prost-protovalidate-types)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Generated Rust types for the [buf.validate](https://github.com/bufbuild/protovalidate) protobuf schema, built with `prost` and `prost-reflect`.

## What this crate provides

- All message and enum types from `buf/validate/validate.proto` (e.g. `FieldRules`, `MessageRules`, `OneofRules`).
- A shared `DESCRIPTOR_POOL` containing the file descriptor set for runtime reflection.
- Extension traits for extracting constraint annotations from `prost-reflect` descriptors (`FieldConstraintsExt`, `MessageConstraintsExt`, `OneofConstraintsExt`, and more).
- Typed helper functions (`field_constraints_typed`, `message_constraints_typed`, `oneof_constraints_typed`, `predefined_constraints_typed`) for callers that need concrete decode errors.

## When to use this crate

Most users should depend on [`prost-protovalidate`](https://crates.io/crates/prost-protovalidate) directly, which includes the evaluation engine and re-exports the types needed for validation.

Use `prost-protovalidate-types` when you only need the generated types or descriptor pool without the constraint evaluation engine.

## Compatibility

| prost-protovalidate-types | prost | prost-reflect | MSRV |
| ------------------------- | ----- | ------------- | ---- |
| 0.3.x                     | 0.14  | 0.16          | 1.86 |

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)
