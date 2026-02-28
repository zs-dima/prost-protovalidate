# prost-protovalidate

[![Crates.io](https://img.shields.io/crates/v/prost-protovalidate.svg)](https://crates.io/crates/prost-protovalidate)
[![docs.rs](https://img.shields.io/docsrs/prost-protovalidate)](https://docs.rs/prost-protovalidate)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue.svg)](https://blog.rust-lang.org/2025/04/03/Rust-1.86.0.html)

Runtime validation for Protocol Buffer messages using [buf.validate](https://github.com/bufbuild/protovalidate) rules, specifically built for `prost` and `prost-reflect`.

`prost-protovalidate` interprets `buf.validate` constraints (including Common Expression Language / CEL conditions) attached to protobuf messages at runtime, enabling robust input validation directly from your single source of truth—your `.proto` files.

## Key Features

- **Proto as single source of truth** — Define validation rules inside `.proto` files using `buf.validate` and enforce them automatically in Rust.
- **Runtime validation** — Leverages `prost-reflect` to dynamically inspect message fields and evaluate complex validation rules at runtime.
- **CEL Evaluation** — Fully supports compiling and evaluating Common Expression Language (CEL) conditions for cross-field or complex constraints.
- **Edition 2023 support** — Normalizes Edition 2023 descriptors (including `DELIMITED` group encoding) so `prost-reflect` 0.16 handles them correctly.
- **Modular Crates** — Clear separation between raw protobuf types (`prost-protovalidate-types`) and the runtime validation engine (`prost-protovalidate`).

## Crates

| Crate                                                          | Purpose                                                         | Cargo section    |
| -------------------------------------------------------------- | --------------------------------------------------------------- | ---------------- |
| [prost-protovalidate-types](crates/prost-protovalidate-types/) | `buf.validate` proto types with prost and prost-reflect support | `[dependencies]` |
| [prost-protovalidate](crates/prost-protovalidate/)             | Runtime validation engine (CEL parsing, constraint evaluation)  | `[dependencies]` |

## Quick Start

Add the dependencies to your `Cargo.toml`:

```toml
[dependencies]
prost = "0.14"
prost-protovalidate = "0.1"
```

### Usage

Annotate your `.proto` files with `buf.validate` rules:

```protobuf
syntax = "proto3";

import "buf/validate/validate.proto";

message CreateUserRequest {
  string name = 1 [(buf.validate.field).string.min_len = 1];
  int32 age = 2 [(buf.validate.field).int32.gte = 18];
}
```

In your Rust code, run the validator against a generated `prost` message using the provided `validate` shortcut:

```rust
use prost_protovalidate::validate;

let request = CreateUserRequest {
    name: "Alice".to_string(),
    age: 25,
};

match validate(&request) {
    Ok(_) => println!("Validation passed!"),
    Err(e) => println!("Validation failed: {}", e),
}
```

Or cache a `Validator` instance if you need to perform multiple validations efficiently:

```rust
use prost_protovalidate::Validator;

// Creating a Validator parses and caches rules under the hood
let validator = Validator::new();
validator.validate(&request)?;
```

## Compatibility

| prost-protovalidate | prost | prost-reflect | MSRV |
| ------------------- | ----- | ------------- | ---- |
| 0.1.x               | 0.14  | 0.16          | 1.86 |

## Conformance

Full conformance with the bufbuild protovalidate test suite: **2854/2854 tests pass** (0 expected failures).

Conformance uses a pinned upstream harness from
`github.com/bufbuild/protovalidate/tools/protovalidate-conformance`.

Pinned versions are defined in the repository root `Makefile`:

- `PROTOVALIDATE_TOOLS_VERSION`
- `PROTOVALIDATE_SCHEMA_REF`

### Upgrade playbook

1. Bump `PROTOVALIDATE_TOOLS_VERSION` and `PROTOVALIDATE_SCHEMA_REF` in `Makefile`.
2. Sync `validate.proto` using the workflow in
   `crates/prost-protovalidate-types/SYNC.md`.
3. Run conformance and update `expected_failures.yaml` with any new failures:
   - `make conformance`
4. Run regression tests:
   - `cargo test --all-features`
5. Commit version bump and `expected_failures.yaml` changes together.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)
