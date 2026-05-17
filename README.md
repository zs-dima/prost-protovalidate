# prost-protovalidate

[![Crates.io](https://img.shields.io/crates/v/prost-protovalidate.svg)](https://crates.io/crates/prost-protovalidate)
[![docs.rs](https://img.shields.io/docsrs/prost-protovalidate)](https://docs.rs/prost-protovalidate)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue.svg)](https://blog.rust-lang.org/2025/04/03/Rust-1.86.0.html)

Validation for Protocol Buffer messages using [buf.validate](https://github.com/bufbuild/protovalidate) rules, built for `prost` and `prost-reflect` — with an optional **compile-time validation path via [`prost-protovalidate-build`](crates/prost-protovalidate-build/)** for schemas without CEL.

By default, `prost-protovalidate` evaluates `buf.validate` constraints (including Common Expression Language / CEL expressions) at runtime through `prost-reflect`, enforcing rules directly from your single source of truth — your `.proto` files. For schemas without CEL, `prost-protovalidate-build` generates `impl Validate` at compile time so validation runs through monomorphized direct field access — the fastest path at runtime: no reflection, no CEL interpreter on the hot path.

## Key Features

- **Compile-time validation (fastest path at runtime)** — [`prost-protovalidate-build`](crates/prost-protovalidate-build/) emits `impl Validate` for messages with standard-only rules; no `prost-reflect` transcoding, no CEL interpreter, monomorphized direct field access. Combined with `default-features = false` on `prost-protovalidate`, the entire `cel` / `chrono` / `paste` / `thiserror` 1.x subtree drops out of your build. Trades binary size and build time for hot-path speed; messages with CEL automatically fall back to the runtime `Validator` (with a `cargo:warning=` diagnostic, never silently skipped).
- **Proto as single source of truth** — Define validation rules inside `.proto` files using `buf.validate` and enforce them automatically in Rust.
- **Runtime validation with CEL** — Leverages `prost-reflect` to dynamically inspect message fields and evaluate complex validation rules, including arbitrary CEL expressions, at runtime.
- **CEL Evaluation** — Fully supports compiling and evaluating Common Expression Language (CEL) conditions for cross-field or complex constraints.
- **Edition 2023 support** — Normalizes Edition 2023 descriptors (including `DELIMITED` group encoding) so `prost-reflect` 0.16 handles them correctly.
- **Modular Crates** — Clear separation between raw protobuf types (`prost-protovalidate-types`) and the runtime validation engine (`prost-protovalidate`).

## Crates

| Crate                                                          | Purpose                                                         | Cargo section          |
| -------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------- |
| [prost-protovalidate-types](crates/prost-protovalidate-types/) | `buf.validate` proto types with prost and prost-reflect support | `[dependencies]`       |
| [prost-protovalidate](crates/prost-protovalidate/)             | Runtime validation engine (CEL parsing, constraint evaluation)  | `[dependencies]`       |
| [prost-protovalidate-build](crates/prost-protovalidate-build/) | Compile-time code generator for validation                      | `[build-dependencies]` |

## Quick Start

Add the dependencies to your `Cargo.toml`:

```toml
[dependencies]
prost = "0.14"
prost-protovalidate = "0.4"
```

### Feature Flags

| Feature | Default | Description                                         |
| ------- | ------- | --------------------------------------------------- |
| `cel`   | Yes     | CEL expression evaluation and `chrono` time support |

To disable CEL for a lighter dependency footprint (removes `cel`, `chrono`,
`paste`, and `thiserror` 1.x transitive deps):

```toml
[dependencies]
prost-protovalidate = { version = "0.4", default-features = false }
```

Without `cel`, standard rules (range checks, string constraints, format
validators, etc.) work normally. Messages with CEL expressions or predefined
CEL rules will produce a `CompilationError` at validation time.

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
| 0.4.x               | 0.14  | 0.16          | 1.86 |

## Validation Modes

Three validation modes cover different use cases:

### Compile-time validation (fastest at runtime, no CEL)

For messages with **only** standard rules (no CEL). Validators are generated
at compile time and run through monomorphized direct field access — **no
`prost-reflect` transcoding, no CEL interpreter, no dynamic dispatch** on
the hot path. Combined with `default-features = false` on
`prost-protovalidate`, the entire `cel` / `chrono` / `paste` / `thiserror`
1.x subtree drops out of your build. Requires `prost-protovalidate-build` in
`[build-dependencies]`.

```rust
use prost_protovalidate::Validate;

msg.validate()?;
```

### Runtime validation with CEL (full conformance)

For messages with CEL expressions or mixed rules. Uses `prost-reflect`
dynamic dispatch and the CEL interpreter at runtime.

```rust
use prost_protovalidate::Validator;

let validator = Validator::new();
validator.validate(&msg)?;
```

### Runtime validation without CEL (lightweight)

For services that don't use CEL. Disabling the `cel` feature removes `cel`,
`chrono`, `paste`, and transitive `thiserror` 1.x deps. Pairs naturally with
compile-time validators above for a CEL-free dependency tree end to end.

```toml
[dependencies]
prost-protovalidate = { version = "0.4", default-features = false }
```

Standard rules work normally; messages with CEL rules produce a
`CompilationError`.

### Which mode for which message

| Proto rules                               | `Validate` trait generated? | How to validate                          |
| ----------------------------------------- | --------------------------- | ---------------------------------------- |
| Standard only (min_len, gte, email, etc.) | Yes                         | `msg.validate()` (compile-time, fastest) |
| CEL only (expressions)                    | No                          | `validator.validate(&msg)` (runtime)     |
| Mixed (standard + CEL)                    | No                          | `validator.validate(&msg)` (runtime)     |
| Nested runtime-only dependencies          | No                          | `validator.validate(&msg)` (runtime)     |
| No rules                                  | No                          | —                                        |

## Build-Time Code Generation

Add `prost-protovalidate-build` to your build dependencies:

```toml
[dependencies]
prost = "0.14"
prost-protovalidate = "0.4"

[build-dependencies]
prost-build = "0.14"
prost-protovalidate-build = "0.4"
```

In your `build.rs`:

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?)
        .join("file_descriptor_set.bin");

    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["proto/service.proto"], &["proto/"])?;

    prost_protovalidate_build::Builder::new()
        .file_descriptor_set_path(&descriptor_path)?
        .compile()?;

    Ok(())
}
```

Include the generated validators alongside your prost-generated code:

```rust,ignore
include!(concat!(env!("OUT_DIR"), "/validate_impl.rs"));
```

Messages with CEL or predefined CEL rules are skipped during code
generation (with a `cargo:warning` explaining why). Messages that
transitively depend on runtime-only nested validation are also skipped to
avoid partial generated validation. Use the runtime `Validator` for those
messages.

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
