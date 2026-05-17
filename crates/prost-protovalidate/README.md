# prost-protovalidate

[![Crates.io](https://img.shields.io/crates/v/prost-protovalidate.svg)](https://crates.io/crates/prost-protovalidate)
[![docs.rs](https://img.shields.io/docsrs/prost-protovalidate)](https://docs.rs/prost-protovalidate)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue.svg)](https://blog.rust-lang.org/2025/04/03/Rust-1.86.0.html)

Validation for Protocol Buffer messages using [buf.validate](https://github.com/bufbuild/protovalidate) rules, built for `prost` and `prost-reflect` — with an optional **compile-time validation path via [`prost-protovalidate-build`](https://crates.io/crates/prost-protovalidate-build)** for schemas without CEL.

By default, dynamically inspects `prost-reflect` message descriptors, compiles `buf.validate` constraint annotations (including CEL expressions), and evaluates them against concrete message instances at runtime. For schemas without CEL, `prost-protovalidate-build` generates `impl Validate` at compile time so validation runs through monomorphized direct field access — the fastest path at runtime: no reflection, no CEL interpreter on the hot path.

## Quick Start

```toml
[dependencies]
prost = "0.14"
prost-protovalidate = "0.3"
```

Annotate your `.proto` files with `buf.validate` rules:

```protobuf
syntax = "proto3";

import "buf/validate/validate.proto";

message CreateUserRequest {
  string name = 1 [(buf.validate.field).string.min_len = 1];
  int32 age = 2 [(buf.validate.field).int32.gte = 18];
}
```

Validate in Rust:

```rust
use prost_protovalidate::validate;

let request = CreateUserRequest {
    name: "Alice".to_string(),
    age: 25,
};

match validate(&request) {
    Ok(()) => println!("Validation passed!"),
    Err(e) => println!("Validation failed: {e}"),
}
```

For repeated validations, construct a `Validator` once to cache compiled rules:

```rust
use prost_protovalidate::Validator;

let validator = Validator::new();
validator.validate(&request)?;
```

## Features

- **Compile-time validation via `prost-protovalidate-build` (fastest at runtime)** — companion crate [`prost-protovalidate-build`](https://crates.io/crates/prost-protovalidate-build) emits `impl Validate` at compile time for messages with standard-only rules. Monomorphized direct field access, no `prost-reflect` transcoding, no CEL interpreter on the hot path. Disable the `cel` feature to also drop `cel`, `chrono`, `paste`, and transitive `thiserror` 1.x from your dependency tree. Messages that need CEL fall back to the runtime `Validator` automatically (with a `cargo:warning=` diagnostic, never silently skipped).
- **Dynamic field inspection** via `prost-reflect` descriptors — no static code generation needed for validators.
- **CEL evaluation** — compiles and evaluates Common Expression Language expressions for cross-field and complex constraints.
- **Aggregated violations** — collects all constraint failures instead of short-circuiting on the first error.
- **Evaluation caching** — `Validator` caches compiled AST/CEL rules, avoiding re-parsing on every call.

## Compatibility

| prost-protovalidate | prost | prost-reflect | MSRV |
| ------------------- | ----- | ------------- | ---- |
| 0.3.x               | 0.14  | 0.16          | 1.86 |

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)
