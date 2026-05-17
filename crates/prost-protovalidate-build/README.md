# prost-protovalidate-build

Compile-time code generator for Protocol Buffer validation using [buf.validate](https://github.com/bufbuild/protovalidate) rules, built for `prost` — direct field access at runtime, no reflection, no CEL interpreter on the hot path.

Generates `impl prost_protovalidate::Validate` for messages with standard `buf.validate` field constraints. Messages containing CEL expressions are excluded at build time and fall back to runtime evaluation via `prost_protovalidate::Validator`.

## Usage

Add the dependency to your `Cargo.toml`:

```toml
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

Include the generated validation code alongside prost output:

```rust,ignore
include!(concat!(env!("OUT_DIR"), "/validate_impl.rs"));
```

## Supported Rules

- **Scalar**: bool const, numeric comparisons (gt/gte/lt/lte/const/in/not_in), string (min_len/max_len/pattern/prefix/suffix/contains/in/not_in/well-known formats), bytes (min_len/max_len/pattern/prefix/suffix/in/not_in/well-known formats), enum (const/in/not_in/defined_only)
- **Repeated**: min_items/max_items, per-item scalar constraints
- **Map**: min_pairs/max_pairs, per-key and per-value scalar constraints
- **Message**: required, nested recursive validation
- **Duration/Timestamp**: comparison constraints (gt/gte/lt/lte/const)
- **FieldMask**: const, in/not_in with prefix path matching
- **Any**: type_url in/not_in
- **WKT wrappers**: `google.protobuf.*Value` types unwrapped to inner scalar rules
- **Oneof**: required (must have a variant set)
- **Ignore**: `IGNORE_ALWAYS`, `IGNORE_IF_ZERO_VALUE`, `IGNORE_UNSPECIFIED` with presence semantics

## Limitations

- **CEL expressions** are not evaluated at build time. Messages with CEL rules (field-level or message-level) are skipped with a `cargo:warning`.
- **Predefined CEL constraints** (custom rules) are not supported.
- **Nested runtime-only dependencies** (for example, nested CEL or unsupported nested rules) cause parent message codegen to be skipped to prevent partial validation.

## License

[MIT](../../LICENSE-MIT) OR [Apache-2.0](../../LICENSE-APACHE)
