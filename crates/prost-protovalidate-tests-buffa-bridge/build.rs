use std::env;
use std::path::PathBuf;

/// Compiles `bridge.proto` for the **buffa** backend in `runtime_bridge` mode:
///
/// 1. `prost-build` produces the `FileDescriptorSet` (into a scratch dir so its
///    generated Rust never collides with buffa's output).
/// 2. `buffa-build` consumes that exact descriptor set and emits buffa message
///    types + a module-tree include file.
/// 3. `prost-protovalidate-build` in `Backend::Buffa` + `runtime_bridge` mode
///    emits `impl Validate` blocks — inline for the standard-only message, and
///    bridge impls (encode → runtime `Validator`) for the CEL messages — plus
///    the embedded descriptor set the bridge accessor `include_bytes!`es.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto";
    let validate_proto_dir = "../prost-protovalidate-types/proto";

    println!("cargo:rerun-if-changed={proto_dir}");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("file_descriptor_set.bin");

    // Step 1: descriptor set via prost-build (Rust output discarded in a
    // scratch dir — buffa generates the types used by this crate).
    let scratch = out_dir.join("prost_scratch");
    std::fs::create_dir_all(&scratch)?;
    prost_build::Config::new()
        .out_dir(&scratch)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            &[format!("{proto_dir}/bridge.proto")],
            &[proto_dir, validate_proto_dir],
        )?;

    // Step 2: buffa message types from the same descriptor set.
    buffa_build::Config::new()
        .descriptor_set(&descriptor_path)
        .files(&["bridge.proto"])
        .include_file("_buffa_include.rs")
        .compile()?;

    // Step 3: generate `impl Validate` with the buffa backend, routing the CEL
    // messages through the runtime bridge instead of skipping them.
    prost_protovalidate_build::Builder::new()
        .file_descriptor_set_path(&descriptor_path)?
        .backend(prost_protovalidate_build::Backend::Buffa)
        .runtime_bridge(true)
        .compile()?;

    Ok(())
}
