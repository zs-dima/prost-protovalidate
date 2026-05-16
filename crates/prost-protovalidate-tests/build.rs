use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto";
    let validate_proto_dir = "../prost-protovalidate-types/proto";

    println!("cargo:rerun-if-changed={proto_dir}");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("file_descriptor_set.bin");

    // Step 1: Compile test protos → Rust types + file descriptor set.
    // Extern-path buf.validate types to avoid duplicates.
    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor_path)
        .extern_path(".buf.validate", "::prost_protovalidate_types")
        .compile_protos(
            &[format!("{proto_dir}/parity.proto")],
            &[proto_dir, validate_proto_dir],
        )?;

    // Step 2: Generate `impl Validate` from the descriptor set.
    prost_protovalidate_build::Builder::new()
        .file_descriptor_set_path(&descriptor_path)?
        .extern_path(".buf.validate", "::prost_protovalidate_types")
        .compile()?;

    Ok(())
}
