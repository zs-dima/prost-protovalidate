use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto";
    let files = &["buf/validate/validate.proto"];

    for f in files {
        println!("cargo:rerun-if-changed={proto_dir}/{f}");
    }

    let base_path = PathBuf::from(
        env::var("OUT_DIR")
            .map_err(|err| format!("missing OUT_DIR environment variable: {err}"))?,
    );
    let descriptor_path = base_path.join("file_descriptor_set.bin");

    prost_reflect_build::Builder::new()
        .file_descriptor_set_path(&descriptor_path)
        .descriptor_pool("DESCRIPTOR_POOL")
        .compile_protos(files, &[proto_dir])?;

    Ok(())
}
