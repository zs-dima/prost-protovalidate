use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost_protovalidate_build::Builder;

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[test]
fn invalid_regex_rules_skip_codegen_impl_generation() -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = unique_temp_dir("prost-protovalidate-build-invalid-regex");
    let proto_dir = temp_root.join("proto");
    let out_dir = temp_root.join("out");
    fs::create_dir_all(&proto_dir)?;
    fs::create_dir_all(&out_dir)?;

    let proto_path = proto_dir.join("invalid_regex.proto");
    fs::write(
        &proto_path,
        r#"syntax = "proto3";
package invalidregex;
import "buf/validate/validate.proto";

message BadRegex {
  string value = 1 [(buf.validate.field).string.pattern = "["];
}
"#,
    )?;

    let descriptor_path = out_dir.join("file_descriptor_set.bin");
    let prost_out_dir = out_dir.join("prost_out");
    fs::create_dir_all(&prost_out_dir)?;
    let validate_proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("prost-protovalidate-types")
        .join("proto");

    prost_build::Config::new()
        .out_dir(&prost_out_dir)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            &[proto_path.to_string_lossy().as_ref()],
            &[
                proto_dir.to_string_lossy().as_ref(),
                validate_proto_dir.to_string_lossy().as_ref(),
            ],
        )?;

    Builder::new()
        .file_descriptor_set_path(&descriptor_path)?
        .out_dir(&out_dir)
        .compile()?;

    let generated = fs::read_to_string(out_dir.join("validate_impl.rs"))?;
    assert!(
        generated.trim().is_empty(),
        "invalid regex should skip message codegen, got: {generated}"
    );

    let _ = fs::remove_dir_all(temp_root);
    Ok(())
}
