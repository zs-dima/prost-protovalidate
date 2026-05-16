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

fn generate_from_proto(
    file_name: &str,
    proto_source: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let temp_root = unique_temp_dir("prost-protovalidate-build-nested");
    let proto_dir = temp_root.join("proto");
    let out_dir = temp_root.join("out");
    fs::create_dir_all(&proto_dir)?;
    fs::create_dir_all(&out_dir)?;

    let proto_path = proto_dir.join(file_name);
    fs::write(&proto_path, proto_source)?;

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
    let _ = fs::remove_dir_all(temp_root);
    Ok(generated)
}

#[test]
fn nested_runtime_only_children_skip_parent_codegen() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "nested_runtime_only.proto",
        r#"syntax = "proto3";
package nestedruntime;
import "buf/validate/validate.proto";

message Child {
  int32 value = 1 [(buf.validate.field).cel = {
    id: "child.gt0",
    expression: "this > 0"
  }];
}

message Parent {
  string name = 1 [(buf.validate.field).string.min_len = 1];
  Child child = 2;
}

message ParentList {
  string name = 1 [(buf.validate.field).string.min_len = 1];
  repeated Child children = 2;
}

message ParentMap {
  string name = 1 [(buf.validate.field).string.min_len = 1];
  map<string, Child> children = 2;
}
"#,
    )?;

    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for nestedruntime::Child"),
        "CEL child should be runtime-only"
    );
    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for nestedruntime::Parent"),
        "parent with nested runtime-only child must be skipped"
    );
    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for nestedruntime::ParentList"),
        "repeated nested runtime-only child must skip parent"
    );
    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for nestedruntime::ParentMap"),
        "map nested runtime-only child must skip parent"
    );

    Ok(())
}

#[test]
fn recursive_standard_messages_generate_and_validate_map_values()
-> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "recursive_standard.proto",
        r#"syntax = "proto3";
package recursiveok;
import "buf/validate/validate.proto";

message Node {
  int32 value = 1 [(buf.validate.field).int32.gt = 0];
  Node next = 2;
}

message Root {
  map<string, Node> nodes = 1;
}
"#,
    )?;

    assert!(
        generated.contains("impl ::prost_protovalidate::Validate for recursiveok::Node"),
        "recursive standard message should still receive Validate impl"
    );
    assert!(
        generated.contains("impl ::prost_protovalidate::Validate for recursiveok::Root"),
        "parent map holder should receive Validate impl"
    );
    assert!(
        generated.contains("for (_k, _v) in &self.nodes"),
        "map value nested validation loop should be generated"
    );
    assert!(
        generated.contains("::prost_protovalidate::Validate::validate("),
        "map value nested validation should call Validate recursively"
    );

    Ok(())
}
