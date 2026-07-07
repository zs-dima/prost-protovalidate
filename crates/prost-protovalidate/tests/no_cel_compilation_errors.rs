#![cfg(all(feature = "reflect", not(feature = "cel")))]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost_protovalidate::{Error, Validator, ValidatorOption};
use prost_reflect::{DescriptorPool, DynamicMessage};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn build_fixture_descriptor_set() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let temp_root = unique_temp_dir("prost-protovalidate-no-cel");
    let proto_dir = temp_root.join("proto");
    let out_dir = temp_root.join("out");
    fs::create_dir_all(&proto_dir)?;
    fs::create_dir_all(&out_dir)?;

    let fixture_proto = proto_dir.join("fixture.proto");
    fs::write(
        &fixture_proto,
        r#"syntax = "proto2";
package nocel;
import "buf/validate/validate.proto";

extend buf.validate.StringRules {
  optional bool nonempty = 1001 [(buf.validate.predefined).cel = {
    id: "string.nonempty",
    expression: "this != ''",
    message: "value must be non-empty"
  }];
}

message FieldCel {
  optional int32 value = 1 [(buf.validate.field).cel = {
    id: "field.gt0",
    expression: "this > 0"
  }];
}

message MessageCel {
  optional int32 min = 1;
  optional int32 max = 2;
  option (buf.validate.message).cel = {
    id: "message.range",
    expression: "this.min <= this.max"
  };
}

message PredefinedCel {
  optional string name = 1 [(buf.validate.field).string = { [nocel.nonempty]: true }];
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
            &[fixture_proto.to_string_lossy().as_ref()],
            &[
                proto_dir.to_string_lossy().as_ref(),
                validate_proto_dir.to_string_lossy().as_ref(),
            ],
        )?;

    let bytes = fs::read(&descriptor_path)?;
    let _ = fs::remove_dir_all(temp_root);
    Ok(bytes)
}

fn validate_dynamic(descriptor_set_bytes: &[u8], message_full_name: &str) -> Result<(), Error> {
    let pool = DescriptorPool::decode(descriptor_set_bytes).unwrap_or_else(|err| {
        panic!("fixture descriptor set should decode: {err}");
    });
    let descriptor = pool
        .get_message_by_name(message_full_name)
        .unwrap_or_else(|| {
            panic!("fixture message `{message_full_name}` should exist");
        });
    let dynamic = DynamicMessage::new(descriptor);
    let validator = Validator::with_options(&[ValidatorOption::AdditionalDescriptorSetBytes(
        descriptor_set_bytes.to_vec(),
    )]);
    validator.validate(&dynamic)
}

#[test]
fn message_level_cel_requires_cel_feature() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = build_fixture_descriptor_set()?;
    match validate_dynamic(&descriptors, "nocel.MessageCel") {
        Err(Error::Compilation(err)) => {
            assert!(
                err.cause
                    .contains("has CEL expression rules but the `cel` feature is not enabled")
            );
        }
        Ok(()) => panic!("message-level CEL rules should fail compilation without `cel`"),
        Err(other) => panic!("expected CompilationError, got: {other}"),
    }
    Ok(())
}

#[test]
fn field_level_cel_requires_cel_feature() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = build_fixture_descriptor_set()?;
    match validate_dynamic(&descriptors, "nocel.FieldCel") {
        Err(Error::Compilation(err)) => {
            assert!(
                err.cause
                    .contains("has CEL expression rules but the `cel` feature is not enabled")
            );
        }
        Ok(()) => panic!("field-level CEL rules should fail compilation without `cel`"),
        Err(other) => panic!("expected CompilationError, got: {other}"),
    }
    Ok(())
}

#[test]
fn predefined_cel_requires_cel_feature() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = build_fixture_descriptor_set()?;
    match validate_dynamic(&descriptors, "nocel.PredefinedCel") {
        Err(Error::Compilation(err)) => {
            assert!(err.cause.contains("has predefined CEL rules on extension"));
            assert!(err.cause.contains("nocel.nonempty"));
        }
        Ok(()) => panic!("predefined CEL rules should fail compilation without `cel`"),
        Err(other) => panic!("expected CompilationError, got: {other}"),
    }
    Ok(())
}
