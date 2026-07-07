//! Buffa-backend emission tests.
//!
//! Generates code from tiny inline `.proto` sources with
//! `Backend::Buffa` and asserts the emitted shapes: `MessageField`
//! presence (`is_unset`/`is_set`/`as_option`), `EnumValue::to_i32`
//! normalization, verbatim type idents (`UUID` stays `UUID`), and the
//! `fail_on_runtime_only` hard-error mode. Compile/behavior parity is
//! covered end-to-end by the `prost-protovalidate-tests-buffa` crate;
//! these tests pin the emission contract itself.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost_protovalidate_build::{Backend, Builder};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn builder_from_proto(
    file_name: &str,
    proto_source: &str,
) -> Result<(Builder, PathBuf), Box<dyn std::error::Error>> {
    let temp_root = unique_temp_dir("prost-protovalidate-build-buffa");
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

    let builder = Builder::new()
        .file_descriptor_set_path(&descriptor_path)?
        .out_dir(&out_dir)
        .backend(Backend::Buffa);
    Ok((builder, out_dir))
}

fn generate_buffa(
    file_name: &str,
    proto_source: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let (builder, out_dir) = builder_from_proto(file_name, proto_source)?;
    builder.compile()?;
    Ok(fs::read_to_string(out_dir.join("validate_impl.rs"))?)
}

#[test]
fn message_presence_uses_message_field_api() {
    let generated = generate_buffa(
        "presence.proto",
        r#"
syntax = "proto3";
package shapes;
import "buf/validate/validate.proto";

message Inner {
  string value = 1 [(buf.validate.field).string.min_len = 1];
}

message Outer {
  Inner required_inner = 1 [(buf.validate.field).required = true];
  Inner checked_inner = 2;
}
"#,
    )
    .expect("buffa generation should succeed");

    // `required` on a message field checks MessageField::is_unset.
    assert!(
        generated.contains("self.required_inner.is_unset()"),
        "expected is_unset presence check:\n{generated}"
    );
    // Nested validation unwraps through MessageField::as_option.
    assert!(
        generated.contains(".as_option()"),
        "expected as_option unwrap for nested validation:\n{generated}"
    );
    // No prost-shaped Option presence checks on message fields.
    assert!(
        !generated.contains("required_inner.is_none()"),
        "prost-shaped is_none leaked into buffa output:\n{generated}"
    );
}

#[test]
fn enum_rules_normalize_through_to_i32() {
    let generated = generate_buffa(
        "enums.proto",
        r#"
syntax = "proto3";
package shapes;
import "buf/validate/validate.proto";

enum Status {
  STATUS_UNSPECIFIED = 0;
  STATUS_ACTIVE = 1;
  STATUS_BLOCKED = 2;
}

message EnumHolder {
  Status status = 1 [
    (buf.validate.field).enum.defined_only = true,
    (buf.validate.field).enum.not_in = 2
  ];
  repeated Status statuses = 2 [
    (buf.validate.field).repeated.items.enum.defined_only = true
  ];
  optional Status opt_status = 3 [(buf.validate.field).enum.not_in = 2];
}
"#,
    )
    .expect("buffa generation should succeed");

    assert!(
        generated.contains("self.status.to_i32()"),
        "bare enum access must normalize via to_i32:\n{generated}"
    );
    assert!(
        generated.contains("(*_item).to_i32()"),
        "repeated enum items must normalize via to_i32:\n{generated}"
    );
    assert!(
        generated.contains("(*_val).to_i32()"),
        "optional enum unwrap must normalize via to_i32:\n{generated}"
    );
}

#[test]
fn type_idents_stay_verbatim() {
    let generated = generate_buffa(
        "verbatim.proto",
        r#"
syntax = "proto3";
package core.v1;
import "buf/validate/validate.proto";

message UUID {
  string value = 1 [(buf.validate.field).string.uuid = true];
}
"#,
    )
    .expect("buffa generation should succeed");

    // buffa keeps proto names verbatim; prost would rename UUID → Uuid.
    assert!(
        generated.contains("for core::v1::UUID"),
        "expected verbatim UUID impl target:\n{generated}"
    );
    assert!(
        !generated.contains("for core::v1::Uuid"),
        "prost-renamed ident leaked into buffa output:\n{generated}"
    );
}

#[test]
fn nested_message_types_resolve_through_snake_case_module() {
    let generated = generate_buffa(
        "nested.proto",
        r#"
syntax = "proto3";
package shapes;
import "buf/validate/validate.proto";

message Envelope {
  message Payload {
    string body = 1 [(buf.validate.field).string.min_len = 1];
  }
  Payload payload = 1;
}
"#,
    )
    .expect("buffa generation should succeed");

    assert!(
        generated.contains("for shapes::envelope::Payload"),
        "nested type must resolve through the parent's snake_case module:\n{generated}"
    );
}

#[test]
fn wkt_wrapper_and_timestamp_unwrap_via_as_option() {
    let generated = generate_buffa(
        "wkt.proto",
        r#"
syntax = "proto3";
package shapes;
import "buf/validate/validate.proto";
import "google/protobuf/wrappers.proto";
import "google/protobuf/timestamp.proto";

message WktHolder {
  google.protobuf.Int32Value count = 1 [(buf.validate.field).int32.gte = 1];
  google.protobuf.Timestamp when = 2 [(buf.validate.field).timestamp.lt_now = true];
}
"#,
    )
    .expect("buffa generation should succeed");

    assert!(
        generated.contains("self.count.as_option()"),
        "wrapper rules must unwrap via as_option:\n{generated}"
    );
    assert!(
        generated.contains("self.when.as_option()"),
        "timestamp rules must unwrap via as_option:\n{generated}"
    );
    assert!(
        generated.contains("_wkt.value"),
        "wrapper inner access must read .value:\n{generated}"
    );
}

#[test]
fn fail_on_runtime_only_turns_cel_into_build_error() {
    let (builder, _out) = builder_from_proto(
        "cel.proto",
        r#"
syntax = "proto3";
package shapes;
import "buf/validate/validate.proto";

message WithCel {
  int32 value = 1 [(buf.validate.field).cel = {
    id: "value.positive",
    message: "value must be positive",
    expression: "this > 0"
  }];
}
"#,
    )
    .expect("descriptor generation should succeed");

    let err = builder
        .fail_on_runtime_only(true)
        .compile()
        .expect_err("CEL rules must abort generation under fail_on_runtime_only");
    let text = err.to_string();
    assert!(
        text.contains("fail_on_runtime_only") && text.contains("CEL"),
        "error should explain the runtime-only routing: {text}"
    );
}

#[test]
fn without_fail_flag_cel_messages_are_skipped_not_errored() {
    let (builder, out_dir) = builder_from_proto(
        "cel_skip.proto",
        r#"
syntax = "proto3";
package shapes;
import "buf/validate/validate.proto";

message WithCel {
  int32 value = 1 [(buf.validate.field).cel = {
    id: "value.positive",
    message: "value must be positive",
    expression: "this > 0"
  }];
}

message Standard {
  string name = 1 [(buf.validate.field).string.min_len = 1];
}
"#,
    )
    .expect("descriptor generation should succeed");

    builder
        .compile()
        .expect("default mode should skip runtime-only messages");
    let generated =
        fs::read_to_string(out_dir.join("validate_impl.rs")).expect("generated file should exist");
    assert!(
        !generated.contains("WithCel"),
        "CEL message must be skipped:\n{generated}"
    );
    assert!(
        generated.contains("for shapes::Standard"),
        "standard message must still be generated:\n{generated}"
    );
}
