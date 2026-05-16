//! Capability-analyzer routing tests.
//!
//! Exercises shapes that the codegen must *refuse* — emitting an
//! `impl Validate` for them would either fail to compile (real-oneof
//! variants, repeated WKT wrappers) or silently bypass a rule. For each
//! shape we generate code from a tiny inline `.proto` and assert the
//! offending message has no `impl Validate` block.

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
    let temp_root = unique_temp_dir("prost-protovalidate-build-capability");
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
fn virtual_oneof_over_real_oneof_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "virtual_over_real.proto",
        r#"syntax = "proto3";
package virtreal;
import "buf/validate/validate.proto";

// `value` lives inside a real proto `oneof`. Prost stores it under
// `self.choice = Some(Choice::Value(...))` — there is no `self.value`
// struct member, so the virtual oneof's `self.value` access wouldn't
// type-check. Codegen must route this message to runtime.
message HasVirtualOverRealOneof {
  option (buf.validate.message).oneof = { fields: ["value"], required: true };

  oneof choice {
    string value = 1;
  }
}
"#,
    )?;

    assert!(
        !generated
            .contains("impl ::prost_protovalidate::Validate for virtreal::HasVirtualOverRealOneof"),
        "virtual oneof referencing a real-oneof variant must route to runtime, \
         but generated code contained an impl for HasVirtualOverRealOneof.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn repeated_wkt_wrapper_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "repeated_wrapper.proto",
        r#"syntax = "proto3";
package repwrap;
import "google/protobuf/wrappers.proto";
import "buf/validate/validate.proto";

// `repeated google.protobuf.Int32Value` — the singular WKT wrapper
// unwrap path doesn't apply to `Vec<Int32Value>`, so the analyzer must
// not emit a `Validate` impl for the parent.
message HasRepeatedWrapper {
  repeated google.protobuf.Int32Value values = 1 [
    (buf.validate.field).repeated.items.int32.gt = 0
  ];
}
"#,
    )?;

    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for repwrap::HasRepeatedWrapper"),
        "repeated wrapper-typed field must route to runtime.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn map_wkt_wrapper_value_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "map_wrapper.proto",
        r#"syntax = "proto3";
package mapwrap;
import "google/protobuf/wrappers.proto";
import "buf/validate/validate.proto";

// `map<string, google.protobuf.StringValue>` — same reasoning as
// repeated; codegen must route the parent to runtime.
message HasMapWrapper {
  map<string, google.protobuf.StringValue> by_key = 1 [
    (buf.validate.field).map.values.string.min_len = 1
  ];
}
"#,
    )?;

    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for mapwrap::HasMapWrapper"),
        "map field with wrapper value must route to runtime.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn map_entry_message_does_not_get_validate_impl() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "map_entry_skip.proto",
        r#"syntax = "proto3";
package mapentry;
import "buf/validate/validate.proto";

message Inner {
  string name = 1 [(buf.validate.field).string.min_len = 1];
}

message HasMap {
  map<string, Inner> items = 1;
}
"#,
    )?;

    // The synthetic `HasMap.ItemsEntry` is internal to prost-reflect
    // and has no corresponding Rust struct — codegen must not emit
    // an `impl Validate` for it.
    assert!(
        !generated.contains("ItemsEntry"),
        "synthetic map-entry message must not receive a Validate impl.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn keyword_named_fields_generate_raw_identifiers() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "keyword_fields.proto",
        r#"syntax = "proto3";
package kw;
import "buf/validate/validate.proto";

message HasKeywords {
  string type = 1 [(buf.validate.field).string.min_len = 1];
  string mod = 2 [(buf.validate.field).string.min_len = 1];
  string match = 3 [(buf.validate.field).string.min_len = 1];
}
"#,
    )?;

    assert!(
        generated.contains("impl ::prost_protovalidate::Validate for kw::HasKeywords"),
        "expected a Validate impl for HasKeywords.\n\nGenerated:\n{generated}",
    );
    assert!(
        generated.contains("self.r#type") || generated.contains("self.r\\#type"),
        "expected `self.r#type` raw-identifier access.\n\nGenerated:\n{generated}",
    );
    assert!(
        generated.contains("self.r#mod") || generated.contains("self.r\\#mod"),
        "expected `self.r#mod` raw-identifier access.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn real_oneof_scalar_with_rules_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    // A scalar field with rules living inside a real proto `oneof` is
    // stored by prost as a variant of `Option<Enum>` — `self.value` does
    // not exist as a struct member. Codegen must route the parent to
    // runtime instead of emitting an `impl Validate` that would fail to
    // compile.
    let generated = generate_from_proto(
        "real_oneof_rules.proto",
        r#"syntax = "proto3";
package realoneof;
import "buf/validate/validate.proto";

message HasRealOneofRules {
  oneof choice {
    string value = 1 [(buf.validate.field).string.min_len = 1];
    int32  count = 2 [(buf.validate.field).int32.gt = 0];
  }
}
"#,
    )?;

    assert!(
        !generated
            .contains("impl ::prost_protovalidate::Validate for realoneof::HasRealOneofRules"),
        "real-oneof scalar with rules must route to runtime.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn predefined_cel_on_extension_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    // User-declared predefined CEL rules attach to extension *descriptors*
    // of buf.validate rule messages (here: extending StringRules), not to
    // user field options. The codegen must inspect those extension
    // descriptors and route any field carrying predefined CEL to the
    // runtime validator.
    let generated = generate_from_proto(
        "predefined_cel.proto",
        r#"syntax = "proto2";
package predef;
import "buf/validate/validate.proto";

extend buf.validate.StringRules {
  optional bool ascii_only = 1234 [(buf.validate.predefined).cel = {
    id: "string.ascii_only",
    expression: "this.matches('^[\\x00-\\x7F]*$')"
  }];
}

message HasPredefinedCel {
  optional string label = 1 [(buf.validate.field) = {
    string: { [predef.ascii_only]: true }
  }];
}
"#,
    )?;

    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for predef::HasPredefinedCel"),
        "field carrying predefined CEL must route to runtime.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn extern_path_message_gets_no_impl() -> Result<(), Box<dyn std::error::Error>> {
    // When the user maps a proto package to a Rust type owned by another
    // crate via `Builder::extern_path`, codegen cannot legally emit
    // `impl prost_protovalidate::Validate for ::other_crate::…` (orphan
    // rule). The owning crate is responsible for validation.
    let temp_root = unique_temp_dir("prost-protovalidate-build-extern");
    let proto_dir = temp_root.join("proto");
    let out_dir = temp_root.join("out");
    fs::create_dir_all(&proto_dir)?;
    fs::create_dir_all(&out_dir)?;

    let proto_source = r#"syntax = "proto3";
package extpkg;
import "buf/validate/validate.proto";

message ExternedThing {
  string name = 1 [(buf.validate.field).string.min_len = 1];
}
"#;
    let proto_path = proto_dir.join("extern.proto");
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
        .extern_path(".extpkg", "::other_crate::extpkg")
        .out_dir(&out_dir)
        .compile()?;

    let generated = fs::read_to_string(out_dir.join("validate_impl.rs"))?;
    let _ = fs::remove_dir_all(temp_root);

    assert!(
        !generated.contains("ExternedThing"),
        "extern-pathed messages must not get a Validate impl.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn repeated_unique_on_floats_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    // `repeated.unique` on `float`/`double`/message elements can't be
    // implemented with a plain HashSet (no `Eq`/`Hash`). Codegen must
    // route such messages to runtime, which uses canonical-bits encoding.
    let generated = generate_from_proto(
        "unique_floats.proto",
        r#"syntax = "proto3";
package uniqfloat;
import "buf/validate/validate.proto";

message HasUniqueFloats {
  repeated float xs = 1 [(buf.validate.field).repeated.unique = true];
}
"#,
    )?;

    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for uniqfloat::HasUniqueFloats"),
        "repeated.unique on floats must route to runtime.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn repeated_unique_on_messages_routed_to_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let generated = generate_from_proto(
        "unique_messages.proto",
        r#"syntax = "proto3";
package uniqmsg;
import "buf/validate/validate.proto";

message Item { string id = 1; }

message HasUniqueMessages {
  repeated Item items = 1 [(buf.validate.field).repeated.unique = true];
}
"#,
    )?;

    assert!(
        !generated.contains("impl ::prost_protovalidate::Validate for uniqmsg::HasUniqueMessages"),
        "repeated.unique on messages must route to runtime.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn repeated_unique_on_strings_still_generated() -> Result<(), Box<dyn std::error::Error>> {
    // Sanity check: hashable element kinds keep the codegen fast path.
    let generated = generate_from_proto(
        "unique_strings.proto",
        r#"syntax = "proto3";
package uniqstr;
import "buf/validate/validate.proto";

message HasUniqueStrings {
  repeated string names = 1 [(buf.validate.field).repeated.unique = true];
}
"#,
    )?;

    assert!(
        generated.contains("impl ::prost_protovalidate::Validate for uniqstr::HasUniqueStrings"),
        "repeated.unique on strings should be codegen'd.\n\nGenerated:\n{generated}",
    );

    Ok(())
}

#[test]
fn proto2_required_scalar_uses_default_check_not_is_none() -> Result<(), Box<dyn std::error::Error>>
{
    // proto2 `required` scalars have `supports_presence() == true` AND
    // `is_required() == true`, but prost stores them as bare `T`, not
    // `Option<T>`. Emitting `self.mandatory.is_none()` would produce
    // `error[E0599]: no method named is_none found for type i32`.
    //
    // Regression guard for the B1 fix that switched `generate_required_check`
    // from `supports_presence()` to
    // `kind().as_message().is_some() || (supports_presence() && !is_required())`.
    let generated = generate_from_proto(
        "proto2_required.proto",
        r#"syntax = "proto2";
package p2req;
import "buf/validate/validate.proto";

message Proto2Required {
  required int32 mandatory = 1 [(buf.validate.field).required = true];
}
"#,
    )?;

    assert!(
        generated.contains("impl ::prost_protovalidate::Validate for p2req::Proto2Required"),
        "proto2 message with required scalar must still receive an impl.\n\nGenerated:\n{generated}",
    );
    assert!(
        !generated.contains("self.mandatory.is_none()"),
        "proto2 required scalar must not emit is_none() on bare T.\n\nGenerated:\n{generated}",
    );

    Ok(())
}
