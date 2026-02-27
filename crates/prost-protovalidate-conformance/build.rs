fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto";
    let types_proto_dir = "../prost-protovalidate-types/proto";
    let proto_file = "buf/validate/conformance/harness/harness.proto";

    println!("cargo:rerun-if-changed={proto_dir}/{proto_file}");

    // Map only the specific buf.validate types referenced by harness.proto.
    // Using ".buf.validate" would also suppress buf.validate.conformance.harness types.
    prost_build::Config::new()
        .extern_path(
            ".buf.validate.Violations",
            "::prost_protovalidate_types::Violations",
        )
        .extern_path(
            ".buf.validate.Violation",
            "::prost_protovalidate_types::Violation",
        )
        .extern_path(
            ".buf.validate.FieldPath",
            "::prost_protovalidate_types::FieldPath",
        )
        .extern_path(
            ".buf.validate.FieldPathElement",
            "::prost_protovalidate_types::FieldPathElement",
        )
        .compile_protos(
            &[format!("{proto_dir}/{proto_file}")],
            &[proto_dir, types_proto_dir],
        )?;

    Ok(())
}
