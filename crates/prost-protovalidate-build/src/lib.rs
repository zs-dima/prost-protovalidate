//! Build-time code generator for zero-cost Protocol Buffer validation.
//!
//! Generates `impl prost_protovalidate::Validate` for messages that have
//! **only** standard `buf.validate` rules (no CEL expressions). Messages
//! with any CEL rules are excluded and must use the runtime
//! `prost_protovalidate::Validator` instead.
//!
//! # Usage
//!
//! In your `build.rs`:
//!
//! ```rust,no_run
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // First, compile protos with prost-build (writes descriptor set)
//!     let descriptor_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?)
//!         .join("file_descriptor_set.bin");
//!     prost_build::Config::new()
//!         .file_descriptor_set_path(&descriptor_path)
//!         .compile_protos(&["proto/service.proto"], &["proto/"])?;
//!
//!     // Then generate validation impls
//!     prost_protovalidate_build::Builder::new()
//!         .file_descriptor_set_path(&descriptor_path)?
//!         .compile()?;
//!     Ok(())
//! }
//! ```
//!
//! Then include the generated code alongside the prost-generated code:
//!
//! ```rust,ignore
//! include!(concat!(env!("OUT_DIR"), "/validate_impl.rs"));
//! ```

mod codegen;
mod message;
mod naming;
mod rules;

use std::fs;
use std::path::{Path, PathBuf};

use prost_reflect::DescriptorPool;

/// Builder for configuring and running the validation code generator.
#[derive(Default)]
pub struct Builder {
    file_descriptor_set_bytes: Option<Vec<u8>>,
    out_dir: Option<PathBuf>,
    extern_paths: Vec<(String, String)>,
}

impl Builder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the file descriptor set bytes directly.
    #[must_use]
    pub fn file_descriptor_set_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.file_descriptor_set_bytes = Some(bytes);
        self
    }

    /// Read the file descriptor set from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn file_descriptor_set_path(mut self, path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = fs::read(path.as_ref()).map_err(|e| Error::Io {
            path: path.as_ref().to_path_buf(),
            source: e,
        })?;
        self.file_descriptor_set_bytes = Some(bytes);
        Ok(self)
    }

    /// Override the output directory (defaults to `OUT_DIR` env var).
    #[must_use]
    pub fn out_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.out_dir = Some(path.into());
        self
    }

    /// Map a proto package path to a Rust module path.
    ///
    /// This is equivalent to prost-build's `extern_path` and should match
    /// your prost-build configuration.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// prost_protovalidate_build::Builder::new()
    ///     .extern_path(".my.package", "::my_crate::my_package");
    /// ```
    #[must_use]
    pub fn extern_path(
        mut self,
        proto_path: impl Into<String>,
        rust_path: impl Into<String>,
    ) -> Self {
        self.extern_paths
            .push((proto_path.into(), rust_path.into()));
        self
    }

    /// Run the code generator.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor set is missing, cannot be parsed,
    /// or the output file cannot be written.
    pub fn compile(self) -> Result<(), Error> {
        let fds_bytes = self
            .file_descriptor_set_bytes
            .ok_or(Error::MissingDescriptorSet)?;

        // Decode the raw bytes directly into a prost-reflect DescriptorPool.
        // Using prost_types::FileDescriptorSet::decode() first would strip
        // extension data (buf.validate.field, etc.) from proto options since
        // prost does not preserve unknown fields by default.
        let pool = DescriptorPool::decode(fds_bytes.as_slice())
            .map_err(|e| Error::Decode(e.to_string()))?;

        let out_dir = match self.out_dir {
            Some(dir) => dir,
            None => PathBuf::from(std::env::var("OUT_DIR").map_err(|_| Error::MissingOutDir)?),
        };

        let naming_ctx = naming::NamingContext::new(&self.extern_paths);
        let tokens = codegen::generate(&pool, &naming_ctx);

        let file = syn::parse2(tokens).map_err(|e| Error::Codegen(e.to_string()))?;
        let formatted = prettyplease::unparse(&file);

        fs::create_dir_all(&out_dir).map_err(|e| Error::Io {
            path: out_dir.clone(),
            source: e,
        })?;

        let output_path = out_dir.join("validate_impl.rs");
        fs::write(&output_path, formatted).map_err(|e| Error::Io {
            path: output_path,
            source: e,
        })?;

        Ok(())
    }
}

/// Errors that can occur during code generation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No file descriptor set was provided.
    #[error(
        "no file descriptor set provided; call file_descriptor_set_bytes() or file_descriptor_set_path()"
    )]
    MissingDescriptorSet,

    /// The `OUT_DIR` environment variable is not set.
    #[error("OUT_DIR environment variable not set; call out_dir() or run from build.rs")]
    MissingOutDir,

    /// Failed to decode the file descriptor set.
    #[error("failed to decode file descriptor set: {0}")]
    Decode(String),

    /// Code generation produced invalid tokens.
    #[error("code generation error: {0}")]
    Codegen(String),

    /// I/O error reading or writing files.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// The path that caused the error.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A constraint could not be decoded from proto extensions.
    #[error("constraint decode error: {0}")]
    ConstraintDecode(String),
}
