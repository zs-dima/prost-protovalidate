//! Backend selection — which protobuf runtime the generated `impl Validate`
//! blocks target.
//!
//! The rule evaluation logic is backend-independent; what differs is the
//! *storage shape* of generated message structs. Every shape-dependent
//! emission goes through the helpers on [`Backend`]:
//!
//! | shape | `Prost` | `Buffa` |
//! |---|---|---|
//! | message field | `Option<T>` / `Option<Box<T>>` | `MessageField<T>` |
//! | enum field | bare `i32` | `EnumValue<E>` (open) / `E` (closed) |
//! | `optional` scalar | `Option<T>` | `Option<T>` (identical) |
//! | repeated / map | `Vec<T>` / `HashMap<K, V>` | identical (hasher differs — irrelevant to emission) |
//! | real oneof | `Option<OneofEnum>` | identical |
//! | type idents | renamed to `UpperCamelCase` | verbatim proto names |

use proc_macro2::{Ident, TokenStream};
use quote::quote;

/// The protobuf runtime whose generated message types the emitted
/// `impl Validate` blocks will access.
///
/// Select via [`Builder::backend`](crate::Builder::backend). Defaults to
/// [`Backend::Prost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Backend {
    /// `prost` / `prost-build` generated types (the default).
    #[default]
    Prost,
    /// [`buffa`](https://crates.io/crates/buffa) generated types
    /// (`MessageField<T>` presence, `EnumValue<E>` enums, verbatim type
    /// names).
    Buffa,
}

impl Backend {
    /// Presence test for a message-typed field: `true` when **unset**.
    pub(crate) fn msg_field_is_unset(self, field: &TokenStream) -> TokenStream {
        match self {
            Self::Prost => quote! { #field.is_none() },
            Self::Buffa => quote! { #field.is_unset() },
        }
    }

    /// Presence test for a message-typed field: `true` when **set**.
    pub(crate) fn msg_field_is_set(self, field: &TokenStream) -> TokenStream {
        match self {
            Self::Prost => quote! { #field.is_some() },
            Self::Buffa => quote! { #field.is_set() },
        }
    }

    /// Unwrap a set message-typed field, binding `bind` to `&T` inside `body`.
    /// Emits nothing (skips `body`) when the field is unset.
    pub(crate) fn if_msg_field_set(
        self,
        field: &TokenStream,
        bind: &Ident,
        body: &TokenStream,
    ) -> TokenStream {
        match self {
            Self::Prost => quote! {
                if let ::core::option::Option::Some(ref #bind) = #field {
                    #body
                }
            },
            Self::Buffa => quote! {
                if let ::core::option::Option::Some(#bind) = #field.as_option() {
                    #body
                }
            },
        }
    }

    /// Normalize an enum-typed access expression to its `i32` wire value.
    ///
    /// prost stores enum fields as bare `i32` — the access passes through.
    /// buffa stores `EnumValue<E>` for open enums and `E` for closed enums;
    /// both provide a `to_i32()` method, so one emission covers both.
    pub(crate) fn enum_to_i32(self, access: &TokenStream) -> TokenStream {
        match self {
            Self::Prost => access.clone(),
            Self::Buffa => quote! { #access.to_i32() },
        }
    }
}

#[cfg(test)]
mod tests {
    use quote::{format_ident, quote};

    use super::Backend;

    #[test]
    fn presence_shapes_per_backend() {
        let field = quote! { self.inner };
        assert_eq!(
            Backend::Prost.msg_field_is_unset(&field).to_string(),
            "self . inner . is_none ()"
        );
        assert_eq!(
            Backend::Buffa.msg_field_is_unset(&field).to_string(),
            "self . inner . is_unset ()"
        );
        assert_eq!(
            Backend::Prost.msg_field_is_set(&field).to_string(),
            "self . inner . is_some ()"
        );
        assert_eq!(
            Backend::Buffa.msg_field_is_set(&field).to_string(),
            "self . inner . is_set ()"
        );
    }

    #[test]
    fn unwrap_binds_by_ref_in_prost_and_via_as_option_in_buffa() {
        let field = quote! { self.inner };
        let bind = format_ident!("_nested");
        let body = quote! { touch(_nested); };

        let prost = Backend::Prost
            .if_msg_field_set(&field, &bind, &body)
            .to_string();
        assert!(
            prost.contains("Some (ref _nested) = self . inner"),
            "{prost}"
        );

        let buffa = Backend::Buffa
            .if_msg_field_set(&field, &bind, &body)
            .to_string();
        assert!(
            buffa.contains("Some (_nested) = self . inner . as_option ()"),
            "{buffa}"
        );
    }

    #[test]
    fn enum_access_gets_to_i32_only_in_buffa() {
        let access = quote! { self.status };
        assert_eq!(
            Backend::Prost.enum_to_i32(&access).to_string(),
            "self . status"
        );
        assert_eq!(
            Backend::Buffa.enum_to_i32(&access).to_string(),
            "self . status . to_i32 ()"
        );
    }
}
