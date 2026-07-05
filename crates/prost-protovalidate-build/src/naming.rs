//! Proto-to-Rust name conversion following prost conventions.

use proc_macro2::TokenStream;
use quote::quote;

/// Context for converting proto fully-qualified names to Rust type paths.
pub(crate) struct NamingContext {
    extern_paths: Vec<(String, String)>,
}

impl NamingContext {
    pub(crate) fn new(extern_paths: &[(String, String)]) -> Self {
        Self {
            extern_paths: extern_paths.to_vec(),
        }
    }

    /// Whether the supplied proto fully-qualified name maps to a Rust type
    /// owned by another crate (declared via [`Builder::extern_path`]).
    ///
    /// Codegen must skip such messages: implementing `Validate` for a
    /// foreign type from this user's crate would violate Rust's orphan rule
    /// (both the trait `prost_protovalidate::Validate` and the target type
    /// would be foreign).
    pub(crate) fn is_extern(&self, proto_full_name: &str) -> bool {
        for (proto_prefix, _) in &self.extern_paths {
            let normalized = proto_prefix.strip_prefix('.').unwrap_or(proto_prefix);
            if proto_full_name == normalized {
                return true;
            }
            let with_dot = format!("{normalized}.");
            if proto_full_name.starts_with(&with_dot) {
                return true;
            }
        }
        false
    }

    /// Convert a proto fully-qualified name to a Rust type token stream.
    ///
    /// Checks `extern_paths` first, then falls back to prost's default convention:
    /// - Package segments become module names (lowercase)
    /// - Message names keep `PascalCase`
    /// - Nested messages: parent becomes `snake_case` module
    pub(crate) fn proto_to_rust_type(&self, proto_full_name: &str) -> TokenStream {
        // Check extern_paths for a matching prefix
        for (proto_prefix, rust_prefix) in &self.extern_paths {
            let normalized = proto_prefix.strip_prefix('.').unwrap_or(proto_prefix);
            if let Some(suffix) = proto_full_name.strip_prefix(normalized) {
                let suffix = suffix.strip_prefix('.').unwrap_or(suffix);
                if suffix.is_empty() {
                    let path: TokenStream = rust_prefix.parse().unwrap_or_else(|_| quote! {});
                    return path;
                }
                let suffix_path = default_proto_to_rust(suffix);
                let prefix_path: TokenStream = rust_prefix.parse().unwrap_or_else(|_| quote! {});
                return quote! { #prefix_path :: #suffix_path };
            }
        }

        default_proto_to_rust(proto_full_name)
    }
}

/// Convert a proto path to Rust using prost's default naming conventions.
fn default_proto_to_rust(proto_path: &str) -> TokenStream {
    let parts: Vec<&str> = proto_path.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return quote! {};
    }

    let mut tokens = TokenStream::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            tokens.extend(quote! { :: });
        }

        let is_last = i == parts.len() - 1;
        let first_char_upper = part.chars().next().is_some_and(|c| c.is_ascii_uppercase());

        // Non-last uppercase parts are nesting parents → `snake_case`.
        // The last part is the type ident → prost's `UpperCamelCase` renaming
        // (proto `UUID` becomes Rust `Uuid`). Package parts keep their casing.
        let ident = if !is_last && first_char_upper {
            let snake = to_snake_case(part);
            quote::format_ident!("{}", escape_keyword(&snake))
        } else if is_last {
            let camel = to_upper_camel_case(part);
            quote::format_ident!("{}", escape_keyword(&camel))
        } else {
            quote::format_ident!("{}", escape_keyword(part))
        };
        tokens.extend(quote! { #ident });
    }

    tokens
}

/// Convert a proto message name to prost's Rust type ident casing.
///
/// Mirrors `prost-build` (`heck::ToUpperCamelCase`): acronym runs collapse
/// (`UUID` → `Uuid`, `HTTPRule` → `HttpRule`), conventional `PascalCase`
/// names pass through unchanged. Built on [`to_snake_case`] so acronym
/// boundary handling stays identical in both directions.
pub(crate) fn to_upper_camel_case(s: &str) -> String {
    to_snake_case(s)
        .split('_')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}

/// Convert `PascalCase` or `camelCase` to `snake_case`.
pub(crate) fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                // Don't add underscore if previous char was uppercase (acronym)
                let prev = s.as_bytes()[i - 1];
                if prev.is_ascii_lowercase() || prev.is_ascii_digit() {
                    result.push('_');
                } else if i + 1 < s.len() && s.as_bytes()[i + 1].is_ascii_lowercase() {
                    // End of acronym: XMLParser -> xml_parser
                    result.push('_');
                }
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Convert proto field name (which may be camelCase) to `snake_case` for Rust.
///
/// Reserved Rust keywords are wrapped as raw identifiers (e.g. `type` → `r#type`)
/// so the result can be passed directly to [`quote::format_ident!`].
pub(crate) fn field_to_rust_name(proto_name: &str) -> String {
    escape_keyword(&to_snake_case(proto_name))
}

/// Escape Rust reserved keywords.
fn escape_keyword(s: &str) -> String {
    match s {
        "as" | "break" | "const" | "continue" | "crate" | "else" | "enum" | "extern" | "false"
        | "fn" | "for" | "if" | "impl" | "in" | "let" | "loop" | "match" | "mod" | "move"
        | "mut" | "pub" | "ref" | "return" | "self" | "Self" | "static" | "struct" | "super"
        | "trait" | "true" | "type" | "unsafe" | "use" | "where" | "while" | "async" | "await"
        | "dyn" | "abstract" | "become" | "box" | "do" | "final" | "macro" | "override"
        | "priv" | "typeof" | "unsized" | "virtual" | "yield" | "try" => {
            format!("r#{s}")
        }
        _ => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("MyMessage"), "my_message");
        assert_eq!(to_snake_case("HTTPResponse"), "http_response");
        assert_eq!(to_snake_case("XMLParser"), "xml_parser");
        assert_eq!(to_snake_case("simpleCase"), "simple_case");
        assert_eq!(to_snake_case("already_snake"), "already_snake");
    }

    #[test]
    fn type_idents_mirror_prost_upper_camel_case() {
        // prost-build renames message types to UpperCamelCase; generated
        // impls must reference the renamed idents or they will not resolve.
        assert_eq!(
            default_proto_to_rust("core.v2.UUID").to_string(),
            "core :: v2 :: Uuid"
        );
        assert_eq!(
            default_proto_to_rust("auth.v2.AuthenticateRequest").to_string(),
            "auth :: v2 :: AuthenticateRequest"
        );
        assert_eq!(
            default_proto_to_rust("pkg.HTTPRule").to_string(),
            "pkg :: HttpRule"
        );
        assert_eq!(
            default_proto_to_rust("pkg.Outer.Inner").to_string(),
            "pkg :: outer :: Inner"
        );
    }

    #[test]
    fn test_to_upper_camel_case() {
        assert_eq!(to_upper_camel_case("UUID"), "Uuid");
        assert_eq!(to_upper_camel_case("HTTPRule"), "HttpRule");
        assert_eq!(
            to_upper_camel_case("AuthenticateRequest"),
            "AuthenticateRequest"
        );
        assert_eq!(to_upper_camel_case("already_snake"), "AlreadySnake");
        assert_eq!(to_upper_camel_case("XMLParser"), "XmlParser");
        // Digit boundaries mirror prost/heck: uppercase after a digit is a
        // word start; lowercase after a digit is not.
        assert_eq!(to_upper_camel_case("V2Ray"), "V2Ray");
        assert_eq!(to_upper_camel_case("Foo2bar"), "Foo2bar");
    }

    #[test]
    fn test_escape_keyword() {
        assert_eq!(escape_keyword("type"), "r#type");
        assert_eq!(escape_keyword("name"), "name");
        assert_eq!(escape_keyword("impl"), "r#impl");
    }

    #[test]
    fn field_to_rust_name_escapes_reserved_identifiers() {
        // Proto fields named after Rust keywords must round-trip into raw identifiers
        // so `quote::format_ident!` can accept them.
        assert_eq!(field_to_rust_name("type"), "r#type");
        assert_eq!(field_to_rust_name("mod"), "r#mod");
        assert_eq!(field_to_rust_name("as"), "r#as");
        assert_eq!(field_to_rust_name("try"), "r#try");
        assert_eq!(field_to_rust_name("match"), "r#match");
        assert_eq!(field_to_rust_name("self"), "r#self");
        // `to_snake_case` lowercases first, so `Self` collapses to `self`
        // and gets the same `r#self` raw-identifier wrapping.
        assert_eq!(field_to_rust_name("Self"), "r#self");
    }

    #[test]
    fn field_to_rust_name_snake_cases_camel_input() {
        assert_eq!(field_to_rust_name("camelCaseField"), "camel_case_field");
        assert_eq!(field_to_rust_name("HTTPResponseCode"), "http_response_code");
        assert_eq!(field_to_rust_name("already_snake"), "already_snake");
    }
}
