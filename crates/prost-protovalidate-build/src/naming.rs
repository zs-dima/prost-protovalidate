//! Proto-to-Rust name conversion for both codegen backends.
//!
//! The prost path follows prost-build conventions (message idents renamed to
//! `UpperCamelCase`, nesting parents as `snake_case` modules) and converts
//! names on the fly. The buffa path mirrors buffa-codegen exactly: type
//! idents are kept **verbatim** (proto `UUID` stays Rust `UUID`), nesting
//! parents use buffa's `snake_case`, and top-level nested-types modules are
//! deconflicted against sub-package modules — so the whole map is
//! precomputed from the descriptor pool instead of guessed from name shape.

use std::collections::{HashMap, HashSet};

use proc_macro2::TokenStream;
use prost_reflect::{DescriptorPool, MessageDescriptor};
use quote::quote;

use crate::{Backend, Error};

/// Reserved module name buffa-codegen keeps for ancillary generated types;
/// participates in nested-module deconfliction exactly like a sub-package.
const BUFFA_SENTINEL_MOD: &str = "__buffa";

/// Context for converting proto fully-qualified names to Rust type paths.
pub(crate) struct NamingContext {
    backend: Backend,
    extern_paths: Vec<(String, String)>,
    /// Buffa mode only: proto message full name → Rust path string
    /// (e.g. `auth::v1::UUID`), resolved from the descriptor pool with
    /// buffa-codegen's naming rules. Empty in prost mode.
    buffa_type_map: HashMap<String, String>,
}

impl NamingContext {
    pub(crate) fn new(
        extern_paths: &[(String, String)],
        backend: Backend,
        pool: &DescriptorPool,
    ) -> Self {
        let buffa_type_map = match backend {
            Backend::Prost => HashMap::new(),
            Backend::Buffa => build_buffa_type_map(pool),
        };
        Self {
            backend,
            extern_paths: extern_paths.to_vec(),
            buffa_type_map,
        }
    }

    pub(crate) fn backend(&self) -> Backend {
        self.backend
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

    /// Convert a proto field name to the backend's Rust field identifier.
    ///
    /// Both backends snake-case the name and escape Rust keywords; they
    /// differ in corner cases (digit word boundaries, non-raw-able keywords
    /// like `self`), so each mirrors its own code generator.
    pub(crate) fn field_ident(&self, proto_name: &str) -> proc_macro2::Ident {
        match self.backend {
            Backend::Prost => quote::format_ident!("{}", field_to_rust_name(proto_name)),
            Backend::Buffa => buffa_field_ident(proto_name),
        }
    }

    /// Convert a proto fully-qualified message name to a Rust type token
    /// stream.
    ///
    /// Checks `extern_paths` first. The prost fallback derives the path from
    /// the name shape (prost-build conventions); the buffa fallback looks up
    /// the pool-derived map and errors on a miss rather than guessing.
    ///
    /// # Errors
    ///
    /// Buffa mode only: the message is not in the descriptor pool the map
    /// was built from (a codegen invariant violation, not a user error).
    pub(crate) fn proto_to_rust_type(&self, proto_full_name: &str) -> Result<TokenStream, Error> {
        // Check extern_paths for a matching prefix
        for (proto_prefix, rust_prefix) in &self.extern_paths {
            let normalized = proto_prefix.strip_prefix('.').unwrap_or(proto_prefix);
            if let Some(suffix) = proto_full_name.strip_prefix(normalized) {
                let suffix = suffix.strip_prefix('.').unwrap_or(suffix);
                if suffix.is_empty() {
                    let path: TokenStream = rust_prefix.parse().unwrap_or_else(|_| quote! {});
                    return Ok(path);
                }
                let suffix_path = match self.backend {
                    Backend::Prost => default_proto_to_rust(suffix),
                    Backend::Buffa => buffa_suffix_to_rust(suffix)?,
                };
                let prefix_path: TokenStream = rust_prefix.parse().unwrap_or_else(|_| quote! {});
                return Ok(quote! { #prefix_path :: #suffix_path });
            }
        }

        match self.backend {
            Backend::Prost => Ok(default_proto_to_rust(proto_full_name)),
            Backend::Buffa => {
                let path = self.buffa_type_map.get(proto_full_name).ok_or_else(|| {
                    Error::Codegen(format!(
                        "buffa type map has no entry for `{proto_full_name}` \
                         (message missing from the descriptor pool)"
                    ))
                })?;
                path.parse().map_err(|e| {
                    Error::Codegen(format!("buffa path `{path}` is not a valid Rust path: {e}"))
                })
            }
        }
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

/// Convert `PascalCase` or `camelCase` to `snake_case` (prost/heck flavor).
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

// --- buffa naming (mirrors buffa-codegen) ---

/// Build the full message-name → Rust-path map for buffa mode by walking the
/// descriptor pool with buffa-codegen's resolution rules:
///
/// * package segments become modules verbatim (keyword-escaped),
/// * message type idents stay verbatim (keyword-escaped),
/// * a top-level message's nested types live in a `snake_case(Name)` module,
///   deconflicted against sibling sub-package modules by appending `_`,
/// * deeper nesting uses plain `snake_case(Name)` modules.
fn build_buffa_type_map(pool: &DescriptorPool) -> HashMap<String, String> {
    let packages: HashSet<String> = pool.files().map(|f| f.package_name().to_string()).collect();

    // Direct sub-package segments per package: `foo` → {"bar"} when any file
    // lives in `foo.bar` or deeper. These become sibling modules of `foo`'s
    // message-nesting modules and drive deconfliction.
    let mut children: HashMap<String, HashSet<String>> = HashMap::new();
    for package in &packages {
        if package.is_empty() {
            continue;
        }
        let segments: Vec<&str> = package.split('.').collect();
        for i in 0..segments.len() {
            let parent = segments[..i].join(".");
            children
                .entry(parent)
                .or_default()
                .insert(segments[i].to_string());
        }
    }

    // Top-level messages per package, in pool file order then declaration
    // order (matching buffa-codegen's traversal).
    let mut package_order: Vec<String> = Vec::new();
    let mut package_messages: HashMap<String, Vec<MessageDescriptor>> = HashMap::new();
    for file in pool.files() {
        let package = file.package_name().to_string();
        let entry = package_messages.entry(package.clone()).or_insert_with(|| {
            package_order.push(package.clone());
            Vec::new()
        });
        entry.extend(file.messages());
    }

    let mut map = HashMap::new();
    for package in &package_order {
        let messages = &package_messages[package];
        let child_set = children.get(package).cloned().unwrap_or_default();
        let names: Vec<String> = messages.iter().map(|m| m.name().to_string()).collect();
        let modules = deconflict_package_modules(&names, &child_set);

        let package_path = package
            .split('.')
            .filter(|s| !s.is_empty())
            .map(escape_buffa_ident)
            .collect::<Vec<_>>()
            .join("::");

        for (message, module) in messages.iter().zip(modules) {
            insert_buffa_paths(&mut map, message, &package_path, &module);
        }
    }
    map
}

/// Register `msg` and its nested messages (recursively) into the type map.
///
/// `scope_path` is the containing Rust module path; `nested_module` is the
/// module name for this message's own nested types (deconflicted for
/// top-level messages, plain `snake_case` deeper down).
fn insert_buffa_paths(
    map: &mut HashMap<String, String>,
    msg: &MessageDescriptor,
    scope_path: &str,
    nested_module: &str,
) {
    let ident = escape_buffa_ident(msg.name());
    map.insert(msg.full_name().to_string(), join_mod(scope_path, &ident));

    let nested_scope = join_mod(scope_path, nested_module);
    for child in msg.child_messages() {
        // Synthetic map-entry messages have no public Rust type.
        if child.is_map_entry() {
            continue;
        }
        insert_buffa_paths(map, &child, &nested_scope, &buffa_snake_case(child.name()));
    }
}

fn join_mod(scope: &str, segment: &str) -> String {
    if scope.is_empty() {
        segment.to_string()
    } else {
        format!("{scope}::{segment}")
    }
}

/// Deconflict the nested-types module names for one package's top-level
/// messages against the sub-package modules in the same scope. Mirrors
/// buffa-codegen's `deconflict_package_modules`: colliding names get `_`
/// appended until unique; assignment runs in sorted order so the result is
/// independent of declaration order.
fn deconflict_package_modules(message_names: &[String], children: &HashSet<String>) -> Vec<String> {
    let bases: Vec<String> = message_names.iter().map(|n| buffa_snake_case(n)).collect();

    let mut taken: HashSet<String> = children.clone();
    taken.insert(BUFFA_SENTINEL_MOD.to_string());
    taken.extend(bases.iter().cloned());

    let mut out = bases.clone();
    let mut order: Vec<usize> = (0..bases.len()).collect();
    order.sort_by(|&a, &b| bases[a].cmp(&bases[b]));
    for i in order {
        if !children.contains(&bases[i]) {
            continue;
        }
        let mut candidate = format!("{}_", bases[i]);
        while taken.contains(&candidate) {
            candidate.push('_');
        }
        taken.insert(candidate.clone());
        out[i] = candidate;
    }
    out
}

/// buffa-codegen's `to_snake_case`. Differs from the prost flavor on digit
/// boundaries (`V2Ray` → `v2ray`, prost gives `v2_ray`) and is Unicode-aware.
pub(crate) fn buffa_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            // Insert `_` before an uppercase that follows lowercase (fooBar),
            // or before the start of a new word after an acronym run (XMLHttp).
            if prev.is_lowercase() || (prev.is_uppercase() && next_is_lower) {
                result.push('_');
            }
        }
        result.extend(c.to_lowercase());
    }
    result
}

/// Escape an identifier the way buffa-codegen does for type/module position:
/// raw-able keywords get `r#`, path-position keywords (`self`, `super`,
/// `Self`, `crate`) get a `_` suffix, everything else passes through.
fn escape_buffa_ident(name: &str) -> String {
    if !is_rust_keyword(name) {
        return name.to_string();
    }
    if matches!(name, "self" | "super" | "Self" | "crate") {
        format!("{name}_")
    } else {
        format!("r#{name}")
    }
}

/// Proto field name → buffa Rust field ident (buffa snake case + buffa
/// keyword escaping).
fn buffa_field_ident(proto_name: &str) -> proc_macro2::Ident {
    let snake = buffa_snake_case(proto_name);
    if is_rust_keyword(&snake) {
        if matches!(snake.as_str(), "self" | "super" | "Self" | "crate") {
            quote::format_ident!("{}_", snake)
        } else {
            proc_macro2::Ident::new_raw(&snake, proc_macro2::Span::call_site())
        }
    } else {
        quote::format_ident!("{}", snake)
    }
}

/// Rust keywords across editions (buffa-codegen's list, editions ≤ 2024).
fn is_rust_keyword(name: &str) -> bool {
    matches!(
        name,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "gen"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "try"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
    )
}

/// Buffa-style conversion for an extern-path suffix (`Outer.Inner` relative
/// to the extern prefix): nesting parents as buffa `snake_case` modules, the
/// final segment verbatim. Extern crates' internal module deconfliction is
/// not observable here, but extern messages are never impl targets (the
/// capability analyzer skips them), so this only serves diagnostics.
fn buffa_suffix_to_rust(suffix: &str) -> Result<TokenStream, Error> {
    let parts: Vec<&str> = suffix.split('.').filter(|s| !s.is_empty()).collect();
    let mut path = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            path.push_str("::");
        }
        if i == parts.len() - 1 {
            path.push_str(&escape_buffa_ident(part));
        } else {
            path.push_str(&escape_buffa_ident(&buffa_snake_case(part)));
        }
    }
    path.parse().map_err(|e| {
        Error::Codegen(format!(
            "extern suffix `{suffix}` produced invalid Rust path `{path}`: {e}"
        ))
    })
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

    // --- buffa naming ---

    #[test]
    fn buffa_snake_case_matches_buffa_codegen() {
        assert_eq!(buffa_snake_case("MyMessage"), "my_message");
        assert_eq!(buffa_snake_case("HTTPResponse"), "http_response");
        assert_eq!(buffa_snake_case("XMLHttp"), "xml_http");
        assert_eq!(buffa_snake_case("simpleCase"), "simple_case");
        assert_eq!(buffa_snake_case("already_snake"), "already_snake");
        // Digit boundary: buffa does NOT split after a digit (prost does).
        assert_eq!(buffa_snake_case("V2Ray"), "v2ray");
        assert_eq!(to_snake_case("V2Ray"), "v2_ray");
    }

    #[test]
    fn buffa_field_idents_use_buffa_keyword_escapes() {
        assert_eq!(buffa_field_ident("type").to_string(), "r#type");
        assert_eq!(buffa_field_ident("normal").to_string(), "normal");
        // Non-raw-able keywords get `_` suffix (the prost path would emit
        // the invalid raw ident `r#self`; buffa mirrors its codegen).
        assert_eq!(buffa_field_ident("self").to_string(), "self_");
    }

    #[test]
    fn deconfliction_appends_underscores_on_package_collision() {
        let names = vec!["Oof".to_string(), "Other".to_string()];
        let children: HashSet<String> = ["oof".to_string()].into_iter().collect();
        let modules = deconflict_package_modules(&names, &children);
        assert_eq!(modules, vec!["oof_".to_string(), "other".to_string()]);
    }

    #[test]
    fn deconfliction_is_declaration_order_independent() {
        let children: HashSet<String> = ["oof".to_string()].into_iter().collect();
        let forward =
            deconflict_package_modules(&["Oof".to_string(), "Zed".to_string()], &children);
        let reversed =
            deconflict_package_modules(&["Zed".to_string(), "Oof".to_string()], &children);
        assert_eq!(forward, vec!["oof_", "zed"]);
        assert_eq!(reversed, vec!["zed", "oof_"]);
    }

    #[test]
    fn escape_buffa_ident_covers_raw_and_suffix_forms() {
        assert_eq!(escape_buffa_ident("type"), "r#type");
        assert_eq!(escape_buffa_ident("UUID"), "UUID");
        assert_eq!(escape_buffa_ident("self"), "self_");
        assert_eq!(escape_buffa_ident("Self"), "Self_");
    }
}
