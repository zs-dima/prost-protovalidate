//! Bytes rule code generation.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::{BytesRules, bytes_rules};

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
pub(crate) fn generate(
    rules: &BytesRules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    // Const — runtime formats `{c:?}` (Vec<u8> Debug, e.g. `[1, 2, 3]`).
    if let Some(ref c) = rules.r#const {
        let c_bytes = c.as_slice();
        let msg = format!("value must be {c_bytes:?}");
        checks.push(quote! {
            if #value_access.as_slice() != [#(#c_bytes),*] {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.const", #msg,
                ));
            }
        });
    }

    // Exact length — runtime message has no trailing " bytes".
    if let Some(len) = rules.len {
        let len_usize = len as usize;
        let msg = format!("value length must be {len} bytes");
        checks.push(quote! {
            if #value_access.len() != #len_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.len", #msg,
                ));
            }
        });
    }

    // Min length
    if let Some(min) = rules.min_len {
        let min_usize = min as usize;
        let msg = format!("value length must be at least {min} bytes");
        checks.push(quote! {
            if #value_access.len() < #min_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.min_len", #msg,
                ));
            }
        });
    }

    // Max length
    if let Some(max) = rules.max_len {
        let max_usize = max as usize;
        let msg = format!("value length must be at most {max} bytes");
        checks.push(quote! {
            if #value_access.len() > #max_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.max_len", #msg,
                ));
            }
        });
    }

    // Pattern (regex on UTF-8 interpretation).
    //
    // Canonical buf protovalidate refuses to apply the regex to non-UTF-8
    // input — the runtime evaluator surfaces that as a `RuntimeError`. The
    // generated `Validate` impl returns `Result<(), ValidationError>` and
    // cannot express a runtime error, so it produces a `bytes.pattern`
    // violation for invalid UTF-8 instead. This is the only behavioral
    // divergence between codegen and runtime; it does not affect any
    // valid-UTF-8 input.
    //
    // The capability analyzer rejects messages with un-compilable patterns
    // (see `find_invalid_regex` in `codegen.rs`), so the `expect` below is
    // unreachable in practice; we prefer a loud panic over a silent
    // mismatch if the regex crate ever regresses.
    if let Some(ref pattern) = rules.pattern {
        let msg = format!("value must match regex pattern `{pattern}`");
        checks.push(quote! {
            {
                static RE: ::std::sync::LazyLock<::prost_protovalidate::regex::Regex> =
                    ::std::sync::LazyLock::new(|| {
                        ::prost_protovalidate::regex::Regex::new(#pattern)
                            .expect("pattern validated at codegen time")
                    });
                if let Ok(s) = ::std::str::from_utf8(&#value_access) {
                    if !RE.is_match(s) {
                        violations.push(::prost_protovalidate::Violation::new(
                            #proto_name, "bytes.pattern", #msg,
                        ));
                    }
                } else {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "bytes.pattern", #msg,
                    ));
                }
            }
        });
    }

    // Prefix — runtime formats `{prefix:?}` (Vec<u8> Debug).
    if let Some(ref prefix) = rules.prefix {
        let prefix_bytes = prefix.as_slice();
        let msg = format!("value does not have prefix {prefix_bytes:?}");
        checks.push(quote! {
            if !#value_access.starts_with(&[#(#prefix_bytes),*]) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.prefix", #msg,
                ));
            }
        });
    }

    // Suffix — runtime formats `{suffix:?}`.
    if let Some(ref suffix) = rules.suffix {
        let suffix_bytes = suffix.as_slice();
        let msg = format!("value does not have suffix {suffix_bytes:?}");
        checks.push(quote! {
            if !#value_access.ends_with(&[#(#suffix_bytes),*]) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.suffix", #msg,
                ));
            }
        });
    }

    // Contains.
    //
    // An empty `contains` literal is trivially satisfied — emitting
    // `windows(0)` would panic at runtime, so we skip emission entirely.
    if let Some(ref contains) = rules.contains {
        if !contains.is_empty() {
            let c_bytes = contains.as_slice();
            let c_len = c_bytes.len();
            let msg = format!("value does not contain {c_bytes:?}");
            checks.push(quote! {
                if !#value_access.windows(#c_len).any(|w| w == [#(#c_bytes),*]) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "bytes.contains", #msg,
                    ));
                }
            });
        }
    }

    // In
    if !rules.r#in.is_empty() {
        let vals: Vec<_> = rules
            .r#in
            .iter()
            .map(|v| {
                let b = v.as_slice();
                quote! { &[#(#b),*][..] }
            })
            .collect();
        checks.push(quote! {
            if ![#(#vals),*].contains(&#value_access.as_slice()) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.in", "value must be in list",
                ));
            }
        });
    }

    // Not-in
    if !rules.not_in.is_empty() {
        let vals: Vec<_> = rules
            .not_in
            .iter()
            .map(|v| {
                let b = v.as_slice();
                quote! { &[#(#b),*][..] }
            })
            .collect();
        checks.push(quote! {
            if [#(#vals),*].contains(&#value_access.as_slice()) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.not_in", "value must not be in list",
                ));
            }
        });
    }

    // Well-known byte format validators
    if let Some(wk) = rules.well_known {
        checks.extend(generate_well_known(wk, value_access, proto_name));
    }

    checks
}

/// Generate well-known bytes format checks (ip, ipv4, ipv6, uuid).
fn generate_well_known(
    wk: bytes_rules::WellKnown,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    match wk {
        bytes_rules::WellKnown::Ip(true) => vec![quote! {
            if #value_access.is_empty() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.ip_empty", "value is empty, which is not a valid IP address",
                ));
            } else if #value_access.len() != 4 && #value_access.len() != 16 {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.ip", "value must be a valid IP address",
                ));
            }
        }],
        bytes_rules::WellKnown::Ipv4(true) => vec![quote! {
            if #value_access.is_empty() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.ipv4_empty", "value is empty, which is not a valid IPv4 address",
                ));
            } else if #value_access.len() != 4 {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.ipv4", "value must be a valid IPv4 address",
                ));
            }
        }],
        bytes_rules::WellKnown::Ipv6(true) => vec![quote! {
            if #value_access.is_empty() {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.ipv6_empty", "value is empty, which is not a valid IPv6 address",
                ));
            } else if #value_access.len() != 16 {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.ipv6", "value must be a valid IPv6 address",
                ));
            }
        }],
        bytes_rules::WellKnown::Uuid(true) => vec![quote! {
            if #value_access.is_empty() {
                violations.push(::prost_protovalidate::Violation::new_constraint(
                    #proto_name, "bytes.uuid_empty", "bytes.uuid",
                ));
            } else if #value_access.len() != 16 {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "bytes.uuid", "value must be a valid UUID",
                ));
            }
        }],
        _ => Vec::new(),
    }
}
