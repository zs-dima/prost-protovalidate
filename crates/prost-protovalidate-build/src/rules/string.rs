//! String rule code generation.

use proc_macro2::TokenStream;
use quote::quote;

use prost_protovalidate_types::{StringRules, string_rules};

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
pub(crate) fn generate(
    rules: &StringRules,
    value_access: &TokenStream,
    proto_name: &str,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    // Const
    if let Some(ref c) = rules.r#const {
        let msg = format!("must equal `{c}`");
        checks.push(quote! {
            if #value_access != #c {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.const", #msg,
                ));
            }
        });
    }

    // Exact character length
    if let Some(len) = rules.len {
        let len_usize = len as usize;
        let msg = format!("must be {len} characters");
        checks.push(quote! {
            if #value_access.chars().count() != #len_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.len", #msg,
                ));
            }
        });
    }

    // Min length (characters)
    if let Some(min) = rules.min_len {
        let min_usize = min as usize;
        let msg = format!("value length must be at least {min} characters");
        checks.push(quote! {
            if #value_access.chars().count() < #min_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.min_len", #msg,
                ));
            }
        });
    }

    // Max length (characters)
    if let Some(max) = rules.max_len {
        let max_usize = max as usize;
        let msg = format!("value length must be at most {max} characters");
        checks.push(quote! {
            if #value_access.chars().count() > #max_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.max_len", #msg,
                ));
            }
        });
    }

    // Exact byte length
    if let Some(len) = rules.len_bytes {
        let len_usize = len as usize;
        let msg = format!("must be {len} bytes");
        checks.push(quote! {
            if #value_access.len() != #len_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.len_bytes", #msg,
                ));
            }
        });
    }

    // Min bytes
    if let Some(min) = rules.min_bytes {
        let min_usize = min as usize;
        let msg = format!("must be at least {min} bytes");
        checks.push(quote! {
            if #value_access.len() < #min_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.min_bytes", #msg,
                ));
            }
        });
    }

    // Max bytes
    if let Some(max) = rules.max_bytes {
        let max_usize = max as usize;
        let msg = format!("must be at most {max} bytes");
        checks.push(quote! {
            if #value_access.len() > #max_usize {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.max_bytes", #msg,
                ));
            }
        });
    }

    // Pattern (regex).
    //
    // The capability analyzer (see `find_invalid_regex` in `codegen.rs`)
    // ensures only valid patterns reach codegen; the `expect` below
    // surfaces a future regex-crate regression loudly instead of
    // misreporting validation as a silent pattern mismatch.
    if let Some(ref pattern) = rules.pattern {
        let msg = format!("does not match regex pattern `{pattern}`");
        checks.push(quote! {
            {
                static RE: ::std::sync::LazyLock<::prost_protovalidate::regex::Regex> =
                    ::std::sync::LazyLock::new(|| {
                        ::prost_protovalidate::regex::Regex::new(#pattern)
                            .expect("pattern validated at codegen time")
                    });
                if !RE.is_match(&#value_access) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "string.pattern", #msg,
                    ));
                }
            }
        });
    }

    // Prefix
    if let Some(ref prefix) = rules.prefix {
        let msg = format!("does not have prefix `{prefix}`");
        checks.push(quote! {
            if !#value_access.starts_with(#prefix) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.prefix", #msg,
                ));
            }
        });
    }

    // Suffix
    if let Some(ref suffix) = rules.suffix {
        let msg = format!("does not have suffix `{suffix}`");
        checks.push(quote! {
            if !#value_access.ends_with(#suffix) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.suffix", #msg,
                ));
            }
        });
    }

    // Contains
    if let Some(ref contains) = rules.contains {
        let msg = format!("does not contain substring `{contains}`");
        checks.push(quote! {
            if !#value_access.contains(#contains) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.contains", #msg,
                ));
            }
        });
    }

    // Not contains
    if let Some(ref not_contains) = rules.not_contains {
        let msg = format!("contains substring `{not_contains}`");
        checks.push(quote! {
            if #value_access.contains(#not_contains) {
                violations.push(::prost_protovalidate::Violation::new(
                    #proto_name, "string.not_contains", #msg,
                ));
            }
        });
    }

    // In list — sort to match the deterministic runtime format
    // (`format!("must be in list {sorted:?}")` where `sorted: Vec<&String>`).
    if !rules.r#in.is_empty() {
        let mut sorted: Vec<&String> = rules.r#in.iter().collect();
        sorted.sort();
        let vals = sorted;
        checks.push(quote! {
            {
                let _s: &str = &#value_access;
                if ![#(#vals),*].contains(&_s) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "string.in", format!("must be in list {:?}", &[#(#vals),*]),
                    ));
                }
            }
        });
    }

    // Not-in list — same sorted format.
    if !rules.not_in.is_empty() {
        let mut sorted: Vec<&String> = rules.not_in.iter().collect();
        sorted.sort();
        let vals = sorted;
        checks.push(quote! {
            {
                let _s: &str = &#value_access;
                if [#(#vals),*].contains(&_s) {
                    violations.push(::prost_protovalidate::Violation::new(
                        #proto_name, "string.not_in", format!("must not be in list {:?}", &[#(#vals),*]),
                    ));
                }
            }
        });
    }

    // Well-known format validators
    let strict = rules.strict.unwrap_or(true);
    if let Some(wk) = rules.well_known {
        checks.extend(generate_well_known(wk, value_access, proto_name, strict));
    }

    checks
}

/// Generate well-known string format checks.
#[allow(clippy::too_many_lines)]
fn generate_well_known(
    wk: string_rules::WellKnown,
    value_access: &TokenStream,
    proto_name: &str,
    strict: bool,
) -> Vec<TokenStream> {
    match wk {
        string_rules::WellKnown::Email(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "email",
                quote! { ::prost_protovalidate::validators::is_email(&#value_access) },
            )]
        }
        string_rules::WellKnown::Hostname(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "hostname",
                quote! { ::prost_protovalidate::validators::is_hostname(&#value_access) },
            )]
        }
        string_rules::WellKnown::Ip(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ip",
                quote! { ::prost_protovalidate::validators::is_ip(&#value_access) },
            )]
        }
        string_rules::WellKnown::Ipv4(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ipv4",
                quote! { ::prost_protovalidate::validators::is_ipv4(&#value_access) },
            )]
        }
        string_rules::WellKnown::Ipv6(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ipv6",
                quote! { ::prost_protovalidate::validators::is_ipv6(&#value_access) },
            )]
        }
        string_rules::WellKnown::Uri(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "uri",
                quote! { ::prost_protovalidate::validators::is_uri(&#value_access) },
            )]
        }
        string_rules::WellKnown::UriRef(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "uri_ref",
                quote! { ::prost_protovalidate::validators::is_uri_ref(&#value_access) },
            )]
        }
        string_rules::WellKnown::Uuid(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "uuid",
                quote! { ::prost_protovalidate::validators::is_uuid(&#value_access) },
            )]
        }
        string_rules::WellKnown::Tuuid(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "tuuid",
                quote! { ::prost_protovalidate::validators::is_tuuid(&#value_access) },
            )]
        }
        string_rules::WellKnown::Ulid(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ulid",
                quote! { ::prost_protovalidate::validators::is_ulid(&#value_access) },
            )]
        }
        string_rules::WellKnown::Address(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "address",
                quote! {
                    ::prost_protovalidate::validators::is_hostname(&#value_access)
                    || ::prost_protovalidate::validators::is_ip(&#value_access)
                },
            )]
        }
        string_rules::WellKnown::HostAndPort(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "host_and_port",
                quote! { ::prost_protovalidate::validators::is_host_and_port(&#value_access, false) },
            )]
        }
        string_rules::WellKnown::IpWithPrefixlen(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ip_with_prefixlen",
                quote! { ::prost_protovalidate::validators::is_ip_prefix(&#value_access, false) },
            )]
        }
        string_rules::WellKnown::Ipv4WithPrefixlen(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ipv4_with_prefixlen",
                quote! { ::prost_protovalidate::validators::is_ipv4_prefix(&#value_access, false) },
            )]
        }
        string_rules::WellKnown::Ipv6WithPrefixlen(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ipv6_with_prefixlen",
                quote! { ::prost_protovalidate::validators::is_ipv6_prefix(&#value_access, false) },
            )]
        }
        string_rules::WellKnown::IpPrefix(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ip_prefix",
                quote! { ::prost_protovalidate::validators::is_ip_prefix(&#value_access, true) },
            )]
        }
        string_rules::WellKnown::Ipv4Prefix(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ipv4_prefix",
                quote! { ::prost_protovalidate::validators::is_ipv4_prefix(&#value_access, true) },
            )]
        }
        string_rules::WellKnown::Ipv6Prefix(true) => {
            vec![format_check(
                value_access,
                proto_name,
                "ipv6_prefix",
                quote! { ::prost_protovalidate::validators::is_ipv6_prefix(&#value_access, true) },
            )]
        }
        string_rules::WellKnown::WellKnownRegex(kind) => {
            match prost_protovalidate_types::KnownRegex::try_from(kind) {
                Ok(prost_protovalidate_types::KnownRegex::HttpHeaderName) => {
                    vec![quote! {
                        if !::prost_protovalidate::validators::is_http_header_name(&#value_access, #strict) {
                            let rule_id = if #value_access.is_empty() {
                                "string.well_known_regex.header_name_empty"
                            } else {
                                "string.well_known_regex.header_name"
                            };
                            violations.push(::prost_protovalidate::Violation::new_constraint(
                                #proto_name, rule_id, "string.well_known_regex",
                            ));
                        }
                    }]
                }
                Ok(prost_protovalidate_types::KnownRegex::HttpHeaderValue) => {
                    vec![quote! {
                        if !::prost_protovalidate::validators::is_http_header_value(&#value_access, #strict) {
                            violations.push(::prost_protovalidate::Violation::new_constraint(
                                #proto_name,
                                "string.well_known_regex.header_value",
                                "string.well_known_regex",
                            ));
                        }
                    }]
                }
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

/// Generate the standard two-phase format check:
/// 1. Empty string → `{format}_empty` violation
/// 2. Invalid format → `string.{format}` violation
#[allow(clippy::needless_pass_by_value)]
fn format_check(
    value_access: &TokenStream,
    proto_name: &str,
    format_name: &str,
    is_valid: TokenStream,
) -> TokenStream {
    let empty_rule_id = format!("string.{format_name}_empty");
    let format_rule_id = format!("string.{format_name}");
    let rule_path = format!("string.{format_name}");

    quote! {
        if #value_access.is_empty() {
            violations.push(::prost_protovalidate::Violation::new_constraint(
                #proto_name, #empty_rule_id, #rule_path,
            ));
        } else if !(#is_valid) {
            violations.push(::prost_protovalidate::Violation::new_constraint(
                #proto_name, #format_rule_id, #rule_path,
            ));
        }
    }
}
