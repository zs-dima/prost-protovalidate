use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

use regex::Regex;

use prost_protovalidate_types::rules_meta::string as meta;

use crate::config::ValidationConfig;
use crate::error::{CompilationError, Error, ValidationError};
use crate::violation::Violation;

use crate::formats::{
    IpVersion, is_email, is_host_and_port, is_hostname, is_ip, is_ip_prefix, is_ipv6,
    is_protobuf_dot_fqn, is_protobuf_fqn, is_tuuid, is_ulid, is_uri, is_uri_ref, is_uuid,
    is_valid_http_header_name_loose, is_valid_http_header_name_strict,
    is_valid_http_header_value_loose, is_valid_http_header_value_strict,
};

pub(crate) struct StringRuleEval {
    r#const: Option<String>,
    len: Option<u64>,
    min_len: Option<u64>,
    max_len: Option<u64>,
    len_bytes: Option<u64>,
    min_bytes: Option<u64>,
    max_bytes: Option<u64>,
    pattern: Option<Regex>,
    prefix: Option<String>,
    suffix: Option<String>,
    contains: Option<String>,
    not_contains: Option<String>,
    r#in: HashSet<String>,
    not_in: HashSet<String>,
    strict: bool,
    well_known: Option<WellKnownStringRule>,
}

#[derive(Debug, Clone, Copy)]
enum WellKnownStringRule {
    Email,
    Hostname,
    Ip,
    Ipv4,
    Ipv6,
    Uri,
    UriRef,
    Uuid,
    Tuuid,
    Address,
    IpWithPrefixLen,
    Ipv4WithPrefixLen,
    Ipv6WithPrefixLen,
    IpPrefix,
    Ipv4Prefix,
    Ipv6Prefix,
    HostAndPort,
    Ulid,
    ProtobufFqn,
    ProtobufDotFqn,
    HttpHeaderName,
    HttpHeaderValue,
}

impl StringRuleEval {
    pub fn new(rules: &prost_protovalidate_types::StringRules) -> Result<Self, CompilationError> {
        let pattern = rules
            .pattern
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| CompilationError {
                cause: format!("invalid regex pattern: {e}"),
            })?;

        let well_known = parse_well_known_string_rule(rules.well_known.as_ref())?;

        Ok(Self {
            r#const: rules.r#const.clone(),
            len: rules.len,
            min_len: rules.min_len,
            max_len: rules.max_len,
            len_bytes: rules.len_bytes,
            min_bytes: rules.min_bytes,
            max_bytes: rules.max_bytes,
            pattern,
            prefix: rules.prefix.clone(),
            suffix: rules.suffix.clone(),
            contains: rules.contains.clone(),
            not_contains: rules.not_contains.clone(),
            r#in: rules.r#in.iter().cloned().collect(),
            not_in: rules.not_in.iter().cloned().collect(),
            strict: rules.strict.unwrap_or(true),
            well_known,
        })
    }

    pub fn tautology(&self) -> bool {
        self.r#const.is_none()
            && self.len.is_none()
            && self.min_len.is_none()
            && self.max_len.is_none()
            && self.len_bytes.is_none()
            && self.min_bytes.is_none()
            && self.max_bytes.is_none()
            && self.pattern.is_none()
            && self.prefix.is_none()
            && self.suffix.is_none()
            && self.contains.is_none()
            && self.not_contains.is_none()
            && self.r#in.is_empty()
            && self.not_in.is_empty()
            && self.well_known.is_none()
    }

    #[allow(clippy::too_many_lines)]
    pub fn evaluate(
        &self,
        val: &prost_reflect::Value,
        _cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(s) = val.as_str() else {
            return Ok(());
        };

        let mut violations = Vec::new();

        if let Some(ref c) = self.r#const {
            if s != c {
                violations.push(Violation::new("", meta::CONST_ID, meta::const_message(c)));
            }
        }

        // Safety: usize always fits in u64 (max usize ≤ u64::MAX on all targets)
        #[allow(clippy::cast_possible_truncation)]
        let char_count = s.chars().count() as u64;

        if let Some(len) = self.len {
            if char_count != len {
                violations.push(Violation::new("", meta::LEN_ID, meta::len_message(len)));
            }
        }
        if let Some(min) = self.min_len {
            if char_count < min {
                violations.push(Violation::new(
                    "",
                    meta::MIN_LEN_ID,
                    meta::min_len_message(min),
                ));
            }
        }
        if let Some(max) = self.max_len {
            if char_count > max {
                violations.push(Violation::new(
                    "",
                    meta::MAX_LEN_ID,
                    meta::max_len_message(max),
                ));
            }
        }

        // Safety: usize always fits in u64 (max usize ≤ u64::MAX on all targets)
        #[allow(clippy::cast_possible_truncation)]
        let byte_len = s.len() as u64;

        if let Some(len) = self.len_bytes {
            if byte_len != len {
                violations.push(Violation::new(
                    "",
                    meta::LEN_BYTES_ID,
                    meta::len_bytes_message(len),
                ));
            }
        }
        if let Some(min) = self.min_bytes {
            if byte_len < min {
                violations.push(Violation::new(
                    "",
                    meta::MIN_BYTES_ID,
                    meta::min_bytes_message(min),
                ));
            }
        }
        if let Some(max) = self.max_bytes {
            if byte_len > max {
                violations.push(Violation::new(
                    "",
                    meta::MAX_BYTES_ID,
                    meta::max_bytes_message(max),
                ));
            }
        }

        if let Some(ref pat) = self.pattern {
            if !pat.is_match(s) {
                violations.push(Violation::new(
                    "",
                    meta::PATTERN_ID,
                    meta::pattern_message(pat.as_str()),
                ));
            }
        }

        if let Some(ref prefix) = self.prefix {
            if !s.starts_with(prefix.as_str()) {
                violations.push(Violation::new(
                    "",
                    meta::PREFIX_ID,
                    meta::prefix_message(prefix),
                ));
            }
        }
        if let Some(ref suffix) = self.suffix {
            if !s.ends_with(suffix.as_str()) {
                violations.push(Violation::new(
                    "",
                    meta::SUFFIX_ID,
                    meta::suffix_message(suffix),
                ));
            }
        }
        if let Some(ref contains) = self.contains {
            if !s.contains(contains.as_str()) {
                violations.push(Violation::new(
                    "",
                    meta::CONTAINS_ID,
                    meta::contains_message(contains),
                ));
            }
        }
        if let Some(ref not_contains) = self.not_contains {
            if s.contains(not_contains.as_str()) {
                violations.push(Violation::new(
                    "",
                    meta::NOT_CONTAINS_ID,
                    meta::not_contains_message(not_contains),
                ));
            }
        }

        if !self.r#in.is_empty() && !self.r#in.contains(s) {
            let items: Vec<String> = self.r#in.iter().cloned().collect();
            violations.push(Violation::new("", meta::IN_ID, meta::in_message(&items)));
        }
        if self.not_in.contains(s) {
            let items: Vec<String> = self.not_in.iter().cloned().collect();
            violations.push(Violation::new(
                "",
                meta::NOT_IN_ID,
                meta::not_in_message(&items),
            ));
        }

        if let Some(wk) = self.well_known {
            if let Some(v) = check_well_known(s, wk, self.strict) {
                violations.push(v);
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

fn parse_well_known_string_rule(
    rule: Option<&prost_protovalidate_types::string_rules::WellKnown>,
) -> Result<Option<WellKnownStringRule>, CompilationError> {
    use prost_protovalidate_types::string_rules::WellKnown;

    let Some(wk) = rule else {
        return Ok(None);
    };

    let parsed = match wk {
        WellKnown::Email(true) => Some(WellKnownStringRule::Email),
        WellKnown::Hostname(true) => Some(WellKnownStringRule::Hostname),
        WellKnown::Ip(true) => Some(WellKnownStringRule::Ip),
        WellKnown::Ipv4(true) => Some(WellKnownStringRule::Ipv4),
        WellKnown::Ipv6(true) => Some(WellKnownStringRule::Ipv6),
        WellKnown::Uri(true) => Some(WellKnownStringRule::Uri),
        WellKnown::UriRef(true) => Some(WellKnownStringRule::UriRef),
        WellKnown::Uuid(true) => Some(WellKnownStringRule::Uuid),
        WellKnown::Tuuid(true) => Some(WellKnownStringRule::Tuuid),
        WellKnown::Address(true) => Some(WellKnownStringRule::Address),
        WellKnown::IpWithPrefixlen(true) => Some(WellKnownStringRule::IpWithPrefixLen),
        WellKnown::Ipv4WithPrefixlen(true) => Some(WellKnownStringRule::Ipv4WithPrefixLen),
        WellKnown::Ipv6WithPrefixlen(true) => Some(WellKnownStringRule::Ipv6WithPrefixLen),
        WellKnown::IpPrefix(true) => Some(WellKnownStringRule::IpPrefix),
        WellKnown::Ipv4Prefix(true) => Some(WellKnownStringRule::Ipv4Prefix),
        WellKnown::Ipv6Prefix(true) => Some(WellKnownStringRule::Ipv6Prefix),
        WellKnown::HostAndPort(true) => Some(WellKnownStringRule::HostAndPort),
        WellKnown::Ulid(true) => Some(WellKnownStringRule::Ulid),
        WellKnown::ProtobufFqn(true) => Some(WellKnownStringRule::ProtobufFqn),
        WellKnown::ProtobufDotFqn(true) => Some(WellKnownStringRule::ProtobufDotFqn),
        WellKnown::WellKnownRegex(v) => match prost_protovalidate_types::KnownRegex::try_from(*v) {
            Ok(prost_protovalidate_types::KnownRegex::HttpHeaderName) => {
                Some(WellKnownStringRule::HttpHeaderName)
            }
            Ok(prost_protovalidate_types::KnownRegex::HttpHeaderValue) => {
                Some(WellKnownStringRule::HttpHeaderValue)
            }
            Ok(prost_protovalidate_types::KnownRegex::Unspecified) => None,
            Err(_) => {
                return Err(CompilationError {
                    cause: format!("unsupported string.well_known_regex enum value: {v}"),
                });
            }
        },
        WellKnown::Email(false)
        | WellKnown::Hostname(false)
        | WellKnown::Ip(false)
        | WellKnown::Ipv4(false)
        | WellKnown::Ipv6(false)
        | WellKnown::Uri(false)
        | WellKnown::UriRef(false)
        | WellKnown::Address(false)
        | WellKnown::Uuid(false)
        | WellKnown::Tuuid(false)
        | WellKnown::IpWithPrefixlen(false)
        | WellKnown::Ipv4WithPrefixlen(false)
        | WellKnown::Ipv6WithPrefixlen(false)
        | WellKnown::IpPrefix(false)
        | WellKnown::Ipv4Prefix(false)
        | WellKnown::Ipv6Prefix(false)
        | WellKnown::HostAndPort(false)
        | WellKnown::Ulid(false)
        | WellKnown::ProtobufFqn(false)
        | WellKnown::ProtobufDotFqn(false) => None,
    };

    Ok(parsed)
}

fn check_well_known(s: &str, rule: WellKnownStringRule, strict: bool) -> Option<Violation> {
    // HTTP-header rules have their own id scheme (a shared rule path and a
    // nested empty variant for names only).
    match rule {
        WellKnownStringRule::HttpHeaderName => {
            let valid = if strict {
                is_valid_http_header_name_strict(s)
            } else {
                is_valid_http_header_name_loose(s)
            };
            if valid {
                return None;
            }
            let rule_id = if s.is_empty() {
                meta::HEADER_NAME_EMPTY_ID
            } else {
                meta::HEADER_NAME_ID
            };
            return Some(Violation::new_constraint(
                "",
                rule_id,
                meta::WELL_KNOWN_REGEX_PATH,
            ));
        }
        WellKnownStringRule::HttpHeaderValue => {
            let valid = if strict {
                is_valid_http_header_value_strict(s)
            } else {
                is_valid_http_header_value_loose(s)
            };
            if valid {
                return None;
            }
            return Some(Violation::new_constraint(
                "",
                meta::HEADER_VALUE_ID,
                meta::WELL_KNOWN_REGEX_PATH,
            ));
        }
        _ => {}
    }

    let name = well_known_name(rule);
    if s.is_empty() {
        return Some(Violation::new_constraint(
            "",
            meta::well_known_empty_id(name),
            meta::well_known_id(name),
        ));
    }

    let valid = match rule {
        WellKnownStringRule::Email => is_email(s),
        WellKnownStringRule::Hostname => is_hostname(s),
        WellKnownStringRule::Ip => is_ip(s),
        WellKnownStringRule::Ipv4 => Ipv4Addr::from_str(s).is_ok(),
        WellKnownStringRule::Ipv6 => is_ipv6(s),
        WellKnownStringRule::Uri => is_uri(s),
        WellKnownStringRule::UriRef => is_uri_ref(s),
        WellKnownStringRule::Uuid => is_uuid(s),
        WellKnownStringRule::Tuuid => is_tuuid(s),
        WellKnownStringRule::Address => is_hostname(s) || is_ip(s),
        WellKnownStringRule::IpWithPrefixLen => is_ip_prefix(s, IpVersion::Any, false),
        WellKnownStringRule::Ipv4WithPrefixLen => is_ip_prefix(s, IpVersion::V4, false),
        WellKnownStringRule::Ipv6WithPrefixLen => is_ip_prefix(s, IpVersion::V6, false),
        WellKnownStringRule::IpPrefix => is_ip_prefix(s, IpVersion::Any, true),
        WellKnownStringRule::Ipv4Prefix => is_ip_prefix(s, IpVersion::V4, true),
        WellKnownStringRule::Ipv6Prefix => is_ip_prefix(s, IpVersion::V6, true),
        WellKnownStringRule::HostAndPort => is_host_and_port(s, true),
        WellKnownStringRule::Ulid => is_ulid(s),
        WellKnownStringRule::ProtobufFqn => is_protobuf_fqn(s),
        WellKnownStringRule::ProtobufDotFqn => is_protobuf_dot_fqn(s),
        WellKnownStringRule::HttpHeaderName | WellKnownStringRule::HttpHeaderValue => {
            unreachable!("header rules are handled above")
        }
    };
    if valid {
        None
    } else {
        let id = meta::well_known_id(name);
        Some(Violation::new_constraint("", id.clone(), id))
    }
}

/// The well-known format name as it appears in rule ids
/// (`string.{name}` / `string.{name}_empty`).
fn well_known_name(rule: WellKnownStringRule) -> &'static str {
    match rule {
        WellKnownStringRule::Email => "email",
        WellKnownStringRule::Hostname => "hostname",
        WellKnownStringRule::Ip => "ip",
        WellKnownStringRule::Ipv4 => "ipv4",
        WellKnownStringRule::Ipv6 => "ipv6",
        WellKnownStringRule::Uri => "uri",
        WellKnownStringRule::UriRef => "uri_ref",
        WellKnownStringRule::Uuid => "uuid",
        WellKnownStringRule::Tuuid => "tuuid",
        WellKnownStringRule::Address => "address",
        WellKnownStringRule::IpWithPrefixLen => "ip_with_prefixlen",
        WellKnownStringRule::Ipv4WithPrefixLen => "ipv4_with_prefixlen",
        WellKnownStringRule::Ipv6WithPrefixLen => "ipv6_with_prefixlen",
        WellKnownStringRule::IpPrefix => "ip_prefix",
        WellKnownStringRule::Ipv4Prefix => "ipv4_prefix",
        WellKnownStringRule::Ipv6Prefix => "ipv6_prefix",
        WellKnownStringRule::HostAndPort => "host_and_port",
        WellKnownStringRule::Ulid => "ulid",
        WellKnownStringRule::ProtobufFqn => "protobuf_fqn",
        WellKnownStringRule::ProtobufDotFqn => "protobuf_dot_fqn",
        WellKnownStringRule::HttpHeaderName | WellKnownStringRule::HttpHeaderValue => {
            unreachable!("header rules use their own id scheme")
        }
    }
}

#[cfg(test)]
mod tests {
    use prost_protovalidate_types::{StringRules, string_rules::WellKnown};

    use super::StringRuleEval;

    #[test]
    fn string_rule_eval_rejects_unknown_well_known_regex_enum() {
        let rules = StringRules {
            well_known: Some(WellKnown::WellKnownRegex(i32::MAX)),
            ..Default::default()
        };

        match StringRuleEval::new(&rules) {
            Ok(_) => panic!("unknown string.well_known_regex enum values must fail compilation"),
            Err(err) => {
                assert!(
                    err.cause
                        .contains("unsupported string.well_known_regex enum value")
                );
            }
        }
    }
}
