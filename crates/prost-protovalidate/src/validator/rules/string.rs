use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::str::FromStr;

use regex::Regex;
use std::sync::LazyLock;
use uriparse::{URI, URIReference};

use crate::config::ValidationConfig;
use crate::error::{CompilationError, Error, ValidationError};
use crate::violation::Violation;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("email regex must compile")
});
static ULID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$").expect("ulid regex must compile")
});
static PROTOBUF_FQN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[A-Za-z_][A-Za-z_0-9]*(\\.[A-Za-z_][A-Za-z_0-9]*)*$")
        .expect("protobuf fqn regex must compile")
});
static PROTOBUF_DOT_FQN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^\\.[A-Za-z_][A-Za-z_0-9]*(\\.[A-Za-z_][A-Za-z_0-9]*)*$")
        .expect("protobuf dot fqn regex must compile")
});
static HTTP_HEADER_NAME_STRICT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^:?[0-9a-zA-Z!#$%&\\'*+-.^_|~\\x60]+$")
        .expect("strict HTTP header name regex must compile")
});
static HTTP_HEADER_NAME_LOOSE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[^\\x00\\x0A\\x0D]+$").expect("loose HTTP header name regex must compile")
});
static HTTP_HEADER_VALUE_STRICT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[^\\x00-\\x08\\x0A-\\x1F\\x7F]*$")
        .expect("strict HTTP header value regex must compile")
});
static HTTP_HEADER_VALUE_LOOSE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^[^\\x00\\x0A\\x0D]*$").expect("loose HTTP header value regex must compile")
});

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
                violations.push(Violation::new(
                    "",
                    "string.const",
                    format!("must equal `{c}`"),
                ));
            }
        }

        // Safety: usize always fits in u64 (max usize ≤ u64::MAX on all targets)
        #[allow(clippy::cast_possible_truncation)]
        let char_count = s.chars().count() as u64;

        if let Some(len) = self.len {
            if char_count != len {
                violations.push(Violation::new(
                    "",
                    "string.len",
                    format!("must be {len} characters"),
                ));
            }
        }
        if let Some(min) = self.min_len {
            if char_count < min {
                violations.push(Violation::new(
                    "",
                    "string.min_len",
                    format!("must be at least {min} characters"),
                ));
            }
        }
        if let Some(max) = self.max_len {
            if char_count > max {
                violations.push(Violation::new(
                    "",
                    "string.max_len",
                    format!("must be at most {max} characters"),
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
                    "string.len_bytes",
                    format!("must be {len} bytes"),
                ));
            }
        }
        if let Some(min) = self.min_bytes {
            if byte_len < min {
                violations.push(Violation::new(
                    "",
                    "string.min_bytes",
                    format!("must be at least {min} bytes"),
                ));
            }
        }
        if let Some(max) = self.max_bytes {
            if byte_len > max {
                violations.push(Violation::new(
                    "",
                    "string.max_bytes",
                    format!("must be at most {max} bytes"),
                ));
            }
        }

        if let Some(ref pat) = self.pattern {
            if !pat.is_match(s) {
                violations.push(Violation::new(
                    "",
                    "string.pattern",
                    format!("does not match regex pattern `{pat}`"),
                ));
            }
        }

        if let Some(ref prefix) = self.prefix {
            if !s.starts_with(prefix.as_str()) {
                violations.push(Violation::new(
                    "",
                    "string.prefix",
                    format!("does not have prefix `{prefix}`"),
                ));
            }
        }
        if let Some(ref suffix) = self.suffix {
            if !s.ends_with(suffix.as_str()) {
                violations.push(Violation::new(
                    "",
                    "string.suffix",
                    format!("does not have suffix `{suffix}`"),
                ));
            }
        }
        if let Some(ref contains) = self.contains {
            if !s.contains(contains.as_str()) {
                violations.push(Violation::new(
                    "",
                    "string.contains",
                    format!("does not contain substring `{contains}`"),
                ));
            }
        }
        if let Some(ref not_contains) = self.not_contains {
            if s.contains(not_contains.as_str()) {
                violations.push(Violation::new(
                    "",
                    "string.not_contains",
                    format!("contains substring `{not_contains}`"),
                ));
            }
        }

        if !self.r#in.is_empty() && !self.r#in.contains(s) {
            violations.push(Violation::new(
                "",
                "string.in",
                format!("must be in list {:?}", self.r#in),
            ));
        }
        if self.not_in.contains(s) {
            violations.push(Violation::new(
                "",
                "string.not_in",
                format!("must not be in list {:?}", self.not_in),
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

#[allow(clippy::too_many_lines)]
fn check_well_known(s: &str, rule: WellKnownStringRule, strict: bool) -> Option<Violation> {
    match rule {
        WellKnownStringRule::Email => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.email_empty",
                    "value is empty, which is not a valid email address",
                ));
            }
            if !is_email(s) {
                return Some(Violation::new(
                    "",
                    "string.email",
                    "must be a valid email address",
                ));
            }
        }
        WellKnownStringRule::Hostname => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.hostname_empty",
                    "value is empty, which is not a valid hostname",
                ));
            }
            if !is_hostname(s) {
                return Some(Violation::new(
                    "",
                    "string.hostname",
                    "must be a valid hostname",
                ));
            }
        }
        WellKnownStringRule::Ip => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.ip_empty",
                    "value is empty, which is not a valid IP address",
                ));
            }
            if !is_ip(s) {
                return Some(Violation::new(
                    "",
                    "string.ip",
                    "must be a valid IP address",
                ));
            }
        }
        WellKnownStringRule::Ipv4 => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.ipv4_empty",
                    "value is empty, which is not a valid IPv4 address",
                ));
            }
            if Ipv4Addr::from_str(s).is_err() {
                return Some(Violation::new(
                    "",
                    "string.ipv4",
                    "must be a valid IPv4 address",
                ));
            }
        }
        WellKnownStringRule::Ipv6 => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.ipv6_empty",
                    "value is empty, which is not a valid IPv6 address",
                ));
            }
            if !is_ipv6(s) {
                return Some(Violation::new(
                    "",
                    "string.ipv6",
                    "must be a valid IPv6 address",
                ));
            }
        }
        WellKnownStringRule::Uri => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.uri_empty",
                    "value is empty, which is not a valid URI",
                ));
            }
            if !is_uri(s) {
                return Some(Violation::new("", "string.uri", "must be a valid URI"));
            }
        }
        WellKnownStringRule::UriRef => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.uri_ref_empty",
                    "value is empty, which is not a valid URI reference",
                ));
            }
            if !is_uri_ref(s) {
                return Some(Violation::new(
                    "",
                    "string.uri_ref",
                    "must be a valid URI reference",
                ));
            }
        }
        WellKnownStringRule::Uuid => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.uuid_empty",
                    "value is empty, which is not a valid UUID",
                ));
            }
            if !is_uuid(s) {
                return Some(Violation::new("", "string.uuid", "must be a valid UUID"));
            }
        }
        WellKnownStringRule::Tuuid => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.tuuid_empty",
                    "value is empty, which is not a valid trimmed UUID",
                ));
            }
            if !is_tuuid(s) {
                return Some(Violation::new(
                    "",
                    "string.tuuid",
                    "must be a valid trimmed UUID",
                ));
            }
        }
        WellKnownStringRule::Address => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.address_empty",
                    "value is empty, which is not a valid address",
                ));
            }
            if !is_hostname(s) && !is_ip(s) {
                return Some(Violation::new(
                    "",
                    "string.address",
                    "must be a valid hostname or IP address",
                ));
            }
        }
        WellKnownStringRule::IpWithPrefixLen
        | WellKnownStringRule::Ipv4WithPrefixLen
        | WellKnownStringRule::Ipv6WithPrefixLen => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.ip_with_prefixlen_empty",
                    "value is empty, which is not a valid IP with prefix length",
                ));
            }
            let valid = match rule {
                WellKnownStringRule::IpWithPrefixLen => is_ip_prefix(s, IpVersion::Any, false),
                WellKnownStringRule::Ipv4WithPrefixLen => is_ip_prefix(s, IpVersion::V4, false),
                WellKnownStringRule::Ipv6WithPrefixLen => is_ip_prefix(s, IpVersion::V6, false),
                _ => false,
            };
            if !valid {
                let (rule_id, message) = match rule {
                    WellKnownStringRule::IpWithPrefixLen => (
                        "string.ip_with_prefixlen",
                        "must be a valid IP with prefix length",
                    ),
                    WellKnownStringRule::Ipv4WithPrefixLen => (
                        "string.ipv4_with_prefixlen",
                        "must be a valid IPv4 address with prefix length",
                    ),
                    WellKnownStringRule::Ipv6WithPrefixLen => (
                        "string.ipv6_with_prefixlen",
                        "must be a valid IPv6 address with prefix length",
                    ),
                    _ => unreachable!("handled above"),
                };
                return Some(Violation::new("", rule_id, message));
            }
        }
        WellKnownStringRule::IpPrefix
        | WellKnownStringRule::Ipv4Prefix
        | WellKnownStringRule::Ipv6Prefix => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.ip_prefix_empty",
                    "value is empty, which is not a valid IP prefix",
                ));
            }
            let valid = match rule {
                WellKnownStringRule::IpPrefix => is_ip_prefix(s, IpVersion::Any, true),
                WellKnownStringRule::Ipv4Prefix => is_ip_prefix(s, IpVersion::V4, true),
                WellKnownStringRule::Ipv6Prefix => is_ip_prefix(s, IpVersion::V6, true),
                _ => false,
            };
            if !valid {
                let (rule_id, message) = match rule {
                    WellKnownStringRule::IpPrefix => {
                        ("string.ip_prefix", "must be a valid IP prefix")
                    }
                    WellKnownStringRule::Ipv4Prefix => {
                        ("string.ipv4_prefix", "must be a valid IPv4 prefix")
                    }
                    WellKnownStringRule::Ipv6Prefix => {
                        ("string.ipv6_prefix", "must be a valid IPv6 prefix")
                    }
                    _ => unreachable!("handled above"),
                };
                return Some(Violation::new("", rule_id, message));
            }
        }
        WellKnownStringRule::HostAndPort => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.host_and_port_empty",
                    "value is empty, which is not a valid host and port pair",
                ));
            }
            if !is_host_and_port(s, true) {
                return Some(Violation::new(
                    "",
                    "string.host_and_port",
                    "must be a valid host (hostname or IP address) and port pair",
                ));
            }
        }
        WellKnownStringRule::Ulid => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.ulid_empty",
                    "value is empty, which is not a valid ULID",
                ));
            }
            if !is_ulid(s) {
                return Some(Violation::new("", "string.ulid", "must be a valid ULID"));
            }
        }
        WellKnownStringRule::ProtobufFqn => {
            if s.is_empty() {
                return Some(
                    Violation::new(
                        "",
                        "string.protobuf_fqn_empty",
                        "value is empty, which is not a valid fully-qualified Protobuf name",
                    )
                    .with_rule_path("string.protobuf_fqn"),
                );
            }
            if !is_protobuf_fqn(s) {
                return Some(Violation::new(
                    "",
                    "string.protobuf_fqn",
                    "must be a valid fully-qualified Protobuf name",
                ));
            }
        }
        WellKnownStringRule::ProtobufDotFqn => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.protobuf_dot_fqn_empty",
                    "value is empty, which is not a valid fully-qualified Protobuf name with a leading dot",
                )
                .with_rule_path("string.protobuf_dot_fqn"));
            }
            if !is_protobuf_dot_fqn(s) {
                return Some(Violation::new(
                    "",
                    "string.protobuf_dot_fqn",
                    "must be a valid fully-qualified Protobuf name with a leading dot",
                ));
            }
        }
        WellKnownStringRule::HttpHeaderName => {
            if s.is_empty() {
                return Some(Violation::new(
                    "",
                    "string.well_known_regex.header_name_empty",
                    "value is empty, which is not a valid HTTP header name",
                ));
            }
            let valid = if strict {
                HTTP_HEADER_NAME_STRICT_REGEX.is_match(s)
            } else {
                HTTP_HEADER_NAME_LOOSE_REGEX.is_match(s)
            };
            if !valid {
                return Some(Violation::new(
                    "",
                    "string.well_known_regex.header_name",
                    "must be a valid HTTP header name",
                ));
            }
        }
        WellKnownStringRule::HttpHeaderValue => {
            let valid = if strict {
                HTTP_HEADER_VALUE_STRICT_REGEX.is_match(s)
            } else {
                HTTP_HEADER_VALUE_LOOSE_REGEX.is_match(s)
            };
            if !valid {
                return Some(Violation::new(
                    "",
                    "string.well_known_regex.header_value",
                    "must be a valid HTTP header value",
                ));
            }
        }
    }
    None
}

pub(crate) fn is_email(s: &str) -> bool {
    EMAIL_REGEX.is_match(s)
}

pub(crate) fn is_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.is_empty() {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    // Right-most label must not be all digits
    if let Some(last) = labels.last() {
        if last.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

pub(crate) fn is_ip(s: &str) -> bool {
    Ipv4Addr::from_str(s).is_ok() || is_ipv6(s)
}

pub(crate) fn is_ipv6(s: &str) -> bool {
    // Support zone identifiers (e.g., "fe80::1%eth0")
    let addr = s.split('%').next().unwrap_or(s);
    Ipv6Addr::from_str(addr).is_ok()
}

pub(crate) fn is_uri(s: &str) -> bool {
    if has_invalid_uri_scheme_prefix(s) {
        return false;
    }
    catch_unwind(AssertUnwindSafe(|| URI::try_from(s).is_ok())).unwrap_or(false)
}

pub(crate) fn is_uri_ref(s: &str) -> bool {
    if has_invalid_uri_scheme_prefix(s) {
        return false;
    }
    catch_unwind(AssertUnwindSafe(|| URIReference::try_from(s).is_ok())).unwrap_or(false)
}

fn has_invalid_uri_scheme_prefix(s: &str) -> bool {
    let Some(scheme_end) = s.find(':') else {
        return false;
    };

    let first_hier_delim = s.find(|c| ['/', '?', '#'].contains(&c));
    if first_hier_delim.is_some_and(|idx| idx < scheme_end) {
        return false;
    }

    let scheme = &s[..scheme_end];
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return true;
    };
    if !first.is_ascii_alphabetic() {
        return true;
    }
    !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn is_uuid(s: &str) -> bool {
    // UUID format: 8-4-4-4-12 hex digits
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    for (part, &expected) in parts.iter().zip(&expected_lens) {
        if part.len() != expected || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

fn is_tuuid(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_ulid(s: &str) -> bool {
    ULID_REGEX.is_match(s)
}

fn is_protobuf_fqn(s: &str) -> bool {
    PROTOBUF_FQN_REGEX.is_match(s)
}

fn is_protobuf_dot_fqn(s: &str) -> bool {
    PROTOBUF_DOT_FQN_REGEX.is_match(s)
}

#[derive(Clone, Copy)]
enum IpVersion {
    Any,
    V4,
    V6,
}

pub(crate) fn is_ip_with_version(s: &str, version: i64) -> bool {
    match version {
        0 => is_ip(s),
        4 => Ipv4Addr::from_str(s).is_ok(),
        6 => is_ipv6(s),
        _ => false,
    }
}

pub(crate) fn is_ip_prefix_with_options(s: &str, version: i64, strict: bool) -> bool {
    let version = match version {
        0 => IpVersion::Any,
        4 => IpVersion::V4,
        6 => IpVersion::V6,
        _ => return false,
    };
    is_ip_prefix(s, version, strict)
}

fn is_ip_prefix(s: &str, version: IpVersion, strict: bool) -> bool {
    match version {
        IpVersion::Any => {
            is_ip_prefix(s, IpVersion::V4, strict) || is_ip_prefix(s, IpVersion::V6, strict)
        }
        IpVersion::V4 => is_ipv4_prefix(s, strict),
        IpVersion::V6 => is_ipv6_prefix(s, strict),
    }
}

fn is_ipv4_prefix(s: &str, strict: bool) -> bool {
    let Some((address, prefix_len)) = split_prefix(s) else {
        return false;
    };
    if prefix_len > 32 {
        return false;
    }
    let Ok(ip) = Ipv4Addr::from_str(address) else {
        return false;
    };
    !strict || ipv4_is_prefix_only(ip, prefix_len)
}

fn is_ipv6_prefix(s: &str, strict: bool) -> bool {
    let Some((address, prefix_len)) = split_prefix(s) else {
        return false;
    };
    if prefix_len > 128 {
        return false;
    }
    let Ok(ip) = Ipv6Addr::from_str(address.split('%').next().unwrap_or(address)) else {
        return false;
    };
    !strict || ipv6_is_prefix_only(ip, prefix_len)
}

fn split_prefix(s: &str) -> Option<(&str, u8)> {
    let (address, prefix) = s.split_once('/')?;
    if address.is_empty() || prefix.is_empty() {
        return None;
    }
    if prefix.len() > 1 && prefix.starts_with('0') {
        return None;
    }
    if !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parsed = prefix.parse::<u8>().ok()?;
    Some((address, parsed))
}

fn ipv4_is_prefix_only(ip: Ipv4Addr, prefix_len: u8) -> bool {
    let bits = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    bits == (bits & mask)
}

fn ipv6_is_prefix_only(ip: Ipv6Addr, prefix_len: u8) -> bool {
    let bits = u128::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    };
    bits == (bits & mask)
}

pub(crate) fn is_host_and_port(s: &str, port_required: bool) -> bool {
    if s.is_empty() {
        return false;
    }

    if s.starts_with('[') {
        let Some(bracket_end) = s.rfind(']') else {
            return false;
        };
        let host = &s[1..bracket_end];
        let after_host = &s[bracket_end + 1..];
        if after_host.is_empty() {
            return !port_required && is_ipv6(host);
        }
        let Some(port) = after_host.strip_prefix(':') else {
            return false;
        };
        return is_ipv6(host) && is_port(port);
    }

    let Some(split_idx) = s.rfind(':') else {
        return !port_required && (is_hostname(s) || Ipv4Addr::from_str(s).is_ok());
    };
    let host = &s[..split_idx];
    let port = &s[split_idx + 1..];
    (is_hostname(host) || Ipv4Addr::from_str(host).is_ok()) && is_port(port)
}

fn is_port(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.len() > 1 && s.starts_with('0') {
        return false;
    }
    if !s.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    s.parse::<u16>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::{
        IpVersion, StringRuleEval, WellKnownStringRule, check_well_known, is_host_and_port,
        is_ip_prefix, is_protobuf_dot_fqn, is_protobuf_fqn, is_tuuid, is_ulid, is_uri, is_uri_ref,
    };
    use prost_protovalidate_types::{StringRules, string_rules::WellKnown};

    #[test]
    fn uri_ref_rejects_invalid_sequences() {
        assert!(is_uri_ref("https://example.com/path?q=1#f"));
        assert!(is_uri_ref("./foo/bar?baz=quux"));
        assert!(!is_uri_ref("http://exa mple.com"));
    }

    #[test]
    fn ip_prefix_strictness_matches_rule_modes() {
        assert!(is_ip_prefix("192.168.1.1/24", IpVersion::V4, false));
        assert!(!is_ip_prefix("192.168.1.1/24", IpVersion::V4, true));
        assert!(is_ip_prefix("192.168.1.0/24", IpVersion::V4, true));
        assert!(is_ip_prefix("2001:db8::1/64", IpVersion::V6, false));
        assert!(!is_ip_prefix("2001:db8::1/64", IpVersion::V6, true));
    }

    #[test]
    fn host_and_port_requires_valid_host_and_canonical_port() {
        assert!(is_host_and_port("example.com:8080", true));
        assert!(is_host_and_port("[2001:db8::1]:443", true));
        assert!(!is_host_and_port("not a host:80", true));
        assert!(!is_host_and_port("example.com:080", true));
        assert!(!is_host_and_port("[2001:db8::1]443", true));
    }

    #[test]
    fn additional_well_known_string_formats_validate() {
        assert!(is_tuuid("550e8400e29b41d4a716446655440000"));
        assert!(!is_tuuid("550e8400-e29b-41d4-a716-446655440000"));

        assert!(is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!is_ulid("81ARZ3NDEKTSV4RRFFQ69G5FAV"));

        assert!(is_protobuf_fqn("google.protobuf.Timestamp"));
        assert!(!is_protobuf_fqn(".google.protobuf.Timestamp"));

        assert!(is_protobuf_dot_fqn(".google.protobuf.Timestamp"));
        assert!(!is_protobuf_dot_fqn("google.protobuf.Timestamp"));
    }

    #[test]
    fn protobuf_fqn_and_dot_fqn_patterns_match_conformance_cases() {
        assert!(is_protobuf_fqn("buf.validate"));
        assert!(is_protobuf_fqn("my_package.MyMessage"));
        assert!(is_protobuf_fqn("_any_Crazy_CASE_with_01234_numbers"));
        assert!(is_protobuf_fqn("c3p0"));
        assert!(!is_protobuf_fqn(""));
        assert!(!is_protobuf_fqn(".x"));
        assert!(!is_protobuf_fqn("x."));
        assert!(!is_protobuf_fqn("a..b"));
        assert!(!is_protobuf_fqn("1a"));
        assert!(!is_protobuf_fqn("a$"));

        assert!(is_protobuf_dot_fqn(".buf.validate"));
        assert!(is_protobuf_dot_fqn(".my_package.MyMessage"));
        assert!(is_protobuf_dot_fqn("._any_Crazy_CASE_with_01234_numbers"));
        assert!(!is_protobuf_dot_fqn(""));
        assert!(!is_protobuf_dot_fqn(".x."));
        assert!(!is_protobuf_dot_fqn(".a..b"));
        assert!(!is_protobuf_dot_fqn(".1a"));
        assert!(!is_protobuf_dot_fqn(".a$"));
    }

    #[test]
    fn uri_helpers_never_panic_on_malformed_inputs() {
        let panic_inputs = [
            ".foo://example.com",
            "-foo://example.com",
            ":foo://example.com",
            "foo%20bar://example.com",
        ];

        for input in panic_inputs {
            assert!(!is_uri(input), "is_uri must be panic-safe for {input:?}");
            assert!(
                !is_uri_ref(input),
                "is_uri_ref must be panic-safe for {input:?}"
            );
        }
    }

    #[test]
    fn protobuf_empty_violations_keep_base_rule_path() {
        let fqn = check_well_known("", WellKnownStringRule::ProtobufFqn, true)
            .expect("protobuf_fqn empty should violate");
        assert_eq!(fqn.rule_id, "string.protobuf_fqn_empty");
        assert_eq!(fqn.rule_path, "string.protobuf_fqn");

        let dot_fqn = check_well_known("", WellKnownStringRule::ProtobufDotFqn, true)
            .expect("protobuf_dot_fqn empty should violate");
        assert_eq!(dot_fqn.rule_id, "string.protobuf_dot_fqn_empty");
        assert_eq!(dot_fqn.rule_path, "string.protobuf_dot_fqn");
    }

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
