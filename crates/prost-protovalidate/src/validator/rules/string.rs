use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;

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

/// Strict HTTP header name: token chars per RFC 7230's `token` rule.
/// Allowed characters: `!#$%&'*+-.0-9A-Za-z^_``|~`, with optional `:` prefix for pseudo-headers.
fn is_valid_http_header_name_strict(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Only ASCII
    let bytes = s.as_bytes();
    // Optional leading colon (pseudo-header), but `:` alone is not valid
    let start = usize::from(bytes[0] == b':');
    if start >= bytes.len() {
        return false;
    }
    // Trailing colon is not allowed
    if bytes[bytes.len() - 1] == b':' {
        return false;
    }
    for &b in &bytes[start..] {
        if !is_token_char(b) {
            return false;
        }
    }
    true
}

/// Token characters per RFC 7230 §3.2.6
fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'0'..=b'9' |
        b'A'..=b'Z' |
        b'^' | b'_' | b'`' |
        b'a'..=b'z' |
        b'|' | b'~'
    )
}

/// Loose HTTP header name: any non-empty string without NUL, CR, or LF.
fn is_valid_http_header_name_loose(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    !s.bytes().any(|b| b == 0x00 || b == 0x0A || b == 0x0D)
}

/// Strict HTTP header value: no NUL, control chars (0x00-0x08, 0x0A-0x1F), or DEL (0x7F).
/// HT (0x09) IS allowed per RFC 7230.
fn is_valid_http_header_value_strict(s: &str) -> bool {
    !s.bytes()
        .any(|b| matches!(b, 0x00..=0x08 | 0x0A..=0x1F | 0x7F))
}

/// Loose HTTP header value: no NUL, CR, or LF.
fn is_valid_http_header_value_loose(s: &str) -> bool {
    !s.bytes().any(|b| b == 0x00 || b == 0x0A || b == 0x0D)
}

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
                    format!("value length must be at least {min} characters"),
                ));
            }
        }
        if let Some(max) = self.max_len {
            if char_count > max {
                violations.push(Violation::new(
                    "",
                    "string.max_len",
                    format!("value length must be at most {max} characters"),
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
        | WellKnown::Ulid(false) => None,
    };

    Ok(parsed)
}

#[allow(clippy::too_many_lines)]
fn check_well_known(s: &str, rule: WellKnownStringRule, strict: bool) -> Option<Violation> {
    match rule {
        WellKnownStringRule::Email => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.email_empty",
                    "string.email",
                ));
            }
            if !is_email(s) {
                return Some(Violation::new_constraint(
                    "",
                    "string.email",
                    "string.email",
                ));
            }
        }
        WellKnownStringRule::Hostname => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.hostname_empty",
                    "string.hostname",
                ));
            }
            if !is_hostname(s) {
                return Some(Violation::new_constraint(
                    "",
                    "string.hostname",
                    "string.hostname",
                ));
            }
        }
        WellKnownStringRule::Ip => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.ip_empty",
                    "string.ip",
                ));
            }
            if !is_ip(s) {
                return Some(Violation::new_constraint("", "string.ip", "string.ip"));
            }
        }
        WellKnownStringRule::Ipv4 => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.ipv4_empty",
                    "string.ipv4",
                ));
            }
            if Ipv4Addr::from_str(s).is_err() {
                return Some(Violation::new_constraint("", "string.ipv4", "string.ipv4"));
            }
        }
        WellKnownStringRule::Ipv6 => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.ipv6_empty",
                    "string.ipv6",
                ));
            }
            if !is_ipv6(s) {
                return Some(Violation::new_constraint("", "string.ipv6", "string.ipv6"));
            }
        }
        WellKnownStringRule::Uri => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.uri_empty",
                    "string.uri",
                ));
            }
            if !is_uri(s) {
                return Some(Violation::new_constraint("", "string.uri", "string.uri"));
            }
        }
        WellKnownStringRule::UriRef => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.uri_ref_empty",
                    "string.uri_ref",
                ));
            }
            if !is_uri_ref(s) {
                return Some(Violation::new_constraint(
                    "",
                    "string.uri_ref",
                    "string.uri_ref",
                ));
            }
        }
        WellKnownStringRule::Uuid => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.uuid_empty",
                    "string.uuid",
                ));
            }
            if !is_uuid(s) {
                return Some(Violation::new_constraint("", "string.uuid", "string.uuid"));
            }
        }
        WellKnownStringRule::Tuuid => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.tuuid_empty",
                    "string.tuuid",
                ));
            }
            if !is_tuuid(s) {
                return Some(Violation::new_constraint(
                    "",
                    "string.tuuid",
                    "string.tuuid",
                ));
            }
        }
        WellKnownStringRule::Address => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.address_empty",
                    "string.address",
                ));
            }
            if !is_hostname(s) && !is_ip(s) {
                return Some(Violation::new_constraint(
                    "",
                    "string.address",
                    "string.address",
                ));
            }
        }
        WellKnownStringRule::IpWithPrefixLen
        | WellKnownStringRule::Ipv4WithPrefixLen
        | WellKnownStringRule::Ipv6WithPrefixLen => {
            let (empty_id, rule_path) = match rule {
                WellKnownStringRule::IpWithPrefixLen => {
                    ("string.ip_with_prefixlen_empty", "string.ip_with_prefixlen")
                }
                WellKnownStringRule::Ipv4WithPrefixLen => (
                    "string.ipv4_with_prefixlen_empty",
                    "string.ipv4_with_prefixlen",
                ),
                WellKnownStringRule::Ipv6WithPrefixLen => (
                    "string.ipv6_with_prefixlen_empty",
                    "string.ipv6_with_prefixlen",
                ),
                _ => unreachable!(),
            };
            if s.is_empty() {
                return Some(Violation::new_constraint("", empty_id, rule_path));
            }
            let valid = match rule {
                WellKnownStringRule::IpWithPrefixLen => is_ip_prefix(s, IpVersion::Any, false),
                WellKnownStringRule::Ipv4WithPrefixLen => is_ip_prefix(s, IpVersion::V4, false),
                WellKnownStringRule::Ipv6WithPrefixLen => is_ip_prefix(s, IpVersion::V6, false),
                _ => false,
            };
            if !valid {
                return Some(Violation::new_constraint("", rule_path, rule_path));
            }
        }
        WellKnownStringRule::IpPrefix
        | WellKnownStringRule::Ipv4Prefix
        | WellKnownStringRule::Ipv6Prefix => {
            let (empty_id, rule_path) = match rule {
                WellKnownStringRule::IpPrefix => ("string.ip_prefix_empty", "string.ip_prefix"),
                WellKnownStringRule::Ipv4Prefix => {
                    ("string.ipv4_prefix_empty", "string.ipv4_prefix")
                }
                WellKnownStringRule::Ipv6Prefix => {
                    ("string.ipv6_prefix_empty", "string.ipv6_prefix")
                }
                _ => unreachable!(),
            };
            if s.is_empty() {
                return Some(Violation::new_constraint("", empty_id, rule_path));
            }
            let valid = match rule {
                WellKnownStringRule::IpPrefix => is_ip_prefix(s, IpVersion::Any, true),
                WellKnownStringRule::Ipv4Prefix => is_ip_prefix(s, IpVersion::V4, true),
                WellKnownStringRule::Ipv6Prefix => is_ip_prefix(s, IpVersion::V6, true),
                _ => false,
            };
            if !valid {
                return Some(Violation::new_constraint("", rule_path, rule_path));
            }
        }
        WellKnownStringRule::HostAndPort => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.host_and_port_empty",
                    "string.host_and_port",
                ));
            }
            if !is_host_and_port(s, true) {
                return Some(Violation::new_constraint(
                    "",
                    "string.host_and_port",
                    "string.host_and_port",
                ));
            }
        }
        WellKnownStringRule::Ulid => {
            if s.is_empty() {
                return Some(Violation::new_constraint(
                    "",
                    "string.ulid_empty",
                    "string.ulid",
                ));
            }
            if !is_ulid(s) {
                return Some(Violation::new_constraint("", "string.ulid", "string.ulid"));
            }
        }
        WellKnownStringRule::HttpHeaderName => {
            let valid = if strict {
                is_valid_http_header_name_strict(s)
            } else {
                is_valid_http_header_name_loose(s)
            };
            if !valid {
                let rule_id = if s.is_empty() {
                    "string.well_known_regex.header_name_empty"
                } else {
                    "string.well_known_regex.header_name"
                };
                return Some(Violation::new_constraint(
                    "",
                    rule_id,
                    "string.well_known_regex",
                ));
            }
        }
        WellKnownStringRule::HttpHeaderValue => {
            let valid = if strict {
                is_valid_http_header_value_strict(s)
            } else {
                is_valid_http_header_value_loose(s)
            };
            if !valid {
                return Some(Violation::new_constraint(
                    "",
                    "string.well_known_regex.header_value",
                    "string.well_known_regex",
                ));
            }
        }
    }
    None
}

pub(crate) fn is_email(s: &str) -> bool {
    if s != s.trim() || s.contains(char::is_whitespace) {
        return false;
    }
    if !s.is_ascii() {
        return false;
    }
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // Reject quoted strings, comments, and mailbox format
    if local.contains('"') || local.contains('(') || local.contains('<') {
        return false;
    }
    // Local part: only unreserved characters
    if !EMAIL_REGEX.is_match(s) {
        return false;
    }
    // Domain must be a valid hostname (not IP literal)
    if domain.starts_with('[') {
        return false;
    }
    // Reject trailing dot in domain
    if domain.ends_with('.') {
        return false;
    }
    // Email domain: valid labels but no "last label must not be all digits" rule
    is_email_domain(domain)
}

pub(crate) fn is_hostname(s: &str) -> bool {
    if s != s.trim() {
        return false;
    }
    if !s.is_ascii() {
        return false;
    }
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

/// Validate hostname labels for email domain (no "last label must not be all digits" rule).
fn is_email_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    for label in s.split('.') {
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
    true
}

pub(crate) fn is_ip(s: &str) -> bool {
    if s.is_empty() || s != s.trim() {
        return false;
    }
    is_ipv4_strict(s) || is_ipv6_any(s)
}

fn is_ipv4_strict(s: &str) -> bool {
    if s != s.trim() {
        return false;
    }
    Ipv4Addr::from_str(s).is_ok()
}

/// Parse IPv6, accepting zone IDs (e.g., `fe80::1%eth0`).
fn is_ipv6_any(s: &str) -> bool {
    if s != s.trim() {
        return false;
    }
    // Split off zone ID
    let (addr, zone) = match s.find('%') {
        Some(idx) => (&s[..idx], Some(&s[idx + 1..])),
        None => (s, None),
    };
    // Reject empty zone IDs
    if let Some(z) = zone {
        if z.is_empty() {
            return false;
        }
    }
    Ipv6Addr::from_str(addr).is_ok()
}

/// Strict IPv6 without zone IDs.
fn is_ipv6_strict(s: &str) -> bool {
    if s != s.trim() || s.contains('%') {
        return false;
    }
    Ipv6Addr::from_str(s).is_ok()
}

pub(crate) fn is_ipv6(s: &str) -> bool {
    is_ipv6_any(s)
}

pub(crate) fn is_uri(s: &str) -> bool {
    if !is_valid_uri_chars(s) {
        return false;
    }
    // Try parsing directly first.
    if let Ok(uri) = fluent_uri::Uri::parse(s) {
        return is_valid_uri_host(&uri);
    }
    // fluent_uri doesn't support RFC 6874 IPv6 zone IDs.
    // Strip the zone ID and retry.
    if let Some(stripped) = strip_ipv6_zone_id(s) {
        if let Ok(uri) = fluent_uri::Uri::parse(stripped.as_str()) {
            return is_valid_uri_host(&uri);
        }
    }
    false
}

pub(crate) fn is_uri_ref(s: &str) -> bool {
    if !is_valid_uri_chars(s) {
        return false;
    }
    if let Ok(uri) = fluent_uri::UriRef::parse(s) {
        return is_valid_uri_ref_host(&uri);
    }
    if let Some(stripped) = strip_ipv6_zone_id(s) {
        if let Ok(uri) = fluent_uri::UriRef::parse(stripped.as_str()) {
            return is_valid_uri_ref_host(&uri);
        }
    }
    false
}

/// Check that a parsed URI's host reg-name (if present) has valid pct-encoded UTF-8.
fn is_valid_uri_host(uri: &fluent_uri::Uri<&str>) -> bool {
    let Some(authority) = uri.authority() else {
        return true;
    };
    is_valid_reg_name_utf8(authority.host())
}

/// Check that a parsed URI-reference's host reg-name has valid pct-encoded UTF-8.
fn is_valid_uri_ref_host(uri: &fluent_uri::UriRef<&str>) -> bool {
    let Some(authority) = uri.authority() else {
        return true;
    };
    is_valid_reg_name_utf8(authority.host())
}

/// Validate that pct-decoded bytes in a reg-name host form valid UTF-8.
/// IP-literal hosts (starting with `[`) are not checked.
fn is_valid_reg_name_utf8(host: &str) -> bool {
    // IP-literals are enclosed in brackets — skip UTF-8 check.
    if host.starts_with('[') {
        return true;
    }
    let decoded = pct_decode_bytes(host);
    std::str::from_utf8(&decoded).is_ok()
}

/// Decode percent-encoded bytes in a string. Non-pct-encoded ASCII bytes
/// are passed through unchanged.
fn pct_decode_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) =
                (hex_digit_value(bytes[i + 1]), hex_digit_value(bytes[i + 2]))
            {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hex_digit_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strip an IPv6 zone ID (RFC 6874) from a URI string.
/// Zone IDs appear as `%25<zone>` inside `[...]` IP-literal hosts.
/// Returns `None` if no zone ID is found, the zone ID is empty, or the
/// zone ID contains invalid characters / invalid pct-encoded UTF-8.
fn strip_ipv6_zone_id(s: &str) -> Option<String> {
    let bracket_open = s.find('[')?;
    let bracket_close = s[bracket_open..].find(']').map(|i| bracket_open + i)?;
    let host_inner = &s[bracket_open + 1..bracket_close];
    let zone_offset = host_inner.find("%25")?;
    let zone_id = &host_inner[zone_offset + 3..];
    // Reject empty zone IDs.
    if zone_id.is_empty() {
        return None;
    }
    // Validate zone ID characters: unreserved chars and valid pct-encoding.
    if !is_valid_zone_id(zone_id) {
        return None;
    }
    // Validate that pct-decoded zone ID is valid UTF-8.
    if std::str::from_utf8(&pct_decode_bytes(zone_id)).is_err() {
        return None;
    }
    // Reconstruct without the zone ID.
    let mut result = String::with_capacity(s.len());
    result.push_str(&s[..bracket_open + 1 + zone_offset]);
    result.push(']');
    result.push_str(&s[bracket_close + 1..]);
    Some(result)
}

/// Validate zone ID characters per RFC 6874:
/// `ZoneID = 1*( unreserved / pct-encoded )`
fn is_valid_zone_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            // Must be valid pct-encoding.
            if i + 2 >= bytes.len() {
                return false;
            }
            if !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
                return false;
            }
            i += 3;
        } else if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            // unreserved
            i += 1;
        } else {
            return false;
        }
    }
    true
}

/// Pre-validate URI characters per RFC 3986.
/// Reject control characters, spaces, carets, and invalid percent-encoding.
fn is_valid_uri_chars(s: &str) -> bool {
    if s != s.trim() {
        return false;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Reject control characters (0x00-0x1F, 0x7F)
        if b <= 0x1F || b == 0x7F {
            return false;
        }
        // Reject space
        if b == b' ' {
            return false;
        }
        // Reject caret, backslash, backtick, curly braces, pipe
        if matches!(b, b'^' | b'\\' | b'{' | b'}' | b'|') {
            return false;
        }
        // Validate percent-encoding
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return false;
            }
            if !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
                return false;
            }
            i += 3;
            continue;
        }
        // Reject non-ASCII
        if b > 0x7E {
            return false;
        }
        i += 1;
    }
    true
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

#[derive(Clone, Copy)]
enum IpVersion {
    Any,
    V4,
    V6,
}

pub(crate) fn is_ip_with_version(s: &str, version: i64) -> bool {
    match version {
        0 => is_ip(s),
        4 => is_ipv4_strict(s),
        6 => is_ipv6_strict(s),
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
    if s != s.trim() {
        return false;
    }
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
    if s != s.trim() {
        return false;
    }
    let Some((address, prefix_len)) = split_prefix(s) else {
        return false;
    };
    if prefix_len > 128 {
        return false;
    }
    // Reject zone IDs in prefix notation
    if address.contains('%') {
        return false;
    }
    let Ok(ip) = Ipv6Addr::from_str(address) else {
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
    if s.is_empty() || s != s.trim() {
        return false;
    }

    if s.starts_with('[') {
        let Some(bracket_end) = s.rfind(']') else {
            return false;
        };
        let host = &s[1..bracket_end];
        let after_host = &s[bracket_end + 1..];
        if after_host.is_empty() {
            return !port_required && is_ipv6_any(host);
        }
        let Some(port) = after_host.strip_prefix(':') else {
            return false;
        };
        return is_ipv6_any(host) && is_port(port);
    }

    // Reject bare names in brackets
    if s.contains('[') || s.contains(']') {
        return false;
    }

    let Some(split_idx) = s.rfind(':') else {
        return !port_required && (is_hostname(s) || is_ipv4_strict(s));
    };
    let host = &s[..split_idx];
    let port = &s[split_idx + 1..];
    (is_hostname(host) || is_ipv4_strict(host)) && is_port(port)
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
    use pretty_assertions::assert_eq;
    use prost_protovalidate_types::{StringRules, string_rules::WellKnown};

    use super::{
        IpVersion, StringRuleEval, is_host_and_port, is_ip_prefix, is_tuuid, is_ulid, is_uri,
        is_uri_ref,
    };

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

    // ---- URI helper function unit tests ----

    use super::{
        hex_digit_value, is_valid_reg_name_utf8, is_valid_zone_id, pct_decode_bytes,
        strip_ipv6_zone_id,
    };

    #[test]
    fn hex_digit_value_maps_ascii_hex_chars() {
        assert_eq!(hex_digit_value(b'0'), Some(0));
        assert_eq!(hex_digit_value(b'9'), Some(9));
        assert_eq!(hex_digit_value(b'a'), Some(10));
        assert_eq!(hex_digit_value(b'f'), Some(15));
        assert_eq!(hex_digit_value(b'A'), Some(10));
        assert_eq!(hex_digit_value(b'F'), Some(15));
        assert_eq!(hex_digit_value(b'g'), None);
        assert_eq!(hex_digit_value(b'G'), None);
        assert_eq!(hex_digit_value(b' '), None);
        assert_eq!(hex_digit_value(b'%'), None);
    }

    #[test]
    fn pct_decode_bytes_decodes_valid_sequences() {
        assert_eq!(pct_decode_bytes("hello"), b"hello");
        assert_eq!(pct_decode_bytes("%20"), b" ");
        assert_eq!(pct_decode_bytes("a%20b"), b"a b");
        assert_eq!(pct_decode_bytes("%C3%96"), b"\xC3\x96"); // Ö in UTF-8
    }

    #[test]
    fn pct_decode_bytes_passes_through_malformed_sequences() {
        // Incomplete pct-encoding at end
        assert_eq!(pct_decode_bytes("%2"), b"%2");
        assert_eq!(pct_decode_bytes("%"), b"%");
        // Invalid hex digits
        assert_eq!(pct_decode_bytes("%GG"), b"%GG");
        // Empty string
        assert_eq!(pct_decode_bytes(""), b"");
    }

    #[test]
    fn is_valid_zone_id_accepts_unreserved_and_pct_encoded() {
        assert!(is_valid_zone_id("eth0"));
        assert!(is_valid_zone_id("en-0"));
        assert!(is_valid_zone_id("my.iface"));
        assert!(is_valid_zone_id("iface_1"));
        assert!(is_valid_zone_id("a~b"));
        assert!(is_valid_zone_id("%25")); // pct-encoded '%'
        assert!(is_valid_zone_id("eth%250"));
    }

    #[test]
    fn is_valid_zone_id_rejects_invalid_chars() {
        // Note: empty string vacuously passes char validation;
        // the empty check is in strip_ipv6_zone_id.
        assert!(!is_valid_zone_id("eth 0")); // space
        assert!(!is_valid_zone_id("eth[0")); // bracket
        assert!(!is_valid_zone_id("eth/0")); // slash
        assert!(!is_valid_zone_id("%G0")); // invalid hex
        assert!(!is_valid_zone_id("%2")); // incomplete pct-encoding
        assert!(!is_valid_zone_id("%")); // bare percent
    }

    #[test]
    fn is_valid_reg_name_utf8_accepts_valid_hosts() {
        assert!(is_valid_reg_name_utf8("example.com"));
        assert!(is_valid_reg_name_utf8("[::1]")); // IP-literal skipped
        assert!(is_valid_reg_name_utf8("foo%C3%96bar")); // valid UTF-8 pct-encoded
        assert!(is_valid_reg_name_utf8("")); // empty reg-name is valid
    }

    #[test]
    fn is_valid_reg_name_utf8_rejects_invalid_utf8() {
        // %C3 alone is an incomplete UTF-8 sequence, but followed by 'x' (not valid continuation)
        assert!(!is_valid_reg_name_utf8("foo%c3x%96"));
        // Lone high byte
        assert!(!is_valid_reg_name_utf8("%FF"));
    }

    #[test]
    fn strip_ipv6_zone_id_removes_valid_zone() {
        let input = "http://[fe80::1%25eth0]:8080/path";
        let result = strip_ipv6_zone_id(input);
        assert_eq!(result.as_deref(), Some("http://[fe80::1]:8080/path"));
    }

    #[test]
    fn strip_ipv6_zone_id_returns_none_when_no_zone() {
        assert!(strip_ipv6_zone_id("http://[::1]:80/path").is_none());
        assert!(strip_ipv6_zone_id("http://example.com").is_none());
        assert!(strip_ipv6_zone_id("no-brackets").is_none());
    }

    #[test]
    fn strip_ipv6_zone_id_rejects_empty_zone() {
        // %25 with nothing after it
        assert!(strip_ipv6_zone_id("http://[fe80::1%25]:80/").is_none());
    }

    #[test]
    fn strip_ipv6_zone_id_rejects_invalid_zone_chars() {
        // Space in zone ID
        assert!(strip_ipv6_zone_id("http://[fe80::1%25eth 0]:80/").is_none());
    }

    #[test]
    fn strip_ipv6_zone_id_rejects_invalid_zone_utf8() {
        // Zone ID with invalid UTF-8 pct-encoding
        assert!(strip_ipv6_zone_id("http://[fe80::1%25%FF]:80/").is_none());
    }

    #[test]
    fn uri_accepts_ipv6_with_valid_zone_id() {
        assert!(is_uri("http://[fe80::1%25eth0]:8080/path"));
        assert!(is_uri("http://[fe80::a%25en1]/"));
    }

    #[test]
    fn uri_rejects_ipv6_with_empty_zone_id() {
        assert!(!is_uri("http://[fe80::1%25]:8080/path"));
    }

    #[test]
    fn uri_rejects_invalid_reg_name_utf8() {
        assert!(!is_uri("https://foo%c3x%96/path"));
    }
}
