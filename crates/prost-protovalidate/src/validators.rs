//! Format validators for well-known string constraints.
//!
//! These validators implement the format checking logic used by `buf.validate`
//! well-known string rules. They are exposed publicly so that generated
//! validation code (from `prost-protovalidate-build`) can call them directly
//! without reimplementing the validation logic.

use crate::validator::rules::string as internal;

/// Returns `true` if `s` is a valid email address.
///
/// Checks for a non-empty local part and domain separated by `@`, with the
/// domain being a valid hostname or IP address literal.
#[inline]
#[must_use]
pub fn is_email(s: &str) -> bool {
    internal::is_email(s)
}

/// Returns `true` if `s` is a valid hostname per RFC 1123.
#[inline]
#[must_use]
pub fn is_hostname(s: &str) -> bool {
    internal::is_hostname(s)
}

/// Returns `true` if `s` is a valid IPv4 or IPv6 address.
#[inline]
#[must_use]
pub fn is_ip(s: &str) -> bool {
    internal::is_ip(s)
}

/// Returns `true` if `s` is a valid IPv4 address.
#[inline]
#[must_use]
pub fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Returns `true` if `s` is a valid IPv6 address (including zone IDs).
#[inline]
#[must_use]
pub fn is_ipv6(s: &str) -> bool {
    internal::is_ipv6(s)
}

/// Returns `true` if `s` is a valid absolute URI per RFC 3986.
#[inline]
#[must_use]
pub fn is_uri(s: &str) -> bool {
    internal::is_uri(s)
}

/// Returns `true` if `s` is a valid URI reference (absolute or relative) per RFC 3986.
#[inline]
#[must_use]
pub fn is_uri_ref(s: &str) -> bool {
    internal::is_uri_ref(s)
}

/// Returns `true` if `s` is a valid UUID in `8-4-4-4-12` hex format.
#[inline]
#[must_use]
pub fn is_uuid(s: &str) -> bool {
    internal::is_uuid(s)
}

/// Returns `true` if `s` is a valid trimmed UUID (32 hex digits, no hyphens).
#[inline]
#[must_use]
pub fn is_tuuid(s: &str) -> bool {
    internal::is_tuuid(s)
}

/// Returns `true` if `s` is a valid ULID (26 Crockford base32 characters).
#[inline]
#[must_use]
pub fn is_ulid(s: &str) -> bool {
    internal::is_ulid(s)
}

/// Returns `true` if `s` is a valid IPv4 or IPv6 CIDR prefix (e.g. `192.168.0.0/16`).
///
/// When `strict` is `true`, host bits beyond the prefix length must be zero.
#[inline]
#[must_use]
pub fn is_ip_prefix(s: &str, strict: bool) -> bool {
    internal::is_ipv4_prefix(s, strict) || internal::is_ipv6_prefix(s, strict)
}

/// Returns `true` if `s` is a valid IPv4 CIDR prefix (e.g. `10.0.0.0/8`).
///
/// When `strict` is `true`, host bits beyond the prefix length must be zero.
#[inline]
#[must_use]
pub fn is_ipv4_prefix(s: &str, strict: bool) -> bool {
    internal::is_ipv4_prefix(s, strict)
}

/// Returns `true` if `s` is a valid IPv6 CIDR prefix (e.g. `2001:db8::/32`).
///
/// When `strict` is `true`, host bits beyond the prefix length must be zero.
#[inline]
#[must_use]
pub fn is_ipv6_prefix(s: &str, strict: bool) -> bool {
    internal::is_ipv6_prefix(s, strict)
}

/// Returns `true` if `s` is a valid `host:port` pair.
///
/// When `port_required` is `true`, the port component must be present.
#[inline]
#[must_use]
pub fn is_host_and_port(s: &str, port_required: bool) -> bool {
    internal::is_host_and_port(s, port_required)
}

/// Returns `true` if `s` is a valid HTTP header name.
///
/// When `strict` is `true`, validates against RFC 7230 token characters.
/// When `strict` is `false`, only rejects NUL, CR, and LF.
#[inline]
#[must_use]
pub fn is_http_header_name(s: &str, strict: bool) -> bool {
    if strict {
        internal::is_valid_http_header_name_strict(s)
    } else {
        internal::is_valid_http_header_name_loose(s)
    }
}

/// Returns `true` if `s` is a valid HTTP header value.
///
/// When `strict` is `true`, rejects NUL, control chars (except HT), and DEL.
/// When `strict` is `false`, only rejects NUL, CR, and LF.
#[inline]
#[must_use]
pub fn is_http_header_value(s: &str, strict: bool) -> bool {
    if strict {
        internal::is_valid_http_header_value_strict(s)
    } else {
        internal::is_valid_http_header_value_loose(s)
    }
}

/// Returns `true` if `path` is covered by `candidate` under `FieldMask`
/// path-coverage semantics — either `path` equals `candidate`, or
/// `candidate` is a prefix of `path` at a path-segment boundary
/// (i.e. `path == "{candidate}.{rest}"`).
///
/// Allocation-free; used by both the runtime evaluator and generated
/// `field_mask.in` / `field_mask.not_in` checks.
#[inline]
#[must_use]
pub fn fieldmask_covers(candidate: &str, path: &str) -> bool {
    path == candidate
        || (path.len() > candidate.len()
            && path.starts_with(candidate)
            && path.as_bytes()[candidate.len()] == b'.')
}

#[cfg(test)]
mod tests {
    use super::fieldmask_covers;

    #[test]
    fn fieldmask_covers_exact() {
        assert!(fieldmask_covers("user.email", "user.email"));
    }

    #[test]
    fn fieldmask_covers_subpath() {
        assert!(fieldmask_covers("user", "user.email"));
        assert!(fieldmask_covers("user.profile", "user.profile.name"));
    }

    #[test]
    fn fieldmask_covers_rejects_partial_segment() {
        // "user" does not cover "username" — the boundary character is `e`, not `.`.
        assert!(!fieldmask_covers("user", "username"));
        // Likewise for deeper segments.
        assert!(!fieldmask_covers("user.email", "user.emailaddress"));
    }

    #[test]
    fn fieldmask_covers_rejects_shorter_path() {
        // candidate longer than path can never cover it.
        assert!(!fieldmask_covers("user.email", "user"));
    }

    #[test]
    fn fieldmask_covers_empty_strings() {
        // Empty candidate covers any path that starts with `.` (degenerate but
        // consistent with the algebra); equal-empty covers empty.
        assert!(fieldmask_covers("", ""));
        assert!(!fieldmask_covers("user", ""));
    }
}
