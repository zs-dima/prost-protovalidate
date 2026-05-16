use std::hint::black_box;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use prost::Message;
use prost_reflect::ReflectMessage;

use prost_protovalidate::Validator;
use prost_protovalidate::types::{BoolRules, StringRules};
use prost_protovalidate::validators;

/// Bench a `Fn(&str) -> bool` validator with byte-throughput reporting.
///
/// Reports MiB/s of input bytes — the meaningful comparable metric for
/// O(input length) format validators. The input is `black_box`ed so the
/// compiler cannot fold the call, and the result is `black_box`ed so it
/// cannot be eliminated as dead. `&'static str` keeps the contract simple
/// for the only callers we have (string literals).
fn bench_str(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    input: &'static str,
    f: impl Fn(&str) -> bool,
) {
    group.throughput(Throughput::Bytes(input.len() as u64));
    group.bench_function(name, |b| {
        b.iter(|| black_box(f(black_box(input))));
    });
}

// ---------------------------------------------------------------------------
// transcode_to_dynamic benchmarks
// ---------------------------------------------------------------------------

fn bench_transcode(c: &mut Criterion) {
    let mut group = c.benchmark_group("transcode_to_dynamic");

    // Small message: BoolRules (2 fields)
    let small = BoolRules {
        r#const: Some(true),
        ..BoolRules::default()
    };
    group.throughput(Throughput::Bytes(small.encoded_len() as u64));
    group.bench_function("small", |b| {
        b.iter(|| black_box(black_box(&small).transcode_to_dynamic()));
    });

    // Medium message: StringRules with several fields set
    let medium = StringRules {
        min_len: Some(1),
        max_len: Some(255),
        min_bytes: Some(1),
        max_bytes: Some(1024),
        prefix: Some("test_".to_string()),
        suffix: Some("_end".to_string()),
        contains: Some("required".to_string()),
        not_contains: Some("forbidden".to_string()),
        r#in: vec!["allowed_a".to_string(), "allowed_b".to_string()],
        not_in: vec!["blocked".to_string()],
        ..StringRules::default()
    };
    group.throughput(Throughput::Bytes(medium.encoded_len() as u64));
    group.bench_function("medium", |b| {
        b.iter(|| black_box(black_box(&medium).transcode_to_dynamic()));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// format_validators benchmarks — every public validator, valid + invalid.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // Exhaustive matrix over every public validator.
fn bench_format_validators(c: &mut Criterion) {
    let mut group = c.benchmark_group("format_validators");

    // is_email
    bench_str(
        &mut group,
        "email_valid",
        "user@example.com",
        validators::is_email,
    );
    bench_str(
        &mut group,
        "email_invalid",
        "not-an-email",
        validators::is_email,
    );

    // is_hostname
    bench_str(
        &mut group,
        "hostname_valid",
        "sub.example.com",
        validators::is_hostname,
    );
    bench_str(
        &mut group,
        "hostname_invalid",
        "-bad.hostname",
        validators::is_hostname,
    );

    // is_ip (accepts both v4 and v6)
    bench_str(&mut group, "ip_valid_v4", "192.168.1.1", validators::is_ip);
    bench_str(&mut group, "ip_valid_v6", "2001:db8::1", validators::is_ip);
    bench_str(
        &mut group,
        "ip_invalid",
        "999.999.999.999",
        validators::is_ip,
    );

    // is_ipv4
    bench_str(&mut group, "ipv4_valid", "10.0.0.1", validators::is_ipv4);
    bench_str(&mut group, "ipv4_invalid", "::1", validators::is_ipv4);

    // is_ipv6
    bench_str(&mut group, "ipv6_valid", "::1", validators::is_ipv6);
    bench_str(&mut group, "ipv6_invalid", "10.0.0.1", validators::is_ipv6);

    // is_uri
    bench_str(
        &mut group,
        "uri_valid",
        "https://example.com/path?q=1",
        validators::is_uri,
    );
    bench_str(&mut group, "uri_invalid", "not a uri", validators::is_uri);

    // is_uri_ref
    bench_str(
        &mut group,
        "uri_ref_valid",
        "/path?q=1",
        validators::is_uri_ref,
    );
    bench_str(
        &mut group,
        "uri_ref_invalid",
        "not\\a\\uri",
        validators::is_uri_ref,
    );

    // is_uuid
    bench_str(
        &mut group,
        "uuid_valid",
        "550e8400-e29b-41d4-a716-446655440000",
        validators::is_uuid,
    );
    bench_str(
        &mut group,
        "uuid_invalid",
        "550e8400e29b41d4a716446655440000",
        validators::is_uuid,
    );

    // is_tuuid (UUID without dashes)
    bench_str(
        &mut group,
        "tuuid_valid",
        "550e8400e29b41d4a716446655440000",
        validators::is_tuuid,
    );
    bench_str(
        &mut group,
        "tuuid_invalid",
        "550e8400-e29b-41d4-a716-446655440000",
        validators::is_tuuid,
    );

    // is_ulid (Crockford base32, exactly 26 chars, no I/L/O/U)
    bench_str(
        &mut group,
        "ulid_valid",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        validators::is_ulid,
    );
    bench_str(
        &mut group,
        "ulid_invalid",
        "01ARZ3NDEKTSV4RRFFQ69G5FAU",
        validators::is_ulid,
    );

    // is_host_and_port (port required)
    bench_str(&mut group, "host_and_port_valid", "example.com:8080", |s| {
        validators::is_host_and_port(s, true)
    });
    bench_str(&mut group, "host_and_port_invalid", "example.com", |s| {
        validators::is_host_and_port(s, true)
    });

    // is_ip_prefix (strict — host bits must be zero)
    bench_str(&mut group, "ip_prefix_valid", "192.168.0.0/16", |s| {
        validators::is_ip_prefix(s, true)
    });
    bench_str(&mut group, "ip_prefix_invalid", "192.168.0.1/16", |s| {
        validators::is_ip_prefix(s, true)
    });

    // is_ipv4_prefix (strict)
    bench_str(&mut group, "ipv4_prefix_valid", "10.0.0.0/8", |s| {
        validators::is_ipv4_prefix(s, true)
    });
    bench_str(&mut group, "ipv4_prefix_invalid", "10.0.0.1/8", |s| {
        validators::is_ipv4_prefix(s, true)
    });

    // is_ipv6_prefix (strict)
    bench_str(&mut group, "ipv6_prefix_valid", "2001:db8::/32", |s| {
        validators::is_ipv6_prefix(s, true)
    });
    bench_str(&mut group, "ipv6_prefix_invalid", "2001:db8::1/32", |s| {
        validators::is_ipv6_prefix(s, true)
    });

    // is_http_header_name (strict — RFC 7230 token chars only)
    bench_str(&mut group, "http_header_name_valid", "Content-Type", |s| {
        validators::is_http_header_name(s, true)
    });
    bench_str(&mut group, "http_header_name_invalid", "Bad Header", |s| {
        validators::is_http_header_name(s, true)
    });

    // is_http_header_value (strict — rejects CRLF / control chars)
    bench_str(
        &mut group,
        "http_header_value_valid",
        "text/html; charset=utf-8",
        |s| validators::is_http_header_value(s, true),
    );
    bench_str(
        &mut group,
        "http_header_value_invalid",
        "value\r\nInjected",
        |s| validators::is_http_header_value(s, true),
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// validate_end_to_end benchmarks
// ---------------------------------------------------------------------------

fn bench_validate_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_end_to_end");
    group.throughput(Throughput::Elements(1));

    let validator = Validator::new();
    let bool_msg = BoolRules {
        r#const: Some(true),
        ..BoolRules::default()
    };
    let string_msg = StringRules {
        min_len: Some(1),
        max_len: Some(255),
        ..StringRules::default()
    };

    // Warm the cache
    let _ = validator.validate(&bool_msg);
    let _ = validator.validate(&string_msg);

    group.bench_function("cached_small", |b| {
        b.iter(|| black_box(validator.validate(black_box(&bool_msg))));
    });

    group.bench_function("cached_medium", |b| {
        b.iter(|| black_box(validator.validate(black_box(&string_msg))));
    });

    group.bench_function("cold", |b| {
        b.iter(|| {
            let fresh = Validator::new();
            black_box(fresh.validate(black_box(&bool_msg)))
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// validate convenience function benchmark
// ---------------------------------------------------------------------------

fn bench_validate_convenience(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_convenience");
    group.throughput(Throughput::Elements(1));

    let msg = BoolRules {
        r#const: Some(true),
        ..BoolRules::default()
    };
    group.bench_function("bool_rules", |b| {
        b.iter(|| black_box(prost_protovalidate::validate(black_box(&msg))));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_transcode,
    bench_format_validators,
    bench_validate_end_to_end,
    bench_validate_convenience,
);
criterion_main!(benches);
