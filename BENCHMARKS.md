# Benchmark Baseline

Command used:

```bash
cargo bench -p prost-protovalidate --all-features
```

Date: 2026-05-16

Every bench group carries a `criterion::Throughput` annotation (added with the
criterion 0.8 upgrade). `transcode_to_dynamic` reports MiB/s of encoded wire
bytes (`prost::Message::encoded_len`). `format_validators` reports MiB/s of
input string bytes. `validate_end_to_end` and `validate_convenience` report
elements (messages) per second.

## Message-level benchmarks

| Benchmark                            | Time range          | Throughput range          |
| ------------------------------------ | ------------------- | ------------------------- |
| `transcode_to_dynamic/small`         | 214-219 ns          | 8.72-8.90 MiB/s           |
| `transcode_to_dynamic/medium`        | 1.81-1.89 µs        | 38.31-39.95 MiB/s         |
| `validate_end_to_end/cached_small`   | 367-370 ns          | 2.70-2.73 Melem/s         |
| `validate_end_to_end/cached_medium`  | 444-464 ns          | 2.15-2.25 Melem/s         |
| `validate_end_to_end/cold`           | 6.38-6.70 ms        | 149-157 elem/s            |
| `validate_convenience/bool_rules`    | 374-383 ns          | 2.61-2.67 Melem/s         |

## Format validators — valid + invalid input matrix

Each public validator in [`prost_protovalidate::validators`](crates/prost-protovalidate/src/validators.rs)
is benched on both a valid and an invalid input. Throughput is reported in
MiB/s of the input string.

| Benchmark                                       | Time range        | Throughput range  |
| ----------------------------------------------- | ----------------- | ----------------- |
| `format_validators/email_valid`                 | 147-150 ns        | 102-104 MiB/s     |
| `format_validators/email_invalid`               | 42-44 ns          | 260-275 MiB/s     |
| `format_validators/hostname_valid`              | 118-119 ns        | 120-121 MiB/s     |
| `format_validators/hostname_invalid`            | 79-82 ns          | 152-157 MiB/s     |
| `format_validators/ip_valid_v4`                 | 31-32 ns          | 327-330 MiB/s     |
| `format_validators/ip_valid_v6`                 | 103 ns            | 101-102 MiB/s     |
| `format_validators/ip_invalid`                  | 68-70 ns          | 203-209 MiB/s     |
| `format_validators/ipv4_valid`                  | 15 ns             | 508-513 MiB/s     |
| `format_validators/ipv4_invalid`                | 5 ns              | 539-562 MiB/s     |
| `format_validators/ipv6_valid`                  | 44 ns             | 65.4-65.6 MiB/s   |
| `format_validators/ipv6_invalid`                | 35 ns             | 215-218 MiB/s     |
| `format_validators/uri_valid`                   | 211-215 ns        | 124-126 MiB/s     |
| `format_validators/uri_invalid`                 | 16 ns             | 545-547 MiB/s     |
| `format_validators/uri_ref_valid`               | 65-68 ns          | 127-133 MiB/s     |
| `format_validators/uri_ref_invalid`             | 18-19 ns          | 450-466 MiB/s     |
| `format_validators/uuid_valid`                  | 200-206 ns        | 166-172 MiB/s     |
| `format_validators/uuid_invalid`                | 1.7-1.8 ns        | 16.80-17.19 GiB/s |
| `format_validators/tuuid_valid`                 | 26 ns             | 1.14 GiB/s        |
| `format_validators/tuuid_invalid`               | 1.4-1.5 ns        | 22.68-23.59 GiB/s |
| `format_validators/ulid_valid`                  | 54-57 ns          | 437-454 MiB/s     |
| `format_validators/ulid_invalid`                | 48 ns             | 514-521 MiB/s     |
| `format_validators/host_and_port_valid`         | 152-156 ns        | 97-100 MiB/s      |
| `format_validators/host_and_port_invalid`       | 30-31 ns          | 334-352 MiB/s     |
| `format_validators/ip_prefix_valid`             | 45 ns             | 296 MiB/s         |
| `format_validators/ip_prefix_invalid`           | 98 ns             | 136 MiB/s         |
| `format_validators/ipv4_prefix_valid`           | 40 ns             | 236-237 MiB/s     |
| `format_validators/ipv4_prefix_invalid`         | 38-39 ns          | 244-249 MiB/s     |
| `format_validators/ipv6_prefix_valid`           | 89-90 ns          | 138-139 MiB/s     |
| `format_validators/ipv6_prefix_invalid`         | 101-106 ns        | 126-133 MiB/s     |
| `format_validators/http_header_name_valid`      | 19-20 ns          | 579-595 MiB/s     |
| `format_validators/http_header_name_invalid`    | 6.4-6.6 ns        | 1.42-1.45 GiB/s   |
| `format_validators/http_header_value_valid`     | 30-31 ns          | 735-772 MiB/s     |
| `format_validators/http_header_value_invalid`   | 8.3 ns            | 1.68 GiB/s        |

## Notes

- 38 benchmarks total: 2 transcode, 32 format validators (16 × {valid, invalid}),
  3 end-to-end, 1 convenience.
- Numbers are hardware/OS/compiler dependent. Use this file as a regression
  baseline, not an absolute performance target.
- The criterion 0.8 upgrade auto-removed prior result files on first run; the
  comparison percentages criterion prints alongside fresh runs are meaningless
  until a stable baseline is re-established on each machine.
- Invalid inputs typically benchmark several × faster than valid inputs because
  validators short-circuit on the first disqualifying character. The
  `uuid_invalid` / `tuuid_invalid` / `http_header_name_invalid` /
  `http_header_value_invalid` cases at GiB/s reflect fast rejection on the
  first wrong character.
- `bench_validate_convenience` was renamed from a top-level
  `validate_convenience` benchmark to `validate_convenience/bool_rules` (now
  grouped, with `Throughput::Elements(1)`) for consistency with the other
  benches.
- The bench file uses `default-features = false` on the `criterion` dep, so no
  plotting / HTML reports are generated locally — only the terminal-text
  output above. Enable `--features html_reports` ad-hoc if needed.
