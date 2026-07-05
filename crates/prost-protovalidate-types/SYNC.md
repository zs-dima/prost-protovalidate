# prost-protovalidate-types schema sync

`proto/buf/validate/validate.proto` is vendored from the upstream
`bufbuild/protovalidate` GitHub repo at the ref `PROTOVALIDATE_SCHEMA_REF`
in the root `Makefile` (currently `v1.1.1`).

## Sync

From the repo root:

```
make sync-schema
```

To preview a different ref without changing the `Makefile`:

```
make sync-schema PROTOVALIDATE_SCHEMA_REF=v1.2.0
```

CI runs `make sync-schema-check` on every pull request and fails if the
committed file does not match the pinned ref.

## Policy

- Do not edit `proto/buf/validate/validate.proto` manually.
- Bump `PROTOVALIDATE_SCHEMA_REF` and `PROTOVALIDATE_TOOLS_VERSION` in the
  root `Makefile` together unless a deliberate split is required. The
  conformance harness binary (`PROTOVALIDATE_TOOLS_VERSION`) carries the
  test corpus.
- Canonical violation rule ids and message text live in one place:
  `src/rules_meta.rs` in this crate. Both the runtime evaluator and the
  build-time code generator consume it, so a corpus bump that changes
  message text is applied there once. The parity suite in
  `crates/prost-protovalidate-tests` (including the descriptor-driven
  sweep) then re-proves that both engines emit identical violations.
