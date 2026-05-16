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
  test corpus, and the hardcoded violation messages in
  `crates/prost-protovalidate/src/validator/rules/` and
  `crates/prost-protovalidate-build/src/rules/` must match the corpus.
