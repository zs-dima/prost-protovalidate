# prost-protovalidate-types schema sync

`buf.validate` schema is synced from a pinned upstream `protovalidate` GitHub ref.

Pinned source URL template:

`https://raw.githubusercontent.com/bufbuild/protovalidate/$PROTOVALIDATE_SCHEMA_REF/proto/protovalidate/buf/validate/validate.proto`

The default `PROTOVALIDATE_SCHEMA_REF` is defined in the repository root
`Makefile` and should stay aligned with `PROTOVALIDATE_TOOLS_VERSION`.

Local destination:

`crates/prost-protovalidate-types/proto/buf/validate/validate.proto`

## Sync commands

From repository root (Linux/macOS):

```bash
SCHEMA_REF="$(awk '/^PROTOVALIDATE_SCHEMA_REF[[:space:]]*\\?=/{print $3}' Makefile)"
curl -fsSL \
  "https://raw.githubusercontent.com/bufbuild/protovalidate/${SCHEMA_REF}/proto/protovalidate/buf/validate/validate.proto" \
  -o crates/prost-protovalidate-types/proto/buf/validate/validate.proto
```

From repository root (PowerShell):

```powershell
$schemaRef =
  (Select-String -Path Makefile -Pattern '^PROTOVALIDATE_SCHEMA_REF\s*\?=\s*(\S+)$')
  .Matches[0].Groups[1].Value
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/bufbuild/protovalidate/$schemaRef/proto/protovalidate/buf/validate/validate.proto" `
  -OutFile "crates/prost-protovalidate-types/proto/buf/validate/validate.proto"
```

## Policy

- Do not edit `proto/buf/validate/validate.proto` manually.
- Keep `validate.proto` aligned to `PROTOVALIDATE_SCHEMA_REF`.
- Bump `PROTOVALIDATE_SCHEMA_REF` and `PROTOVALIDATE_TOOLS_VERSION` together unless a deliberate split is required.
