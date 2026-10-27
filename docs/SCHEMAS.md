# Schemas and compatibility

These are the formats other programs and people depend on. Their shape is pinned in `internal/schema/testdata/schemas.golden`, and `go test ./internal/schema` fails on any change that was not made on purpose.

| Schema | Where | Version field | Current |
|---|---|---|---|
| Report JSON | `pensec report --format json`, `report.json` in bundles | `schema_version` | 1 |
| Evidence record | `.pensec/private/evidence/*.json`, `evidence/` in bundles | `schema_version` | 1 |
| Bundle manifest | `manifest.json` in `pensec export` bundles | `schema_version` | 1 |
| Coverage CSV | `pensec report --format csv` header row | shares the report version | 1 |
| MCP tools | names, input schemas and annotations of `pensec mcp` tools | shares the report version | 1 |
| Project config | `.pensec/config.yaml` | `schema_version` | 1 |
| Scope manifest | `.pensec/scope.yaml` | `schema_version` | 1 |
| Ledger | `.pensec/private/state.db` | `meta.schema_version` (number of migrations) | 2 |

SARIF output follows SARIF 2.1.0 and is not versioned separately.

## Rules

- **Adding** an optional field, a new MCP tool or a new CSV column at the end is compatible. The version stays the same; the golden file is updated in the same pull request so the change is reviewed.
- **Removing, renaming or retyping** a field, removing an MCP tool or changing a tool's inputs is breaking. It needs a version bump, a note in the release, and readers that reject or migrate the old version. The schema test refuses such a change without the bump.
- **Ledger**: published migrations are never edited. A schema change adds a new migration at the end; opening a ledger with a newer schema than the binary knows fails instead of guessing.
- **Config and scope manifest**: unknown fields are rejected (strict YAML decoding), and an unknown `schema_version` is refused, so a newer file is never half-understood by an older binary.

## Changing a schema

1. Make the change and bump the version if it is breaking.
2. Run `go test ./internal/schema -update`, review the diff of `schemas.golden`, and commit it with the change.
3. Describe the change in the pull request and the release notes.
