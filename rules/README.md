# Bundled rule packs

## Semgrep (`semgrep/`)

PandaWard ships a small, reviewed set of Semgrep rules for JavaScript/TypeScript, Python, Go and Java. They are embedded in the `pandaward` binary and run automatically whenever `semgrep` is installed. They are local files, so they work with `scan.allow_tool_network: false`. Rules set in `scan.semgrep_config` or `.pandaward/semgrep/` run in addition to them. Results in test and fixture files are skipped and counted in the adapter line, as in the built-in checks; set `scan.semgrep_include_tests: true` to keep them for rules other than the bundled ones.

| File | Covers |
|---|---|
| `javascript.yaml` | eval, shell exec, SQL string building, raw HTML sinks, JWT `none`, SSRF, path traversal |
| `python.yaml` | eval/exec, shell=True, SQL formatting, pickle/yaml.load, `verify=False`, SSRF, path traversal, template injection |
| `go.yaml` | SQL via Sprintf, `sh -c`, `InsecureSkipVerify`, math/rand for secrets, SSRF, path traversal |
| `java.yaml` | SQL concatenation, Runtime.exec, native deserialization, weak ciphers, path traversal, SSRF |

### Mapping to controls

Every rule names a catalog control in `metadata.pandaward-control`. A finding raises that control's status (PASS to SUSPECTED, SUSPECTED to FAIL) but never lowers it, so a clean Semgrep run cannot hide a FAIL from the built-in checks. Rules without a more specific control (SSRF, path traversal, template injection) count for D-006, as do rules from your own configuration. All Semgrep results are recorded as hypotheses until a human confirms them.

### Writing or changing a rule

- Give it an id starting with `pandaward-`, a `pandaward-control`, a `cwe` and a clear message.
- Add at least one `ruleid:` (must match) and one `ok:` (must not match) case to the fixture file with the same base name (`javascript.js`, `python.py`, `go.go`, `java.java`).
- Run `semgrep --test rules/semgrep` and `go test ./rules`. The Go test checks ids, mappings and fixtures without semgrep; it runs `semgrep --test` too when semgrep is on PATH.

The Go fixture has a `//go:build ignore` tag so it is not part of the build.

### License

These rules were written for PandaWard and are licensed under the project license (AGPL-3.0-only, see `LICENSE`). They are not copied or derived from the Semgrep Registry, whose rules are under the separate Semgrep Rules License. Semgrep itself is not bundled; install it yourself if you want these rules to run.
