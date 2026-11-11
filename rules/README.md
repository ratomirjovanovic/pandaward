# Bundled rule packs

## Semgrep (`semgrep/`)

PandaWard ships a reviewed set of Semgrep rules for JavaScript/TypeScript, Python, Go and Java. They are embedded in the `pandaward` binary and run automatically whenever `semgrep` or `opengrep` is installed (`scan.semgrep_engine` picks one; Opengrep also follows taint through functions in the same file). Most injection rules are taint rules: they report a sink only when request data, or in Python the text a language model returned, reaches it, and they stop at recognized sanitizers and guards. They are local files, so they work with `scan.allow_tool_network: false`. Rules set in `scan.semgrep_config` or `.pandaward/semgrep/` run in addition to them. Results in test and fixture files are skipped and counted in the adapter line, as in the built-in checks; set `scan.semgrep_include_tests: true` to keep them for rules other than the bundled ones. Registry rules that rate themselves `confidence: LOW` are kept but weighted down: an `audit` rule is listed as info and does not decide its control, and a `vuln` rule counts as low at most. Bundled rules and registry rules rated MEDIUM or HIGH keep their severity.

| File | Covers |
|---|---|
| `javascript.yaml` | taint: SQL (including Supabase `.or()` filters), SSRF, path traversal (Node, Express and Koa request fields, archive entry names), reflected XSS, open redirect; patterns: eval and `Function`, shell exec under every import form and `shelljs`/`execa`, raw HTML sinks, jQuery HTML insertion and plugin options, JWT `none`, prototype pollution through recursive merges and path setters, incomplete sanitization and URL scheme checks, errors sent as HTML |
| `python.yaml` | taint (Flask and Django request data, model output): eval, OS command, SQL, path traversal, LDAP, XPath, XSS, open redirect, trust boundary, XXE, SSRF; patterns: pickle/yaml.load, `verify=False`, template injection, weak hashes, the `random` module, insecure cookies |
| `go.yaml` | SQL via Sprintf, `sh -c`, `InsecureSkipVerify`, math/rand for secrets; taint: SSRF, path traversal |
| `java.yaml` | taint (servlet request data, types matched fully qualified or imported): SQL, OS command, path traversal, LDAP, XPath, XSS, trust boundary, SSRF; patterns: native deserialization, weak ciphers and hashes, `java.util.Random`, insecure cookies |

How these rules score on the OWASP Benchmark for Java and Python and on the OpenSSF CVE Benchmark is in [`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md) and on [pandaward.dev/benchmarks](https://pandaward.dev/benchmarks/).

### Mapping to controls

Every rule names a catalog control in `metadata.pandaward-control`. A finding raises that control's status (PASS to SUSPECTED, SUSPECTED to FAIL) but never lowers it, so a clean Semgrep run cannot hide a FAIL from the built-in checks. Rules without a more specific control (SSRF, path traversal, template injection) count for D-006, as do rules from your own configuration. All Semgrep results are recorded as hypotheses until a human confirms them.

A rule that decides the same weakness as a built-in heuristic lists the heuristic in `metadata.pandaward-supersedes` (for example `[code.sql-concat, code.sql-template, code.sql-unsafe-raw]`). When Semgrep or Opengrep completed, the replaced heuristic's signals are dropped for that language and the rule's result counts instead; without a completed run nothing changes.

### Writing or changing a rule

- Give it an id starting with `pandaward-`, a `pandaward-control`, a `cwe` and a clear message.
- Add at least one `ruleid:` (must match) and one `ok:` (must not match) case to the fixture file with the same base name (`javascript.js`, `python.py`, `go.go`, `java.java`).
- Run `semgrep --test rules/semgrep` and `go test ./rules`. The Go test checks ids, mappings and fixtures without semgrep; it runs `semgrep --test` and `opengrep --test` too when they are on PATH. CI runs both, and the `benchmarks` workflow fails when a change lowers an OWASP or CVE benchmark score.

The Go fixture has a `//go:build ignore` tag so it is not part of the build.

### License

These rules were written for PandaWard and are licensed under the project license (AGPL-3.0-only, see `LICENSE`). They are not copied or derived from the Semgrep Registry, whose rules are under the separate Semgrep Rules License. Semgrep and Opengrep are not bundled; install one yourself if you want these rules to run.
