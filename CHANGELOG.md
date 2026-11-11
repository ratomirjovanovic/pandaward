# Changelog

All notable changes to PandaWard. Versions follow the release tags; each release page has binaries, checksums, the SBOM and build provenance. PandaWard was called PenSec before 0.2.0.

## [Unreleased]

### Added
- Control D-007 finds regular expressions with catastrophic backtracking (ReDoS) in JavaScript and TypeScript: regex literals and `RegExp(...)` strings are analysed as automata. Exponential patterns are suspected findings; polynomial ones are listed as info, since they matter only for long input from outside. On the OpenSSF CVE Benchmark the built-in rules now detect 21 of 24 ReDoS CVEs, up from none, and recognize 17 fixes (#332).
- Opengrep can run the Semgrep rules: `scan.semgrep_engine` picks `semgrep` or `opengrep`; without it Semgrep is used and Opengrep is the fallback. Opengrep runs with intra-file taint. On Windows the tool home gets its own `LOCALAPPDATA`, without which Opengrep crashes (#314).
- `tools/owaspbench --engine builtin,semgrep,opengrep` measures the bundled Semgrep rules on both engines next to the built-in rules, with engine versions and the rule set hash; `docs/BENCHMARKS.md` has the new baseline (#314).
- `tools/owaspbench --suite python` measures PandaWard on OWASP BenchmarkPython (1,230 test cases, 14 categories), fetched at a pinned commit at run time; `docs/BENCHMARKS.md` has the first Python baseline (#315).
- `tools/cvebench` measures PandaWard on the OpenSSF CVE Benchmark: real CVEs in JavaScript and TypeScript projects, scored on the commit before and after each fix (detected, fix recognized, still flagged after the fix); `docs/BENCHMARKS.md` has the first JavaScript baseline (#316).
- Benchmark quality gates: the `benchmarks` workflow measures the OWASP Java and Python suites on every engine for pull requests that touch rules or engines, and the CVE benchmark weekly, and fails when a score drops below `tools/benchgate/baseline.json`. Rule fixtures run on Opengrep as well as Semgrep (#317).
- A benchmark page on pandaward.dev shows the latest results and the history per release, with links to the raw results and the commands to reproduce them. Each release gets `owasp-java.json`, `owasp-python.json` and `cve.json` attached (#318).
- pandaward.dev/benchmarks also shows the latest successful weekly or manual benchmark run of main, and is rebuilt when such a run finishes, so rule improvements appear before the next release (#335).
- `tools/cvebench` scores PandaWard as a whole, `pandaward`: the built-in rules plus Semgrep, as a scan runs them. pandaward.dev shows it first in the CVE table and the history (#341).

### Changed
- JavaScript rules recognize fixes: path traversal is not reported after a check that compares the path with its root, tests it for `..` or calls `isPathInside` and stops the request, nor through `path.join('/', ...)` or a regular expression that removes `..`; a shell command is not reported after a regular expression test that stops on bad input; `innerHTML` is not reported for values passed through `DOMPurify.sanitize` or an escape function. On the OpenSSF CVE Benchmark Semgrep and Opengrep recognize 39 fixes instead of 27 and are still flagged after the fix in 18 CVEs instead of 33; three CVEs whose vulnerable commit already had a bypassable check (CVE-2018-3712, CVE-2018-3713, CVE-2018-3718) are no longer detected, and the baseline is lowered by those three (#345).
- JavaScript rules know more call shapes: `Function(...)` without `new`, `exec` wrapped by `util.promisify`, `execa.shell` and `execa.command`, and the new `pandaward-js-error-to-html` reports an error sent as the response body, which Express sends as HTML. On the OpenSSF CVE Benchmark this adds 6 detected CVEs and 1 recognized fix for Semgrep and Opengrep, with no CVE lost (#346).
- JavaScript rules for incomplete escaping and redirects: `pandaward-js-incomplete-sanitization` reports `replace()` calls that escape only the first match or remove a markup or traversal sequence in one pass, `pandaward-js-incomplete-url-scheme-check` reports `javascript:` checks that let `data:` through, and `pandaward-js-open-redirect` follows request data to redirects and `Location` headers. On the OpenSSF CVE Benchmark this adds 9 detected CVEs and 5 recognized fixes for Semgrep and Opengrep, with no CVE lost (#344).
- JavaScript rules for client-side XSS through jQuery: `pandaward-js-jquery-html` reports non-constant HTML passed to `.html()`, markup built by concatenation passed to `$()`, `.append()` and similar, `execCommand('insertHTML')` and `createElement` with concatenation; `pandaward-js-jquery-plugin-option` reports plugin options passed to `$()` or to a jQuery insertion method, as in the Bootstrap tooltip, collapse and affix CVEs. On the OpenSSF CVE Benchmark the Semgrep and Opengrep rules detect 69 CVEs instead of 60 and recognize 32 fixes instead of 27, with no CVE lost (#334).
- The CVE benchmark baseline is raised to the measurement of main after #330 and #332: built-in rules 45 CVEs detected and 28 fixes recognized, Semgrep and Opengrep 60 and 27, up from 23 and 10, and 13 and 6 (#339).
- `tools/cvebench` progress lines show how many CVEs are done, the elapsed time and an estimate of the time left, so a CI run can be followed in its live log (#337).
- JavaScript rules: `pandaward-js-prototype-pollution` reports recursive merges that write `target[key]` without a `__proto__` or own-property check; path traversal follows `req.url`, `req.path`, headers and cookies of Node, Express and Koa requests and archive entry names to `fs`, `send` and `fstream` sinks; the shell rule finds `child_process` exec under every import form and `shelljs`; `pandaward-js-reflected-xss` follows request data to `res.send`, `res.write` and `res.end`. On the OpenSSF CVE Benchmark the bundled rules detect several times more CVEs, with no CVE lost (#330).
- With Semgrep or Opengrep installed, Java and Python files no longer get findings from the built-in SQL, shell, eval, deserialization, weak hash and weak random heuristics: a bundled rule that decides the same weakness lists them in `pandaward-supersedes`, and its result counts instead. Controls say how many signals were replaced, and an open finding only a replaced heuristic raised is closed with a note. Without a completed Semgrep or Opengrep run nothing changes. On the OWASP Benchmark the merged Java SQL score goes from 0.027 to 0.282 and the Python command injection score from -0.154 to +0.626 (#328).
- Python rules follow Flask and Django request data, and the text a language model returns, to its sink: eval, OS command, SQL, file path, LDAP, XPath, XSS, open redirect, session and XXE are taint rules, with propagators through list, dict and config objects, and new rules for weak hashes, the `random` module and insecure cookies. `pandaward-py-sql-string` is now `pandaward-py-sql-injection`. On the OWASP Benchmark for Python the bundled rules score 0.530 on Opengrep and 0.433 on Semgrep, up from 0.059 and 0.039 (#326).
- Java rules follow request data to its sink: SQL, OS command, file path, LDAP, XPath, HTML response and session sinks are taint rules, with new rules for weak hashes, `java.util.Random`, insecure cookies and DES or Blowfish in any mode. Types are matched fully qualified as well as imported. `pandaward-java-sql-string` is now `pandaward-java-sql-injection`. On the OWASP Benchmark for Java the bundled rules score 0.723 on Opengrep and 0.467 on Semgrep, up from 0.000 (#324).
- In a git repository, directories git ignores and does not track are no longer scanned: the inventory line names them, results external scanners report there are dropped, and secrets gitleaks finds there stay listed as info. `inventory.include_ignored: true` scans them again (#312).

### Fixed
- Built with Go 1.27.4, which fixes GO-2026-6859 in `net/http` (#358).
- pandaward.dev/benchmarks published an older run of main right after a new one succeeded: the rebuild now takes the run that triggered it, and otherwise the newest successful run from the unfiltered listing (#353).
- The bundled JavaScript SQL rule no longer reports constants and numbers in template literals on Opengrep, which binds an interpolation with its `${...}` (#317).
- In Go files, a rule match inside a string literal is data: inside a `regexp` pattern it is dropped, inside other strings it is listed as info. Go SQL built only from literals and constants is no longer reported (#306).
- A-003 no longer compares routes from test and fixture files with the OpenAPI contract, so test servers do not raise `inventory.undeclared-route` findings or keep A-003 from passing (#310).

## [0.2.14] - 2026-11-08

### Added
- Runtime checks for the last undecided runtime controls in `pandaward test --profile staging-active` (#296):
  - G-002: `contract: {check: true}` sends every secured GET or HEAD operation of the OpenAPI contract without credentials and expects a denial (#297).
  - B-003: `flow_checks` replay login, reset and MFA flows with negative steps the server must refuse (#298).
  - F-002 and Q-002: `effect_checks` repeat an action in sequence or at once and check with a read-only probe that it took effect once (#299).
  - P-003: `llm_checks` send five built-in prompt-injection payloads in a data field and look for a canary only a model that obeyed them would produce (#300).
- State-changing requests (POST, PUT, PATCH, DELETE) as a separate opt-in: allowed only with `environment: staging` or `local`, sent only for flow, effect and LLM checks, and listed by `pandaward scope approve` (#298).
- Identity provisioning output can carry `inputs` for request bodies and headers, kept in memory only (#298).

### Fixed
- `innerHTML` and `outerHTML` assignments built from literals, constants and escape helpers, and Prisma `$queryRaw` tagged templates, are proven safe instead of reported (#295).

### Changed
- Built with Go 1.27.3; `go install` and source builds need Go 1.27 or later.
- modernc.org/sqlite 1.62.0.

## [0.2.13] - 2026-11-05

- Bump modernc.org/sqlite from 1.61.0 to 1.61.1 in the go-modules group (#237) by @dependabot[bot]
- Add attested verdicts for manual controls (#276)
- Draft scope manifests, provision test identities, name the ZAP install (#278)

## [0.2.12] - 2026-11-04

- Detect the wrong plugin variant before scanning (#266)
- Prove html-sink values safe and list file-only SQL builders as info (#267)
- Show how coverage was decided and a path to 100% (#268)
- Decide A-002 for Next.js apps from the file-system route table (#269)
- Drop osv results for packages an override replaces with local code (#270)
- Keep runtime verdicts across passive scans while they stay valid (#271)
- Explain scope approval input and test profiles in the CLI (#272)

## [0.2.11] - 2026-11-04

- Detect hidden and injected instructions in agent files and MCP tool descriptions (#254)
- Decide controls without signals a person dismissed as false positive (#251)
- Say what network scanners send, and offer the switch once (#250)
- Strip invisible tag and zero-width characters in Sanitize (#256)

## [0.2.10] - 2026-11-04

- Fix A-002 false negative on Next.js server actions (#169)
- Mask GitHub tokens glued to surrounding text (#236)
- Weight down low-confidence Semgrep registry rules (#238)
- Skip constant markup and fixed SQL choices in JavaScript rules (#239)
- Fix false positives in DB URL, PEM stub, workspace lockfile and OAuth callback checks (#241)
- Fix false positives in built-in code rules (#242)
- List placeholder-shaped gitleaks matches as info (#240)
- Flag floating tool installs and tag-only images in CI workflows (#243)
- Report CSPs that allow unsafe inline or eval scripts (#244)
- Flag RLS policies on privileged columns and tracked tool-local settings (#245)

## [0.2.9] - 2026-10-31

- Show scan progress with a percentage and the time left (#180)
- Offer false-positive reports only while the rule still fires (#185)
- Skip semgrep results in test and fixture code by default (#186)
- List gitleaks hits in untracked, git-ignored files as info (#187)
- Ask for the feedback mode wherever triage is recorded (#188)

## [0.2.8] - 2026-10-30

- Read the rule of a report from its table or title (#173)
- Check every documented pandaward command against the CLI (#174)
- Ask for feedback once and file grouped reports, including missed issues (#175)
- Let a human mark a fixed finding as remediated (#176)

## [0.2.7] - 2026-10-29

- Do not treat sign-in callbacks as webhooks (#162)
- Do not flag SQL built from constants in pandaward-js-sql-string (#165)
- Do not flag fetches to a fixed origin in pandaward-js-ssrf (#166)
- Apply inventory.exclude to every adapter's signals (#161)

## [0.2.6] - 2026-10-29

- Show live reviewer progress during the guided assessment (#154)

## [0.2.5] - 2026-10-29

- Keep finding identity stable across fixes and moved files (#150)

## [0.2.4] - 2026-10-29

- Mark releases latest, and build the hostile fixture's JSON with json.Marshal (#141)
- Remove the MobSF key after sanitizing, not only before (#145)
- Point links at pandaward.dev (#143)
- Say on the site that telemetry is opt-in, and name Go 1.26 (#147)

## [0.2.3] - 2026-10-29

- Bump pre-commit from 4.0.1 to 4.7.0 in /.github/requirements (#133) by @dependabot[bot]
- Bump modernc.org/sqlite from 1.34.5 to 1.61.0 in the go-modules group (#132) by @dependabot[bot]
- Bump the actions group with 10 updates (#134) by @dependabot[bot]
- Send opt-in telemetry to telemetry.pandaward.dev, off the command's path (#137)

## [0.2.2] - 2026-10-29

- Always skip the .pandaward and .pensec state directories (#120)
- Fix bundled Semgrep false positives and run the rule fixtures in CI (#122)
- Add an optional MobSF adapter for APK and IPA files (#118)
- Build with Go 1.26.10 and gate CI and releases on govulncheck (#126)
- Pin pre-commit by hash, add Dependabot, CodeQL and fuzz tests (#128)
- Add opt-in usage telemetry, off by default (#124)
- Stop overclaiming confidence on secrets and SQL templates (#131)

## [0.2.1] - 2026-10-28

- Stop the file walk once its deadline has passed (#113)
- Ship an MCPB bundle and server.json for the MCP Registry (#111)
- Publish a plugin-directory branch without binaries (#115)

## [0.2.0] - 2026-10-28

- Rename the project to Pandaward and release 0.2.0 (#108)

## [0.1.6] - 2026-10-28

### Upgrade notes
- Update the `pensec` CLI together with the plugin. 0.1.6 adds `runtime.android_package` and `runtime.ios_bundle_id` to `.pensec/config.yaml`; older binaries reject unknown keys. Existing files keep working.
- New configs list `apktool` in `scan.adapters`. To use it in an existing project, add `apktool` to that list.
- The catalog is now `2026.10-m4` with four new controls (K-004, K-005, L-003, L-004), so the first scan after the update does not carry results over from older assessments.

### Highlights
- Mobile source checks: credentials in plain SharedPreferences and world-readable storage (K-004), `get-task-allow` outside debug entitlements (L-003), `kSecAttrAccessibleAlways` and credentials in UserDefaults (L-004) (#14).
- Optional apktool adapter: `.apk` files in the project are decoded (resources only, the app's code is never run) and their manifest goes through the Android checks (K-005) (#14).
- `pensec test --profile local-runtime`: reads the configured test build's storage on an Android emulator (K-003) or in an iOS simulator on macOS (L-002) and reports credential-like keys by name, never their values. Real devices are refused; anything missing is `BLOCKED` with the reason (#14).
- The hostile-repository self-test runs in CI on every OS and before every release, and a new case checks that scanner output claiming confirmation stays a hypothesis (#15).
- Android sources under `com/example` in `src/main/` are no longer skipped as sample code (#101).

## [0.1.5] - 2026-10-28

### Upgrade notes
- Update the `pensec` CLI together with the plugin. 0.1.5 adds `runtime.zap_path` to `.pensec/config.yaml` and `zap`, `identities` and `authorization_checks` to `.pensec/scope.yaml`; older binaries reject unknown keys. Existing files keep working.
- Claude Code does not update third-party marketplaces unless auto-update is on: `/plugin`, Marketplaces, `pensec`, Enable auto-update. Or run `claude plugin marketplace update pensec` and `claude plugin update pensec-windows@pensec` (`pensec@pensec` on macOS and Linux), then restart.
- On Windows keep only `pensec-windows@pensec`. If `pensec@pensec` is also installed, the MCP server does not connect; see [Troubleshooting](https://github.com/ratomirjovanovic/pensec/wiki/Troubleshooting).

### Highlights
- `pensec test --profile staging-active` runs your installed ZAP (Java 17+) against approved staging or local targets: spider and passive scan for M-001, and the active scan for D-005 when the manifest sets `zap.active_scan: true`. Every ZAP request, including HTTPS, goes through the PenSec scope guard: origins, excluded paths, methods, request budget, rate limit and address checks, and a stop after three consecutive 429 or 5xx answers. A failed run is `ERROR`, a cut-short run `INCONCLUSIVE` (#13).
- Authorization checks with test identities: list identities (credentials come from environment variables and are never stored) and read-only checks in the scope manifest. Each check is sent as every identity and anonymously; object checks decide C-001 (BOLA), function checks C-002 and revoked identities B-004 (#12).
- `pensec doctor` shows whether ZAP is installed.
- Documentation for updating and uninstalling, with every file PenSec creates (#92).

## [0.1.4] - 2026-10-28

### Upgrade notes
- Update the `pensec` CLI (Homebrew, Scoop, release binary or `go install`) together with the plugin. `pensec init` from 0.1.4 writes a new `hooks` section to `.pensec/config.yaml`, and older binaries reject unknown config keys. Existing configs without the section keep working and get the default `hooks.auto_retest: true`.
- The Claude Code plugin now retests automatically after Claude edits code. Set `hooks.auto_retest: false` in `.pensec/config.yaml` to turn that off.

### Highlights
- Hands-free plugin: ask Claude to check the project's security or run `/pensec:start`. Claude runs the whole assessment, asks one question at the end and carries out what you choose, with a retest after every fix (#80).
- Automatic retest: a Stop hook retests the files edited in a turn, within 40 seconds, and hands new or reopened findings back to Claude. A clean retest stays silent (#82).
- `pensec findings apply --file decisions.json --by <name>` records many triage decisions in one transaction, and the plugin shows the whole list in one confirmation prompt (#83).
- The website shows the install commands for the visitor's platform (#87).

## [0.1.3] - 2026-10-28

- Clone plugin sources over HTTPS (#46)
- Report the module version for go install builds (#49)
- Update install instructions in README, website and VERIFYING.md (#50)
- Run OpenSSF Scorecard and show its badge (#63)
- Add pre-commit hooks (#60)
- Add Homebrew, Scoop and winget packages (#62)
- Add a GitHub Action (#59)
- Validate optional scanner adapters against real tool output (#67)
- Measure built-in rules on the OWASP Benchmark (#64)
- Add an animated terminal demo generated from a real session (#65)
- Collect false positive and false negative reports and prioritize rule fixes (#68)
- Import findings from SARIF files (#61)
- Add a guided assessment: pensec assess and /pensec:start (#70)

## [0.1.2] - 2026-10-28

- Freeze schemas and pin them with a golden test (#41)
- Declare the plugin MCP server inline and keep plugin branches byte-exact (#44)

## [0.1.1] - 2026-10-27

- Deterministic SBOM serial number for the release attestation (#39)


[Unreleased]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.14...HEAD
[0.2.14]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.13...v0.2.14
[0.2.13]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ratomirjovanovic/pandaward/releases/tag/v0.1.1
