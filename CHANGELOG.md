# Changelog

All notable changes to PandaWard. Versions follow the release tags; each release page has binaries, checksums, the SBOM and build provenance. PandaWard was called PenSec before 0.2.0.

## [Unreleased]

### Fixed
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
