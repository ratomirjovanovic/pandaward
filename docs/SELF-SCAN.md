# PandaWard scanning itself

This page records what the passive scan reports on this repository, how to repeat it, and how each finding was read. It is a reading of one scan on one day, not a claim that the code has no weaknesses: decisive coverage was 23 of 44 applicable controls, and 21 are not decided by a passive scan (see "What the scan did not decide").

## Repeat it

```sh
go build -o pandaward ./cmd/pandaward
./pandaward scan
./pandaward status
./pandaward findings
```

The same scan runs in CI as the `self-scan` workflow, through the action, with the exclusions in `.pandaward/config.yaml`. Pull requests fail on findings of medium or higher that the base commit does not have.

## Result of 22 November 2026

Scan of `main` at `5d164a9` with the exclusion described below. 575 assets, 4 git-ignored directories not scanned, 30 seconds, 227 MB peak memory.

| Adapter | Signals | Note |
|---|---|---|
| builtin-inventory | 0 | |
| builtin-secrets | 7 | all in test files, see below |
| builtin-code | 17 | all information, see below |
| builtin-taint | 1 | one high, see below |
| builtin-cicd | 0 | 11 workflows |
| builtin-supply | 0 | lockfiles, install scripts, requirement pins, MCP configs |
| gitleaks | 367 | placeholder-shaped values and test data, see below |
| semgrep | 0 | 133 signals in excluded or git-ignored paths dropped |
| osv-scanner | blocked | it sends package names and versions to api.osv.dev; the scan does not allow tool network access by default |

Open findings by severity: 1 high, 8 low, 329 information (338 in total). No critical, no medium.

## The one high finding

`taint.go-ssrf` at `internal/zap/proxy.go:157`. The proxy that sits between ZAP and the target builds an outgoing request from the URL ZAP sent (`http.NewRequestWithContext(..., u.String(), ...)`). That is what a forward proxy does, so the rule is right that the request URL comes from the request. It is not reachable by an unscoped caller: the request is sent with `p.g.RoundTrip(out)`, and `scope.Guard.RoundTrip` runs `admit` first (`internal/scope/guard.go`), which refuses a URL outside the approved manifest (`InScope`), a method that is not allowed, a state-changing method outside staging or local, and anything past the request budget or after a halt. A CONNECT is also checked against the manifest's https origins before the tunnel opens (`originInScope`). The engine does not know that `Guard.RoundTrip` is an allowlist, so the finding stays open and is a false positive on this reading.

## Low findings

All eight are test files that contain a fake value on purpose, to test redaction or secret detection:

- `internal/engine/staging_test.go` (2, GitHub token shape), `cmd/pandaward/lab_test.go` (3, API key shape), `internal/redact/fuzz_test.go` (private key block), `internal/redact/redact_test.go` (database URL with a password, and a generic key).

## Information findings

- `internal/benchmark/corpus.go` and `internal/catalog/catalog.go`: the rule corpus holds vulnerable and safe code samples as strings, so the code rules match them.
- `research/agent-safety/runs/*/episodes.jsonl`: recorded agent transcripts of the Agent Safety Lab that contain token-shaped canary strings.
- `internal/adapters/*_test.go`: placeholder-shaped test values.

## Exclusions

`.pandaward/config.yaml` excludes `research/advisorybench`. The advisory data files there (`advisories-*.tsv`) hold commit hashes and versions copied from public advisory databases. gitleaks reported 53 high `sourcegraph-access-token` findings and a medium `generic-api-key` on those hexadecimal strings, which are not credentials. The exclusion also hides the benchmark scripts in that directory, which are research tooling and not part of the product. The other exclusions (fixtures that are vulnerable on purpose, generated output) are listed in the same file with the reason.

## What the scan did not decide

21 of the 44 applicable controls stay undecided and the scan says so instead of passing them: 10 need an approved scope and an active test against a running instance, 5 need a reviewer's attestation with file and line evidence, 3 need the open suspected findings triaged, 1 needs osv-scanner network access (a choice for the person running the scan), 1 (route completeness) cannot be proven automatically, and 1 check was planned and did not run. The numbers above say what a passive scan of the source found. They do not say the product is secure.
