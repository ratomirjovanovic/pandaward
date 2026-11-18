# Independent measurement on Snyk VulnBench 2.0 (issue #467)

Written before the run. The results go in a separate file, added after the run, and nothing in this protocol is changed afterwards.

## What is measured

- Suite: Snyk VulnBench 2.0, dataset 2.0.0, repository `snyk-labs/snyk-vulnbench` at commit `385a3751046b62f30b61f9dfadb26d6d7dfc52aa` (28 October 2026), license Apache 2.0. The 20 `fixtures/app-project-*` applications with 108 attacker-reachable reference vulnerabilities in `findings-attacker-reachable.json`: by primary language of the project (a project that mixes Go, Python or Java with JavaScript counts under the first): Go 6 projects with 32 references, Python 5 with 34, JavaScript and TypeScript 7 with 30, Java 2 with 12.
- PandaWard: commit `734bfa7fb33ad407ceb17098418f927ad61a0afa` (tag `vulnbench2-freeze`), built from source. Engine, rules and specifications are not changed between this protocol and the run, and the run is done once, in two configurations: (1) the default configuration with Semgrep 1.182.1 installed, which is what a developer who has Semgrep gets, so PandaWard's bundled Semgrep rules run too; (2) built-in only, with `scan.adapters` limited to `builtin-code` and `builtin-taint`, which is what a developer without any other tool gets. No other analyzer is installed that PandaWard could call except those named here.
- Date of the run: 18 November 2026.
- The rules and taint specifications were never tuned on these applications. The developer has not scanned them before. They were chosen because the OWASP Benchmarks and the OpenSSF CVE Benchmark were used while the engines were built (issue #467).

## How a finding is matched to a reference

A reference lists files and lines, some marked `source` or `sink`. A finding matches a reference when it is reported in the file of one of the reference's sink lines and its start line is within 2 lines of that sink line. This is looser than the suite's own rule, which also requires the source within 2 lines; PandaWard's findings carry the sink line and, for taint flows, a flow text, so the source is not compared. Two figures are reported:

1. Located: any finding of any rule matches the reference.
2. Same weakness: a finding whose rule is of the reference's weakness class (SQL injection, command injection, path traversal, XSS, SSRF, open redirect, deserialization, code injection, prototype pollution, ReDoS) matches the reference.

Findings are counted at the severities PandaWard rates as high or critical by default and also at all severities, both shown. Findings that match no reference are listed per application and counted; the reference list is not exhaustive, so they are not all false positives, and none is called one without a look at the code.

## What is published

Per reference: found or missed, by which rule, and for each miss the reason when it is known (language without a taint front end, flow across a function the engine does not follow, no sink in the specification). Per language and per weakness totals, with Wilson 95% intervals. The OWASP rows elsewhere are development benchmarks and are labelled so.
