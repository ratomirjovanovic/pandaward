# PandaWard against Semgrep OSS on the same references (issue #544)

Written before the run. The results go in a separate file, added after the run, and nothing in this protocol is changed afterwards.

## Question

Does the PandaWard engine locate more of the labelled vulnerabilities than Semgrep OSS with its public rule sets, per language and per weakness class, and where does it locate fewer? The VulnBench result in `research/vulnbench/RESULTS.md` compared PandaWard with its own bundled Semgrep rules, which is not this.

## Suites

1. Snyk VulnBench 2.0, dataset 2.0.0, commit `385a3751046b62f30b61f9dfadb26d6d7dfc52aa`, the 20 `fixtures/app-project-*` applications and their 108 references, scored as in `research/vulnbench/PROTOCOL.md` (a finding in the file of a reference's sink and within 2 lines of it).
2. The PHP set of `research/phpbench/PROTOCOL.md`: the 100 advisories of `selected.tsv`, scored as there (the changed region of the fix commit, window of 5 lines), once its own results are published.

## Configurations

- A, PandaWard alone: the commit tagged `semgrep-compare-freeze`, built from source, default configuration with the built-in adapters only (`builtin-code`, `builtin-taint`).
- B, Semgrep alone: Semgrep OSS 1.182.1 (the community engine, no Pro rules, no login), `semgrep scan --metrics=off --json` with the rule sets `p/default`, `p/security-audit` and the pack of the language of the project (`p/php`, `p/python`, `p/java`, `p/javascript` and `p/typescript` for JavaScript and TypeScript, `p/golang`). A project with several languages gets each pack. The packs are fetched on the day of the run and the resolved rules are saved with the results, because the registry changes.
- C, both: the union of the findings of A and B, computed offline per reference. It is not the product's default configuration, which replaces some built-in rules by bundled Semgrep ones (#533).

## Scoring

A reference is located when any finding of the configuration is within the window of its sink. It is located with the same weakness when the finding's class equals the reference's: for PandaWard by the words of the rule id as before, for Semgrep by the CWE in the rule's metadata mapped to the same classes, and by the words of its rule id when the metadata has none. Severity "high or critical" is a PandaWard high or critical finding and a Semgrep ERROR. Both are shown at all severities and at high or critical.

Findings that match no reference are counted per application for each configuration, at high or critical, and not judged: the applications have unlabelled vulnerabilities, so this is a noise indicator and not a false positive rate. On the PHP set the fixed commit is scanned as in its protocol.

## What is published

For each configuration and each language and class: located and same-weakness counts with Wilson 95% intervals. Then the two lists that matter: references only A locates and references only B locates, with the rules that found them. Any failure of a tool (exit codes, timeouts, parse errors) is listed per application. Every discarded run is disclosed.

## Known bias, stated now

- VulnBench is no longer held out for PandaWard. The Go front end, the NestJS and constructor-injection support and the other changes after the first run were made with the misses in view, so A on VulnBench is a development number. Semgrep was not tuned on it. The PHP set is held out for A and for B.
- The sets favor taint flows. Weaknesses that a pattern finds but a flow does not (hardcoded secrets, weak crypto, missing headers) are only counted if a reference is one.
- One run per configuration. Semgrep is deterministic; PandaWard is deterministic at a fixed commit.

## What will not be claimed

- That PandaWard "is better than Semgrep" in general. Only the counts and the lists above, on these two sets.
- Anything about Semgrep Pro, the commercial rules, or other tools.
- That a located reference is the exact sink on the PHP set.
