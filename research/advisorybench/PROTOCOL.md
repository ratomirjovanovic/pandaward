# Independent measurement on GitHub Advisory fix commits: Python, Java and Go (issue #467)

Written before the run. The results go in a separate file, added after the run, and nothing in this protocol is changed afterwards. A change that turns out to be needed is made in a new file and the run it affects is labelled.

## Why

The OWASP Benchmarks are public and were used while the engines were built, and VulnBench 2.0 has been used since its frozen run. This measures the three languages with a full taint front end on real projects with a public, third-party ground truth that nobody tuned on. It repeats the method of `research/phpbench` (PHP, #542), which gave a first honest figure for a weak language; this is the figure for the strong ones. JavaScript and TypeScript are left out on purpose: the OpenSSF CVE Benchmark, which the JavaScript rules were developed on, is built from the same kind of advisories, so the sets would overlap.

## What is measured

- Source: the GitHub Advisory Database, reviewed advisories of the `pip`, `maven` and `go` ecosystems, read with the REST API (`/advisories?ecosystem=<e>&type=reviewed&cwes=79,89,78,77,22,98,601,94,918`) on 20 November 2026 by `fetch.py`. The lists are saved as `advisories-pip.tsv`, `advisories-maven.tsv` and `advisories-go.tsv` before any project is scanned.
- Classes: advisories whose CWEs include 79 (XSS), 89 (SQL injection), 78 or 77 (command injection), 22 (path traversal), 98 (file inclusion), 601 (open redirect), 94 (code injection) or 918 (SSRF).
- Selection, fixed here and applied by `select.py` without looking at any result: per ecosystem, take the advisories in ascending order of GHSA id; keep one when it has exactly one distinct reference of the form `https://github.com/<owner>/<repo>/commit/<sha>`, the commit has one parent and changes at least one source file of the language (`.py`, `.java`, `.go`) outside test paths, and the repository is not one the engines were developed or measured on (pygoat, WebGoat, OWASP BenchmarkJava and BenchmarkPython, Snyk VulnBench). Stop at 30 advisories per ecosystem, 90 in all. A commit that cannot be fetched is skipped and counted, and the next advisory takes its place. The result is `selected-pip.tsv`, `selected-maven.tsv` and `selected-go.tsv`, committed with this protocol.
- PandaWard: main at commit `a92416a` (the build of that commit, SHA-256 of the binary recorded in the results), built from source. Default configuration of the built-in adapters only (`builtin-code`, `builtin-taint`), no Semgrep, no network. Engine, rules and specifications are not changed between this protocol and the run, and the run is done once, in one go.
- The rules were never tuned on these projects. Some of the projects may have been scanned by the developer among other applications in earlier work; none was scanned for this purpose.
- A scan has a limit of 900 seconds. A scan that does not finish is a failed scan, listed, and counted as not scored; it is not counted as a miss.

## Reference and matching

For an advisory, the vulnerable state is the parent of the fix commit and the fixed state is the commit. The reference is the old-side line ranges of the source hunks of the fix in the language (`git diff -U0 parent commit`; a hunk that only adds lines is the line before the insertion), in non-test files.

A finding of the vulnerable state matches when it is in a changed file and its start line is within 5 lines of a reference range. This is wider than the 2 lines used for VulnBench because the line a patch changes is often a few lines from the sink; so a match shows that the engine reports something in the code that was fixed, not that it reports the exact sink.

1. Located: any finding of the built-in adapters matches.
2. Same weakness: a finding of the class of the advisory's CWE matches (rule id words as in `research/vulnbench/score.py`).

Both are shown at all severities and at high or critical only, per ecosystem and per class, with Wilson 95% intervals.

## False positives

The fixed commit is scanned too. A finding of the class of the advisory that still matches the changed region after the fix is counted as reported after the fix. This over-counts, because a fix can leave a different weakness there, and the cases are read by hand before they are called false positives. Findings elsewhere in these projects are counted per project but not judged, because the projects have vulnerabilities nobody has labelled.

## Comparison with Semgrep

After the PandaWard run, Semgrep OSS (version recorded) is run on the same vulnerable states with the registry rulesets `p/default`, `p/security-audit` and the language pack (`p/python`, `p/java`, `p/golang`), as in the PHP comparison (`research/semgrep-compare`), and scored with the same match rule. The resolved rule files are not saved; this is a disclosed deviation from a fully reproducible comparison. No claim is made beyond this set and these rulesets.

## What is published

Per advisory: located or missed, by which rule, the reason for each miss when it is known (flow through a framework the specification does not model, a call the engine does not follow, no sink in the specification, a weakness that is not a taint flow such as missing authorization), and the finding after the fix. Per ecosystem and class totals with Wilson 95% intervals, the list of skipped advisories, the failed scans and every discarded attempt.

## What will not be claimed

- That PandaWard "finds X% of vulnerabilities". The set is advisories with one fix commit, which favors small, local fixes.
- That a located reference is the exact sink.
- Anything about projects or classes outside this set. Weaknesses that are not taint flows are counted as missed and listed, not removed.
- A result for JavaScript or TypeScript, or for languages without a taint front end.
