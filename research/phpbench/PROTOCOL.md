# Independent measurement of PHP on GitHub Advisory fix commits (issue #542)

Written before the run. The results go in a separate file, added after the run, and nothing in this protocol is changed afterwards. A change that turns out to be needed is made in a new file and the run it affects is labelled.

## Why

The PHP front end (#513, #540) was checked by hand on DVWA, which the rules were developed against, and on two clean libraries. VulnBench 2.0 has no PHP reference. This measures PHP on real projects with a public, third-party ground truth.

## What is measured

- Source: the GitHub Advisory Database, reviewed advisories of the Composer ecosystem, read with the REST API (`/advisories?ecosystem=composer&type=reviewed&cwes=...`) on 18 November 2026. The list is saved as `advisories.tsv` before any project is scanned.
- Classes: advisories whose CWEs include 79 (XSS), 89 (SQL injection), 78 or 77 (command injection), 22 (path traversal), 98 (file inclusion), 601 (open redirect), 94 (code injection) or 918 (SSRF).
- Selection, fixed here and applied by `select.py` without looking at any result: take the advisories in ascending order of GHSA id; keep one when it has exactly one distinct reference of the form `https://github.com/<owner>/<repo>/commit/<sha>`, the commit has one parent and changes at least one `.php` file outside test directories, and the repository is not `slimphp/Slim`, `Seldaek/monolog` or `digininja/DVWA` (which the engine was developed on). Stop at 100 advisories. A commit that cannot be fetched is skipped and counted, and the next advisory takes its place.
- PandaWard: the commit tagged `phpbench-freeze` (main after PR #541), built from source. Default configuration, the built-in adapters only (`builtin-code`, `builtin-taint`), no Semgrep. Engine, rules and specifications are not changed between this protocol and the run, and the run is done once, in one go.
- The rules were never tuned on these projects and none of them has been scanned by the developer before the run.

## Reference and matching

For an advisory, the vulnerable state is the parent of the fix commit and the fixed state is the commit. The reference is the old-side line ranges of the PHP hunks of the fix (`git diff -U0 parent commit`; a hunk that only adds lines is the line before the insertion), in non-test PHP files.

A finding of the vulnerable state matches when it is in a changed file and its start line is within 5 lines of a reference range. This is wider than the 2 lines used for VulnBench because the line a patch changes is often a few lines from the sink; so a match shows that the engine reports something in the code that was fixed, not that it reports the exact sink.

1. Located: any finding of the built-in adapters matches.
2. Same weakness: a finding of the class of the advisory's CWE matches (rule id words as in `research/vulnbench/score.py`).

Both are shown at all severities and at high or critical only.

## False positives

The fixed commit is scanned too. A finding of the class of the advisory that still matches the changed region after the fix is counted as reported after the fix. This over-counts, because a fix can leave a different weakness there, and the cases are read by hand before they are called false positives. Findings elsewhere in these projects are counted per project but not judged, because the projects have vulnerabilities nobody has labelled.

## What is published

Per advisory: located or missed, by which rule, the reason for each miss when it is known (flow through a framework the specification does not model, include or autoload the engine does not follow, no sink in the specification, a weakness that is not a taint flow such as missing authorization), and the finding after the fix. Per class totals with Wilson 95% intervals, the list of skipped advisories, and every discarded attempt.

## What will not be claimed

- That PandaWard "finds X% of PHP vulnerabilities". The set is advisories with one fix commit, which favors small, local fixes.
- That a located reference is the exact sink.
- Anything about projects or classes outside this set. Weaknesses that are not taint flows are counted as missed and listed, not removed.
- Any comparison with another tool, because none is run.
