# Results: GitHub Advisory fix commits for Python, Java and Go (issue #467)

The run follows [PROTOCOL.md](PROTOCOL.md), which was published before it (PR #572). Date of the run: 20 November 2026. PandaWard: main at `a92416a` (`pandaward 0.2.18-0.20261120102250-a92416abe60e`), the binary has SHA-256 `72e79896194bb37b9108b117b72854ba14f216f762a569de044cfc167b1d2031`, default configuration of the built-in adapters only, no Semgrep, no network. 90 advisories (30 per ecosystem), all 180 scans finished within the limit, none failed. Per advisory: `pandaward-<ecosystem>-refs.csv`.

## PandaWard

A reference is located when a finding of any rule is within 5 lines of a line the fix changed (protocol).

| Language | Advisories | Located | Same weakness | Located at high or critical | Reported after the fix |
|---|---|---|---|---|---|
| Python | 30 | 6 (20%, 95% interval 10% to 37%) | 6 | 6 | 6 |
| Java | 30 | 0 (0% to 11%) | 0 | 0 | 0 |
| Go | 30 | 1 (1% to 17%) | 0 | 1 | 0 |
| All | 90 | 7 (8%, 4% to 15%) | 6 | 7 | 6 |

Python by class: path traversal 1 of 9, code injection 2 of 5, XSS 0 of 6, SSRF 1 of 3, command injection 2 of 6, open redirect 0 of 1. Java and Go: nothing located except one Go SSRF advisory (gitea), where the finding is `code.tls-verify-off`, not a weakness of the advisory's class.

All six located Python advisories are also reported after the fix, so the figure says that the engine reports something in the code that was fixed, not that it separates the vulnerable code from the fixed one. In those cases the fix keeps the flagged call (for example `eval` or a shell call) and adds a check or a different argument; each should be read by hand before it is called a false positive, and that has not been done.

This is a low number, lower than the 13% measured for PHP, and it is the main result of the run. It is not a number for the engine on all vulnerabilities, because the set is advisories with one fix commit (protocol), but it shows that on the ordinary vulnerabilities of real projects the built-in engines mostly report nothing near the code that was fixed. For comparison, VulnBench 2.0 gave 55 of 108 (51%) on the built-in engines in its frozen run, before any rule was tuned on it, and about 90 of 108 afterwards. The advisory set is harder than VulnBench in kind (more missing checks, more libraries and plugins), so the two figures are not the same measurement, and part of the gap is likely what tuning on a public suite buys; that part is not measured.

## Where the misses are

`miss-categories.tsv` assigns each advisory to one of three groups, mechanically: located; findings in a changed file but not near the change; no finding in any changed file.

| Language | Located | Findings in the changed file, elsewhere | No finding in a changed file |
|---|---|---|---|
| Python | 6 | 7 | 17 |
| Java | 0 | 4 | 26 |
| Go | 1 | 4 | 25 |

A look at the diffs of some misses, not all, shows two kinds that no taint rule could find:

- **Missing authorization or request-method checks.** Many Java advisories are Jenkins plugins whose fix adds `@POST` or a permission check (`checkAdministerPermission()`) to an existing form handler. The code before the fix has no tainted flow; the weakness is the absence of a check.
- **A stored or derived value used as a path.** A Go path traversal advisory (a web content path read from the database) fixes the code that builds a path from a stored name; there is no request source in the flow.

The reading is a sample, and the remaining misses were not analysed one by one, so the shares of missing-check, stored-value and framework-API cases are not known. A miss analysis per advisory like the one for PHP (`research/phpbench/MISSES.md`) has not been done.

## Semgrep OSS on the same advisories

Semgrep 1.182.1 (OSS), `--config p/default --config p/security-audit` and the registry pack of the language (`p/python`, `p/java` or `p/golang`), the public rules, `--metrics=off`, the same 90 checkouts, the same rule for locating a reference (a finding of any rule within 5 lines of a changed line, `score.py`), scanned by `run_semgrep.py`. Per advisory: `semgrep-<ecosystem>-refs.csv`. The packs were downloaded for the run; they are not frozen at a commit, which is a limit of this comparison.

| Language | Advisories | Located | Same weakness | Located at high or critical | Reported after the fix |
|---|---|---|---|---|---|
| Python | 30 | 9 (30%) | 6 | 2 | 2 |
| Java | 30 | 5 (17%) | 0 | 3 | 0 |
| Go | 30 | 2 (7%) | 1 | 0 | 1 |
| All | 90 | 16 (18%) | 7 | 5 | 3 |

Against PandaWard's 7 of 90 (8%): both located 6, only PandaWard 1, only Semgrep 10, neither 73; together 17 of 90 (19%). On this set Semgrep with a language pack locates more references than the built-in engines of PandaWard (16 against 7), mostly in Python (9 against 6) and Java (5 against 0), but at lower severity: 5 of its 16 are high or critical, against 7 of 7 for PandaWard. By the right class (CWE words in the rule) Semgrep located 7 advisories and PandaWard 6. The intervals overlap (Semgrep 11% to 27%, PandaWard 4% to 15%), so with 90 advisories the difference is suggestive, not established. Neither tool finds 73 of 90: the missing-check and stored-value cases above are out of reach for both.

The VulnBench 2.0 comparison with Semgrep is in `research/vulnbench`; the two sets differ (attacker-reachable vulnerabilities in applications against advisories with one fix commit), and PandaWard was tuned on VulnBench, so the two results are not the same measurement.

## What this does not show

- That the set is representative: advisories with one fix commit favor local fixes and exclude advisories whose fix spans several commits.
- The exact sink of a located reference (5-line window).
- Anything about tools other than Semgrep OSS with the language registry pack.
- Java, Go and Python on the vulnerabilities that are not in this set.

## Deviations and discarded attempts

None. The run was done once, in one go (two processes claiming advisories from the same list, as in the PHP run). A background task of the harness was stopped by the operating system for low memory; it was only a waiting task and the scan processes were not affected.
