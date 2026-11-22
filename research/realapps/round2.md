# Round 2: ordinary open-source applications

Targets, rule and commits: [targets-round2.md](targets-round2.md), published before the scan (PR #573). Scan: 19 applications at the pinned commits, built from main at `a1fe9e9` (the engine of main until `a92416a`), the built-in adapters only, no Semgrep, no network, limit of 900 seconds per scan; every scan finished. Every finding of high or critical severity (271) has a verdict and a reason in [round2-findings.csv](round2-findings.csv). Findings of lower severity are not judged.

## How the verdicts were made

Seven reviewers (language-model agents) each read a share of the findings with the source at the pinned commit, read-only, and wrote a verdict with a reason. True needed a traced flow or an equally concrete weakness; false positive needed a reason in the code. I read the reason of the 71 data-flow findings (every taint rule) and opened the source for five of them (the redirects in mirotalksfu, `get_safe_return_url` in linkding, and the three findings below); the verdicts of the pattern rules (SQL strings, `eval`, shell calls, TLS flags) were not checked one by one in the source. Treat the false positive counts as the reviewers' judgement with that spot check, not as proof.

## Results

| Verdict | Findings |
|---|---|
| True | 3 (1.1%) |
| False positive | 268 (98.9%) |
| Unclear | 0 |

The three true findings are all TLS certificate verification switched off in production code: two in LDAP connections of one application and one in the SMTP transport of another (whose source carries a comment saying the behavior is kept on purpose from an older Node version). They are hardening issues that need a network position, not remote vulnerabilities. Disclosure: file, line and flow are withheld in the CSV for these three until the maintainers have been told; the project with the LDAP finding has private vulnerability reporting and the report is prepared; the other project's policy asks for an email to its security address and its code comment shows the maintainers know. Nothing is published about them beyond the class.

By application (high and critical findings, all findings): Commafeed 0 of 0, ConvertX 1 of 5, Bastillion 9 of 9, PraisonAI 105 of 177, audiobookshelf 48 of 203, metube 1 of 2, bytechef 2 of 51, nightingale 32 of 45 (2 true), pangolin 12 of 32, gotify 4 of 4, listmonk 1 of 27, linkwarden 3 of 24, dockge 2 of 2, neko 6 of 10, mirotalksfu 28 of 122, planka 5 of 18, sandstorm 1 of 72 (1 true), linkding 10 of 17, wger 1 of 8.

## What it says

- **A high or critical finding of the built-in engines on an ordinary, maintained project was a real problem in 1 case of 90.** The precision on this set is very low. Round 1 (projects that are vulnerable on purpose) had 48%; ordinary projects have few real, remotely exploitable weaknesses, and the engines report many shapes that these projects have already handled.
- **Where the false positives come from** (`rule`, count in the CSV): dynamic SQL built from validated table names and bound values (`code.sql-template`, `code.sql-unsafe-raw`, `code.sql-concat`: 117 of 268); `eval`, shell and deserialization calls in the intended features of agent and operations tools (`code.py-eval`, `code.py-shell`, `code.go-shell`, `code.py-deserialize`); disabled TLS verification that an administrator chose; and data-flow findings where the engine does not see the guard: redirects that cannot leave the site, because the target starts with a constant path (`'/whoAreYou/' + room`) or is the current page (13 findings in one application), values checked by a validator the specification does not know (`get_safe_return_url`, `isValidRoomName`, `sanitizeFilename`, `filterXSS`), a generated or sanitized file name, and values that never come from a request (browser code calling its own server, a developer script).
- **Recall is not measured here**: nothing says how many real vulnerabilities these projects have.

## What this does not show

- That PandaWard is wrong more often than other tools: no other tool was run on these projects.
- That the 268 are certainly false: they are reviewer verdicts with a spot check.
- Anything about Java and PHP beyond three Java applications and none in PHP.

## Rescan after the fixes

The clusters above became fixes (#589, #590, #591, #592, #593, #594, #596, #597, #598, #599). The same 19 applications at the same pinned commits were scanned again with the built-in adapters of main (`e6eee83`), and each remaining high or critical finding was matched to its verdict by file, rule and line.

| Rule group | High or critical before | After |
|---|---|---|
| SQL built from strings (`code.sql-template`, `code.sql-concat`, `code.sql-unsafe-raw`) | 117 | 50 |
| TLS verification off (`code.tls-verify-off`) | 19 | 7 |
| `eval` and `exec` in Python (`code.py-eval`) | 16 | 5 |
| Shell calls in Python (`code.py-shell`) | 13 | 6 |
| Open redirect, JavaScript (`taint.js-open-redirect`) | 16 | 5 |
| Cross-site scripting, JavaScript (`taint.js-xss`) | 9 | 6 |
| All rules | 271 | 153 |

Of the 153, 150 are findings that carry a false-positive verdict and 3 are the true TLS findings, which are still reported (no fix removed a true finding). Four groups were not touched and remain whole: path traversal in Python and Go, deserialization with `yaml.FullLoader`, constant `bash -c` commands in Go, and the JavaScript SQL flows.

What this does not show: the fixes were written from these same findings, so the drop measures that the clusters are fixed, not that the engines are more precise on code they have not seen. The verdicts of the pattern rules were not rechecked in the source one by one (see above). Round 3 on new applications is the way to measure that.

## Follow-up

The false positive clusters become issues, each with the cases as a regression set (the constant-prefix redirect first, because it is a plain engine gap and 13 findings). See #470.
