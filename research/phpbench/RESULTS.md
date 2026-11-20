# PHP measurement on GitHub Advisory fix commits: results

Issues #542 and #544. Protocol: `PROTOCOL.md` here and `../semgrep-compare/PROTOCOL.md`, both written before the run. The PHP set was not used to develop either tool, so this is a held-out measurement for PandaWard and for Semgrep.

PandaWard: the build of the `phpbench-freeze` tag, default configuration, built-in adapters only. Semgrep: OSS 1.182.1, rule sets `p/default`, `p/security-audit`, `p/php`, no login.

## Result

91 of the 100 selected advisories were scanned by both tools. Window of 5 lines around the changed region of the fix. Wilson 95% intervals.

| | PandaWard (A) | Semgrep (B) | both (C) |
|---|---|---|---|
| located, any finding | 12/91 (8% to 22%) | 8/91 (5% to 16%) | 15/91 (10% to 25%) |
| same weakness class | 10/91 (6% to 19%) | 4/91 (2% to 11%) | 11/91 (7% to 20%) |
| high or critical | 12/91 (8% to 22%) | 5/91 (2% to 12%) | 14/91 (9% to 24%) |
| still reported in the fixed state | 10/91 | 4/91 | |

By class (located / same weakness):

| class | advisories | PandaWard | Semgrep |
|---|---|---|---|
| CWE-79 (XSS) | 56 | 3 / 3 | 2 / 0 |
| CWE-89 (SQL injection) | 12 | 3 / 3 | 2 / 2 |
| CWE-22 (path traversal) | 7 | 1 / 1 | 2 / 1 |
| CWE-94 (code injection) | 5 | 0 / 0 | 0 / 0 |
| CWE-78 (command injection) | 4 | 2 / 2 | 1 / 0 |
| CWE-601 (open redirect) | 4 | 0 / 0 | 0 / 0 |
| CWE-918 (SSRF) | 2 | 2 / 0 | 1 / 1 |
| other | 1 | 1 / 1 | 0 / 0 |

The list of references that only one tool locates, with the rule, is in `../semgrep-compare/php-only.csv`. Per advisory results are in `pandaward-refs.csv` and `semgrep-refs.csv`.

## How to read it

- Both tools miss most of the set. PandaWard locates about 13 percent, Semgrep about 9 percent. This is far below what either reaches on VulnBench, and it is the number to quote for PHP, not the VulnBench one.
- PandaWard locates more references and, above all, more of the right class. 4 of the 8 references Semgrep locates are matched only by a rule of another class (for example `exec-use` or a CORS rule near an XSS fix), which is why its same-weakness count is 4. The intervals overlap, so the difference between the two tools is suggestive, not established.
- 10 of the 12 references PandaWard locates are also reported after the fix. On this set a located reference therefore does not show that the engine tells the vulnerable code from the fixed code. The cases were not read one by one.
- The set favors small, local fixes, and it is dominated by XSS (56 of 91). It does not say what share of all PHP vulnerabilities PandaWard finds.
- Why the misses happen is in `MISSES.md`. It is a post hoc analysis and was done on the first 78 advisories; it says that a large part of the misses is not source-to-sink flow in one file at all (second-order values, helper functions without a source, library-internal fixes, changes that are not code).

## What went wrong in the run, and what was done

- The work drive became full at about 16:20 during the first PandaWard run. 13 advisories were never fetched, one was left unfinished and two scans failed at that moment. Those 16 were run again with the same binary and script on another drive. Three of them failed again (Dolibarr twice, AVideo once) and stay failed.
- Six advisories that finished at 16:17 to 16:20 had identical results for the vulnerable and the fixed state. They were run again as well. The rerun gave identical vulnerable and fixed results again, so this was probably real (a large fix that does not change any finding), not a result of the full disk.
- 9 advisories are not scored for either tool: 6 PandaWard scans exceeded the 900 second limit (Dolibarr 4, moodle 2; the scan time of large PHP projects is issue #556, which was fixed after the freeze and is not in the build used here), and 3 failed again on the rerun. Semgrep was not run on them. The result is therefore for the advisories that PandaWard could scan, which skews toward smaller projects.
- Deviation from the Semgrep protocol: the resolved rule files were not saved, only the pack names, so the Semgrep run cannot be reproduced exactly. Semgrep ran with a limit of 30 seconds per rule and file, and none of its scans failed.
- The class of a Semgrep finding comes from the CWE in its metadata, as in the VulnBench comparison. A located reference of the wrong class is still counted as located, as the protocol says.
- Semgrep and PandaWard were each run once. Nothing was changed in the engine or in the rules after the freeze.

## Not claimed

- That PandaWard finds 13 percent of PHP vulnerabilities, or that it is better than Semgrep in general. The set, the window and the missing large projects limit what the numbers say.
- That a located reference is the exact sink. The window is 5 lines.
- Anything about PHP frameworks that the specification does not model beyond what `MISSES.md` reports.
