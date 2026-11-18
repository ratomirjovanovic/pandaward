# Round 1: applications that are vulnerable by design

Targets and commits: [targets.md](targets.md), published before the scan. Scan: `pandaward scan` with default settings on the pinned commits, built from `main`. Every high and critical finding (112) has a verdict and a reason in [round1-findings.csv](round1-findings.csv).

## How the verdicts were made

An agent read each finding with the cited source and proposed a verdict. Every reason was then read, and 6 findings were opened in the source. The review changed 8 verdicts: one finding whose title does not match its line, one build-time task, and six fake or lesson-only values that are now "unclear". This is not a hand triage of every finding, so the numbers below are a first measurement, not the final one for #470.

## Results (high and critical findings)

| Application | Findings | True | False positive | Unclear |
|---|---|---|---|---|
| Juice Shop | 37 | 23 | 14 | 0 |
| WebGoat | 23 | 3 | 18 | 2 |
| DVWA | 15 | 10 | 5 | 0 |
| Vulnerable-Flask-App | 13 | 5 | 8 | 0 |
| pygoat | 11 | 4 | 3 | 4 |
| NodeGoat | 9 | 8 | 1 | 0 |
| dvpwa | 2 | 0 | 2 | 0 |
| DVGA | 2 | 1 | 0 | 1 |
| **All** | **112** | **54 (48%)** | **51 (46%)** | **7 (6%)** |

95 distinct locations carry the 112 findings: some lines are reported by two rules.

## What it says

- **Dynamic code evaluation is the problem.** 31 of the 37 findings of this kind are false positives (84%), and they are 31 of the 51 false positives overall. Almost all are `eval` in vendored or static browser code (Closure loader, Materialize, an old menu script, a packed DVWA challenge) where the string is a constant or built from numbers and page-defined ids. A high-severity finding needs a data flow from an untrusted source, not just the presence of `eval`.
- Real ones that were found: shell and SQL built from request data in DVWA and NodeGoat, `eval` of request fields in NodeGoat, hardcoded private keys and SQL injection in Juice Shop, `pickle.loads` and `yaml.load` on uploads, JWT verification switched off, the Docker socket mounted in pygoat's compose file.
- **One rule misfire:** in Vulnerable-Flask-App a TLS certificate finding sits on a JWT verification line.
- Juice Shop's code-fix snippet files hold vulnerable variants next to fixed ones, so findings in them are true for the snippet but not for the running route.

## What this does not show

- Recall: the authors' own lists of vulnerabilities were not compared with the findings, so misses are not counted yet.
- General accuracy: these applications are vulnerable on purpose, so a high finding is often real. Ordinary projects come in a second round with its own published list and the projects' disclosure policies.
- The sample of opened findings is small (6), so the verdicts of the agent that were not changed are still unverified in the source.

## Module-level recall on DVWA (#513)

DVWA has one directory per vulnerability. Before the PHP line rules, PandaWard reported findings in 7 of the 19 vulnerability directories and most of those were secret or HTML sink noise. The PHP rules (SQL built by variable interpolation, request input in HTML, include and redirect from request input, uploads) bring that to findings in 16 of 19, with 35 new findings, all in the low, medium and high levels and none in the `impossible` level, which is the safe version. The three directories without a finding are file inclusion (the request variable is set in one file and included in another), cryptography and weak session ids. Findings are hypotheses at high or medium; they were checked by reading a few of them, not all 35. Stored XSS, CSRF, brute force and access control are not decided by a line rule; they need a PHP data flow front end.
