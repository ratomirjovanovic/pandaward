# Round 3: ordinary open-source applications the engines were not fixed against (issue #470)

Written before the scan. The applications and commits below are fixed by the rule in [select_round3.py](select_round3.py), applied on 22 November 2026 without looking at any scan result. The results go in a separate file after the scan and nothing here changes afterwards.

Why a round 3: the fixes after round 2 (#589 to #601) were written from the round 2 findings, so a rescan of those applications cannot say whether precision improved on code the engines were not shaped by. These applications are not in round 1 or round 2.

## Rule

The rule of round 2 ([targets-round2.md](targets-round2.md)) with one addition: the repositories of round 2 are skipped, so the applications are the next ones in the same ranking. The rule is mechanical and keeps what it selects: some of the entries are thin (a configuration repository, a template list) and Java has none, because no Java repository passed the filters. They stay in; a finding count on a thin repository says little and the per-application table shows that.

## Applications

| Language | Repository | Stars | Commit | Commit date | Security policy |
|---|---|---|---|---|---|
| TypeScript | [getmaxun/maxun](https://github.com/getmaxun/maxun) | 18543 | `ac3436f03f2a3cb750478fc5e940e4b2ee29be4f` | 2026-11-20 | [policy](https://github.com/getmaxun/maxun/security/policy) |
| TypeScript | [suitenumerique/docs](https://github.com/suitenumerique/docs) | 17004 | `0fed646108925811b1682b53bc15fb27012eac60` | 2026-11-21 | [policy](https://github.com/suitenumerique/docs/security/policy) |
| TypeScript | [documenso/documenso](https://github.com/documenso/documenso) | 15863 | `80550e78b3e4852f87e9968e24b1984c427e4430` | 2026-11-20 | [policy](https://github.com/documenso/documenso/security/policy) |
| TypeScript | [blinkospace/blinko](https://github.com/blinkospace/blinko) | 11234 | `a1c71e67f653f88aabee93c6e5dc433ef5780d18` | 2026-11-05 | [policy](https://github.com/blinkospace/blinko/security/policy) |
| JavaScript | [stoatchat/self-hosted](https://github.com/stoatchat/self-hosted) | 2691 | `b435b8e2201051dc4265e49be1534eb0db296ce9` | 2026-11-22 | [policy](https://github.com/stoatchat/self-hosted/security/policy) |
| JavaScript | [ever-co/ever-traduora](https://github.com/ever-co/ever-traduora) | 2140 | `241db22c3a7ac5ecc47496abd8afc362d29fe26f` | 2026-11-22 | [policy](https://github.com/ever-co/ever-traduora/security/policy) |
| JavaScript | [DialmasterOrg/Youtarr](https://github.com/DialmasterOrg/Youtarr) | 1831 | `d973881d53f29a708fd367bdce96c3044af0d2d9` | 2026-11-22 | [policy](https://github.com/DialmasterOrg/Youtarr/security/policy) |
| JavaScript | [fireshare-app/fireshare](https://github.com/fireshare-app/fireshare) | 1530 | `dd28105cdbed2498d650e6d7faac4517bcaf813b` | 2026-11-20 | [policy](https://github.com/fireshare-app/fireshare/security/policy) |
| Python | [baserow/baserow](https://github.com/baserow/baserow) | 6376 | `1aaa2e50bc76efd1109dec64378a0fdbd099e632` | 2026-11-20 | [policy](https://github.com/baserow/baserow/security/policy) |
| Python | [mediacms-io/mediacms](https://github.com/mediacms-io/mediacms) | 5198 | `99a180165f5d3a49bdfcb2c16eab4a2c4d260357` | 2026-11-19 | [policy](https://github.com/mediacms-io/mediacms/security/policy) |
| Python | [babybuddy/babybuddy](https://github.com/babybuddy/babybuddy) | 2951 | `1638cfb02e2681c5a0c2f24fdf8d20048fda995a` | 2026-11-14 | [policy](https://github.com/babybuddy/babybuddy/security/policy) |
| Python | [lissy93/portainer-templates](https://github.com/lissy93/portainer-templates) | 2935 | `1b3e58d7db08743054a7850394f03ccfc7be8f47` | 2026-11-22 | [policy](https://github.com/lissy93/portainer-templates/security/policy) |
| Go | [0xJacky/nginx-ui](https://github.com/0xJacky/nginx-ui) | 11815 | `f142566668085b369a2af19296b974ebae6a0d7f` | 2026-11-22 | [policy](https://github.com/0xJacky/nginx-ui/security/policy) |
| Go | [pocket-id/pocket-id](https://github.com/pocket-id/pocket-id) | 10419 | `ac3a462de94c5962dac797477e2d3d2f1c6935d1` | 2026-11-20 | [policy](https://github.com/pocket-id/pocket-id/security/policy) |
| Go | [go-vikunja/vikunja](https://github.com/go-vikunja/vikunja) | 6137 | `2ba8cef799cf12f7d0cf1196a180d75a2890c873` | 2026-11-22 | [policy](https://github.com/go-vikunja/vikunja/security/policy) |
| Go | [umputun/remark42](https://github.com/umputun/remark42) | 5653 | `0cdfcdd7e31ba07108d7e1226a2750d5ccbd55b0` | 2026-11-22 | [policy](https://github.com/umputun/remark42/security/policy) |

## Scan and triage

- PandaWard: main at the commit recorded in the results, built from source; the default configuration with the built-in adapters and no Semgrep, no network. One scan per application at the commit above, with a limit of 900 seconds.
- Every finding of high or critical severity gets a verdict (true, false positive, unclear) and a reason, as in round 1 (`round1-findings.csv`). Verdicts that rest on reading the source are marked as such; a finding is called true only when the vulnerable flow is traced in the source at that commit.
- Findings of lower severity are counted per application but not judged.
- For comparison, Semgrep with its public `p/default` rules is run on the same commits and its findings of severity ERROR are counted and judged the same way, so the false positive rate of PandaWard can be read against a free tool on the same code.

## Disclosure

A finding that is true and exploitable is reported to the maintainers privately, through the project's security policy, before anything about it is published. This round publishes the totals (findings, true, false positive, unclear) and the false positives with their reasons. A true finding is published only after the maintainers have fixed it or after their disclosure window, and findings the maintainers accept are counted separately. Until then the file lists it by application and class without file, line or payload.

## What will not be claimed

- A recall figure: a project's unlabelled vulnerabilities are unknown.
- That the numbers describe other projects, or that a maintainer's acceptance proves exploitability beyond what the report shows.
