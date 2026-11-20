# Round 2: ordinary open-source applications (issue #470)

Written before the scan. The applications and commits below are fixed by the rule in [select_round2.py](select_round2.py), applied on 20 November 2026 without looking at any scan result. The results go in a separate file after the scan and nothing here changes afterwards.

## Rule

For each of five languages (TypeScript, JavaScript, Python, Java, Go), the repositories of the GitHub search `language:<L> topic:self-hosted stars:1000..25000 created:<2024-11-20 pushed:>2026-08-20 archived:false fork:false`, by stars, descending; keep one when it has a published security policy, is no list of links, and the repository is at most 300 MB; stop at 4 per language. Only three Java repositories passed, so the set has 19 applications. They are ordinary projects people run, not applications that are vulnerable on purpose, and none was chosen for how PandaWard behaves on it.

## Applications

| Language | Repository | Stars | Commit | Commit date | Security policy |
|---|---|---|---|---|---|
| TypeScript | [louislam/dockge](https://github.com/louislam/dockge) | 24861 | `0329dabb5003f206d4fd9f7403a6af26d7138497` | 2026-10-23 | [policy](https://github.com/louislam/dockge/security/policy) |
| TypeScript | [fosrl/pangolin](https://github.com/fosrl/pangolin) | 23898 | `c845d95cfaee26ebee334d29d32b9a679b3b1dbb` | 2026-11-19 | [policy](https://github.com/fosrl/pangolin/security/policy) |
| TypeScript | [linkwarden/linkwarden](https://github.com/linkwarden/linkwarden) | 20483 | `24adcc146ba356632859a1e8adb4bffae2874d11` | 2026-11-10 | [policy](https://github.com/linkwarden/linkwarden/security/policy) |
| TypeScript | [C4illin/ConvertX](https://github.com/C4illin/ConvertX) | 19751 | `83efa669dd183fbbb4e871b9ec915de3157af74e` | 2026-11-19 | [policy](https://github.com/C4illin/ConvertX/security/policy) |
| JavaScript | [advplyr/audiobookshelf](https://github.com/advplyr/audiobookshelf) | 15072 | `5de038dafda294d13ca48861eda7d4405bbd7368` | 2026-11-19 | [policy](https://github.com/advplyr/audiobookshelf/security/policy) |
| JavaScript | [plankanban/planka](https://github.com/plankanban/planka) | 12698 | `2cf423824a09f84df7dc3acf0ded9a700292d882` | 2026-11-06 | [policy](https://github.com/plankanban/planka/security/policy) |
| JavaScript | [sandstorm-io/sandstorm](https://github.com/sandstorm-io/sandstorm) | 7081 | `a97cf3ee19d3bf2761cd597583ca5d998de425d8` | 2026-05-26 | [policy](https://github.com/sandstorm-io/sandstorm/security/policy) |
| JavaScript | [miroslavpejic85/mirotalksfu](https://github.com/miroslavpejic85/mirotalksfu) | 3162 | `8448a836fd4aa5e14c6c24ab0534e97761eff94d` | 2026-11-20 | [policy](https://github.com/miroslavpejic85/mirotalksfu/security/policy) |
| Python | [alexta69/metube](https://github.com/alexta69/metube) | 15310 | `7746086e0e920925cb14c8f4843084e29548a877` | 2026-11-14 | [policy](https://github.com/alexta69/metube/security/policy) |
| Python | [sissbruecker/linkding](https://github.com/sissbruecker/linkding) | 11434 | `27b7303baf41bb28babc610ac8eaa486e1ddfab5` | 2026-09-13 | [policy](https://github.com/sissbruecker/linkding/security/policy) |
| Python | [MervinPraison/PraisonAI](https://github.com/MervinPraison/PraisonAI) | 9363 | `8179765c0f95fea253f7e639d7501985a39588a8` | 2026-11-19 | [policy](https://github.com/MervinPraison/PraisonAI/security/policy) |
| Python | [wger-project/wger](https://github.com/wger-project/wger) | 7296 | `aebe882a87c2236be896dde085b1d02b185999b9` | 2026-11-17 | [policy](https://github.com/wger-project/wger/security/policy) |
| Java | [Athou/commafeed](https://github.com/Athou/commafeed) | 3651 | `d21c5256e7077443799b91e81920326add840eb8` | 2026-11-20 | [policy](https://github.com/Athou/commafeed/security/policy) |
| Java | [Loophole-LLC/Bastillion](https://github.com/Loophole-LLC/Bastillion) | 3555 | `30efb971aa50607af324c3b3be500ae727ed5329` | 2026-11-16 | [policy](https://github.com/Loophole-LLC/Bastillion/security/policy) |
| Java | [bytechefhq/bytechef](https://github.com/bytechefhq/bytechef) | 1062 | `2d316023a03eda01803d75b2cab1be67b7bec1cf` | 2026-11-20 | [policy](https://github.com/bytechefhq/bytechef/security/policy) |
| Go | [knadh/listmonk](https://github.com/knadh/listmonk) | 24393 | `e735e0b23421192a4c1b18b6221f4708b872fcd5` | 2026-11-14 | [policy](https://github.com/knadh/listmonk/security/policy) |
| Go | [m1k1o/neko](https://github.com/m1k1o/neko) | 22699 | `8fd303c932e9189a25dfdce0acb31157940b02e7` | 2026-11-18 | [policy](https://github.com/m1k1o/neko/security/policy) |
| Go | [gotify/server](https://github.com/gotify/server) | 16223 | `01086b95a8b69ee87383f6e8bcae601d8c33384b` | 2026-11-09 | [policy](https://github.com/gotify/server/security/policy) |
| Go | [ccfos/nightingale](https://github.com/ccfos/nightingale) | 13507 | `c36e20a0acda814fa8ba8e6621a205fa9d0b1700` | 2026-11-19 | [policy](https://github.com/ccfos/nightingale/security/policy) |

## Scan and triage

- PandaWard: main at the commit recorded in the results, built from source; the default configuration with the built-in adapters and no Semgrep, no network. One scan per application at the commit above, with a limit of 900 seconds.
- Every finding of high or critical severity gets a verdict (true, false positive, unclear) and a reason, as in round 1 (`round1-findings.csv`). Verdicts that rest on reading the source are marked as such; a finding is called true only when the vulnerable flow is traced in the source at that commit.
- Findings of lower severity are counted per application but not judged.

## Disclosure

A finding that is true and exploitable is reported to the maintainers privately, through the project's security policy, before anything about it is published. This round publishes the totals (findings, true, false positive, unclear) and the false positives with their reasons. A true finding is published only after the maintainers have fixed it or after their disclosure window, and findings the maintainers accept are counted separately. Until then the file lists it by application and class without file, line or payload.

## What will not be claimed

- A recall figure: a project's unlabelled vulnerabilities are unknown.
- That the numbers describe other projects, or that a maintainer's acceptance proves exploitability beyond what the report shows.
