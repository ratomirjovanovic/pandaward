# Triage measurements

An agent (headless Claude Code, no tools, the source file in the prompt) judges a finding as `true_positive` or `false_positive`. The oracle is the OWASP Benchmark label. Findings come from `owaspbench --emit-findings` on BenchmarkJava at the pinned commit. The held-out split is one test case in five, fixed by a hash of the case name, and was run once after the development runs.

| File | Engine | Split | Findings |
|---|---|---|---|
| java-builtin-dev-sonnet.jsonl | PandaWard built-in rules | development | 160 |
| java-builtin-heldout-sonnet.jsonl | PandaWard built-in rules | held-out | 87 |
| java-semgrep-default-dev-sonnet.jsonl | semgrep p/default | development | 120 |

Score any file: `pandaward lab triage score --out FILE`. Reproduce: `pandaward lab triage run --findings F --checkout BenchmarkJava --engine builtin --n 80 --seed 2 --model sonnet --out FILE`.

Limits: a synthetic benchmark that is public and may be in the model's training data; the built-in findings that can be labelled are all SQL injection; one model; one agent prompt. The evidence gate (cited line must exist and match) removed nothing here because every verdict passed it. A verdict is a hypothesis; nothing in this track closes a finding.
