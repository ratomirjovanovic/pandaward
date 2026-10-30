# False positives and false negatives

PandaWard's rules get better from reports by the people who use them. This page describes how a report travels from a user's machine to a fixed rule, and how reports are grouped and prioritized as their number grows.

## 1. Reporting

PandaWard never sends anything without the user's confirmation. It prepares reports, shows exactly what they contain, and files them only after the user agrees.

### In a guided review

The first `/pandaward:start` in a project asks once how feedback should work and why it matters, and stores the answer in `.pandaward/private/feedback.json` (private, so one person's choice never applies to a whole team):

| Mode | What happens |
|---|---|
| `batch` | After triage, PandaWard lists every report not sent yet and files them after one confirmation |
| `ask` | The assistant offers the reports and asks first (also the behavior before a choice is made) |
| `off` | Reports are never offered; they can still be prepared by hand |

Reports are built from the ledger, one per rule or control:

- **False positives**: rule findings a person closed as false positives, grouped by rule, with the number of findings and the file types. A reviewer's hypothesis closed as a false positive is not a report about a rule and is left out.
- **Missed issues**: reviewer findings a person confirmed (or fixed) where no rule reported the same control in the same file. These are problems the scanners did not catch, so PandaWard finds them without the user having to notice. The report lists which adapters ran.

```sh
pandaward feedback mode batch     # or ask, off; without an argument it prints the current mode
pandaward feedback pending        # reports not sent yet
pandaward feedback submit         # shows them and asks before sending
```

`submit` files the reports with the GitHub CLI when `gh` is installed and signed in. When an open report about the same rule exists, it adds a comment with the new counts and a :+1: instead of a duplicate; the dashboard counts the upvote. Without `gh` it prints prefilled issue links. Either way the findings are marked as reported and not offered again. In Claude Code the assistant runs `pandaward feedback submit --yes`, and the PandaWard hook shows the user every report in a confirmation prompt first; in a terminal without `--yes`, `submit` asks itself and refuses when it cannot ask.

### One report by hand

```sh
pandaward feedback false-positive PW-0007 --note "the value is a compile-time constant"
pandaward feedback false-negative --rule D-003 --note "f-string passed to cursor.execute"
pandaward feedback summary        # rules this project closed as false positives
```

In Claude Code, `/pandaward:feedback` does the same. The MCP tool `pandaward_pending_feedback` lists the reports not sent yet, and `pandaward_prepare_feedback` prepares a single report from the conversation. Both return `sent: false`.

### What a report contains

A default report contains only:

| Field | Example |
|---|---|
| kind | false-positive |
| rule, control | `code.sql-concat`, D-003 |
| severity, confidence | high, HYPOTHESIS |
| adapter and tool version | builtin-code 0.1.3, semgrep 1.182.0 |
| PandaWard and catalog version | 0.1.3, 2026.10-m3 |
| file type | `.py`, `Dockerfile`, `github-workflow.yml` |
| findings (grouped reports) | 6 |
| adapters run (missed issues) | builtin-code, semgrep |

`--include-path` adds the redacted path and line, `--include-snippet` up to 12 redacted lines of code. Both need the user's explicit choice and are never added to grouped reports. The issue forms ask the reporter to confirm that the report holds no secrets or private data.

Before filing a single report, `pandaward feedback` prints a link to existing open reports about the same rule; upvoting one with :+1: counts as much as a new report and avoids duplicates.

## 2. Grouping and priorities

The `rule-quality` workflow runs on every report change and daily:

1. Reports filed with `gh` cannot carry the issue form's labels, so the workflow labels new issues whose title starts with `[false-positive]` or `[false-negative]`.
2. It reads all open `false-positive` and `false-negative` issues through the REST API with pagination, so there is no cap on the number of reports.
3. It groups them by rule (the form's rule field, else the Rule or Control row of the report table, else the issue title) and, inside a rule, by file type, so a rule that misfires only on one language shows up as one cluster.
4. It scores each rule: `2 x missed + false positives + upvotes + (distinct reporters - 1)`. Missed issues weigh double because they can hide real vulnerabilities.
5. It labels each report with `rule:<id>` and `priority:P1` (score 6 or more), `P2` (3 or more) or `P3`, and rewrites the pinned **Rule quality dashboard** issue with the ranked table (top 200 rules; the rest stay reachable by label).

Issue text is untrusted. It is only parsed by `tools/rulequality`, rule names are reduced to `[a-z0-9._-]`, and nothing from an issue reaches a shell. The plan is deterministic: the same issues always give the same labels and dashboard.

## 3. Fixing

1. Take the highest priority rule from the dashboard.
2. Turn the report's example into a benchmark case: a safe case for a false positive, a vulnerable case for a false negative (`internal/benchmark/corpus.go`, or the rule's fixtures under `rules/semgrep/`).
3. Change the rule until `go test ./...` and `pandaward benchmark --strict` pass.
4. Reference the issues with `Closes #...` in the pull request. Closed reports drop out of the dashboard on the next run.

Because each fix adds a benchmark case, a fixed report cannot silently come back, and the per-rule precision and recall in `pandaward benchmark` grow with real cases from users.
