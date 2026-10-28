# False positives and false negatives

PenSec's rules get better from reports by the people who use them. This page describes how a report travels from a user's machine to a fixed rule, and how reports are grouped and prioritized as their number grows.

## 1. Reporting

PenSec never sends anything by itself. It prepares a report and a prefilled GitHub issue link; the user reads it and decides whether to submit.

```sh
pensec feedback false-positive PSEC-0007 --note "the value is a compile-time constant"
pensec feedback false-negative --rule D-003 --note "f-string passed to cursor.execute"
pensec feedback summary        # rules this project closed as false positives
```

In Claude Code, `/pensec:feedback` does the same, and the MCP tool `pensec_prepare_feedback` lets the assistant prepare a report from the conversation. It returns the report and the link with `sent: false`.

A default report contains only:

| Field | Example |
|---|---|
| kind | false-positive |
| rule, control | `code.sql-concat`, D-003 |
| severity, confidence | high, HYPOTHESIS |
| adapter and tool version | builtin-code 0.1.3, semgrep 1.182.0 |
| PenSec and catalog version | 0.1.3, 2026.10-m3 |
| file type | `.py`, `Dockerfile`, `github-workflow.yml` |

`--include-path` adds the redacted path and line, `--include-snippet` up to 12 redacted lines of code. Both need the user's explicit choice. The issue forms ask the reporter to confirm that the report holds no secrets or private data.

Before filing, `pensec feedback` prints a link to existing open reports about the same rule; upvoting one with :+1: counts as much as a new report and avoids duplicates.

## 2. Grouping and priorities

The `rule-quality` workflow runs on every report change and daily:

1. It reads all open `false-positive` and `false-negative` issues through the REST API with pagination, so there is no cap on the number of reports.
2. It groups them by rule (the form's rule field) and, inside a rule, by file type, so a rule that misfires only on one language shows up as one cluster.
3. It scores each rule: `2 x missed + false positives + upvotes + (distinct reporters - 1)`. Missed issues weigh double because they can hide real vulnerabilities.
4. It labels each report with `rule:<id>` and `priority:P1` (score 6 or more), `P2` (3 or more) or `P3`, and rewrites the pinned **Rule quality dashboard** issue with the ranked table (top 200 rules; the rest stay reachable by label).

Issue text is untrusted. It is only parsed by `tools/rulequality`, rule names are reduced to `[a-z0-9._-]`, and nothing from an issue reaches a shell. The plan is deterministic: the same issues always give the same labels and dashboard.

## 3. Fixing

1. Take the highest priority rule from the dashboard.
2. Turn the report's example into a benchmark case: a safe case for a false positive, a vulnerable case for a false negative (`internal/benchmark/corpus.go`, or the rule's fixtures under `rules/semgrep/`).
3. Change the rule until `go test ./...` and `pensec benchmark --strict` pass.
4. Reference the issues with `Closes #...` in the pull request. Closed reports drop out of the dashboard on the next run.

Because each fix adds a benchmark case, a fixed report cannot silently come back, and the per-rule precision and recall in `pensec benchmark` grow with real cases from users.
