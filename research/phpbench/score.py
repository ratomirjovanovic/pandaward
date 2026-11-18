"""Score the run of research/phpbench/PROTOCOL.md.

usage: python -I score.py selected.tsv work_dir out_prefix
Writes <out_prefix>-refs.csv (one line per advisory) and prints the tables.
"""
import csv
import collections
import json
import math
import os
import re
import sys

sel, work, out = sys.argv[1:4]
CLASS = {
    "79": ["xss"], "89": ["sql"], "78": ["command", "cmd", "shell"], "77": ["command", "cmd", "shell"],
    "22": ["path", "traversal"], "98": ["file-inclusion", "include"], "601": ["redirect"],
    "94": ["code-injection", "eval"], "918": ["ssrf"],
}
HIGH = {"high", "critical"}
WINDOW = 5


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def ranges(diff):
    """old-side ranges per file of `git diff -U0`, tests excluded."""
    res, cur = collections.defaultdict(list), None
    for line in diff.splitlines():
        if line.startswith("--- "):
            cur = line[4:].lstrip("a/") if line != "--- /dev/null" else None
        elif line.startswith("@@") and cur:
            m = re.match(r"@@ -(\d+)(?:,(\d+))? ", line)
            s, n = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            res[cur].append((s, s + max(n, 1) - 1))
    return {f: r for f, r in res.items() if f.endswith(".php") and not re.search(r"(^|/)(tests?|spec|specs|__tests__)/", f.lower())}


def hits(findings, refs, words, high_only):
    any_hit = cls_hit = None
    for f in findings:
        if high_only and (f.get("severity") or "").lower() not in HIGH:
            continue
        file = f["file"].replace("\\", "/")
        for rf, rs in refs.items():
            if file != rf:
                continue
            if any(a - WINDOW <= f["start_line"] <= b + WINDOW for a, b in rs):
                any_hit = any_hit or f
                if any(w in f["rule_id"].lower() for w in words):
                    cls_hit = cls_hit or f
    return any_hit, cls_hit


rows = []
for line in open(sel, encoding="utf-8"):
    ghsa, cwes, repo, fix, parent, _ = line.rstrip("\n").split("\t")
    d = os.path.join(work, ghsa)
    row = {"id": ghsa, "repo": repo, "cwes": cwes}
    if not os.path.exists(os.path.join(d, "done")):
        row["status"] = "no result"
        rows.append(row)
        continue
    refs = ranges(open(os.path.join(d, "diff.txt"), encoding="utf-8").read())
    vuln = json.load(open(os.path.join(d, "vuln.json")))
    fixed = json.load(open(os.path.join(d, "fixed.json")))
    words = sorted({w for c in cwes.split(",") for w in CLASS.get(c.replace("CWE-", ""), [])})
    row["status"] = "ok"
    row["findings"] = len(vuln)
    for tag, high in (("all", False), ("high", True)):
        a, c = hits(vuln, refs, words, high)
        row[f"located_{tag}"] = bool(a)
        row[f"same_{tag}"] = bool(c)
        row[f"rule_{tag}"] = (c or a or {}).get("rule_id", "")
    _, after = hits(fixed, refs, words, False)
    row["after_fix"] = bool(after)
    row["after_fix_rule"] = (after or {}).get("rule_id", "")
    rows.append(row)

keys = ["id", "repo", "cwes", "status", "findings", "located_all", "same_all", "rule_all", "located_high", "same_high", "rule_high", "after_fix", "after_fix_rule"]
with open(out + "-refs.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, keys, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)


def cls(r):
    for c in ("79", "89", "78", "77", "22", "98", "601", "94", "918"):
        if "CWE-" + c in r["cwes"].split(","):
            return {"77": "78"}.get(c, c)
    return "other"


ok = [r for r in rows if r["status"] == "ok"]
print(f"{len(ok)} scanned of {len(rows)}")
groups = {"all": ok}
for r in ok:
    groups.setdefault("CWE-" + cls(r), []).append(r)
print("| group | advisories | located (all) | same weakness (all) | located (high+) | reported after fix |")
print("|---|---|---|---|---|---|")
for g, rs in groups.items():
    n = len(rs)

    def cell(k):
        s = sum(1 for r in rs if r[k])
        lo, hi = wilson(s, n)
        return f"{s}/{n} ({lo:.0%} to {hi:.0%})"
    print(f"| {g} | {n} | {cell('located_all')} | {cell('same_all')} | {cell('located_high')} | {cell('after_fix')} |")
