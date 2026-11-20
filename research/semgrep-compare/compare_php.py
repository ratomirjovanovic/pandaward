"""Combine the two scored configurations of PROTOCOL.md on the PHP set.

usage: python -I compare_php.py A-refs.csv B-refs.csv out_prefix
A and B are the outputs of research/phpbench/score.py for PandaWard and for
Semgrep. Only advisories scanned by both are counted. Prints per class the
counts of A, B and C (union) with Wilson 95% intervals and writes the list
of references only one tool locates.
"""
import collections
import csv
import math
import sys

a_path, b_path, out = sys.argv[1:4]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - r) / d), (c + r) / d)


def load(p):
    return {r["id"]: r for r in csv.DictReader(open(p, encoding="utf-8")) if r["status"] == "ok"}


A, B = load(a_path), load(b_path)
ids = sorted(set(A) & set(B))
print(f"scanned by both: {len(ids)} (A {len(A)}, B {len(B)})")
t = lambda r, k: r[k] == "True"
groups = collections.defaultdict(list)
for i in ids:
    groups["all"].append(i)
    for c in A[i]["cwes"].split(","):
        if c in ("CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-94", "CWE-601", "CWE-918", "CWE-98"):
            groups[c].append(i)
            break
    else:
        groups["other"].append(i)


def cell(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({lo:.0%} to {hi:.0%})"


for key, name in (("located_all", "located"), ("same_all", "same weakness"), ("located_high", "high or critical")):
    print(f"\n{name}\n| group | refs | PandaWard (A) | Semgrep (B) | both (C) |\n|---|---|---|---|---|")
    for g, gi in groups.items():
        n = len(gi)
        a = sum(t(A[i], key) for i in gi)
        b = sum(t(B[i], key) for i in gi)
        c = sum(t(A[i], key) or t(B[i], key) for i in gi)
        print(f"| {g} | {n} | {cell(a, n)} | {cell(b, n)} | {cell(c, n)} |")

with open(out + "-only.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "cwes", "only", "rule"])
    for i in ids:
        a, b = t(A[i], "located_all"), t(B[i], "located_all")
        if a and not b:
            w.writerow([i, A[i]["cwes"], "pandaward", A[i]["rule_all"]])
        if b and not a:
            w.writerow([i, A[i]["cwes"], "semgrep", B[i]["rule_all"]])
