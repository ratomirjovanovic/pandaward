"""Combine the two scored configurations of PROTOCOL.md.

usage: python -I compare.py A-refs.csv B-refs.csv out_prefix
Prints per language and class the counts of A, B and C (union) with Wilson
95% intervals, and writes the lists of references only one tool locates.
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
    return ((c - r) / d, (c + r) / d)


A = {r["id"]: r for r in csv.DictReader(open(a_path, encoding="utf-8"))}
B = {r["id"]: r for r in csv.DictReader(open(b_path, encoding="utf-8"))}
t = lambda r, k: r[k] == "True"
groups = collections.defaultdict(list)
for i, r in A.items():
    groups["all"].append(i)
    groups[r["language"]].append(i)
    groups[r["type"]].append(i)


def cell(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({lo:.0%} to {hi:.0%})"


for key, name in (("located", "located"), ("same_weakness", "same weakness"), ("high_or_critical", "high or critical")):
    print(f"\n{name}\n| group | refs | PandaWard (A) | Semgrep (B) | both (C) |\n|---|---|---|---|---|")
    for g, ids in groups.items():
        n = len(ids)
        a = sum(t(A[i], key) for i in ids)
        b = sum(t(B[i], key) for i in ids)
        c = sum(t(A[i], key) or t(B[i], key) for i in ids)
        print(f"| {g} | {n} | {cell(a, n)} | {cell(b, n)} | {cell(c, n)} |")
with open(out + "-only.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "type", "language", "only", "rule"])
    for i, r in A.items():
        a, b = t(r, "located"), t(B[i], "located")
        if a and not b:
            w.writerow([i, r["type"], r["language"], "pandaward", r["located_rule"]])
        if b and not a:
            w.writerow([i, r["type"], r["language"], "semgrep", B[i]["located_rule"]])
