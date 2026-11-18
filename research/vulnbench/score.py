"""Match PandaWard findings to the VulnBench 2.0 references (see PROTOCOL.md).

usage: python score.py <suite-root> <reports-dir> <out-prefix>
<reports-dir>/<app>.json is `pandaward report -format json` of a scan of
<suite-root>/fixtures/<app>/project.
"""
import csv, glob, json, os, re, sys, collections, math

suite, reports, out = sys.argv[1:4]
CLASS = {
    "sql-injection": ["sql"], "command-injection": ["command", "cmd", "shell"],
    "path-traversal": ["path", "traversal"], "xss": ["xss"], "ssrf": ["ssrf"],
    "open-redirect": ["redirect"], "insecure-deserialization": ["deserial", "pickle", "yaml"],
    "code-injection": ["code-injection", "eval"], "prototype-pollution": ["prototype"],
    "redos": ["redos", "regex"],
}


def load(p):
    t = re.sub(r"^\s*//.*$", "", open(p, encoding="utf-8").read(), flags=re.M)
    return json.loads(t)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def norm(f):
    return f.replace("\\", "/").lstrip("./")


rows = []
unmatched = collections.defaultdict(list)
for d in sorted(glob.glob(os.path.join(suite, "fixtures", "app-project-*"))):
    app = os.path.basename(d)
    fx = json.load(open(os.path.join(d, "fixture.json"), encoding="utf-8"))
    lang = ("Go" if "go" in fx["languages"] else "Python" if "python" in fx["languages"]
            else "Java" if "java" in fx["languages"] else "JavaScript/TypeScript")
    refs = load(os.path.join(d, "findings-attacker-reachable.json"))["vulnerabilities"]
    rp = os.path.join(reports, app + ".json")
    findings = json.load(open(rp, encoding="utf-8"))["findings"] or [] if os.path.exists(rp) else []
    used = set()
    for r in refs:
        sinks = [x for x in r["filesRelated"] if x.get("type") == "sink"] or r["filesRelated"][-1:]
        hit_any = hit_cls = None
        for i, f in enumerate(findings):
            ff = norm(f["file"])
            for s in sinks:
                if ff.endswith(norm(s["file"])) and abs(f["start_line"] - s["line"]) <= 2:
                    used.add(i)
                    hit_any = hit_any or f
                    words = CLASS.get(r["type"], [r["type"]])
                    if any(w in f["rule_id"].lower() for w in words):
                        hit_cls = hit_cls or f
        sev = lambda f: f["severity"] if f else ""
        rows.append({
            "app": app, "language": lang, "id": r["id"], "type": r["type"],
            "located": bool(hit_any), "located_rule": hit_any["rule_id"] if hit_any else "",
            "located_severity": sev(hit_any), "same_weakness": bool(hit_cls),
            "same_weakness_rule": hit_cls["rule_id"] if hit_cls else "",
            "high_or_critical": bool(hit_any) and hit_any["severity"] in ("high", "critical"),
        })
    for i, f in enumerate(findings):
        if i not in used and f["severity"] in ("high", "critical") and not f["rule_id"].startswith(("secret", "gitleaks", "supply", "infra")):
            unmatched[app].append((f["rule_id"], f["file"], f["start_line"]))

with open(out + "-refs.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
with open(out + "-unmatched.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["app", "rule", "file", "line"])
    for a, v in unmatched.items():
        for x in v:
            w.writerow([a, *x])


def line(name, sub):
    n = len(sub)
    out_ = [name, str(n)]
    for key in ("located", "same_weakness", "high_or_critical"):
        k = sum(1 for x in sub if x[key])
        lo, hi = wilson(k, n)
        out_.append(f"{k}/{n} ({lo:.0%} to {hi:.0%})")
    return "| " + " | ".join(out_) + " |"


print("| group | references | located | same weakness | located at high or critical |\n|---|---|---|---|---|")
print(line("all", rows))
for g in sorted({r["language"] for r in rows}):
    print(line(g, [r for r in rows if r["language"] == g]))
for g in sorted({r["type"] for r in rows}):
    print(line(g, [r for r in rows if r["type"] == g]))
print("unmatched high or critical code findings:", sum(len(v) for v in unmatched.values()))
