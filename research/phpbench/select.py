"""Select the advisories of research/phpbench/PROTOCOL.md.

Usage: python -I select.py advisories.tsv selected.tsv
advisories.tsv comes from the REST API (see the protocol); one line per
advisory: id, cwes, commit urls separated by spaces. Needs `gh`.
"""
import json
import re
import subprocess
import sys

EXCLUDED = {"slimphp/slim", "seldaek/monolog", "digininja/dvwa"}
COMMIT = re.compile(r"^https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})$")


def api(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    return json.loads(out.stdout) if out.returncode == 0 else None


def is_test(p):
    return bool(re.search(r"(^|/)(tests?|spec|specs|__tests__)/", p.lower()))


def main(src, dst):
    rows = [l.rstrip("\n").split("\t") for l in open(src, encoding="utf-8") if l.strip()]
    rows.sort(key=lambda r: r[0])
    kept, skipped = [], []
    for ghsa, cwes, urls in rows:
        commits = sorted({u for u in urls.split() if COMMIT.match(u)})
        if len(commits) != 1:
            continue
        repo, sha = COMMIT.match(commits[0]).groups()
        if repo.lower() in EXCLUDED:
            continue
        c = api(f"/repos/{repo}/commits/{sha}")
        if c is None:
            skipped.append((ghsa, repo, sha, "not fetchable"))
            continue
        php = [f["filename"] for f in c.get("files", []) if f["filename"].endswith(".php") and not is_test(f["filename"])]
        if not php or len(c.get("parents", [])) != 1:
            continue
        kept.append((ghsa, cwes, repo, c["sha"], c["parents"][0]["sha"], len(php)))
        if len(kept) == 100:
            break
    with open(dst, "w", encoding="utf-8") as f:
        for k in kept:
            f.write("\t".join(map(str, k)) + "\n")
    with open(dst + ".skipped", "w", encoding="utf-8") as f:
        for s in skipped:
            f.write("\t".join(s) + "\n")
    print(len(kept), "selected,", len(skipped), "skipped")


main(sys.argv[1], sys.argv[2])
