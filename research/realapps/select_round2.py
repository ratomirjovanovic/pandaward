"""Select the applications of research/realapps/targets-round2.md.

Usage: python -I select_round2.py targets.tsv
The rule is applied without looking at any scan result. For each language,
take the repositories of the GitHub search

  language:<L> topic:self-hosted stars:1000..25000 created:<2024-11-20 pushed:>2026-08-20
  archived:false fork:false           (sorted by stars, descending)

in order and keep one when it has a published security policy, is no list
of links (no "awesome" in its name or description), and its repository is at
most 300 MB. Stop at 4 per language. The commit is the head of the default
branch at selection time. Needs `gh`.
"""
import json
import subprocess
import sys

LANGS = ["TypeScript", "JavaScript", "Python", "Java", "Go"]
PER = 4
MAX_KB = 300_000


def gh(*args):
    out = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode != 0:
        sys.exit(out.stderr)
    return out.stdout


QUERY = """query($o:String!,$n:String!){repository(owner:$o,name:$n){
  securityPolicyUrl isSecurityPolicyEnabled
  defaultBranchRef{name target{... on Commit{oid committedDate}}}
  primaryLanguage{name}}}"""


def main(dst):
    rows = []
    for lang in LANGS:
        q = f"language:{lang.lower()} topic:self-hosted stars:1000..25000 created:<2024-11-20 pushed:>2026-08-20 archived:false fork:false"
        items = json.loads(gh("api", "-X", "GET", "search/repositories", "-f", f"q={q}", "-f", "sort=stars", "-f", "per_page=40"))["items"]
        kept = 0
        for it in items:
            name = it["full_name"]
            if "awesome" in name.lower() or "awesome" in (it.get("description") or "").lower() or it["size"] > MAX_KB:
                continue
            o, n = name.split("/")
            d = json.loads(gh("api", "graphql", "-f", f"query={QUERY}", "-F", f"o={o}", "-F", f"n={n}"))["data"]["repository"]
            if not d["isSecurityPolicyEnabled"]:
                continue
            c = d["defaultBranchRef"]["target"]
            rows.append((lang, name, it["stargazers_count"], it["size"], c["oid"], c["committedDate"][:10], d["securityPolicyUrl"]))
            kept += 1
            if kept == PER:
                break
    with open(dst, "w", encoding="utf-8") as f:
        for r in rows:
            f.write("\t".join(map(str, r)) + "\n")
    print(len(rows), "applications")


main(sys.argv[1])
