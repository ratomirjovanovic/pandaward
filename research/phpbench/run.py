"""Scan the vulnerable and the fixed state of each selected advisory.

Usage: python -I run.py selected.tsv work_dir pandaward.exe
Writes work_dir/<ghsa>/{vuln,fixed}.json (findings) and diff.txt (git diff -U0).
"""
import json
import os
import subprocess
import sys
import glob


def sh(args, cwd=None, timeout=900):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def scan(pw, d, out):
    if os.path.exists(out):
        return True
    for x in (".pandaward", "rep"):
        sh(["cmd", "/c", "rmdir", "/s", "/q", os.path.join(d, x)])
    sh([pw, "init"], cwd=d)
    r = sh([pw, "scan"], cwd=d)
    sh([pw, "report", "-format", "json", "-out", "./rep"], cwd=d)
    js = glob.glob(os.path.join(d, "rep", "*.json"))
    if not js:
        return False
    data = json.load(open(js[0], encoding="utf-8"))
    json.dump(data.get("findings") or [], open(out, "w"))
    return True


def main(sel, work, pw):
    pw = os.path.abspath(pw)
    for line in open(sel, encoding="utf-8"):
        ghsa, cwe, repo, fix, parent, _ = line.rstrip("\n").split("\t")
        d = os.path.join(work, ghsa)
        os.makedirs(d, exist_ok=True)
        if os.path.exists(os.path.join(d, "done")):
            continue
        g = os.path.join(d, "repo")
        if not os.path.exists(g):
            sh(["git", "init", "-q", g])
            sh(["git", "remote", "add", "origin", f"https://github.com/{repo}.git"], cwd=g)
            r = sh(["git", "fetch", "-q", "--depth", "2", "origin", fix], cwd=g)
            if r.returncode != 0:
                open(os.path.join(d, "failed"), "w").write(r.stderr)
                print(ghsa, "fetch failed")
                continue
        open(os.path.join(d, "diff.txt"), "w", encoding="utf-8").write(sh(["git", "diff", "-U0", parent, fix], cwd=g).stdout)
        ok = True
        for name, sha in (("vuln", parent), ("fixed", fix)):
            sh(["git", "checkout", "-q", "-f", sha], cwd=g)
            ok = scan(pw, g, os.path.join(d, name + ".json")) and ok
        open(os.path.join(d, "done" if ok else "failed"), "w").write("")
        print(ghsa, repo, "ok" if ok else "scan failed", flush=True)


main(*sys.argv[1:4])
