"""Scan the vulnerable and the fixed state of each selected advisory.

Usage: python -I run.py selected.tsv work_dir pandaward.exe
Writes work_dir/<ghsa>/{vuln,fixed}.json (findings) and diff.txt (git diff -U0).
"""
import json
import os
import subprocess
import sys
import glob
import re


SCAN_TIMEOUT = 900  # seconds per scan; a timeout is recorded as a failed scan


def sh(args, cwd=None, timeout=900):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def restrict(d):
    """Keep only the built-in adapters, as the protocol says."""
    p = os.path.join(d, ".pandaward", "config.yaml")
    s = open(p, encoding="utf-8", newline="").read()
    m = re.search(r"(\n\s*adapters:\n)((?:\s+- [^\n]+\n)+)", s)
    ind = re.match(r"\s+", m.group(2)).group(0).strip("\n")
    s = s[: m.start(2)] + ind + "- builtin-code\n" + ind + "- builtin-taint\n" + s[m.end(2):]
    open(p, "w", encoding="utf-8", newline="").write(s)


def scan(pw, d, out):
    if os.path.exists(out):
        return True
    for x in (".pandaward", "rep"):
        sh(["cmd", "/c", "rmdir", "/s", "/q", os.path.join(d, x)])
    sh([pw, "init"], cwd=d)
    restrict(d)
    try:
        sh([pw, "scan"], cwd=d, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False
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
        try:
            os.makedirs(d)  # claims the advisory for this process
        except FileExistsError:
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
            if not ok:
                break  # no point in scanning the fixed state when the vulnerable one failed
        open(os.path.join(d, "done" if ok else "failed"), "w").write("")
        print(ghsa, repo, "ok" if ok else "scan failed", flush=True)


main(*sys.argv[1:4])
