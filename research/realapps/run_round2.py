"""Scan the applications of targets-round2.md at their pinned commits.

Usage: python -I run_round2.py targets.tsv work_dir pandaward.exe
targets.tsv is the output of select_round2.py (language, repo, stars, size,
commit, date, policy). Writes work_dir/<owner>__<repo>/findings.json (all
findings of the report) and state.txt (ok, failed or timeout). A scan runs
with the built-in adapters only, as targets-round2.md says, with a limit of
900 seconds. Windows paths: it removes directories with `cmd /c rmdir`.
"""
import glob
import json
import os
import re
import subprocess
import sys

TIMEOUT = 900


def sh(args, cwd=None, timeout=1800):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def restrict(d):
    p = os.path.join(d, ".pandaward", "config.yaml")
    s = open(p, encoding="utf-8", newline="").read()
    m = re.search(r"(\n\s*adapters:\n)((?:\s+- [^\n]+\n)+)", s)
    ind = re.match(r"\s+", m.group(2)).group(0).strip("\n")
    s = s[: m.start(2)] + ind + "- builtin-code\n" + ind + "- builtin-taint\n" + s[m.end(2):]
    open(p, "w", encoding="utf-8", newline="").write(s)


def main(targets, work, pw):
    pw = os.path.abspath(pw)
    for line in open(targets, encoding="utf-8"):
        lang, repo, _, _, commit, _, _ = line.rstrip("\n").split("\t")
        d = os.path.join(work, repo.replace("/", "__"))
        try:
            os.makedirs(d)  # claims the application for this process
        except FileExistsError:
            continue
        src = os.path.join(d, "src")
        sh(["git", "init", "-q", src])
        sh(["git", "remote", "add", "origin", f"https://github.com/{repo}.git"], cwd=src)
        r = sh(["git", "fetch", "-q", "--depth", "1", "origin", commit], cwd=src)
        state = "failed"
        if r.returncode == 0:
            sh(["git", "checkout", "-q", "-f", commit], cwd=src)
            sh([pw, "init"], cwd=src)
            restrict(src)
            try:
                sh([pw, "scan"], cwd=src, timeout=TIMEOUT)
                sh([pw, "report", "-format", "json", "-out", "./rep"], cwd=src)
                js = glob.glob(os.path.join(src, "rep", "*.json"))
                if js:
                    data = json.load(open(js[0], encoding="utf-8"))
                    json.dump(data.get("findings") or [], open(os.path.join(d, "findings.json"), "w"))
                    state = "ok"
            except subprocess.TimeoutExpired:
                state = "timeout"
        open(os.path.join(d, "state.txt"), "w").write(state)
        print(repo, state, flush=True)


main(*sys.argv[1:4])
