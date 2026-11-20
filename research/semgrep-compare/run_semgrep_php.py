"""Run configuration B of PROTOCOL.md on the PHP set of research/phpbench.

usage: python -I run_semgrep_php.py <phpbench-work-dir> <out-dir> <semgrep-cmd> <selected.tsv>
For each advisory scanned by research/phpbench/run.py (it must have its
repo checkout in <phpbench-work-dir>/<ghsa>/repo), scans the vulnerable and
the fixed state with Semgrep and writes <out-dir>/<ghsa>/{vuln,fixed}.json,
diff.txt and done, in the shape research/phpbench/score.py reads.
"""
import json
import os
import shutil
import subprocess
import sys

CWE_WORDS = {"79": "xss", "89": "sql", "78": "command", "77": "command", "22": "path traversal", "23": "path traversal",
             "918": "ssrf", "601": "redirect", "502": "deserial", "95": "code-injection", "94": "code-injection",
             "98": "file-inclusion"}
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
PACKS = ["p/default", "p/security-audit", "p/php"]


def sh(args, cwd=None, timeout=3600):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def words(extra):
    cwes = extra.get("metadata", {}).get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    out = set()
    for c in cwes:
        n = c.split(":")[0].replace("CWE-", "").strip()
        if n in CWE_WORDS:
            out.add(CWE_WORDS[n])
    return " ".join(sorted(out))


def scan(sg, repo):
    cmd = [sg, "scan", "--metrics=off", "--json", "--quiet", "--exclude", ".pandaward", "--exclude", "rep", "--timeout", "30"]
    for p in PACKS:
        cmd += ["--config", p]
    try:
        r = sh(cmd + ["."], cwd=repo)
        data = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, ValueError):
        return None
    out = []
    for x in data.get("results", []):
        ex = x["extra"]
        out.append({"file": x["path"].replace("\\", "/"), "start_line": x["start"]["line"],
                    "rule_id": "semgrep." + x["check_id"] + " " + words(ex),
                    "severity": SEV.get(ex.get("severity"), "low")})
    return out


def main(work, out, sg, sel):
    for line in open(sel, encoding="utf-8"):
        ghsa, cwe, repo, fix, parent, _ = line.rstrip("\n").split("\t")
        src = os.path.join(work, ghsa)
        dst = os.path.join(out, ghsa)
        if not os.path.exists(os.path.join(src, "done")) or os.path.exists(os.path.join(dst, "done")):
            continue
        os.makedirs(dst, exist_ok=True)
        g = os.path.join(src, "repo")
        ok = True
        for name, sha in (("vuln", parent), ("fixed", fix)):
            sh(["git", "checkout", "-q", "-f", sha], cwd=g)
            res = scan(sg, g)
            if res is None:
                ok = False
                break
            json.dump(res, open(os.path.join(dst, name + ".json"), "w"))
        shutil.copy(os.path.join(src, "diff.txt"), os.path.join(dst, "diff.txt"))
        open(os.path.join(dst, "done" if ok else "failed"), "w").write("")
        print(ghsa, "ok" if ok else "failed", flush=True)
        # the checkout is not needed again and the work disk is small
        sh(["cmd", "/c", "rmdir", "/s", "/q", g])


main(*sys.argv[1:5])
