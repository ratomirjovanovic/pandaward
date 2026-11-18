"""Run configuration B of PROTOCOL.md on VulnBench 2.0.

usage: python -I run_semgrep.py <suite-root> <out-dir> <semgrep-cmd>
Writes <out-dir>/<app>.json in the shape of `pandaward report -format json`
(file, start_line, rule_id, severity) so that research/vulnbench/score.py
scores it; the rule id carries the classes of the rule's CWE metadata.
"""
import json
import os
import subprocess
import sys

PACKS = {"go": ["p/golang"], "python": ["p/python"], "java": ["p/java"],
         "javascript": ["p/javascript"], "typescript": ["p/javascript", "p/typescript"]}
CWE_WORDS = {"79": "xss", "89": "sql", "78": "command", "77": "command", "22": "path traversal", "23": "path traversal",
             "918": "ssrf", "601": "redirect", "502": "deserial", "95": "code-injection", "94": "code-injection",
             "1321": "prototype", "1333": "redos", "98": "file-inclusion"}
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


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


def main(suite, out, sg):
    os.makedirs(out, exist_ok=True)
    for app in sorted(os.listdir(os.path.join(suite, "fixtures"))):
        if not app.startswith("app-project-"):
            continue
        fx = json.load(open(os.path.join(suite, "fixtures", app, "fixture.json"), encoding="utf-8"))
        packs = ["p/default", "p/security-audit"]
        for lang in fx["languages"]:
            for p in PACKS.get(lang, []):
                if p not in packs:
                    packs.append(p)
        cmd = [sg, "scan", "--metrics=off", "--json", "--quiet", "--exclude", ".pandaward", "--timeout", "30"]
        for p in packs:
            cmd += ["--config", p]
        proj = os.path.join(suite, "fixtures", app, "project")
        r = subprocess.run(cmd + ["."], cwd=proj, capture_output=True, text=True, encoding="utf-8", errors="replace")
        try:
            data = json.loads(r.stdout)
        except ValueError:
            data = {"results": [], "errors": [{"message": "no json, exit %d" % r.returncode}]}
        findings = []
        for x in data.get("results", []):
            ex = x["extra"]
            findings.append({"file": x["path"].replace("\\", "/"), "start_line": x["start"]["line"],
                             "rule_id": "semgrep." + x["check_id"] + " " + words(ex),
                             "severity": SEV.get(ex.get("severity"), "low")})
        json.dump({"findings": findings, "errors": [e.get("message", "")[:200] for e in data.get("errors", [])][:20], "exit": r.returncode},
                  open(os.path.join(out, app + ".json"), "w"))
        print(app, r.returncode, len(findings), flush=True)


main(*sys.argv[1:4])
