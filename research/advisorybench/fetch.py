"""Read the advisory list of one ecosystem from the GitHub REST API.

Usage: python -I fetch.py ecosystem advisories.tsv
One line per advisory: id, CWEs separated by commas, reference URLs separated
by spaces. Only the classes of PROTOCOL.md are requested. Needs `gh`.
"""
import json
import subprocess
import sys

CWES = "79,89,78,77,22,98,601,94,918"


def main(eco, dst):
    out = subprocess.run(
        ["gh", "api", "--paginate", "-H", "Accept: application/vnd.github+json",
         f"/advisories?ecosystem={eco}&type=reviewed&cwes={CWES}&per_page=100"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode != 0:
        sys.exit(out.stderr)
    # --paginate prints one JSON array per page, back to back.
    dec, text, pos, items = json.JSONDecoder(), out.stdout, 0, []
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        arr, pos = dec.raw_decode(text, pos)
        items.extend(arr)
    seen = set()
    with open(dst, "w", encoding="utf-8") as f:
        for a in items:
            gid = a["ghsa_id"]
            if gid in seen:
                continue
            seen.add(gid)
            cwes = ",".join(c["cwe_id"] for c in a.get("cwes") or [])
            refs = " ".join(r if isinstance(r, str) else r.get("url", "") for r in a.get("references") or [])
            f.write(f"{gid}\t{cwes}\t{refs}\n")
    print(eco, len(seen), "advisories")


main(sys.argv[1], sys.argv[2])
