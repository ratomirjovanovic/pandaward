#!/usr/bin/env bash
# Builds the static website into site/_out. The demo replays the hands-free
# Claude Code flow: every command output and the hook message come from
# running the real CLI on the bundled synthetic vulnerable fixture. Only the
# short user and Claude messages are written here.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
out="$here/_out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

rm -rf "$out"
mkdir -p "$out/demo"
cp "$here/index.html" "$here/style.css" "$out/"
cp "$here/demo/index.html" "$here/demo/demo.js" "$out/demo/"
if [ -f "$repo/.claude-plugin/icon.png" ]; then cp "$repo/.claude-plugin/icon.png" "$out/icon.png"; fi

version="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$repo/.claude-plugin/plugin.json" | head -n 1)"
bin="$work/pandaward"
(cd "$repo" && go build -ldflags "-X github.com/ratomirjovanovic/pandaward/internal/version.Version=$version" -o "$bin" ./cmd/pandaward)
fixture="$work/acme-shop"
mkdir -p "$fixture"
(cd "$repo" && go run ./tools/demofixture "$fixture")
cd "$fixture"

rec="$work/rec"
mkdir -p "$rec"
run() { # run NAME ARGS...: save the real output of one pandaward command
  local name="$1"
  shift
  "$bin" "$@" >"$rec/$name.txt" 2>&1 || true
}

run assess assess
"$bin" report --format html,json --out "$work/report" >/dev/null
run fixplan fix-plan

# The fix Claude makes for step 1 of the plan.
cp .github/workflows/ci.yml "$work/ci.before"
sed -i.bak 's/on: \[pull_request_target\]/on: [pull_request]/' .github/workflows/ci.yml && rm -f .github/workflows/ci.yml.bak
(diff -u --label a/.github/workflows/ci.yml --label b/.github/workflows/ci.yml "$work/ci.before" .github/workflows/ci.yml || true) >"$rec/fix.diff"
run retest retest --changed

# Later in the session Claude writes a new file; the PostToolUse hook marks
# it changed and the Stop hook retests it when the turn ends.
mkdir -p src
cat > src/export.js <<'EOF'
const { exec } = require('child_process');
module.exports = (req, res) => { exec(`zip /tmp/out.zip ${req.query.file}`); res.sendStatus(202); };
EOF
cp src/export.js "$rec/export.js"
native="$(cygpath -m "$fixture" 2>/dev/null || printf '%s' "$fixture")" # Windows builds need a native path
printf '{"cwd":"%s","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"%s/src/export.js"}}' "$native" "$native" | "$bin" hook post-edit >/dev/null
printf '{"cwd":"%s","hook_event_name":"Stop"}' "$native" | "$bin" hook stop >"$rec/stop.json"

python3 - "$rec" "$out/demo/transcript.json" <<'PY'
import json, pathlib, re, sys
rec, dest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def txt(name):
    return (rec / name).read_text(encoding="utf-8").rstrip("\n")
plan = txt("fixplan.txt").split("\n\n")
stop = json.loads(txt("stop.json"))
# The written messages below describe these outputs; stop the build if the
# outputs no longer match them.
first = plan[1]
assert "pull_request_target" in first, "fix plan step 1 changed: " + first[:80]
fixed = re.search(r"PW-\d+", first).group(0)
delta = re.search(r"\((\d+) new, (\d+) reopened, (\d+) remediated", txt("retest.txt"))
assert delta and delta.group(1) == "0" and delta.group(2) == "0" and delta.group(3) != "0", "retest delta changed"
assert stop.get("decision") == "block" and "1 new" in stop.get("reason", ""), "stop hook output changed"
steps = [
    {"label": "Ask", "items": [
        {"kind": "user", "text": "Check the security of this project."},
        {"kind": "claude", "text": "I'll run the PandaWard assessment from start to finish and keep a checklist. Nothing is sent to any server; PandaWard only reads the repository."},
    ]},
    {"label": "Assess", "items": [
        {"kind": "tool", "cmd": "pandaward assess", "output": txt("assess.txt")},
        {"kind": "claude", "text": "The scan is complete but not everything was decided: BLOCKED, SUSPECTED and UNSUPPORTED controls are gaps, not a clean result. Next, specialist reviewers look at the undecided areas; whatever they find stays a hypothesis until you decide."},
    ]},
    {"label": "Fix plan", "items": [
        {"kind": "tool", "cmd": "pandaward fix-plan", "output": "\n\n".join(plan[:4])},
    ]},
    {"label": "One question", "items": [
        {"kind": "question", "text": "What should I do next?", "options": [
            "Fix the plan now: all steps, or the first N (recommended)",
            "Record the triage results",
            "Install the missing optional scanners, then rescan",
            "Nothing for now",
        ]},
        {"kind": "user", "text": "Fix the first step."},
    ]},
    {"label": "Fix and retest", "items": [
        {"kind": "claude", "text": "Step 1: the workflow runs untrusted pull request code with repository secrets. Switching the trigger to pull_request:"},
        {"kind": "diff", "output": txt("fix.diff")},
        {"kind": "tool", "cmd": "pandaward retest --changed", "output": txt("retest.txt")},
        {"kind": "claude", "text": fixed + " is remediated and nothing new appeared. Shall I continue with the next steps? The hardcoded keys also have to be revoked at the provider, which only you can do; I can remove them from the code meanwhile."},
    ]},
    {"label": "Automatic retest", "items": [
        {"kind": "user", "text": "Add an export endpoint that zips the requested file."},
        {"kind": "file", "cmd": "Write src/export.js", "output": txt("export.js")},
        {"kind": "hook", "cmd": "PandaWard Stop hook", "output": stop.get("reason") or stop.get("systemMessage", "")},
        {"kind": "claude", "text": "PandaWard retested the file I just wrote and found a new high finding: the shell command is built from the request. I'll switch it to execFile with a fixed argument list and an allow-listed file name, unless you want it another way."},
    ]},
]
dest.write_text(json.dumps(steps, ensure_ascii=False), encoding="utf-8")
PY

cp "$work"/report/*.html "$out/demo/report.html"
cp "$work"/report/*.json "$out/demo/report.json"
# Replace temp paths so the published output does not leak runner details.
python3 - "$out/demo" "$work" <<'PY'
import pathlib, sys
d, work = pathlib.Path(sys.argv[1]), sys.argv[2]
for p in d.glob("*"):
    if p.suffix in (".json", ".html"):
        t = p.read_text(encoding="utf-8").replace(work + "/acme-shop", "~/acme-shop").replace(work, "/tmp/demo")
        p.write_text(t, encoding="utf-8")
PY
touch "$out/.nojekyll"
echo "site built in $out"
