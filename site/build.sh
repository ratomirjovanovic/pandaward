#!/usr/bin/env bash
# Builds the static website into site/_out. The demo section is produced by
# running the real CLI against the bundled synthetic vulnerable fixture.
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

bin="$work/pensec"
(cd "$repo" && go build -o "$bin" ./cmd/pensec)
fixture="$work/acme-shop"
mkdir -p "$fixture"
(cd "$repo" && go run ./tools/demofixture "$fixture")

cd "$fixture"

steps=("init" "plan" "scan --quiet" "findings" "graph" "fix-plan" "status" "report --format html,json --out $work/report")
json="["
first=1
for s in "${steps[@]}"; do
  # shellcheck disable=SC2086
  output="$("$bin" $s 2>&1 || true)"
  display="pensec ${s%% --out*}"
  display="${display% --quiet}"
  [ $first -eq 1 ] || json+=","
  first=0
  json+="$(python3 -c 'import json,sys; print(json.dumps({"cmd":sys.argv[1],"output":sys.argv[2]}))' "$display" "$output")"
done
json+="]"
printf '%s\n' "$json" > "$out/demo/transcript.json"
cp "$work"/report/*.html "$out/demo/report.html"
cp "$work"/report/*.json "$out/demo/report.json"
# Replace temp paths so the published output does not leak runner details.
python3 - "$out/demo" "$work" <<'PY'
import pathlib, sys
d, work = pathlib.Path(sys.argv[1]), sys.argv[2]
for p in d.glob("*"):
    if p.suffix in (".json", ".html"):
        t = p.read_text(encoding="utf-8").replace(work, "/tmp/demo")
        p.write_text(t, encoding="utf-8")
PY
touch "$out/.nojekyll"
echo "site built in $out"
