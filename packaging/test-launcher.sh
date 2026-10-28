#!/bin/sh
# Checks the launcher with a real build: it runs a verified binary and
# refuses a modified or missing one. Used in CI on macOS and Linux.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "skip: $(uname -s)"; exit 0 ;; esac
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; arm64 | aarch64) arch=arm64 ;; esac

mkdir -p "$work/bin"
(cd "$repo" && CGO_ENABLED=0 go build -o "$work/bin/pandaward-$os-$arch" ./cmd/pandaward)
cp "$repo/packaging/launcher.sh" "$work/bin/pandaward"
chmod +x "$work/bin/pandaward"
(cd "$work/bin" && if command -v sha256sum >/dev/null; then sha256sum "pandaward-$os-$arch"; else shasum -a 256 "pandaward-$os-$arch"; fi > SHA256SUMS)

"$work/bin/pandaward" version | grep -q '^pandaward ' || { echo "FAIL: verified binary did not run"; exit 1; }
echo "ok: verified binary runs"

# A checkout with core.autocrlf rewrites SHA256SUMS with CRLF line endings.
awk '{ printf "%s\r\n", $0 }' "$work/bin/SHA256SUMS" > "$work/sums.crlf" && cp "$work/sums.crlf" "$work/bin/SHA256SUMS"
"$work/bin/pandaward" version | grep -q '^pandaward ' || { echo "FAIL: CRLF SHA256SUMS was not accepted"; exit 1; }
echo "ok: CRLF SHA256SUMS accepted"

printf 'x' >> "$work/bin/pandaward-$os-$arch"
if "$work/bin/pandaward" version >/dev/null 2>&1; then echo "FAIL: modified binary ran"; exit 1; fi
echo "ok: modified binary refused"

rm "$work/bin/pandaward-$os-$arch"
if "$work/bin/pandaward" version >/dev/null 2>&1; then echo "FAIL: missing binary did not fail"; exit 1; fi
echo "ok: missing binary refused"
