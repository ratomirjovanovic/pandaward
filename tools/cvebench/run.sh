#!/bin/sh
# Fetches the OpenSSF CVE Benchmark at a pinned commit into a temporary
# directory outside the repository and measures PandaWard on its CVEs. Each
# CVE's project is fetched at the commit before and after the fix into
# CVEBENCH_WORK (default: a cvebench directory in the system temp directory),
# which later runs reuse. Nothing from the benchmark or the projects is built,
# installed or run. Arguments go to the tool.
#
# Usage: sh tools/cvebench/run.sh [--engine builtin,semgrep,opengrep] [--cve CVE-2018-3721,...] [--limit n] [--json]
# Set CVEBENCH_KEEP=1 to keep the benchmark checkout and print its path.
set -eu

commit=91c59fd54b2b768c0f310bb0027d2ac59cdf74d4
url=https://github.com/ossf-cve-benchmark/ossf-cve-benchmark

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
bench="$tmp/ossf-cve-benchmark"
if [ "${CVEBENCH_KEEP:-}" = 1 ]; then
	echo "benchmark checkout: $bench" >&2
else
	trap 'rm -rf "$tmp"' EXIT
fi
work=${CVEBENCH_WORK:-${TMPDIR:-/tmp}/cvebench}
mkdir -p "$work"

git init -q "$bench"
g() {
	GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
		git -C "$bench" -c core.hooksPath=/dev/null -c core.autocrlf=false -c core.symlinks=false "$@"
}
g fetch -q --depth 1 "$url" "$commit"
g checkout -q FETCH_HEAD
test "$(g rev-parse HEAD)" = "$commit" || { echo "checkout is not at $commit" >&2; exit 1; }

cd "$repo"
go run ./tools/cvebench --bench "$bench" --work "$work" "$@"
