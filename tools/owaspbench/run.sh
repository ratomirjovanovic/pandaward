#!/bin/sh
# Fetches OWASP BenchmarkJava at the pinned commit into a temporary
# directory outside the repository and measures Pandaward's built-in rules on
# it. The checkout is only read: no build script, Maven goal or other code
# from it is run. Extra arguments go to the tool, e.g. --json.
#
# Usage: sh tools/owaspbench/run.sh [--json]
# Set OWASPBENCH_KEEP=1 to keep the checkout and print its path.
set -eu

commit=f40c618c5a709afce350ef06ed2899c85cf586e9
url=https://github.com/OWASP-Benchmark/BenchmarkJava

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
if [ "${OWASPBENCH_KEEP:-}" = 1 ]; then
	echo "checkout: $work/BenchmarkJava" >&2
else
	trap 'rm -rf "$work"' EXIT
fi

git init -q "$work/BenchmarkJava"
g() {
	GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
		git -C "$work/BenchmarkJava" -c core.hooksPath=/dev/null -c core.autocrlf=false -c core.symlinks=false "$@"
}
g fetch -q --depth 1 "$url" "$commit"
g checkout -q FETCH_HEAD
test "$(g rev-parse HEAD)" = "$commit" || { echo "checkout is not at $commit" >&2; exit 1; }

cd "$repo"
go run ./tools/owaspbench --repo "$work/BenchmarkJava" "$@"
