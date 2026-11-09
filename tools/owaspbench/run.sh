#!/bin/sh
# Fetches an OWASP Benchmark at its pinned commit into a temporary directory
# outside the repository and measures PandaWard on it. The checkout is only
# read: no build script, Maven goal, pip install or other code from it is
# run. Arguments go to the tool; --suite java (default) or --suite python
# picks the benchmark.
#
# Usage: sh tools/owaspbench/run.sh [--suite java|python] [--engine builtin,semgrep,opengrep] [--json]
# Set OWASPBENCH_KEEP=1 to keep the checkout and print its path.
set -eu

suite=java
prev=
for a in "$@"; do
	case "$a" in
	--suite=*) suite=${a#--suite=} ;;
	esac
	if [ "$prev" = --suite ]; then suite=$a; fi
	prev=$a
done

# The pins below must match the suites in score.go (checked by a test).
case "$suite" in
java)
	commit=f40c618c5a709afce350ef06ed2899c85cf586e9 url=https://github.com/OWASP-Benchmark/BenchmarkJava
	;;
python)
	commit=f1291485808b66e20ddb6b01b10dc71b3df8c8ba url=https://github.com/OWASP-Benchmark/BenchmarkPython
	;;
*)
	echo "unknown suite $suite; choose java or python" >&2
	exit 2
	;;
esac

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
checkout="$work/$(basename "$url")"
if [ "${OWASPBENCH_KEEP:-}" = 1 ]; then
	echo "checkout: $checkout" >&2
else
	trap 'rm -rf "$work"' EXIT
fi

git init -q "$checkout"
g() {
	GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
		git -C "$checkout" -c core.hooksPath=/dev/null -c core.autocrlf=false -c core.symlinks=false "$@"
}
g fetch -q --depth 1 "$url" "$commit"
g checkout -q FETCH_HEAD
test "$(g rev-parse HEAD)" = "$commit" || { echo "checkout is not at $commit" >&2; exit 1; }

cd "$repo"
go run ./tools/owaspbench --repo "$checkout" "$@"
