#!/bin/sh
# PenSec launcher for macOS and Linux plugin installs. It selects the binary
# for this platform from the plugin's bin/ directory, verifies it against
# SHA256SUMS, and refuses to run anything that does not match.
set -eu

die() {
	echo "pensec launcher: $*" >&2
	exit 126
}

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported operating system $(uname -s); install the pensec-windows plugin on Windows" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

name="pensec-$os-$arch"
bin="$dir/$name"
[ -f "$bin" ] || die "missing $name in $dir"
[ -f "$dir/SHA256SUMS" ] || die "missing SHA256SUMS in $dir"

want=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$dir/SHA256SUMS")
[ -n "$want" ] || die "no checksum recorded for $name"

if command -v sha256sum >/dev/null 2>&1; then
	got=$(sha256sum "$bin" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
	got=$(shasum -a 256 "$bin" | awk '{print $1}')
else
	die "sha256sum or shasum is required to verify $name"
fi
[ "$got" = "$want" ] || die "checksum mismatch for $name; refusing to run it"

[ -x "$bin" ] || chmod +x "$bin" 2>/dev/null || die "$name is not executable"
exec "$bin" "$@"
