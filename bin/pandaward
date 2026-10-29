#!/bin/sh
# PandaWard launcher for macOS and Linux plugin installs. It selects the binary
# for this platform from the plugin's bin/ directory, verifies it against
# SHA256SUMS, and refuses to run anything that does not match.
#
# The plugin-directory branch ships without binaries. There bin/RELEASE holds
# the release download URL: a missing binary is fetched from it once, checked
# against the pinned SHA256SUMS and only then moved into place.
set -eu

die() {
	echo "pandaward launcher: $*" >&2
	exit 126
}

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported operating system $(uname -s); install the pandaward-windows plugin on Windows" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

name="pandaward-$os-$arch"
bin="$dir/$name"
[ -f "$dir/SHA256SUMS" ] || die "missing SHA256SUMS in $dir"

want=$(awk -v n="$name" '{ sub(/\r$/, "") } $2 == n || $2 == "*" n { print $1 }' "$dir/SHA256SUMS")
[ -n "$want" ] || die "no checksum recorded for $name"

hash() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		die "sha256sum or shasum is required to verify $name"
	fi
}

if [ ! -f "$bin" ]; then
	[ -f "$dir/RELEASE" ] || die "missing $name in $dir"
	base=$(sed -n '1{s/\r$//;p;}' "$dir/RELEASE")
	[ -n "$base" ] || die "empty RELEASE in $dir"
	tmp="$dir/.$name.$$"
	trap 'rm -f "$tmp"' EXIT
	echo "pandaward launcher: downloading $name from $base" >&2
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 2 -o "$tmp" "$base/$name" || die "download of $name failed"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$tmp" "$base/$name" || die "download of $name failed"
	else
		die "curl or wget is required to download $name"
	fi
	[ "$(hash "$tmp")" = "$want" ] || die "checksum mismatch for downloaded $name; refusing to use it"
	chmod +x "$tmp" && mv -f "$tmp" "$bin" || die "cannot install $name in $dir"
	trap - EXIT
fi

[ "$(hash "$bin")" = "$want" ] || die "checksum mismatch for $name; refusing to run it"

[ -x "$bin" ] || chmod +x "$bin" 2>/dev/null || die "$name is not executable"
exec "$bin" "$@"
