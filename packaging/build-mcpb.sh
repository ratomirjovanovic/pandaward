#!/bin/sh
# Builds the MCPB bundle for the MCP Registry from release binaries:
#   sh packaging/build-mcpb.sh VERSION DIST
# DIST must hold the pandaward release binaries; the bundle is written to
# DIST/pandaward-mcp.mcpb and added to DIST/SHA256SUMS.
set -eu
version=$1
dist=$2
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/bin"
sed "s/\"VERSION\"/\"$version\"/" "$here/mcpb/manifest.json" > "$stage/manifest.json"
cp "$here/../.claude-plugin/icon.png" "$stage/icon.png"
cp "$here/launcher.sh" "$stage/bin/pandaward"
for p in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
	cp "$dist/pandaward-$p" "$stage/bin/"
done
cp "$dist/pandaward-windows-amd64.exe" "$stage/bin/pandaward.exe"
chmod 0755 "$stage/bin"/*
(cd "$stage/bin" && sha256sum pandaward-* pandaward.exe > SHA256SUMS)

out="$(CDPATH= cd -- "$dist" && pwd)/pandaward-mcp.mcpb"
rm -f "$out"
# Fixed timestamps and order keep the bundle the same for the same inputs.
find "$stage" -exec touch -d "1980-01-02T00:00:00Z" {} +
(cd "$stage" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -X -q "$out" -@)
(cd "$dist" && sha256sum pandaward-mcp.mcpb >> SHA256SUMS)
echo "$out"
