#!/bin/sh
# Build the release binaries, the SBOM and SHA256SUMS into an output
# directory. The same inputs always give byte-identical outputs, so anyone
# can rebuild a release from its tag and compare the hashes.
#
# Usage: packaging/build-release.sh <version> <outdir>
# Needs the Go version from go.mod; the SBOM step also needs cyclonedx-gomod
# on PATH (skipped with a note when it is missing).
set -eu

version=${1:?version}
out=${2:?output directory}
mkdir -p "$out"

export CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
ldflags="-s -w -buildid= -X github.com/ratomirjovanovic/pensec/internal/version.Version=$version"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
	os=${target%/*}
	arch=${target#*/}
	bin="$out/pensec-$os-$arch"
	[ "$os" = windows ] && bin="$bin.exe"
	# -buildvcs=false: otherwise vcs.modified depends on untracked files in
	# the working tree (including binaries this loop already wrote). The
	# provenance attestation records the exact commit instead.
	GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$bin" ./cmd/pensec
done

# One SBOM covers every binary: all targets link the same modules. Short
# PURLs, no timestamp and no serial number keep it reproducible.
if command -v cyclonedx-gomod >/dev/null 2>&1; then
	cyclonedx-gomod app -licenses -assert-licenses -json -short-purls -noserial -notimestamp \
		-output "$out/pensec.cdx.json" -main cmd/pensec .
else
	echo "cyclonedx-gomod not found; SBOM not generated" >&2
fi

(cd "$out" && sha256sum pensec-* $(ls pensec.cdx.json 2>/dev/null) > SHA256SUMS)
cat "$out/SHA256SUMS"
