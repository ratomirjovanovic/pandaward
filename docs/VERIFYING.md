# Verifying a PenSec release

Every release on GitHub carries, next to the binaries:

- `SHA256SUMS`: checksums of every binary and of the SBOM
- `pensec.cdx.json`: a CycloneDX 1.6 SBOM listing every Go module linked into the binaries, with its version, hash and license
- build provenance and SBOM attestations, signed through GitHub's Sigstore integration and stored with the repository

The binaries are reproducible: building the tag again with the same Go version gives byte-identical files. The release workflow and CI both build twice and fail if the hashes differ.

## 1. Check the checksums

```sh
gh release download v0.1.6 -R ratomirjovanovic/pensec
sha256sum -c SHA256SUMS
```

## 2. Check where the binary was built

```sh
gh attestation verify pensec-linux-amd64 -R ratomirjovanovic/pensec
```

This proves the file was built by this repository's release workflow from the tagged commit. Repeat for the binary you use.

## 3. Check the SBOM attestation

```sh
gh attestation verify pensec-linux-amd64 -R ratomirjovanovic/pensec \
  --predicate-type https://cyclonedx.org/bom
```

The attested SBOM is the same document as `pensec.cdx.json` in the release.

## 4. Rebuild it yourself (optional)

Use the Go version named in `go.mod`, then:

```sh
git clone https://github.com/ratomirjovanovic/pensec && cd pensec
git checkout v0.1.6
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.11.0
sh packaging/build-release.sh 0.1.6 rebuilt
diff rebuilt/SHA256SUMS SHA256SUMS
```

The version argument is the tag without the leading `v`. Without `cyclonedx-gomod` the script skips the SBOM and its line is missing from `SHA256SUMS`; the binary lines must still match.

## Plugin installs

The `plugin` and `plugin-windows` branches that Claude Code installs from contain the same binaries as the release, with a `bin/SHA256SUMS` file. Compare those hashes with the release's `SHA256SUMS`, or run `gh attestation verify` on the file under `bin/`.
