# Releasing

0. Check that the `go` line in `go.mod` names the latest patch of a supported Go release (see [go.dev/dl](https://go.dev/dl/)); Dependabot does not change it. CI and the release job run govulncheck on the source and on the binaries and fail on any reachable vulnerability, including ones in the standard library of an old toolchain.
1. In a release pull request, set the new version in `.claude-plugin/plugin.json`, `Makefile` (`VERSION ?= X.Y.Z-dev`) and, once it exists, the `version` input default in `action.yml`. Tests fail when the plugin and action versions differ.
2. Merge it, then tag `main`: `git tag -a vX.Y.Z -m "PandaWard X.Y.Z"` and `git push origin vX.Y.Z`. The release workflow builds twice, checks that both builds match, attaches binaries, `SHA256SUMS`, the SBOM and `benchmark.json`, attests provenance and the SBOM, and updates the `plugin`, `plugin-windows` and `plugin-directory` branches. The Claude plugin directory tracks `plugin-directory`, because it refuses files over 5 MiB: that branch has no binaries, and its launcher downloads the binary for the platform from the release on first use and runs it only if it matches the pinned `bin/SHA256SUMS`.
3. Verify the release as in [VERIFYING.md](VERIFYING.md).
4. Update the packages in a follow-up pull request:

   ```sh
   sh packaging/update-packages.sh X.Y.Z
   ```

   This rewrites `Formula/pandaward.rb` (Homebrew), `bucket/pandaward.json` (Scoop) and `packaging/winget/X.Y.Z/` from the release's `SHA256SUMS`. The `packages` workflow installs through Homebrew and Scoop and checks that the manifests match the release.
5. winget: submit the three files in `packaging/winget/X.Y.Z/` to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) under `manifests/r/RatomirJovanovic/PandaWard/X.Y.Z/` (for example with `wingetcreate submit`).
6. MCP Registry: the release carries `pandaward-mcp.mcpb`, and step 4 writes `server.json` with its URL and SHA-256. After the packages pull request is merged, publish the metadata from `main` with the [`mcp-publisher`](https://github.com/modelcontextprotocol/registry) CLI:

   ```sh
   mcp-publisher login github     # device flow in the browser, as ratomirjovanovic
   mcp-publisher publish
   ```

   The registry only stores metadata; clients download the bundle from the release and check its hash.
