# Releasing

1. In a release pull request, set the new version in `.claude-plugin/plugin.json`, `Makefile` (`VERSION ?= X.Y.Z-dev`) and, once it exists, the `version` input default in `action.yml`. Tests fail when the plugin and action versions differ.
2. Merge it, then tag `main`: `git tag -a vX.Y.Z -m "PenSec X.Y.Z"` and `git push origin vX.Y.Z`. The release workflow builds twice, checks that both builds match, attaches binaries, `SHA256SUMS`, the SBOM and `benchmark.json`, attests provenance and the SBOM, and updates the `plugin` and `plugin-windows` branches.
3. Verify the release as in [VERIFYING.md](VERIFYING.md).
4. Update the packages in a follow-up pull request:

   ```sh
   sh packaging/update-packages.sh X.Y.Z
   ```

   This rewrites `Formula/pensec.rb` (Homebrew), `bucket/pensec.json` (Scoop) and `packaging/winget/X.Y.Z/` from the release's `SHA256SUMS`. The `packages` workflow installs through Homebrew and Scoop and checks that the manifests match the release.
5. winget: submit the three files in `packaging/winget/X.Y.Z/` to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) under `manifests/r/RatomirJovanovic/PenSec/X.Y.Z/` (for example with `wingetcreate submit`).
