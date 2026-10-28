// Package version holds build metadata.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is overridden at build time with -ldflags "-X github.com/ratomirjovanovic/pandaward/internal/version.Version=...".
// Without it, a binary built by `go install ...@vX.Y.Z` reports the module
// version Go recorded, and a plain source build reports "dev".
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		Version = fromModule(bi.Main.Version)
	}
}

// fromModule turns a module version such as "v0.1.2" into "0.1.2". Source
// builds record "(devel)" or nothing and stay "dev".
func fromModule(v string) string {
	if v == "" || v == "(devel)" {
		return "dev"
	}
	return strings.TrimPrefix(v, "v")
}
