package inventory_test

import (
	"slices"
	"sort"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

// A lockfile at a workspace root covers the member packages its workspace
// patterns match, and nothing else.
func TestMissingLockfileWorkspaces(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"no lockfile anywhere", map[string]string{
			"package.json":     `{"name":"root"}`,
			"sub/package.json": `{"name":"sub"}`,
		}, []string{"package.json", "sub/package.json"}},
		{"root lockfile without workspaces", map[string]string{
			"package.json":      `{"name":"root"}`,
			"package-lock.json": `{"lockfileVersion":3}`,
			"tool/package.json": `{"name":"tool"}`,
		}, []string{"tool/package.json"}},
		{"pnpm workspace", map[string]string{
			"package.json":              `{"name":"root","private":true}`,
			"pnpm-workspace.yaml":       "packages:\n  - 'apps/*'\n  - \"packages/**\"\n",
			"pnpm-lock.yaml":            "lockfileVersion: '9.0'\n",
			"apps/a/package.json":       `{"name":"a"}`,
			"packages/x/y/package.json": `{"name":"y"}`,
			"tools/z/package.json":      `{"name":"z"}`,
		}, []string{"tools/z/package.json"}},
		{"pnpm workspace without lockfile", map[string]string{
			"package.json":        `{"name":"root","private":true}`,
			"pnpm-workspace.yaml": "packages:\n  - 'apps/*'\n",
			"apps/a/package.json": `{"name":"a"}`,
		}, []string{"apps/a/package.json", "package.json"}},
		{"npm workspaces with exclusion", map[string]string{
			"package.json":                 `{"name":"root","workspaces":["packages/*","!packages/legacy"]}`,
			"package-lock.json":            `{"lockfileVersion":3}`,
			"packages/a/package.json":      `{"name":"a"}`,
			"packages/legacy/package.json": `{"name":"legacy"}`,
		}, []string{"packages/legacy/package.json"}},
		{"yarn object workspaces", map[string]string{
			"package.json":     `{"name":"root","workspaces":{"packages":["web"]}}`,
			"yarn.lock":        "# yarn lockfile v1\n",
			"web/package.json": `{"name":"web"}`,
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			inv := walk(t, c.files, inventory.Options{})
			got := slices.Clone(inv.Features["missing_lockfile"])
			sort.Strings(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("missing_lockfile %v, want %v", got, c.want)
			}
		})
	}
}
