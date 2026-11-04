package adapters

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// osvResult builds osv-scanner JSON for one lockfile: each package as
// name@version with one advisory.
func osvResult(lockfile string, pkgs ...[2]string) []byte {
	var ps []string
	for i, p := range pkgs {
		ps = append(ps, fmt.Sprintf(`{"package":{"name":%q,"version":%q,"ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-test-%04d","summary":"advisory","database_specific":{"severity":"HIGH"}}]}`, p[0], p[1], i))
	}
	src, _ := json.Marshal(lockfile)
	return []byte(`{"results":[{"source":{"path":` + string(src) + `,"type":"lockfile"},"packages":[` + strings.Join(ps, ",") + `]}]}`)
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func osvPackages(t *testing.T, root string, raw []byte) ([]string, string) {
	t.Helper()
	tool := osvScanner().(*externalTool)
	sigs, err := tool.normalize(&Context{Root: root}, raw)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range sigs {
		got = append(got, s.Key[:strings.LastIndex(s.Key, "/")])
	}
	return got, tool.note
}

func TestOSVDropsLocalOverrides(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"package.json": `{"name":"mono","private":true,"pnpm":{"overrides":{
			"x": "link:./vendor/x",
			"minimist": "file:./vendor/minimist",
			"lodash": "4.17.21",
			"a>qs": "file:./vendor/qs",
			"left-pad@1": "npm:@acme/left-pad@1.3.0"}}}`,
		"pnpm-workspace.yaml":                "packages:\n  - packages/*\noverrides:\n  shared-utils: workspace:*\n",
		"packages/shared-utils/package.json": `{"name":"shared-utils","version":"1.0.0"}`,
	})
	raw := osvResult(filepath.Join(root, "pnpm-lock.yaml"),
		[2]string{"x", "link:vendor/x"},                         // the linked package: dropped
		[2]string{"minimist", "file:vendor/minimist"},           // what osv-scanner 2.7.0 reports for a file: override: dropped
		[2]string{"shared-utils", "link:packages/shared-utils"}, // a workspace: override: dropped
		[2]string{"lodash", "4.17.20"},                          // override to a fixed registry version: checked by version as before
		[2]string{"qs", "6.5.2"},                                // a copy the parent selector does not reach: kept and noted
		[2]string{"left-pad", "1.3.0"},                          // an npm: alias: kept and noted
		[2]string{"express", "4.17.1"},                          // unrelated: kept
	)
	got, note := osvPackages(t, root, raw)
	want := []string{"lodash@4.17.20", "qs@6.5.2", "left-pad@1.3.0", "express@4.17.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("reported %q, want %q", got, want)
	}
	for _, w := range []string{
		"; 3 result(s) dropped for packages an override replaces with a local package (",
		"x link:./vendor/x in package.json", "minimist file:./vendor/minimist in package.json", "shared-utils workspace:* in pnpm-workspace.yaml",
		"; 2 result(s) kept although an override names the package",
		"qs 6.5.2 (override a>qs file:./vendor/qs in package.json)", "left-pad 1.3.0 (override left-pad@1 npm:@acme/left-pad@1.3.0 in package.json)",
	} {
		if !strings.Contains(note, w) {
			t.Errorf("note lacks %q:\n%s", w, note)
		}
	}
}

// A local entry in the lockfile is dropped only when it is the directory
// the override names; another local package of the same name is reported.
func TestOSVLocalEntryMustMatchOverride(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"package.json": `{"overrides":{"minimist":"file:./vendor/minimist"},"resolutions":{"**/@scope/pkg":"portal:./forks/pkg"}}`,
	})
	raw := osvResult(filepath.Join(root, "pnpm-lock.yaml"),
		[2]string{"minimist", "file:other/minimist"},
		[2]string{"@scope/pkg", "portal:forks/pkg"},
	)
	got, note := osvPackages(t, root, raw)
	if !slices.Equal(got, []string{"minimist@file:other/minimist"}) {
		t.Fatalf("reported %q", got)
	}
	if !strings.Contains(note, "1 result(s) dropped") || !strings.Contains(note, "**/@scope/pkg portal:./forks/pkg") || !strings.Contains(note, "1 result(s) kept") {
		t.Errorf("note: %s", note)
	}
}

// Overrides are read next to the lockfile, so a nested workspace uses its
// own root, and a project without overrides gets no note.
func TestOSVOverridesNextToLockfile(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"package.json":          `{"pnpm":{"overrides":{"x":"link:./vendor/x"}}}`,
		"services/package.json": `{"name":"svc"}`,
	})
	got, note := osvPackages(t, root, osvResult(filepath.Join(root, "services", "pnpm-lock.yaml"), [2]string{"x", "link:vendor/x"}))
	if len(got) != 1 || note != "" {
		t.Errorf("an override of another workspace root applied: %q %q", got, note)
	}
}

func TestOverrideTarget(t *testing.T) {
	for key, want := range map[string]string{
		"minimatch":          "minimatch",
		"minimatch@3":        "minimatch",
		"esbuild@<0.25":      "esbuild",
		"@babel/core@7":      "@babel/core",
		"foo>bar":            "bar",
		"foo@1>@scope/bar@2": "@scope/bar",
	} {
		if got := overrideTarget(key, false); got != want {
			t.Errorf("pnpm key %q: %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]string{"**/lodash": "lodash", "parent/@scope/pkg": "@scope/pkg", "lodash": "lodash"} {
		if got := overrideTarget(key, true); got != want {
			t.Errorf("yarn key %q: %q, want %q", key, got, want)
		}
	}
	ovs := npmOverrides("package.json", "", map[string]any{"foo": map[string]any{".": "1.0.0", "bar": "file:./bar"}, "baz@2": "link:./baz"})
	var got []string
	for _, o := range ovs {
		got = append(got, o.key+"="+o.name+"="+o.value)
	}
	slices.Sort(got)
	if want := []string{"baz@2=baz=link:./baz", "foo=foo=1.0.0", "foo>bar=bar=file:./bar"}; !slices.Equal(got, want) {
		t.Errorf("npm overrides = %q, want %q", got, want)
	}
}
