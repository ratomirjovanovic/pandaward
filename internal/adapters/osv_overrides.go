package adapters

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Package overrides of a JavaScript workspace root. pnpm.overrides,
// overrides (npm) and resolutions (yarn) in package.json, and overrides in
// pnpm-workspace.yaml, can replace a dependency with a local package
// (link:, file:, workspace:, portal:). osv-scanner then still looks the
// package name up and reports the registry package's advisories against
// code that is not installed: with a pnpm file: override, osv-scanner 2.7.0
// lists the package with the version "file:vendor/x". Such results are
// dropped, but only when the lockfile entry itself is the local package
// the override names; a registry version in the lockfile is kept, since
// that is what a frozen install would put in place.

// override is one override entry.
type override struct {
	file  string // project-relative file that declares it
	key   string // as written: pkg, pkg@range, parent>pkg, **/pkg
	name  string // the package it replaces
	value string // the replacement spec
}

// local reports whether the override replaces the package with a local one.
func (o override) local() bool { return localSpec(o.value) }

func localSpec(v string) bool {
	for _, p := range []string{"link:", "file:", "workspace:", "portal:"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// alias returns the target package of an npm: alias override, or "".
func (o override) alias() string {
	if !strings.HasPrefix(o.value, "npm:") {
		return ""
	}
	return stripRange(strings.TrimPrefix(o.value, "npm:"))
}

// stripRange removes a version or range from "name@range", keeping the
// scope of "@scope/name".
func stripRange(s string) string {
	if i := strings.Index(s[min(1, len(s)):], "@"); i >= 0 {
		return s[:i+1]
	}
	return s
}

// overrideTarget returns the package name an override key replaces: the
// last element of "parent>pkg" (pnpm) or "parent/pkg" and "**/pkg" (yarn),
// without its version range.
func overrideTarget(key string, yarn bool) string {
	if i := strings.LastIndex(key, ">"); i >= 0 {
		key = key[i+1:]
	}
	if yarn {
		parts := strings.Split(key, "/")
		last := parts[len(parts)-1]
		if len(parts) >= 2 && strings.HasPrefix(parts[len(parts)-2], "@") {
			last = parts[len(parts)-2] + "/" + last
		}
		key = last
	}
	return stripRange(strings.TrimSpace(key))
}

// readOverrides returns the overrides declared in the package.json and
// pnpm-workspace.yaml of directory dir (project-relative). Files that are
// missing or unreadable add nothing.
func readOverrides(root, dir string) []override {
	var out []override
	read := func(name string) ([]byte, string) {
		rel := path.Join(dir, name)
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || len(b) > 4<<20 {
			return nil, rel
		}
		return b, rel
	}
	if b, rel := read("package.json"); b != nil {
		var pkg struct {
			Pnpm struct {
				Overrides map[string]string `json:"overrides"`
			} `json:"pnpm"`
			Overrides   map[string]any    `json:"overrides"`
			Resolutions map[string]string `json:"resolutions"`
		}
		if json.Unmarshal(b, &pkg) == nil {
			for k, v := range pkg.Pnpm.Overrides {
				out = append(out, override{file: rel, key: k, name: overrideTarget(k, false), value: v})
			}
			for k, v := range pkg.Resolutions {
				out = append(out, override{file: rel, key: k, name: overrideTarget(k, true), value: v})
			}
			out = append(out, npmOverrides(rel, "", pkg.Overrides)...)
		}
	}
	if b, rel := read("pnpm-workspace.yaml"); b != nil {
		var ws struct {
			Overrides map[string]string `yaml:"overrides"`
		}
		if yaml.Unmarshal(b, &ws) == nil {
			for k, v := range ws.Overrides {
				out = append(out, override{file: rel, key: k, name: overrideTarget(k, false), value: v})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file+out[i].key < out[j].file+out[j].key })
	return out
}

// npmOverrides flattens npm's nested overrides: {"parent": {"pkg": "v"}}
// overrides pkg under parent, and "." sets the parent itself.
func npmOverrides(file, parent string, m map[string]any) []override {
	var out []override
	for k, v := range m {
		key := k
		if parent != "" {
			key = parent + ">" + k
		}
		switch x := v.(type) {
		case string:
			name := stripRange(k)
			if k == "." {
				name, key = stripRange(parent[strings.LastIndex(parent, ">")+1:]), parent
			}
			out = append(out, override{file: file, key: key, name: name, value: x})
		case map[string]any:
			out = append(out, npmOverrides(file, key, x)...)
		}
	}
	return out
}

// localTarget returns the project-relative directory a local spec points
// to, resolved against base (the directory of the file that holds it), or
// "" for workspace: specs, which name a version range, not a path.
func localTarget(spec, base string) string {
	i := strings.Index(spec, ":")
	if i < 0 || strings.HasPrefix(spec, "workspace:") {
		return ""
	}
	p := strings.TrimSpace(spec[i+1:])
	if p == "" || path.IsAbs(filepath.ToSlash(p)) || filepath.IsAbs(p) {
		return ""
	}
	return path.Clean(path.Join(base, filepath.ToSlash(p)))
}

// packageName reads the name in dir/package.json, or "".
func packageName(root, dir string) string {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path.Join(dir, "package.json"))))
	if err != nil {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(b, &p)
	return p.Name
}

// overrideVerdict decides what to do with an osv-scanner result for
// package name at version, read from the lockfile in lockDir. It returns
// the override that makes the result a false positive (drop), or one that
// is relevant but leaves the result standing (kept), or neither.
func overrideVerdict(root, lockDir, name, version string, ovs []override) (drop, kept *override) {
	for i := range ovs {
		o := &ovs[i]
		if o.name != name {
			continue
		}
		switch {
		case o.local():
			if !localSpec(version) {
				// The lockfile pins a registry version: either the override
				// does not reach this copy (a range or parent selector) or the
				// lockfile predates it. Either way that version is installed.
				kept = o
				continue
			}
			got := localTarget(version, lockDir)
			if strings.HasPrefix(o.value, "workspace:") {
				// A workspace package stands in; the lockfile entry must be
				// a local directory whose package has this name.
				if got != "" && packageName(root, got) == name {
					return o, nil
				}
				kept = o
				continue
			}
			if want := localTarget(o.value, path.Dir(o.file)); want != "" && want == got {
				return o, nil
			}
			kept = o
		case o.alias() != "":
			// An npm: alias installs another registry package. Only a
			// local alias target would make the advisory moot, and npm:
			// never points to local code, so the result stays.
			kept = o
		}
	}
	return nil, kept
}
