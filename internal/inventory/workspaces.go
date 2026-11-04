package inventory

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// JavaScript workspaces: one lockfile at the workspace root covers every
// member package. A package directory counts as a member only when a root
// declares a pattern that matches it.

// packageJSONWorkspaces returns the "workspaces" patterns of a package.json:
// either an array or the object form {"packages": [...]} used by yarn.
func packageJSONWorkspaces(lines []string) []string {
	var doc struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal([]byte(strings.Join(lines, "\n")), &doc) != nil || len(doc.Workspaces) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(doc.Workspaces, &list) == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(doc.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

var (
	yamlTopKeyRe  = regexp.MustCompile(`^[A-Za-z_][\w-]*\s*:`)
	yamlListRe    = regexp.MustCompile(`^\s*-\s*['"]?([^'"#]+?)['"]?\s*(#.*)?$`)
	yamlPackageRe = regexp.MustCompile(`^packages\s*:\s*(\[(.*)\])?\s*(#.*)?$`)
)

// pnpmWorkspaces returns the "packages" patterns of a pnpm-workspace.yaml,
// in block or flow list form.
func pnpmWorkspaces(lines []string) []string {
	var out []string
	in := false
	for _, l := range lines {
		if m := yamlPackageRe.FindStringSubmatch(strings.TrimRight(l, " \t\r")); m != nil {
			if m[1] != "" {
				for _, p := range strings.Split(m[2], ",") {
					if p = strings.Trim(strings.TrimSpace(p), `'"`); p != "" {
						out = append(out, p)
					}
				}
				return out
			}
			in = true
			continue
		}
		if !in || strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if yamlTopKeyRe.MatchString(l) {
			break
		}
		if m := yamlListRe.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// workspaceMember reports whether rel, a directory relative to the
// workspace root, matches the patterns; a later "!" pattern excludes it.
func workspaceMember(rel string, patterns []string) bool {
	member := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p, "!"), "./"), "/")
		if p == "" {
			continue
		}
		if globSegments(strings.Split(p, "/"), strings.Split(rel, "/")) {
			member = !neg
		}
	}
	return member
}

func globSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if globSegments(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
		return false
	}
	return globSegments(pat[1:], segs[1:])
}

// lockedByWorkspace reports whether the npm package in dir is a member of a
// workspace whose root, an ancestor directory, holds a JavaScript lockfile.
func lockedByWorkspace(dir string, locks map[string]bool, workspaces map[string][]string) bool {
	for a := dir; a != "." && a != "/"; {
		a = path.Dir(a)
		if !locks[a+"|npm"] || len(workspaces[a]) == 0 {
			continue
		}
		rel := dir
		if a != "." {
			rel = strings.TrimPrefix(dir, a+"/")
		}
		if workspaceMember(rel, workspaces[a]) {
			return true
		}
	}
	return false
}
