package py

import (
	"path"
	"sort"
	"strings"
)

// Files maps the Python files of a project to module names, so that an
// import finds the file it names.
type Files struct {
	pkgDirs map[string]bool
	byName  map[string]string
	// bySuffix maps every dotted tail of a file's path to the files that
	// end with it.
	bySuffix map[string][]string
}

// NewFiles indexes slash-separated file paths relative to the project root.
func NewFiles(paths []string) *Files {
	fs := &Files{pkgDirs: map[string]bool{}, byName: map[string]string{}, bySuffix: map[string][]string{}}
	for _, p := range paths {
		if path.Base(p) == "__init__.py" {
			fs.pkgDirs[path.Dir(p)] = true
		}
	}
	sorted := append([]string(nil), paths...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) < len(sorted[j])
		}
		return sorted[i] < sorted[j]
	})
	for _, p := range sorted {
		name, _ := fs.Name(p)
		if name != "" {
			if _, ok := fs.byName[name]; !ok {
				fs.byName[name] = p
			}
		}
		parts := strings.Split(dottedPath(p), ".")
		for i := range parts {
			s := strings.Join(parts[i:], ".")
			fs.bySuffix[s] = append(fs.bySuffix[s], p)
		}
	}
	return fs
}

// dottedPath turns a/b/c.py into a.b.c and a/b/__init__.py into a.b.
func dottedPath(p string) string {
	p = strings.TrimSuffix(p, ".py")
	if path.Base(p) == "__init__" {
		p = path.Dir(p)
		if p == "." {
			return ""
		}
	}
	return strings.ReplaceAll(p, "/", ".")
}

// Name returns the module name of a file, as Python imports it from the
// directory above its outermost package, and whether it is a package's
// __init__.py.
func (fs *Files) Name(p string) (string, bool) {
	pkg := path.Base(p) == "__init__.py"
	dir := path.Dir(p)
	parts := []string{}
	if !pkg {
		parts = append(parts, strings.TrimSuffix(path.Base(p), ".py"))
	}
	for dir != "." && dir != "/" && fs.pkgDirs[dir] {
		parts = append([]string{path.Base(dir)}, parts...)
		dir = path.Dir(dir)
	}
	return strings.Join(parts, "."), pkg
}

// Lookup returns the file of a module name: the file Python would import,
// or else the only file whose path ends with the name (a source root such
// as src/ or web/).
func (fs *Files) Lookup(name string) string {
	if p, ok := fs.byName[name]; ok {
		return p
	}
	if c := fs.bySuffix[name]; len(c) >= 1 {
		return c[0]
	}
	return ""
}
