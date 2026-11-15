package java

import (
	"sort"
	"strings"
)

// Files maps the Java files of a project to class names, so that a
// qualified class name finds its file: org.acme.Utils is the file whose
// path ends with org/acme/Utils.java, whatever source root holds it.
type Files struct {
	bySuffix map[string][]string
}

// NewFiles indexes slash-separated file paths relative to the project root.
func NewFiles(paths []string) *Files {
	fs := &Files{bySuffix: map[string][]string{}}
	sorted := append([]string(nil), paths...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) < len(sorted[j])
		}
		return sorted[i] < sorted[j]
	})
	for _, p := range sorted {
		parts := strings.Split(strings.TrimSuffix(p, ".java"), "/")
		for i := range parts {
			s := strings.Join(parts[i:], ".")
			fs.bySuffix[s] = append(fs.bySuffix[s], p)
		}
	}
	return fs
}

// Lookup returns the file of a qualified class name, or "".
func (fs *Files) Lookup(name string) string {
	if c := fs.bySuffix[name]; len(c) > 0 {
		return c[0]
	}
	return ""
}
