package adapters

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/golang"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

var goModuleRe = regexp.MustCompile(`(?m)^\s*module\s+("?)([^\s"]+)`)

// goDir is a directory of Go files: one package.
type goDir struct {
	files []string // paths
	names map[string]string
}

// goModuleName names the module of a Go file for the engine: the
// directory and the file, with dots replaced.
func goModuleName(p string) string {
	n := strings.ReplaceAll(strings.TrimSuffix(p, ".go"), ".", "_dot_")
	n = strings.ReplaceAll(n, "/", ".")
	return strings.ReplaceAll(n, "-", "_")
}

// goFiles runs the IR engine on the Go files (#534). A directory is a
// package: each file is a module that imports the package-level names of
// its siblings, and a package of the project is imported by its path in
// the module named in go.mod.
func (a taintAdapter) goLang(ctx context.Context, c *Context, res *Result) (files, parseErrors int, err error) {
	dirs := map[string]*goDir{}
	var order []string
	mods := map[string]string{} // directory of go.mod -> module path
	for _, f := range c.Inv.Files {
		if path.Base(f.Path) == "go.mod" {
			if m := goModuleRe.FindStringSubmatch(strings.Join(f.Lines, "\n")); m != nil {
				mods[path.Dir(f.Path)] = m[2]
			}
		}
		if f.Lang != "go" || strings.HasSuffix(f.Path, "_test.go") || IsTestPath(f.Path) {
			continue
		}
		d := path.Dir(f.Path)
		if dirs[d] == nil {
			dirs[d] = &goDir{names: map[string]string{}}
			order = append(order, d)
		}
		dirs[d].files = append(dirs[d].files, f.Path)
	}
	if len(dirs) == 0 {
		return 0, 0, nil
	}
	spec, err := taint.Load("go")
	if err != nil {
		return 0, 0, err
	}
	// the package-level names of each file
	for _, d := range dirs {
		for _, p := range d.files {
			if f := c.Inv.FileByPath(p); f != nil {
				names, _, ok := golang.Decls(p, strings.Join(f.Lines, "\n"))
				if !ok {
					continue
				}
				for _, n := range names {
					if _, dup := d.names[n]; !dup {
						d.names[n] = goModuleName(p)
					}
				}
			}
		}
	}
	// import path -> directory
	byImport := map[string]string{}
	for modDir, mp := range mods {
		for d := range dirs {
			rel, ok := strings.CutPrefix(d, modDir)
			if modDir == "." {
				rel, ok = d, true
			}
			if !ok {
				continue
			}
			rel = strings.Trim(rel, "/")
			ip := mp
			if rel != "" && rel != "." {
				ip = mp + "/" + rel
			}
			byImport[ip] = d
		}
	}
	pkg := func(importPath string) (map[string]string, bool) {
		if d, ok := byImport[importPath]; ok {
			return dirs[d].names, true
		}
		return nil, false
	}
	byName := map[string]string{}
	for _, d := range dirs {
		for _, p := range d.files {
			byName[goModuleName(p)] = p
		}
	}
	parsed := map[string]*ir.Module{}
	proj := flow.New(spec).NewProject(func(n string) (*ir.Module, []string) {
		p, ok := byName[n]
		if !ok {
			return nil, nil
		}
		f := c.Inv.FileByPath(p)
		if f == nil {
			return nil, nil
		}
		if m, ok := parsed[p]; ok {
			return m, f.Lines
		}
		m, errs := golang.Parse(f.Path, strings.Join(f.Lines, "\n"), golang.Env{
			Module:   n,
			Siblings: dirs[path.Dir(p)].names,
			Package:  pkg,
		})
		if errs > 0 {
			parseErrors++
		}
		parsed[p] = m
		return m, f.Lines
	})
	for _, d := range order {
		for _, p := range dirs[d].files {
			if ctx.Err() != nil {
				return files, parseErrors, nil
			}
			files++
			for _, fd := range proj.Module(goModuleName(p)) {
				if f := c.Inv.FileByPath(fd.File); f != nil && !IsTestPath(f.Path) {
					res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
				}
			}
		}
	}
	return files, parseErrors, nil
}
