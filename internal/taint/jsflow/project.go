package jsflow

import (
	"path"
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// Project analyzes the files of one project together. A call of a function
// imported from another file of the project follows that function's
// summary, so a flow from a route handler through a helper module to a sink
// is one finding, reported at the sink with every step on the way.
type Project struct {
	spec     *taint.Spec
	opt      Options
	src      func(string) (string, bool)
	resolver func(from, spec string) string
	paths    map[string]bool
	// deps are the project files each file imports; refs counts for each
	// file the importers whose analysis is still kept. A file's analysis
	// is kept while an importer may need it and freed after that.
	deps     map[string][]string
	refs     map[string]int
	mods     map[string]*analyzer
	busy     map[string]bool
	reported map[string]bool
	seen     map[string]bool
	// ParseErrors counts the files with syntax the parser skipped.
	ParseErrors int
}

// NewProject returns a project of the files in paths (slash-separated and
// relative to the project root). src returns the text of a file. resolve
// maps an import in a file to the file it names, or ""; nil resolves
// relative imports only.
func NewProject(spec *taint.Spec, opt Options, paths []string, src func(string) (string, bool), resolve func(from, spec string) string) *Project {
	p := &Project{spec: spec, opt: opt, src: src, resolver: resolve, paths: map[string]bool{}, deps: map[string][]string{}, refs: map[string]int{},
		mods: map[string]*analyzer{}, busy: map[string]bool{}, reported: map[string]bool{}, seen: map[string]bool{}}
	for _, f := range paths {
		p.paths[f] = true
	}
	for _, f := range paths {
		text, ok := src(f)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, m := range importRe.FindAllStringSubmatch(text, -1) {
			if r := p.resolve(f, m[1]); r != "" && r != f && !seen[r] {
				seen[r] = true
				p.deps[f] = append(p.deps[f], r)
				p.refs[r]++
			}
		}
	}
	return p
}

// importRe finds the module of import, export from and require: a cheap
// pass that only decides how long analyses are kept. An import it misses
// costs a second analysis of that file, not a flow.
var importRe = regexp.MustCompile(`(?:\bfrom|\bimport|\brequire\s*\()\s*\(?\s*['"]([^'"\n]+)['"]`)

// Analyze returns the flows that start in file. A file analyzed before,
// because another file imports it, returns its flows on the first call.
func (p *Project) Analyze(file string) []taint.Finding {
	if p.reported[file] {
		return nil
	}
	m := p.module(file)
	if m == nil {
		return nil
	}
	p.reported[file] = true
	out := m.out
	m.out = nil
	p.release(file)
	return out
}

// release frees the analysis of file once it has been reported and no
// importer needs it, then that of the files it imports in turn.
func (p *Project) release(file string) {
	if !p.reported[file] || p.refs[file] > 0 || p.busy[file] {
		return
	}
	if _, ok := p.mods[file]; !ok {
		return
	}
	delete(p.mods, file)
	for _, d := range p.deps[file] {
		p.refs[d]--
		p.release(d)
	}
}

// module returns the analysis of file, running it on first use. It returns
// nil for a file outside the project or one whose analysis is under way
// (an import cycle).
func (p *Project) module(file string) *analyzer {
	if m, ok := p.mods[file]; ok {
		return m
	}
	if p.busy[file] || !p.paths[file] {
		return nil
	}
	text, ok := p.src(file)
	if !ok {
		return nil
	}
	p.busy[file] = true
	defer delete(p.busy, file)
	f := js.Parse(file, text, js.OptionsFor(file))
	if len(f.Errors) > 0 {
		p.ParseErrors++
	}
	a := newAnalyzer(f, p.spec, p.opt, p)
	a.run(f)
	if p.reported[file] {
		a.out = nil // analyzed again for an import the first pass missed
	}
	p.mods[file] = a
	return a
}

// sourceExts are the extensions an import without one may resolve to.
var sourceExts = []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"}

// resolve returns the project file an import of spec in from names, or "".
func (p *Project) resolve(from, spec string) string {
	spec = strings.TrimSpace(spec)
	var r string
	switch {
	case p.resolver != nil:
		r = p.resolver(from, spec)
	case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
		r = p.file(path.Join(path.Dir(from), spec))
	}
	if !p.paths[r] {
		return ""
	}
	return r
}

// file finds the source file for an import path without its extension or
// with the .js extension TypeScript sources import each other by.
func (p *Project) file(base string) string {
	base = strings.TrimPrefix(base, "./")
	if p.paths[base] {
		return base
	}
	stem := base
	for _, js := range []string{".js", ".jsx", ".mjs", ".cjs"} {
		if s, ok := strings.CutSuffix(base, js); ok {
			stem = s
			break
		}
	}
	for _, e := range sourceExts {
		if p.paths[stem+e] {
			return stem + e
		}
	}
	for _, e := range sourceExts {
		if p.paths[base+"/index"+e] {
			return base + "/index" + e
		}
	}
	return ""
}

// export returns what module file exports as name. depth bounds re-export
// chains.
func (p *Project) export(file, name string, depth int) (val, bool) {
	m := p.module(file)
	if m == nil || depth > 8 {
		return val{}, false
	}
	v, ok := m.exportVals[name]
	if !ok {
		if d, isObj := m.exportVals["default"]; isObj {
			v, ok = d.fields[name]
		}
	}
	if !ok {
		for _, re := range m.reexports {
			var imported string
			switch {
			case re.all && re.name == "": // export * from: all but default
				if name == "default" {
					continue
				}
				imported = name
			case re.name == name:
				imported = re.imported
			default:
				continue
			}
			target := p.resolve(file, re.from)
			if target == "" {
				continue
			}
			if imported == "*" {
				return val{ref: moduleName(re.from), mod: target}, true
			}
			if v, ok = p.export(target, imported, depth+1); ok {
				return v, true
			}
		}
		return val{}, false
	}
	return exported(v, m), true
}

// exported is the value a module exports as another module sees it: its
// functions and objects, analyzed by the module that defines them. Taint
// of the module's own does not travel: its steps are lines of that file.
func exported(v val, m *analyzer) val {
	out := val{fn: v.fn, env: v.env, fields: v.fields, mod: v.mod, ref: v.ref, owner: v.owner}
	if out.owner == nil {
		out.owner = m
	}
	return out
}

// moduleVal is the value of require('./x') or of a namespace import.
func (p *Project) moduleVal(spec, file string) val {
	v := val{ref: moduleName(spec), mod: file}
	if d, ok := p.export(file, "default", 0); ok && d.fn != nil {
		v.fn, v.env, v.owner = d.fn, d.env, d.owner
	}
	return v
}

// reexport is `export { a as b } from './x'` or `export * from './x'`.
type reexport struct {
	name, imported, from string
	all                  bool
}
