package adapters

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/php"
)

// phpMod is a parsed file: the files included into it are lowered in
// place, each with its own range of lines (see php.Slot).
type phpMod struct {
	mod   *ir.Module
	lines []string
	slots []string
}

// phpIncluder finds the files an include can name: a path that ends in seg,
// or, when dynamic, the files of the directory that ends in seg.
func phpIncluder(c *Context, paths []string) func(seg string, dynamic bool) []php.Source {
	return func(seg string, dynamic bool) []php.Source {
		var out []php.Source
		for _, p := range paths {
			var ok bool
			if dynamic {
				dir := strings.Trim(seg, "/")
				ok = dir != "" && path.Dir(p) != "." && (path.Dir(p) == dir || strings.HasSuffix(path.Dir(p), "/"+dir))
			} else {
				ok = p == seg || strings.HasSuffix(p, "/"+seg)
			}
			if !ok {
				continue
			}
			if f := c.Inv.FileByPath(p); f != nil {
				out = append(out, php.Source{Path: p, Src: strings.Join(f.Lines, "\n")})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
		return out
	}
}

// php runs the IR engine on the PHP files (#513). Each file is a module; an
// include whose path can be resolved is lowered in place, so what an
// included file sets is seen by the file that includes it.
func (a taintAdapter) php(ctx context.Context, c *Context, res *Result) (files, parseErrors int, err error) {
	var paths []string
	for _, f := range c.Inv.Files {
		if f.Lang == "php" && !IsTestPath(f.Path) {
			paths = append(paths, f.Path)
		}
	}
	if len(paths) == 0 {
		return 0, 0, nil
	}
	spec, err := taint.Load("php")
	if err != nil {
		return 0, 0, err
	}
	env := &php.Env{Include: phpIncluder(c, paths)}
	// The engine splits qualified names at dots, so a module is named by
	// its path with the dots replaced.
	byName := map[string]string{}
	name := func(p string) string {
		n := strings.ReplaceAll(p, ".", "_dot_")
		byName[n] = p
		return n
	}
	parsed := map[string]*phpMod{}
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
			return m.mod, m.lines
		}
		m, errs, slots := php.ParseEnv(f.Path, strings.Join(f.Lines, "\n"), env)
		if errs > 0 {
			parseErrors++
		}
		m.Name = n
		pm := &phpMod{mod: m, slots: slots, lines: f.Lines}
		if len(slots) > 0 {
			pm.lines = make([]string, (len(slots)+1)*php.Slot)
			copy(pm.lines, f.Lines)
			for i, sp := range slots {
				if sf := c.Inv.FileByPath(sp); sf != nil {
					copy(pm.lines[(i+1)*php.Slot:], sf.Lines)
				}
			}
		}
		parsed[p] = pm
		return pm.mod, pm.lines
	})
	seen := map[string]bool{}
	for _, p := range paths {
		if ctx.Err() != nil {
			return files, parseErrors, nil
		}
		files++
		for _, fd := range proj.Module(name(p)) {
			if pm := parsed[fd.File]; pm != nil {
				unslot(&fd, pm.slots)
			}
			key := fd.File + ":" + fd.Sink.ID + ":" + itoa(fd.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			if f := c.Inv.FileByPath(fd.File); f != nil && !IsTestPath(f.Path) {
				res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
			}
		}
	}
	return files, parseErrors, nil
}

// unslot maps the lines of a finding in a file with included files back to
// the file and line they belong to.
func unslot(fd *taint.Finding, slots []string) {
	home := fd.File
	file := func(line int) (string, int) {
		if k := line / php.Slot; k > 0 && k <= len(slots) {
			return slots[k-1], line % php.Slot
		}
		return home, line
	}
	fd.File, fd.Line = file(fd.Line)
	if fd.EndLine > 0 {
		_, fd.EndLine = file(fd.EndLine)
	}
	steps := make([]taint.Step, len(fd.Steps))
	for i, s := range fd.Steps {
		steps[i] = s
		if k := s.Line / php.Slot; k > 0 && k <= len(slots) {
			steps[i].File, steps[i].Line = slots[k-1], s.Line%php.Slot
		}
	}
	fd.Steps = steps
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
