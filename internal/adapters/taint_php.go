package adapters

import (
	"context"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/php"
)

// php runs the IR engine on the PHP files (#513). Each file is its own
// module: an include is a sink and is not followed.
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
	// The engine splits qualified names at dots, so a module is named by
	// its path with the dots replaced.
	byName := map[string]string{}
	name := func(p string) string {
		n := strings.ReplaceAll(p, ".", "_dot_")
		byName[n] = p
		return n
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
		m, errs := php.Parse(f.Path, strings.Join(f.Lines, "\n"))
		if errs > 0 {
			parseErrors++
		}
		m.Name = n
		parsed[p] = m
		return m, f.Lines
	})
	for _, p := range paths {
		if ctx.Err() != nil {
			return files, parseErrors, nil
		}
		files++
		for _, fd := range proj.Module(name(p)) {
			if f := c.Inv.FileByPath(fd.File); f != nil && !IsTestPath(f.Path) {
				res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
			}
		}
	}
	return files, parseErrors, nil
}
