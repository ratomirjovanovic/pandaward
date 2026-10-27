package engine

import (
	"path"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
)

// adapterWatches reports whether an adapter's result can depend on the
// content of a file. Adapters always analyze the whole inventory when they
// run, so this only decides whether a change requires re-running them.
func adapterWatches(adapter, p string) bool {
	p = strings.TrimSuffix(p, " (deleted)")
	base := strings.ToLower(path.Base(p))
	lang := inventory.LangOf(base)
	switch adapter {
	case "builtin-code":
		return isCodeLang(lang)
	case "builtin-cicd":
		return strings.Contains(p, ".github/workflows/")
	case "builtin-infra":
		return lang == "dockerfile" || lang == "terraform" || lang == "yaml"
	case "builtin-supply":
		switch base {
		case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
			"pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", "go.mod", "go.sum", "gemfile", "gemfile.lock",
			"cargo.toml", "cargo.lock", "composer.json", "composer.lock", ".mcp.json", "mcp.json", "claude_desktop_config.json":
			return true
		}
		return lang == "requirements"
	case "builtin-mobile":
		return base == "androidmanifest.xml" || base == "info.plist"
	}
	// builtin-inventory, builtin-secrets and external tools read every file.
	return true
}

func isCodeLang(lang string) bool {
	switch lang {
	case "javascript", "typescript", "python", "go", "java", "kotlin", "ruby", "php", "csharp", "rust", "swift", "scala", "elixir", "dart", "vue", "svelte", "template", "html", "objc", "c", "cpp":
		return true
	}
	return false
}

// AffectedAdapters returns the enabled adapters that must re-run for paths.
func AffectedAdapters(enabled []string, paths []string) map[string]bool {
	out := map[string]bool{}
	for _, a := range enabled {
		for _, p := range paths {
			if adapterWatches(a, p) {
				out[a] = true
				break
			}
		}
	}
	return out
}

// AffectedControls maps changed paths to the controls whose decision may
// change. Static and external controls follow their adapter. Runtime and
// manual controls follow the domains recorded for the changed paths in the
// last inventory (domains). newFiles are paths that were not part of that
// inventory; they can also change applicability, so every control in their
// domains counts.
func AffectedControls(enabled, paths []string, domains map[string][]string, newFiles []string) map[string]bool {
	ads := AffectedAdapters(enabled, paths)
	touched, newDomains := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		for _, d := range domains[strings.TrimSuffix(p, " (deleted)")] {
			touched[d] = true
		}
	}
	for _, p := range newFiles {
		for _, d := range inventory.DomainsForPath(p) {
			touched[d], newDomains[d] = true, true
		}
	}
	out := map[string]bool{}
	for _, c := range catalog.Controls {
		switch {
		case newDomains[c.Domain]:
			out[c.ID] = true
		case c.Method == catalog.MethodRuntime || c.Method == catalog.MethodManual:
			if touched[c.Domain] {
				out[c.ID] = true
			}
		case ads[c.Adapter]:
			out[c.ID] = true
		}
	}
	// Evidence integrity is re-verified on every scan.
	if len(paths) > 0 {
		out["R-001"] = true
	}
	return out
}

// ApplyStale returns copies of controls and edges with affected decisions
// shown as STALE. The ledger keeps the original decisions; this view is what
// status, reports and coverage use until the next scan.
func ApplyStale(cs []model.ControlResult, es []model.Edge, affected map[string]bool, files []string) ([]model.ControlResult, []model.Edge) {
	if len(affected) == 0 {
		return cs, es
	}
	sample := files
	if len(sample) > 3 {
		sample = append(append([]string{}, sample[:3]...), "...")
	}
	why := "inputs changed since this assessment (" + strings.Join(sample, ", ") + "); re-run `pensec retest`"
	stale := map[string]bool{}
	outC := make([]model.ControlResult, len(cs))
	for i, c := range cs {
		outC[i] = c
		if !affected[c.ID] {
			continue
		}
		switch c.Status {
		case model.StatusBlocked, model.StatusUnsupported:
			// Undecided before and after; nothing to invalidate.
		default:
			outC[i].Reason = "was " + string(c.Status) + ": " + why
			outC[i].Status = model.StatusStale
			stale[c.ID] = true
		}
	}
	outE := make([]model.Edge, len(es))
	for i, e := range es {
		outE[i] = e
		var hit []string
		for _, t := range e.Tests {
			if stale[t] {
				hit = append(hit, t)
			}
		}
		if len(hit) > 0 {
			sort.Strings(hit)
			outE[i].Reason = "was " + string(e.Status) + "; stale linked controls: " + strings.Join(hit, ", ")
			outE[i].Status = model.StatusStale
		}
	}
	return outC, outE
}

// StaleView loads stale files and applies them to an assessment's results.
func (e *Engine) StaleView(asmt string, cs []model.ControlResult, es []model.Edge) ([]model.ControlResult, []model.Edge, []string, error) {
	files, err := e.St.StaleFiles(e.ProjectID)
	if err != nil || len(files) == 0 {
		return cs, es, files, err
	}
	affected, err := e.affected(asmt, files)
	if err != nil {
		return nil, nil, nil, err
	}
	cs2, es2 := ApplyStale(cs, es, affected, files)
	return cs2, es2, files, nil
}

// affected resolves changed paths against the file domains recorded in an
// assessment and returns the controls they invalidate.
func (e *Engine) affected(asmt string, files []string) (map[string]bool, error) {
	domains := map[string][]string{}
	var newFiles []string
	for _, f := range files {
		p := strings.TrimSuffix(f, " (deleted)")
		ds, known, err := e.St.FileDomains(asmt, p)
		if err != nil {
			return nil, err
		}
		if known {
			domains[p] = ds
		} else if p == f {
			newFiles = append(newFiles, p)
		}
	}
	return AffectedControls(e.Cfg.Scan.Adapters, files, domains, newFiles), nil
}
