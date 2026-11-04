package adapters

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// openAPIPaths returns the normalized paths the OpenAPI documents declare
// and the documents that could not be parsed.
func openAPIPaths(inv *inventory.Inventory) (map[string]bool, []string) {
	declared := map[string]bool{}
	var parseErr []string
	for _, p := range inv.Features["openapi"] {
		f := inv.FileByPath(p)
		if f == nil {
			continue
		}
		var doc struct {
			Paths map[string]any `yaml:"paths" json:"paths"`
		}
		text := strings.Join(f.Lines, "\n")
		var err error
		if strings.HasSuffix(p, ".json") {
			err = json.Unmarshal([]byte(text), &doc)
		} else {
			err = yaml.Unmarshal([]byte(text), &doc)
		}
		if err != nil {
			parseErr = append(parseErr, p)
			continue
		}
		for k := range doc.Paths {
			declared[normRoute(k)] = true
		}
	}
	return declared, parseErr
}

// routeIn reports whether normalized route nr matches one of the paths, the
// way A-003 compares them (equal, or one a suffix of the other, which
// tolerates a server prefix).
func routeIn(nr string, paths map[string]bool) bool {
	if paths[nr] {
		return true
	}
	for d := range paths {
		if strings.HasSuffix(nr, d) || strings.HasSuffix(d, nr) {
			return true
		}
	}
	return false
}

// maxBlockers is how many blockers the A-002 reason names; the rest are
// counted.
const maxBlockers = 6

// nextRouteDecision decides A-002 for a repository with a Next.js app. The
// route table is complete by construction when the file system defines
// every route, so A-002 passes when nothing found can add routes outside
// it, and stays INCONCLUSIVE with each blocker named otherwise.
func nextRouteDecision(inv *inventory.Inventory, declared map[string]bool, parseErr []string) Decision {
	t := inv.NextJS
	blockers := append([]string(nil), t.Blockers...)
	notes := append([]string(nil), t.Notes...)

	// The OpenAPI contract must match the table in both directions: a
	// declared path that no file defines is served by something else, and
	// a route missing from the contract means they disagree.
	openapi := "no OpenAPI contract"
	if inv.Has("openapi") {
		if len(parseErr) > 0 {
			blockers = append(blockers, "OpenAPI documents could not be parsed: "+strings.Join(parseErr, ", "))
		}
		table := map[string]bool{}
		var routes []model.Asset
		for _, as := range inv.Assets {
			if as.Kind == "route" {
				table[normRoute(as.Meta["path"])] = true
				routes = append(routes, as)
			}
		}
		var missing, undeclared []string
		for d := range declared {
			if !routeIn(d, table) {
				missing = append(missing, d)
			}
		}
		for _, as := range routes {
			if !routeIn(normRoute(as.Meta["path"]), declared) {
				undeclared = append(undeclared, fmt.Sprintf("%s %s (%s)", as.Meta["method"], as.Meta["path"], as.Locator))
			}
		}
		sort.Strings(missing)
		sort.Strings(undeclared)
		if len(missing) > 0 {
			blockers = append(blockers, fmt.Sprintf("the OpenAPI contract declares %d paths no route file defines (e.g. %s)", len(missing), strings.Join(firstN(missing, 3), ", ")))
		}
		if len(undeclared) > 0 {
			blockers = append(blockers, fmt.Sprintf("%d routes are missing from the OpenAPI contract (e.g. %s; see A-003)", len(undeclared), strings.Join(firstN(undeclared, 3), ", ")))
		}
		if len(missing) == 0 && len(undeclared) == 0 && len(parseErr) == 0 {
			openapi = fmt.Sprintf("the OpenAPI contract matches the route handlers (%d declared paths)", len(declared))
		}
	}

	var apps []string
	for _, a := range t.Apps {
		apps = append(apps, appSummary(a))
		for _, n := range a.MiddlewareNotes {
			notes = append(notes, n)
		}
		notes = append(notes, a.ConfigNotes...)
	}
	if t.SharedActions > 0 {
		apps = append(apps, fmt.Sprintf("%d server actions in shared packages", t.SharedActions))
	}
	var extra []string
	for _, k := range []struct{ feature, label string }{{"graphql_operations", "GraphQL operations"}, {"queue_consumers", "queue consumers"}, {"cron_jobs", "cron jobs"}} {
		if n := len(inv.Features[k.feature]); n > 0 {
			extra = append(extra, fmt.Sprintf("%d %s", n, k.label))
		}
	}
	table := fmt.Sprintf("Next.js file-system route table, %d app(s): %s", len(t.Apps), strings.Join(apps, "; "))
	if len(extra) > 0 {
		table += fmt.Sprintf("; also %s, listed but not HTTP routes of their own", strings.Join(extra, ", "))
	}
	if len(notes) > 0 {
		table += ". Noted: " + strings.Join(notes, "; ")
	}
	if len(blockers) > 0 {
		shown := firstN(blockers, maxBlockers)
		reason := table + ". PASS is blocked because something can add routes outside this table or the table may be incomplete: " + strings.Join(shown, "; ")
		if len(blockers) > len(shown) {
			reason += fmt.Sprintf("; and %d more", len(blockers)-len(shown))
		}
		return Decision{model.StatusInconclusive, reason + ". File references: `pandaward routes`."}
	}
	return Decision{model.StatusPass, table + ". Checked and found nothing that adds routes outside the table: no custom server, next.config rewrites and redirects only to internal paths, no other web framework, server or route registrations, no serverless function directories or platform rewrites to other origins, no PHP, " + openapi + ", no code files skipped. Not counted: files in public/ and static metadata files such as icon.svg or opengraph-image.png, which are served as files without code. File references: `pandaward routes`."}
}

// appSummary describes one app's table with its counts.
func appSummary(a inventory.NextApp) string {
	parts := []string{
		fmt.Sprintf("%d pages", a.Count("page")),
		fmt.Sprintf("%d route handlers (%d methods)", a.Count("route"), methodsOf(a, "route")),
		fmt.Sprintf("%d layouts", a.Count("layout")),
		fmt.Sprintf("%d server actions", a.Actions),
	}
	if n := a.Count("metadata"); n > 0 {
		parts = append(parts, fmt.Sprintf("%d metadata routes", n))
	}
	if a.PagesDir != "" {
		parts = append(parts, fmt.Sprintf("pages/api %d routes", a.Count("api")))
	}
	shape := fmt.Sprintf("%d with dynamic segments, %d catch-all, %d optional catch-all; %d route groups, %d parallel slots, %d intercepting folders",
		a.Dynamic, a.CatchAll, a.OptionalCatchAll, a.Groups, a.Slots, a.Intercepting)
	mw := "no middleware"
	if a.Middleware != "" {
		mw = "middleware " + a.Middleware
	}
	dirs := strings.Trim(strings.Join([]string{a.AppDir, a.PagesDir}, ", "), ", ")
	if dirs == "" {
		dirs = "no app/ or pages/ directory"
	}
	return fmt.Sprintf("%s (%s): %s (%s); %s", a.Root, dirs, strings.Join(parts, ", "), shape, mw)
}

func methodsOf(a inventory.NextApp, kind string) int {
	n := 0
	for _, e := range a.Entries {
		if e.Kind == kind {
			n += max(1, len(e.Methods))
		}
	}
	return n
}

func firstN(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}
