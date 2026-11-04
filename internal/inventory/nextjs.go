package inventory

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// The Next.js route table. In a Next.js app the routes are defined by the
// file system: app/ (App Router) and pages/ (Pages Router). The table lists
// every page, layout, route handler, metadata route, server action and
// middleware with its file, and RouteTable.Blockers lists everything found
// that can add routes outside it (a custom server, rewrites to other
// origins, another web framework or server, serverless functions). A-002
// is decided from it. Nothing here executes or type-checks code; whatever
// cannot be resolved statically is a blocker, never assumed safe.

// NextEntry is one file of a Next.js route table.
type NextEntry struct {
	Kind    string // page, layout, route, api, metadata, middleware
	File    string
	URL     string
	Methods []string // route handlers and pages/api only
}

// NextApp is one Next.js app: a directory with a next dependency or a
// next.config file.
type NextApp struct {
	Root     string // "." for the repository root
	AppDir   string // "" when the app has no app/ directory
	PagesDir string // "" when the app has no pages/ directory
	Entries  []NextEntry
	Actions  int // server actions in files of this app
	// URL shapes among pages and route handlers, and the special folders.
	Dynamic, CatchAll, OptionalCatchAll int
	Groups, Slots, Intercepting         int
	Middleware                          string // file, "" when none
	MiddlewareNotes                     []string
	ConfigNotes                         []string
}

// Count returns the number of entries of one kind.
func (a NextApp) Count(kind string) int {
	n := 0
	for _, e := range a.Entries {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// RouteTable is the Next.js route table of a repository.
type RouteTable struct {
	Apps []NextApp
	// Blockers name what can add routes outside the table, each with a
	// file reference. A-002 cannot pass while there is one.
	Blockers []string
	// Notes are things checked and found harmless.
	Notes []string
	// SharedActions counts server actions in files outside every app root
	// (shared workspace packages).
	SharedActions int
}

var (
	nextPageExts  = map[string]bool{"tsx": true, "ts": true, "jsx": true, "js": true}
	nextConfigRe  = regexp.MustCompile(`^next\.config\.(?:js|mjs|cjs|ts|mts)$`)
	nextMetaRe    = regexp.MustCompile(`^(sitemap|robots|manifest|favicon|icon\d*|apple-icon\d*|opengraph-image\d*|twitter-image\d*)\.([a-z]+)$`)
	nextInterRe   = regexp.MustCompile(`^((?:\(\.{1,3}\))+)(.+)$`)
	nextMethodsRe = regexp.MustCompile(`export\s+(?:async\s+)?(?:function|const|let|var)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)
	nextAsExport  = regexp.MustCompile(`export\s*\{([^}]*)\}`)
	nextAsName    = regexp.MustCompile(`\bas\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*$`)
)

// nextSegments turns the directories of an app/ file into its URL. ok is
// false inside a private folder (_name), which is not routable.
type segInfo struct {
	dynamic, catchAll, optional bool
	groups, slots, intercepts   []string // directory paths, for counting
}

func nextAppURL(dirs []string) (string, segInfo, bool) {
	var out []string
	var info segInfo
	for i, s := range dirs {
		dirPath := strings.Join(dirs[:i+1], "/")
		if strings.HasPrefix(s, "_") {
			return "", info, false
		}
		if strings.HasPrefix(s, "%5F") || strings.HasPrefix(s, "%5f") {
			s = "_" + s[3:]
		}
		if m := nextInterRe.FindStringSubmatch(s); m != nil {
			info.intercepts = append(info.intercepts, dirPath)
			for _, mark := range strings.SplitAfter(m[1], ")") {
				switch mark {
				case "(...)":
					out = nil
				case "(..)":
					if len(out) > 0 {
						out = out[:len(out)-1]
					}
				}
			}
			s = m[2]
		}
		switch {
		case strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")"):
			info.groups = append(info.groups, dirPath)
			continue
		case strings.HasPrefix(s, "@"):
			info.slots = append(info.slots, dirPath)
			continue
		case strings.HasPrefix(s, "[[...") && strings.HasSuffix(s, "]]"):
			info.optional = true
		case strings.HasPrefix(s, "[...") && strings.HasSuffix(s, "]"):
			info.catchAll = true
		case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
			info.dynamic = true
		}
		out = append(out, s)
	}
	return "/" + strings.Join(out, "/"), info, true
}

// nextPagesURL turns a pages/ file path (relative to pages/, without the
// extension) into its URL.
func nextPagesURL(rel string) string {
	rel = strings.TrimSuffix(rel, "/index")
	if rel == "index" {
		rel = ""
	}
	return "/" + rel
}

// nextHandlerURL returns the URL of a Next.js route handler (app/**/route.*)
// or pages/api file, and false for any other file.
func nextHandlerURL(p string) (string, bool) {
	if m := nextRouteRe.FindStringSubmatch(p); m != nil {
		var dirs []string
		if m[1] != "" {
			dirs = strings.Split(m[1], "/")
		}
		u, _, ok := nextAppURL(dirs)
		return u, ok
	}
	if m := nextPagesAPI.FindStringSubmatch(p); m != nil {
		return nextPagesURL("api/" + m[1]), true
	}
	return "", false
}

// nextMethods returns the HTTP methods a route handler file exports.
func nextMethods(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(m string) {
		if m != "" && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	for _, l := range lines {
		for _, m := range nextMethodsRe.FindAllStringSubmatch(l, -1) {
			add(m[1])
		}
		for _, m := range nextAsExport.FindAllStringSubmatch(l, -1) {
			for _, part := range strings.Split(m[1], ",") {
				if mm := nextAsName.FindStringSubmatch(part); mm != nil {
					add(firstNonEmpty(mm[1], mm[2]))
				}
			}
		}
	}
	return out
}

// pkgJSON is the part of package.json the route table reads.
type pkgJSON struct {
	Dependencies    map[string]any    `json:"dependencies"`
	DevDependencies map[string]any    `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

func parsePkg(f *File) (pkgJSON, bool) {
	var p pkgJSON
	err := json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &p)
	return p, err == nil
}

// serverFrameworks are JavaScript packages that serve HTTP routes of their
// own, outside the Next.js file-system table.
var serverFrameworks = []string{"express", "fastify", "koa", "@koa/router", "koa-router", "hono", "@hono/node-server", "elysia", "h3", "restify",
	"@hapi/hapi", "polka", "micro", "connect", "socket.io", "@nestjs/core", "@nestjs/platform-express", "@nestjs/platform-fastify", "json-server"}

var (
	frameworkImportRe = regexp.MustCompile(`(?:\bfrom\s+|\brequire\(\s*|\bimport\(\s*)['"](express|fastify|koa|@koa/router|koa-router|hono|@hono/node-server|elysia|h3|restify|@hapi/hapi|polka|micro|connect|socket\.io|@nestjs/core|@nestjs/platform-express|@nestjs/platform-fastify|json-server)(?:/[^'"]*)?['"]`)
	serverStartRe     = regexp.MustCompile(`\b(?:https?|http2|net)\.createServer\s*\(|\bDeno\.serve\s*\(|\bBun\.serve\s*\(|\bstartStandaloneServer\s*\(|\bnew\s+WebSocketServer\s*\(|\bnew\s+(?:WebSocket|ws)\.Server\s*\(`)
	nodeCreateServer  = regexp.MustCompile(`import\s*\{[^}]*\bcreateServer\b[^}]*\}\s*from\s*['"](?:node:)?(?:http|https|http2|net)['"]`)
	nextDefaultImport = regexp.MustCompile(`import\s+[A-Za-z_$][\w$]*\s*(?:,\s*\{[^}]*\})?\s+from\s+['"]next['"]|require\(\s*['"]next['"]\s*\)`)
	customServerUse   = regexp.MustCompile(`\bgetRequestHandler\s*\(|\bcreateServer\s*\(|\.listen\s*\(`)
	nextScriptRe      = regexp.MustCompile(`(?:^|[\s&;|])next(?:\s+(?:dev|start|build)\b|\s*$)`)
	scriptRunsFileRe  = regexp.MustCompile(`(?:^|[\s&;|])(?:node|ts-node|tsx|bun|nodemon|deno\s+run)\s+(?:-{1,2}[\w-]+(?:=\S*)?\s+)*(?:[\w./-]*\.[cm]?[jt]sx?\b|[\w./-]*server\b)`)
	serverlessDirRe   = regexp.MustCompile(`(?:^|/)(supabase/functions|netlify/functions|netlify/edge-functions)/`)
	nonJSWebManifest  = map[string]bool{"requirements.txt": true, "pyproject.toml": true, "pipfile": true, "go.mod": true, "composer.json": true, "pom.xml": true, "build.gradle": true, "build.gradle.kts": true}
)

// isTestFile reports whether p is test code: test runners load it, the
// deployed app does not. Fixture and example directories are not test
// code here, since they can be deployed.
func isTestFile(p string) bool {
	l := "/" + strings.ToLower(p)
	for _, s := range []string{"/test/", "/tests/", "/__tests__/", "/spec/", "/e2e/", "/__mocks__/", "/testdata/"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return strings.Contains(l, ".test.") || strings.Contains(l, ".spec.") || strings.HasSuffix(l, "_test.go")
}

// under reports whether p lies in directory dir ("." is the root).
func under(p, dir string) bool {
	return dir == "." || strings.HasPrefix(p, dir+"/")
}

func joinDir(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

// nextTable builds the Next.js route table, adds its pages, layouts and
// middleware as assets, and lists what can add routes outside it. It runs
// after the entrypoints are added, so their assets are available.
func (inv *Inventory) nextTable(roots []string) *RouteTable {
	set := map[string]bool{}
	pkgs := map[string]pkgJSON{}
	for _, f := range inv.Files {
		dir, base := path.Dir(f.Path), path.Base(f.Path)
		if base == "package.json" {
			p, ok := parsePkg(f)
			if !ok {
				continue
			}
			pkgs[dir] = p
			if p.Dependencies["next"] != nil || p.DevDependencies["next"] != nil {
				set[dir] = true
			}
		}
		if nextConfigRe.MatchString(base) {
			set[dir] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	var appRoots []string
	for r := range set {
		appRoots = append(appRoots, r)
	}
	sort.Strings(appRoots)
	// owner returns the deepest app root that contains p.
	owner := func(p string) string {
		best := ""
		for _, r := range appRoots {
			if under(p, r) && (best == "" || best == "." || len(r) > len(best)) {
				best = r
			}
		}
		return best
	}
	hasDir := func(root, dir string) bool {
		prefix := joinDir(root, dir) + "/"
		for _, f := range inv.Files {
			if strings.HasPrefix(f.Path, prefix) && owner(f.Path) == root {
				return true
			}
		}
		return false
	}
	t := &RouteTable{}
	tableFiles := map[string]bool{}
	for _, root := range appRoots {
		app := NextApp{Root: root}
		// src/app and src/pages are used only when the root has no app/
		// or pages/ directory.
		for _, d := range []string{"app", "src/app"} {
			if hasDir(root, d) {
				app.AppDir = joinDir(root, d)
				break
			}
		}
		for _, d := range []string{"pages", "src/pages"} {
			if hasDir(root, d) {
				app.PagesDir = joinDir(root, d)
				break
			}
		}
		groups, slots, inter := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, f := range inv.Files {
			if owner(f.Path) != root {
				continue
			}
			switch {
			case app.AppDir != "" && strings.HasPrefix(f.Path, app.AppDir+"/"):
				rel := strings.TrimPrefix(f.Path, app.AppDir+"/")
				segs := strings.Split(rel, "/")
				dirs, base := segs[:len(segs)-1], segs[len(segs)-1]
				u, info, ok := nextAppURL(dirs)
				if !ok {
					continue
				}
				name, ext, _ := strings.Cut(base, ".")
				kind := ""
				switch {
				case (name == "page" || name == "layout" || name == "route") && nextPageExts[ext]:
					kind = name
				case nextMetaRe.MatchString(base):
					kind = "metadata"
				default:
					continue
				}
				e := NextEntry{Kind: kind, File: f.Path, URL: u}
				switch kind {
				case "route":
					e.Methods = nextMethods(f.Lines)
				case "metadata":
					e.URL = strings.TrimSuffix(u, "/") + "/" + metadataName(name, ext)
				}
				if kind == "page" || kind == "route" {
					app.Dynamic += b2i(info.dynamic)
					app.CatchAll += b2i(info.catchAll)
					app.OptionalCatchAll += b2i(info.optional)
				}
				for _, g := range info.groups {
					groups[g] = true
				}
				for _, s := range info.slots {
					slots[s] = true
				}
				for _, s := range info.intercepts {
					inter[s] = true
				}
				app.Entries = append(app.Entries, e)
				tableFiles[f.Path] = true
			case app.PagesDir != "" && strings.HasPrefix(f.Path, app.PagesDir+"/"):
				rel := strings.TrimPrefix(f.Path, app.PagesDir+"/")
				ext := path.Ext(rel)
				if !nextPageExts[strings.TrimPrefix(ext, ".")] {
					continue
				}
				rel = strings.TrimSuffix(rel, ext)
				switch path.Base(rel) {
				case "_app", "_document", "_error", "_middleware":
					continue
				}
				e := NextEntry{Kind: "page", File: f.Path, URL: nextPagesURL(rel)}
				if rel == "api" || strings.HasPrefix(rel, "api/") {
					e.Kind = "api"
					e.Methods = nil
				}
				if strings.Contains(rel, "[[...") {
					app.OptionalCatchAll++
				} else if strings.Contains(rel, "[...") {
					app.CatchAll++
				} else if strings.Contains(rel, "[") {
					app.Dynamic++
				}
				app.Entries = append(app.Entries, e)
				tableFiles[f.Path] = true
			}
		}
		app.Groups, app.Slots, app.Intercepting = len(groups), len(slots), len(inter)
		// Middleware sits next to app/ or pages/: in the root, or in src/
		// when the app uses src/. Next.js 16 calls it proxy.
		base := root
		if strings.HasPrefix(app.AppDir, joinDir(root, "src/")) || strings.HasPrefix(app.PagesDir, joinDir(root, "src/")) {
			base = joinDir(root, "src")
		}
		for _, name := range []string{"middleware", "proxy"} {
			for _, ext := range []string{"ts", "js", "mjs", "tsx", "jsx"} {
				p := joinDir(base, name+"."+ext)
				if f := inv.FileByPath(p); f != nil {
					app.Middleware = p
					app.Entries = append(app.Entries, NextEntry{Kind: "middleware", File: p, URL: "/*"})
					tableFiles[p] = true
					notes, blocks := analyzeMiddleware(f)
					app.MiddlewareNotes = append(app.MiddlewareNotes, notes...)
					t.Blockers = append(t.Blockers, blocks...)
				}
			}
		}
		for _, f := range inv.Files {
			if owner(f.Path) == root && path.Dir(f.Path) == root && nextConfigRe.MatchString(path.Base(f.Path)) {
				notes, blocks := inv.analyzeNextConfig(f)
				app.ConfigNotes = append(app.ConfigNotes, notes...)
				t.Blockers = append(t.Blockers, blocks...)
			}
		}
		if p, ok := pkgs[root]; ok {
			for _, s := range []string{"dev", "start"} {
				if cmd, ok := p.Scripts[s]; ok && !nextScriptRe.MatchString(cmd) && scriptRunsFileRe.MatchString(cmd) {
					t.Blockers = append(t.Blockers, fmt.Sprintf("the %q script in %s runs `%s`, not next (custom server)", s, joinDir(root, "package.json"), cmd))
				}
			}
		}
		t.Apps = append(t.Apps, app)
	}

	// Server actions and route handlers found by the extractors.
	for _, a := range inv.Assets {
		switch a.Kind {
		case "server_action":
			if r := owner(a.Locator); r != "" {
				for i := range t.Apps {
					if t.Apps[i].Root == r {
						t.Apps[i].Actions++
					}
				}
			} else {
				t.SharedActions++
			}
		case "route":
			if a.Meta["framework"] == "nextjs" {
				if !tableFiles[a.Locator] {
					t.Blockers = append(t.Blockers, fmt.Sprintf("Next.js route file %s lies outside the app/ and pages/ directories of every detected app", a.Locator))
				}
				continue
			}
		}
	}
	inv.otherWebSurfaces(t, pkgs)
	inv.skippedInApps(t, appRoots)

	// The table's own assets: route handlers are already "route" assets.
	for _, app := range t.Apps {
		for _, e := range app.Entries {
			if e.Kind == "route" || e.Kind == "api" {
				continue
			}
			kind, method := "page", "GET"
			switch e.Kind {
			case "layout":
				kind, method = "layout", "-"
			case "middleware":
				kind, method = "middleware", "ANY"
			}
			hash := ""
			if f := inv.FileByPath(e.File); f != nil {
				hash = f.SHA256
			}
			inv.addAsset(model.Asset{ID: kind + ":" + e.URL + "@" + e.File, Kind: kind, Locator: e.File, Line: 1, ContentHash: hash, Domains: []string{"A"},
				Meta: map[string]string{"method": method, "path": e.URL, "framework": "nextjs", "confidence": "file-convention", "service": serviceOf(roots, e.File), "role": e.Kind}})
		}
	}
	return t
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// metadataName is the URL name a metadata file is served under.
func metadataName(name, ext string) string {
	switch name {
	case "sitemap":
		return "sitemap.xml"
	case "robots":
		return "robots.txt"
	case "manifest":
		return "manifest.webmanifest"
	case "favicon":
		return "favicon.ico"
	}
	if nextPageExts[ext] {
		return name
	}
	return name + "." + ext
}

// otherWebSurfaces adds a blocker for everything that serves HTTP outside
// the Next.js table: route registrations of other frameworks, server
// framework dependencies and imports, server code, custom Next.js servers,
// serverless function directories and platform configs, PHP code and web
// framework manifests of other languages.
func (inv *Inventory) otherWebSurfaces(t *RouteTable, pkgs map[string]pkgJSON) {
	block := func(format string, a ...any) { t.Blockers = append(t.Blockers, fmt.Sprintf(format, a...)) }
	// Route registrations of other frameworks.
	byFw := map[string][]string{}
	var fws []string
	for _, a := range inv.Assets {
		if (a.Kind == "route" && a.Meta["framework"] != "nextjs") || a.Kind == "grpc_method" {
			fw := a.Meta["framework"]
			if byFw[fw] == nil {
				fws = append(fws, fw)
			}
			byFw[fw] = append(byFw[fw], fmt.Sprintf("%s:%d", a.Locator, a.Line))
		}
	}
	sort.Strings(fws)
	for _, fw := range fws {
		refs := byFw[fw]
		block("%d %s route registrations (e.g. %s)", len(refs), fw, strings.Join(firstN(refs, 3), ", "))
	}
	// Server framework dependencies.
	var dirs []string
	for d := range pkgs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		for _, fw := range serverFrameworks {
			if pkgs[d].Dependencies[fw] != nil {
				block("%s depends on the server framework %s", joinDir(d, "package.json"), fw)
			}
		}
	}
	var php []string
	for _, f := range inv.Files {
		lb := strings.ToLower(path.Base(f.Path))
		switch {
		case nonJSWebManifest[lb] && containsAny(f.Lines, "django", "flask", "fastapi", "starlette", "Django", "Flask", "FastAPI", "gin-gonic", "labstack/echo", "gofiber", "go-chi", "gorilla/mux", "spring-boot", "springframework", "laravel", "symfony", "slim/slim"):
			block("%s declares a web framework", f.Path)
		case lb == "composer.json":
			block("%s: a PHP project serves its own entrypoints", f.Path)
		case lb == "gemfile" && containsAny(f.Lines, "rails", "sinatra", "hanami", "roda"):
			block("%s declares a Ruby web framework", f.Path)
		case lb == "wrangler.toml" || lb == "wrangler.json" || lb == "wrangler.jsonc":
			block("%s deploys a Cloudflare Worker", f.Path)
		case lb == "serverless.yml" || lb == "serverless.yaml" || lb == "serverless.ts":
			block("%s deploys serverless functions", f.Path)
		case lb == "firebase.json" && containsAny(f.Lines, `"functions"`, `"rewrites"`):
			block("%s declares Firebase functions or rewrites", f.Path)
		case lb == "vercel.json":
			inv.vercelJSON(t, f)
		case lb == "vercel.ts" || lb == "vercel.mts":
			if containsAny(f.Lines, "rewrites", "redirects", "routes", "functions") {
				block("%s sets rewrites, redirects, routes or functions in code, which is not evaluated", f.Path)
			}
		case lb == "netlify.toml":
			inv.netlifyTOML(t, f)
		}
		if isTestFile(f.Path) {
			continue
		}
		if f.Lang == "php" {
			php = append(php, f.Path)
			continue
		}
		if serverlessDirRe.MatchString(f.Path) && CodeLangs[f.Lang] {
			block("%s is a serverless function outside the Next.js table", f.Path)
			continue
		}
		if vercelAPIFile(inv, f.Path) {
			block("%s is a Vercel function in an api/ directory", f.Path)
			continue
		}
		if !jsLangs[f.Lang] {
			continue
		}
		text := stripComments(strings.Join(f.Lines, "\n"))
		if m := frameworkImportRe.FindStringSubmatchIndex(text); m != nil {
			block("%s:%d imports the server framework %s", f.Path, lineAt(text, m[0]), text[m[2]:m[3]])
		}
		if nextDefaultImport.MatchString(text) && customServerUse.MatchString(text) {
			block("%s:%d starts a custom Next.js server", f.Path, lineAt(text, customServerUse.FindStringIndex(text)[0]))
		} else if m := serverStartRe.FindStringIndex(text); m != nil {
			block("%s:%d starts an HTTP or WebSocket server", f.Path, lineAt(text, m[0]))
		} else if nodeCreateServer.MatchString(text) {
			block("%s imports createServer from a Node.js server module", f.Path)
		}
	}
	if len(php) > 0 {
		block("%d PHP files (e.g. %s) run in their own runtime with entrypoints outside the Next.js table", len(php), strings.Join(firstN(php, 2), ", "))
	}
}

// vercelAPIFile reports whether p is a function in the api/ directory of a
// Vercel project root (the repository root or a directory with
// vercel.json).
func vercelAPIFile(inv *Inventory, p string) bool {
	dir := path.Dir(p)
	if path.Base(dir) != "api" {
		return false
	}
	switch strings.TrimPrefix(path.Ext(p), ".") {
	case "js", "ts", "mjs", "cjs", "py", "go", "rb":
	default:
		return false
	}
	proj := path.Dir(dir)
	return proj == "." || inv.FileByPath(joinDir(proj, "vercel.json")) != nil
}

// vercelJSON checks rewrites, redirects, routes and functions of a
// vercel.json.
func (inv *Inventory) vercelJSON(t *RouteTable, f *File) {
	var v struct {
		Rewrites  []map[string]any `json:"rewrites"`
		Redirects []map[string]any `json:"redirects"`
		Routes    []map[string]any `json:"routes"`
		Functions map[string]any   `json:"functions"`
		Crons     []map[string]any `json:"crons"`
	}
	if err := json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &v); err != nil {
		t.Blockers = append(t.Blockers, fmt.Sprintf("%s could not be parsed, so its rewrites and functions are unknown", f.Path))
		return
	}
	internal := 0
	check := func(kind string, items []map[string]any, key string) {
		for _, it := range items {
			d, _ := it[key].(string)
			switch destKind(d) {
			case "external":
				t.Blockers = append(t.Blockers, fmt.Sprintf("%s %s to the external origin %s", f.Path, kind, d))
			case "internal":
				internal++
			default:
				t.Blockers = append(t.Blockers, fmt.Sprintf("%s has a %s entry without a resolvable destination", f.Path, kind))
			}
		}
	}
	check("rewrites", v.Rewrites, "destination")
	check("redirects", v.Redirects, "destination")
	for _, r := range v.Routes {
		if _, ok := r["dest"]; ok {
			check("routes", []map[string]any{r}, "dest")
		}
	}
	dir := path.Dir(f.Path)
	for pattern := range v.Functions {
		p := strings.TrimPrefix(pattern, "./")
		if !strings.HasPrefix(p, "app/") && !strings.HasPrefix(p, "pages/") && !strings.HasPrefix(p, "src/app/") && !strings.HasPrefix(p, "src/pages/") {
			t.Blockers = append(t.Blockers, fmt.Sprintf("%s configures functions for %s, outside the Next.js route files", f.Path, joinDir(dir, p)))
		}
	}
	if internal > 0 {
		t.Notes = append(t.Notes, fmt.Sprintf("%s: %d rewrites or redirects to internal paths", f.Path, internal))
	}
	if len(v.Crons) > 0 {
		t.Notes = append(t.Notes, fmt.Sprintf("%s: %d cron jobs call internal paths", f.Path, len(v.Crons)))
	}
}

var (
	netlifyToRe   = regexp.MustCompile(`^\s*to\s*=\s*["']([^"']*)["']`)
	netlifyEdgeRe = regexp.MustCompile(`^\s*\[\[\s*edge_functions\s*\]\]`)
)

func (inv *Inventory) netlifyTOML(t *RouteTable, f *File) {
	internal := 0
	for i, l := range f.Lines {
		if netlifyEdgeRe.MatchString(l) {
			t.Blockers = append(t.Blockers, fmt.Sprintf("%s:%d declares Netlify edge functions", f.Path, i+1))
		}
		if m := netlifyToRe.FindStringSubmatch(l); m != nil {
			if destKind(m[1]) == "external" {
				t.Blockers = append(t.Blockers, fmt.Sprintf("%s:%d redirects or proxies to the external origin %s", f.Path, i+1, m[1]))
			} else {
				internal++
			}
		}
	}
	if internal > 0 {
		t.Notes = append(t.Notes, fmt.Sprintf("%s: %d redirects to internal paths", f.Path, internal))
	}
}

// destKind classifies a rewrite or redirect destination.
func destKind(d string) string {
	switch {
	case strings.HasPrefix(d, "http://") || strings.HasPrefix(d, "https://") || strings.HasPrefix(d, "//"):
		return "external"
	case strings.HasPrefix(d, "/"):
		return "internal"
	}
	return "unknown"
}

// skippedInApps blocks on files the walk skipped that could hold routes or
// server code: anything inside an app root, any code file, and a walk cut
// short by max_files.
func (inv *Inventory) skippedInApps(t *RouteTable, appRoots []string) {
	for _, s := range inv.Skipped {
		i := strings.LastIndex(s, ": ")
		if i < 0 {
			continue
		}
		p, why := s[:i], s[i+2:]
		in := false
		for _, r := range appRoots {
			if under(p, r) {
				in = true
			}
		}
		if in || CodeLangs[langOf(path.Base(p))] || strings.Contains(why, "max_files") || why == "unreadable" {
			t.Blockers = append(t.Blockers, fmt.Sprintf("%s was not analyzed (%s)", p, why))
		}
	}
}

func firstN(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}

func lineAt(text string, off int) int { return strings.Count(text[:off], "\n") + 1 }

// stripComments blanks out JavaScript comments, keeping strings, offsets
// and line breaks, so a commented-out call is not read as code.
func stripComments(s string) string {
	b := []byte(s)
	var quote byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			for ; i < len(b) && !(b[i] == '*' && i+1 < len(b) && b[i+1] == '/'); i++ {
				if b[i] != '\n' {
					b[i] = ' '
				}
			}
			if i+1 < len(b) {
				b[i], b[i+1] = ' ', ' '
				i++
			}
		}
	}
	return string(b)
}

// balanced returns the text between the bracket at open and its match,
// skipping string contents, and the index of the closing bracket (-1 when
// unbalanced).
func balanced(s string, open int) (string, int) {
	pairs := map[byte]byte{'(': ')', '[': ']', '{': '}'}
	var stack []byte
	var quote byte
	for i := open; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			stack = append(stack, pairs[c])
		case ')', ']', '}':
			if len(stack) == 0 || stack[len(stack)-1] != c {
				return "", -1
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return s[open+1 : i], i
			}
		}
	}
	return "", -1
}

// splitTop splits s at top-level commas.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if rest := strings.TrimSpace(s[start:]); rest != "" {
		out = append(out, rest)
	}
	return out
}

// literal returns the value of a JavaScript string literal (a template
// without substitutions counts), or false.
func literal(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return "", false
	}
	q := s[0]
	if (q != '\'' && q != '"' && q != '`') || s[len(s)-1] != q {
		return "", false
	}
	v := s[1 : len(s)-1]
	if strings.ContainsRune(v, rune(q)) || (q == '`' && strings.Contains(v, "${")) {
		return "", false
	}
	return v, true
}

var (
	mwCallRe     = regexp.MustCompile(`(?:\bNextResponse|(?:^|[^\w.$])Response)\.(redirect|rewrite|json|next)\s*\(|\bnew\s+(?:NextResponse|Response)\s*\(`)
	mwStatusRe   = regexp.MustCompile(`\bstatus\s*:\s*(\d{3})\b`)
	mwFuncRe     = regexp.MustCompile(`export\s+(?:default\s+)?(?:async\s+)?function\s*(?:middleware|proxy)?\s*\(|export\s+(?:const|let)\s+(?:middleware|proxy)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=>\s*\{|export\s+default\s+(?:async\s*)?\([^)]*\)\s*(?::[^=]+)?=>\s*\{`)
	mwDelegateRe = regexp.MustCompile(`export\s+default\s+([A-Za-z_$][\w$.]*)\s*\(|export\s+(?:const|let)\s+(?:middleware|proxy)\s*(?::[^=]+)?=\s*([A-Za-z_$][\w$.]*)\s*\(|export\s*\{[^}]*\bas\s+(?:middleware|proxy|default)\b[^}]*\}|export\s+default\s+[A-Za-z_$][\w$]*\s*;?\s*$`)
	mwReturnRe   = regexp.MustCompile(`\breturn\s+(?:await\s+)?([A-Za-z_$][\w$.]*)\s*(\(|;|\n|$|\})`)
	localFuncRe  = regexp.MustCompile(`(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>))`)
	hostMutateRe = `\.(?:host|hostname|protocol|port|origin|href)\s*=[^=]`
)

// analyzeMiddleware reads a Next.js middleware file. Redirects and rewrites
// must resolve to internal paths, and responses it builds itself must carry
// a literal error status (a rejection, not a new route). Anything that
// cannot be resolved statically is a blocker.
func analyzeMiddleware(f *File) (notes, blocks []string) {
	text := stripComments(strings.Join(f.Lines, "\n"))
	ref := func(off int) string { return fmt.Sprintf("%s:%d", f.Path, lineAt(text, off)) }
	loc := mwFuncRe.FindStringIndex(text)
	if loc == nil {
		if m := mwDelegateRe.FindStringIndex(text); m != nil {
			return nil, []string{fmt.Sprintf("middleware %s is created by code from another module; its redirects, rewrites and responses are not evaluated", ref(m[0]))}
		}
		return nil, []string{fmt.Sprintf("middleware %s exports no function PandaWard can read", f.Path)}
	}
	local := map[string]bool{}
	for _, m := range localFuncRe.FindAllStringSubmatch(text, -1) {
		local[firstNonEmpty(m[1], m[2])] = true
	}
	internal, rejections := 0, 0
	for _, m := range mwCallRe.FindAllStringSubmatchIndex(text, -1) {
		open := strings.LastIndex(text[:m[1]], "(")
		args, _ := balanced(text, open)
		kind := "response"
		if m[2] >= 0 {
			kind = text[m[2]:m[3]]
		}
		switch kind {
		case "next":
		case "redirect", "rewrite":
			parts := splitTop(args)
			if len(parts) == 0 {
				blocks = append(blocks, fmt.Sprintf("middleware %s %ss to a target it does not name", ref(m[0]), kind))
				continue
			}
			switch k, why := targetKind(parts[0], text, 0); k {
			case "internal":
				internal++
			case "external":
				blocks = append(blocks, fmt.Sprintf("middleware %s %ss to an external origin (%s)", ref(m[0]), kind, why))
			default:
				blocks = append(blocks, fmt.Sprintf("middleware %s %ss to a target not resolved statically (%s)", ref(m[0]), kind, why))
			}
		default: // json or a constructed response
			if s := mwStatusRe.FindStringSubmatch(args); s != nil && s[1] >= "400" && s[1] < "600" {
				rejections++
			} else {
				blocks = append(blocks, fmt.Sprintf("middleware %s answers requests itself without a literal error status, so it may serve paths outside the table", ref(m[0])))
			}
		}
	}
	// What the exported function returns: only its own body is read, so a
	// helper that returns a boolean is not taken for a response.
	bodyStart := loc[1] - 1
	if text[bodyStart] != '{' {
		_, closeParams := balanced(text, bodyStart)
		bodyStart = -1
		if closeParams > 0 {
			if i := strings.Index(text[closeParams:], "{"); i >= 0 {
				bodyStart = closeParams + i
			}
		}
	}
	bodyEnd := -1
	if bodyStart >= 0 {
		_, bodyEnd = balanced(text, bodyStart)
	}
	if bodyEnd < 0 {
		return nil, []string{fmt.Sprintf("middleware %s: the body of the exported function could not be read", ref(loc[0]))}
	}
	imported := importedNames(text)
	for _, m := range mwReturnRe.FindAllStringSubmatchIndex(text[:bodyEnd], -1) {
		if m[0] < bodyStart {
			continue
		}
		name := text[m[2]:m[3]]
		if strings.HasPrefix(name, "NextResponse.") || name == "Response.json" || name == "Response.redirect" {
			continue
		}
		head, _, dotted := strings.Cut(name, ".")
		if text[m[4]:m[5]] == "(" {
			switch {
			case name == "fetch":
				blocks = append(blocks, fmt.Sprintf("middleware %s returns a fetched response (a proxy)", ref(m[0])))
			case imported[head] || (!dotted && !local[name]):
				blocks = append(blocks, fmt.Sprintf("middleware %s returns the result of %s(), defined in another module", ref(m[0]), name))
			}
			continue
		}
		if dotted {
			if imported[head] {
				blocks = append(blocks, fmt.Sprintf("middleware %s returns %s from another module", ref(m[0]), name))
			}
			continue
		}
		switch name {
		case "null", "undefined", "true", "false":
			continue
		}
		if k, why := responseVar(name, text); k != "ok" {
			blocks = append(blocks, fmt.Sprintf("middleware %s returns %s, %s", ref(m[0]), name, why))
		}
	}
	n := fmt.Sprintf("middleware %s", f.Path)
	switch {
	case internal > 0 && rejections > 0:
		n += fmt.Sprintf(" redirects or rewrites to internal paths (%d) and rejects requests with error statuses (%d)", internal, rejections)
	case internal > 0:
		n += fmt.Sprintf(" redirects or rewrites to internal paths (%d)", internal)
	case rejections > 0:
		n += fmt.Sprintf(" rejects requests with error statuses (%d)", rejections)
	default:
		n += " passes requests through"
	}
	return []string{n}, blocks
}

// assignments returns the right-hand sides assigned to identifier name.
func assignments(name, text string) []string {
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(name) + `\s*(?::\s*[\w$.<>|\[\] ]+)?=([^=>][^\n;]*)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		rhs := strings.TrimSpace(m[1])
		rhs = strings.TrimSpace(strings.TrimPrefix(rhs, "await "))
		out = append(out, rhs)
	}
	return out
}

// targetKind classifies the target of a redirect or rewrite: internal,
// external or unknown, with the reason.
func targetKind(arg, text string, depth int) (string, string) {
	arg = strings.TrimSpace(arg)
	if v, ok := literal(arg); ok {
		if k := destKind(v); k != "unknown" {
			return k, v
		}
		return "unknown", arg
	}
	if strings.HasPrefix(arg, "`") {
		inner := strings.TrimPrefix(arg, "`")
		if strings.HasPrefix(inner, "/") && !strings.HasPrefix(inner, "//") {
			return "internal", arg
		}
		return "unknown", arg
	}
	if strings.HasPrefix(arg, "new URL(") {
		inner, _ := balanced(arg, len("new URL"))
		parts := splitTop(inner)
		if len(parts) > 0 {
			if v, ok := literal(parts[0]); ok {
				if destKind(v) == "external" {
					return "external", v
				}
				if destKind(v) == "internal" && len(parts) == 2 && (strings.Contains(parts[1], ".url") || strings.Contains(parts[1], "nextUrl")) {
					return "internal", arg
				}
			}
		}
		return "unknown", arg
	}
	if regexp.MustCompile(`^[A-Za-z_$][\w$]*\.nextUrl(?:\.clone\(\))?$`).MatchString(arg) {
		return "internal", arg
	}
	if !regexp.MustCompile(`^[A-Za-z_$][\w$]*$`).MatchString(arg) || depth > 2 {
		return "unknown", arg
	}
	if regexp.MustCompile(regexp.QuoteMeta(arg) + hostMutateRe).MatchString(text) {
		return "external", arg + " has its host, protocol, port or href changed"
	}
	rhs := assignments(arg, text)
	if len(rhs) == 0 {
		return "unknown", arg
	}
	for _, r := range rhs {
		if strings.Contains(r, ".nextUrl.clone()") || regexp.MustCompile(`^[A-Za-z_$][\w$]*\.nextUrl$`).MatchString(r) {
			continue
		}
		if k, why := targetKind(r, text, depth+1); k != "internal" {
			return k, why
		}
	}
	return "internal", arg
}

// responseVar checks that a returned identifier only ever holds a response
// built in the file: "ok", or a reason.
func responseVar(name, text string) (string, string) {
	rhs := assignments(name, text)
	if len(rhs) == 0 {
		return "unknown", "whose value is not assigned in the file"
	}
	for _, r := range rhs {
		if strings.HasPrefix(r, "NextResponse.") || strings.HasPrefix(r, "new NextResponse(") || strings.HasPrefix(r, "new Response(") || strings.HasPrefix(r, "Response.") {
			continue
		}
		return "unknown", fmt.Sprintf("which holds %s", strings.Join(firstN(strings.Fields(r), 1), ""))
	}
	return "ok", ""
}

var (
	cfgWrapRe   = regexp.MustCompile(`\b(with[A-Z]\w*)\s*\(`)
	cfgKeyRe    = regexp.MustCompile(`\b(rewrites|redirects)\b`)
	cfgHeadRe   = regexp.MustCompile(`^(?:rewrites|redirects)\s*(?:\(\s*\)\s*(?::\s*[^{]+)?|:\s*(?:async\s+)?(?:function\s*\(\s*\)\s*|\(\s*\)\s*(?::\s*[^=]+)?=>\s*\(?\s*)?)$`)
	cfgDestRe   = regexp.MustCompile(`\bdestination\s*:\s*`)
	cfgEmptyRe  = regexp.MustCompile(`^\s*(?:return\s*)?\[\s*\]\s*;?\s*$`)
	cfgImportRe = regexp.MustCompile(`(?:\bfrom\s+|\brequire\(\s*)['"](\.{1,2}/[^'"]+)['"]`)
	knownWraps  = map[string]bool{"withSentryConfig": true, "withBundleAnalyzer": true, "withNextIntl": true, "withMDX": true, "withPWA": true, "withVanillaExtract": true, "withContentlayer": true}
)

// analyzeNextConfig reads next.config for what can add routes: rewrites
// and redirects (their destinations must be literal internal paths),
// custom page extensions, Sentry's tunnel route, and config wrappers that
// are not known to leave routing alone.
func (inv *Inventory) analyzeNextConfig(f *File) (notes, blocks []string) {
	text := stripComments(strings.Join(f.Lines, "\n"))
	ref := func(off int) string { return fmt.Sprintf("%s:%d", f.Path, lineAt(text, off)) }
	if i := strings.Index(text, "pageExtensions"); i >= 0 {
		blocks = append(blocks, fmt.Sprintf("%s sets pageExtensions; the table uses the default extensions", ref(i)))
	}
	if i := strings.Index(text, "tunnelRoute"); i >= 0 {
		blocks = append(blocks, fmt.Sprintf("%s sets Sentry's tunnelRoute, a proxy route outside the file table", ref(i)))
	}
	for _, m := range cfgWrapRe.FindAllStringSubmatchIndex(text, -1) {
		name := text[m[2]:m[3]]
		if knownWraps[name] || strings.HasSuffix(strings.TrimSpace(text[:m[0]]), "function") {
			continue
		}
		blocks = append(blocks, fmt.Sprintf("%s wraps the config in %s, which may add rewrites or routes", ref(m[0]), name))
	}
	for _, m := range cfgImportRe.FindAllStringSubmatch(text, -1) {
		t := inv.resolveModule(f.Path, m[1])
		if t == "" {
			for _, ext := range []string{".ts", ".mts", ".js", ".mjs"} {
				if inv.FileByPath(path.Join(path.Dir(f.Path), m[1])+ext) != nil {
					t = path.Join(path.Dir(f.Path), m[1]) + ext
					break
				}
			}
		}
		if t == "" {
			blocks = append(blocks, fmt.Sprintf("%s imports %s, which was not found, so its part of the config is unknown", f.Path, m[1]))
			continue
		}
		if tf := inv.FileByPath(t); tf != nil && cfgKeyRe.MatchString(stripComments(strings.Join(tf.Lines, "\n"))) {
			blocks = append(blocks, fmt.Sprintf("%s imports %s, which mentions rewrites or redirects; they are not evaluated across files", f.Path, t))
		}
	}
	internal := 0
	for _, m := range cfgKeyRe.FindAllStringIndex(text, -1) {
		if m[0] > 0 && (text[m[0]-1] == '\'' || text[m[0]-1] == '"' || text[m[0]-1] == '.') {
			continue
		}
		rest := text[m[0]:]
		open := strings.IndexAny(rest, "{[")
		if open < 0 || !cfgHeadRe.MatchString(strings.TrimSpace(rest[:open])) {
			// Only a key or method named rewrites/redirects counts; a bare
			// word elsewhere is not one.
			if strings.HasPrefix(strings.TrimSpace(rest[len(text[m[0]:m[1]]):]), ":") || strings.HasPrefix(strings.TrimSpace(rest[len(text[m[0]:m[1]]):]), "(") {
				blocks = append(blocks, fmt.Sprintf("%s sets %s to a value defined elsewhere", ref(m[0]), text[m[0]:m[1]]))
			}
			continue
		}
		body, end := balanced(rest, open)
		if end < 0 {
			blocks = append(blocks, fmt.Sprintf("%s: %s could not be read", ref(m[0]), text[m[0]:m[1]]))
			continue
		}
		if strings.Contains(body, "...") {
			blocks = append(blocks, fmt.Sprintf("%s spreads %s from values defined elsewhere", ref(m[0]), text[m[0]:m[1]]))
		}
		dests := cfgDestRe.FindAllStringIndex(body, -1)
		if len(dests) == 0 && !cfgEmptyRe.MatchString(body) && strings.TrimSpace(body) != "" {
			blocks = append(blocks, fmt.Sprintf("%s: %s is computed, with no literal destination", ref(m[0]), text[m[0]:m[1]]))
		}
		for _, d := range dests {
			val := body[d[1]:]
			parts := splitTop(val)
			v := ""
			if len(parts) > 0 {
				v = parts[0]
				if i := strings.IndexAny(v, "}\n"); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
			}
			lit, ok := literal(v)
			switch {
			case !ok:
				blocks = append(blocks, fmt.Sprintf("%s: a %s destination is not a literal (%s)", ref(m[0]+open+1+d[0]), text[m[0]:m[1]], v))
			case destKind(lit) == "external":
				blocks = append(blocks, fmt.Sprintf("%s %s to the external origin %s", ref(m[0]+open+1+d[0]), text[m[0]:m[1]], lit))
			case destKind(lit) == "internal":
				internal++
			default:
				blocks = append(blocks, fmt.Sprintf("%s: a %s destination is not a path (%s)", ref(m[0]+open+1+d[0]), text[m[0]:m[1]], lit))
			}
		}
	}
	if internal > 0 {
		notes = append(notes, fmt.Sprintf("%s: %d rewrites or redirects to internal paths", f.Path, internal))
	}
	if i := strings.Index(text, "basePath"); i >= 0 {
		notes = append(notes, fmt.Sprintf("%s sets basePath, which prefixes every URL", ref(i)))
	}
	return notes, blocks
}

var importBindRe = regexp.MustCompile(`import\s+(?:type\s+)?([^'"]*?)\s+from\s+['"]|(?:const|let|var)\s+([^=]+?)\s*=\s*require\(`)

// importedNames returns the identifiers a module binds by import or require.
func importedNames(text string) map[string]bool {
	out := map[string]bool{}
	for _, m := range importBindRe.FindAllStringSubmatch(text, -1) {
		spec := firstNonEmpty(m[1], m[2])
		for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '{' || r == '}' }) {
			f := strings.Fields(part)
			if len(f) > 0 {
				out[f[len(f)-1]] = true
			}
		}
	}
	return out
}
