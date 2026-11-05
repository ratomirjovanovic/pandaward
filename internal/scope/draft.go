package scope

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

// DraftOptions control `pandaward scope init`.
type DraftOptions struct {
	// Target is a URL the user passed. It is the only way a non-local
	// target gets into a draft.
	Target string
}

// Draft is a manifest drafted from the project. It is never approved: a
// person reviews it, fills in the authorization block and approves it.
type Draft struct {
	Targets []DraftTarget
	Routes  []DraftRoute
	Roles   []DraftRole
}

// DraftTarget is a target URL and where it was found.
type DraftTarget struct {
	URL    string
	Source string
}

// DraftRoute is a readable route, with dynamic segments as placeholders.
type DraftRoute struct {
	Method string
	Path   string
	File   string
}

// DraftRole is a role name found in code.
type DraftRole struct {
	Name   string
	Source string
}

// maxDraftRoutes and maxDraftRoles keep the draft readable.
const (
	maxDraftRoutes = 40
	maxDraftRoles  = 12
)

var (
	nextPortRe  = regexp.MustCompile(`(?:^|\s)(?:-p|--port)(?:\s+|=)(\d{2,5})\b`)
	envPortRe   = regexp.MustCompile(`(?:^|\s)PORT=(\d{2,5})\b`)
	envURLKeyRe = regexp.MustCompile(`^(?:NEXT_PUBLIC_|VITE_|PUBLIC_|NUXT_PUBLIC_)?(?:SITE|APP|BASE|PUBLIC|FRONTEND|WEB|NEXTAUTH|AUTH)_?URL$`)
	// Role names: enums and union types named like a role, zod enums on a
	// role field, Postgres enum types, role comparisons in checks.
	roleEnumRe   = regexp.MustCompile(`\benum\s+\w*[Rr]ole\w*\s*\{([^}]*)\}?`)
	roleUnionRe  = regexp.MustCompile(`\btype\s+\w*[Rr]ole\w*\s*=\s*((?:\s*\|?\s*['"][A-Za-z0-9_-]+['"])+)`)
	roleZodRe    = regexp.MustCompile(`\brole\w*\s*:\s*z\.enum\(\s*\[([^\]]*)\]`)
	rolePgEnumRe = regexp.MustCompile(`(?i)create\s+type\s+[\w."]*role[\w"]*\s+as\s+enum\s*\(([^)]*)\)`)
	roleCmpRe    = regexp.MustCompile(`\brole\w*\s*(?:===?|!==?)\s*['"]([A-Za-z0-9_-]{2,32})['"]|\b(?:hasRole|requireRole|isRole|checkRole)\(\s*['"]([A-Za-z0-9_-]{2,32})['"]|\broles?\.includes\(\s*['"]([A-Za-z0-9_-]{2,32})['"]`)
	rlsPolicyRe  = regexp.MustCompile(`(?i)create\s+policy\s+("[^"]+"|\S+)\s+on\s+([\w."]+)`)
	quotedRe     = regexp.MustCompile(`['"]([A-Za-z0-9_-]{2,32})['"]`)
	bareWordRe   = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9_]{1,31})\b`)
	nextSegRe    = regexp.MustCompile(`\[\[?(?:\.\.\.)?([^\]]+)\]?\]`)
	colonSegRe   = regexp.MustCompile(`/:([A-Za-z0-9_]+)`)
	braceSegRe   = regexp.MustCompile(`\{([A-Za-z0-9_]+)(?::[^}]*)?\}`)
)

// devServers maps a dev command to its default port.
var devServers = []struct {
	re   *regexp.Regexp
	port int
}{
	{regexp.MustCompile(`\bnext\s+(?:dev|start)\b`), 3000},
	{regexp.MustCompile(`\bnuxt\s+dev\b|\bnuxi\s+dev\b`), 3000},
	{regexp.MustCompile(`\bastro\s+dev\b`), 4321},
	{regexp.MustCompile(`\bng\s+serve\b`), 4200},
	{regexp.MustCompile(`\b(?:react-router|remix\s+vite:dev|vite)(?:\s+dev)?\b`), 5173},
	{regexp.MustCompile(`\bremix\s+dev\b`), 3000},
}

// BuildDraft reads the project and drafts targets, routes and roles. It
// only reads files; it sends nothing.
func BuildDraft(inv *inventory.Inventory, opt DraftOptions) (*Draft, error) {
	d := &Draft{}
	if opt.Target != "" {
		u, err := ParseTarget(opt.Target)
		if err != nil {
			return nil, fmt.Errorf("--target %q: %w", opt.Target, err)
		}
		d.Targets = append(d.Targets, DraftTarget{URL: strings.TrimSuffix(u.String(), "/"), Source: "--target"})
	} else {
		d.Targets = localTargets(inv)
	}
	d.Routes = draftRoutes(inv)
	d.Roles = draftRoles(inv)
	return d, nil
}

// localTargets finds local dev URLs in package scripts and env examples.
// Only loopback URLs are kept, so a draft never points at production.
func localTargets(inv *inventory.Inventory) []DraftTarget {
	var out []DraftTarget
	seen := map[string]bool{}
	add := func(u, src string) {
		if !seen[u] {
			seen[u] = true
			out = append(out, DraftTarget{URL: u, Source: src})
		}
	}
	var pkgs []*inventory.File
	for _, f := range inv.Files {
		if path.Base(f.Path) == "package.json" && !strings.Contains(f.Path, "node_modules/") {
			pkgs = append(pkgs, f)
		}
	}
	sort.Slice(pkgs, func(i, j int) bool {
		return strings.Count(pkgs[i].Path, "/") < strings.Count(pkgs[j].Path, "/") || (strings.Count(pkgs[i].Path, "/") == strings.Count(pkgs[j].Path, "/") && pkgs[i].Path < pkgs[j].Path)
	})
	dirs := []string{"."}
	for _, f := range pkgs {
		var pj struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &pj) != nil {
			continue
		}
		dir := path.Dir(f.Path)
		if dir != "." {
			dirs = append(dirs, dir)
		}
		for _, name := range []string{"dev", "start", "serve", "preview"} {
			s := pj.Scripts[name]
			if s == "" {
				continue
			}
			for _, ds := range devServers {
				if !ds.re.MatchString(s) {
					continue
				}
				port := ds.port
				if m := nextPortRe.FindStringSubmatch(s); m != nil {
					port, _ = strconv.Atoi(m[1])
				} else if m := envPortRe.FindStringSubmatch(s); m != nil {
					port, _ = strconv.Atoi(m[1])
				}
				add(fmt.Sprintf("http://localhost:%d", port), fmt.Sprintf("%s scripts.%s", f.Path, name))
				break
			}
		}
	}
	for _, dir := range dirs {
		for _, name := range []string{".env.example", ".env.sample", ".env.template", ".env.local.example"} {
			rel := path.Join(dir, name)
			b, err := readSmall(filepath.Join(inv.Root, filepath.FromSlash(rel)))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(b, "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export ")), "=")
				if !ok || !envURLKeyRe.MatchString(strings.TrimSpace(k)) {
					continue
				}
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				u, err := url.Parse(v)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !isLoopbackHost(u.Hostname()) {
					continue
				}
				add(u.Scheme+"://"+u.Host, rel+" "+strings.TrimSpace(k))
			}
		}
	}
	return out
}

func readSmall(p string) (string, error) {
	st, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if st.IsDir() || st.Size() > 64<<10 {
		return "", fmt.Errorf("skipped")
	}
	b, err := os.ReadFile(p)
	return string(b), err
}

func isLoopbackHost(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "127.0.0.1" || h == "::1"
}

// Placeholder turns dynamic route segments into <name> placeholders:
// [id], [...slug], [[...slug]], :id and {id} all become <id>.
func Placeholder(p string) string {
	p = nextSegRe.ReplaceAllString(p, "<$1>")
	p = colonSegRe.ReplaceAllString(p, "/<$1>")
	return braceSegRe.ReplaceAllString(p, "<$1>")
}

// draftRoutes lists readable routes, dynamic ones first because those are
// where object-level authorization is decided.
func draftRoutes(inv *inventory.Inventory) []DraftRoute {
	seen := map[string]bool{}
	var out []DraftRoute
	add := func(method, p, file string) {
		method = strings.ToUpper(method)
		if method != "GET" && method != "HEAD" {
			return
		}
		if p == "" || !strings.HasPrefix(p, "/") {
			return
		}
		p = Placeholder(p)
		k := method + " " + p
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, DraftRoute{Method: method, Path: p, File: file})
	}
	if inv.NextJS != nil {
		for _, app := range inv.NextJS.Apps {
			for _, e := range app.Entries {
				switch e.Kind {
				case "page":
					add("GET", e.URL, e.File)
				case "route", "api":
					for _, m := range e.Methods {
						add(m, e.URL, e.File)
					}
				}
			}
		}
	}
	for _, a := range inv.Assets {
		if a.Kind == "route" {
			add(a.Meta["method"], a.Meta["path"], a.Locator)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		di, dj := strings.Contains(out[i].Path, "<"), strings.Contains(out[j].Path, "<")
		if di != dj {
			return di
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > maxDraftRoutes {
		out = out[:maxDraftRoutes]
	}
	return out
}

// draftRoles collects role names from enums, union types, zod schemas,
// Postgres enum types and role checks, plus tables with RLS policies.
func draftRoles(inv *inventory.Inventory) []DraftRole {
	seen := map[string]bool{}
	var out []DraftRole
	add := func(name, src string) {
		n := strings.ToLower(strings.Trim(name, ` "'`))
		if n == "" || len(n) > 32 || seen[n] || !identityNameRe.MatchString(strings.ReplaceAll(n, " ", "_")) || n == Anonymous {
			return
		}
		seen[n] = true
		out = append(out, DraftRole{Name: n, Source: src})
	}
	files := inv.Files
	// The inventory does not read Prisma schemas; their role enums are
	// read here from the usual places.
	for _, rel := range prismaSchemas(inv) {
		if b, err := readSmall(filepath.Join(inv.Root, filepath.FromSlash(rel))); err == nil {
			files = append(files, &inventory.File{Path: rel, Lang: "prisma", Lines: strings.Split(b, "\n")})
		}
	}
	for _, f := range files {
		if !inventory.CodeLangs[f.Lang] && f.Lang != "sql" && f.Lang != "prisma" {
			continue
		}
		if strings.Contains(f.Path, "node_modules/") || strings.Contains(f.Path, "/test") || strings.Contains(f.Path, ".test.") || strings.Contains(f.Path, ".spec.") {
			continue
		}
		text := strings.Join(f.Lines, "\n")
		where := func(off int) string {
			return fmt.Sprintf("%s:%d", f.Path, strings.Count(text[:off], "\n")+1)
		}
		for _, m := range roleEnumRe.FindAllStringSubmatchIndex(text, -1) {
			body := text[m[2]:m[3]]
			vals := quotedRe.FindAllStringSubmatch(body, -1)
			if len(vals) == 0 {
				// enum Role { ADMIN, MEMBER } or Prisma enum Role { ADMIN USER }
				for _, w := range bareWordRe.FindAllStringSubmatch(body, -1) {
					add(w[1], where(m[0]))
				}
			}
			for _, v := range vals {
				add(v[1], where(m[0]))
			}
		}
		for _, re := range []*regexp.Regexp{roleUnionRe, roleZodRe, rolePgEnumRe} {
			for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
				for _, v := range quotedRe.FindAllStringSubmatch(text[m[2]:m[3]], -1) {
					add(v[1], where(m[0]))
				}
			}
		}
		for _, m := range roleCmpRe.FindAllStringSubmatchIndex(text, -1) {
			for g := 1; g <= 3; g++ {
				if m[2*g] >= 0 {
					add(text[m[2*g]:m[2*g+1]], where(m[0]))
				}
			}
		}
		if f.Lang == "sql" {
			for _, m := range rlsPolicyRe.FindAllStringSubmatchIndex(text, -1) {
				tbl := strings.Trim(text[m[4]:m[5]], `"`)
				k := "rls:" + tbl
				if !seen[k] {
					seen[k] = true
					out = append(out, DraftRole{Name: "", Source: fmt.Sprintf("RLS policy on %s at %s", tbl, where(m[0]))})
				}
			}
		}
		if len(out) >= maxDraftRoles*2 {
			break
		}
	}
	var roles, rls []DraftRole
	for _, r := range out {
		if r.Name == "" {
			rls = append(rls, r)
		} else {
			roles = append(roles, r)
		}
	}
	if len(roles) > maxDraftRoles {
		roles = roles[:maxDraftRoles]
	}
	if len(rls) > maxDraftRoles {
		rls = rls[:maxDraftRoles]
	}
	return append(roles, rls...)
}

// prismaSchemas lists prisma/schema.prisma at the root and next to every
// package.json.
func prismaSchemas(inv *inventory.Inventory) []string {
	seen := map[string]bool{}
	var out []string
	add := func(dir string) {
		rel := path.Join(dir, "prisma", "schema.prisma")
		if !seen[rel] {
			seen[rel] = true
			out = append(out, rel)
		}
	}
	add(".")
	for _, f := range inv.Files {
		if path.Base(f.Path) == "package.json" && !strings.Contains(f.Path, "node_modules/") {
			add(path.Dir(f.Path))
		}
	}
	return out
}

// Render writes the draft as a manifest. The authorization block stays
// empty and acknowledged false, so the draft cannot run until a person
// fills it in and approves it.
func (d *Draft) Render() string {
	var b strings.Builder
	local := len(d.Targets) > 0
	for _, t := range d.Targets {
		if u, err := url.Parse(t.URL); err != nil || !isLoopbackHost(u.Hostname()) {
			local = false
		}
	}
	env := "staging"
	if local {
		env = "local"
	}
	b.WriteString(`# PandaWard scope manifest (schema v1), DRAFTED by ` + "`pandaward scope init`" + `.
# This draft is NOT approved and cannot run as written. Review every line,
# fill in the authorization block, then approve it yourself from an
# interactive terminal:  pandaward scope approve --by "<your name>"
# Editing this file invalidates any previous approval.
schema_version: 1
authorization:
  owner: ""          # person or organization that owns the targets or granted permission
  reference: ""      # written permission, ticket or contract reference
  purpose: ""        # why this test is run
  contact: ""        # incident contact during the test window
  acknowledged: false  # set true only if you are authorized to test every target below
`)
	fmt.Fprintf(&b, "environment: %s   # staging | production | local\n", env)
	b.WriteString("window:\n  start: \"\"          # RFC3339, optional\n  end: \"\"            # RFC3339, optional\n")
	if len(d.Targets) == 0 {
		b.WriteString("targets: []\n#  No local dev URL was found in package scripts or .env examples.\n#  - url: http://localhost:3000\n")
	} else {
		b.WriteString("targets:\n")
		for _, t := range d.Targets {
			fmt.Fprintf(&b, "  - url: %s   # from %s\n", t.URL, t.Source)
		}
	}
	b.WriteString("excluded_paths: []\nallowed_methods: [GET, HEAD]\n")
	if local {
		b.WriteString("allow_private_addresses: true    # the targets above are local dev servers\n")
	} else {
		b.WriteString("allow_private_addresses: false   # true only for a controlled local fixture\n")
	}
	b.WriteString(`limits:
  requests_per_second: 1
  max_requests_total: 100
  timeout_seconds: 10
zap:                 # ZAP baseline, run by: pandaward test --profile staging-active
  active_scan: false   # true sends ZAP attack payloads; never on production
  max_duration_minutes: 10
# Test identities. Credentials never go in this file: value_env names the
# environment variable with the full header value. A project command can
# create them instead (see identity_provisioning below).
identities: []
`)
	var roles, rls []DraftRole
	for _, r := range d.Roles {
		if r.Name == "" {
			rls = append(rls, r)
		} else {
			roles = append(roles, r)
		}
	}
	if len(roles) > 0 {
		b.WriteString("# Roles found in code; add one identity per role and one in another tenant:\n")
		for _, r := range roles {
			env := "PANDAWARD_ID_" + strings.ToUpper(strings.NewReplacer("-", "_", " ", "_").Replace(r.Name))
			fmt.Fprintf(&b, "#  - name: %s            # role %s, found at %s\n#    tenant: \"\"\n#    header: Authorization\n#    value_env: %s\n", strings.ReplaceAll(r.Name, " ", "_"), r.Name, r.Source, env)
		}
	} else {
		b.WriteString("#  - name: owner\n#    tenant: acme\n#    header: Authorization\n#    value_env: PANDAWARD_ID_OWNER\n")
	}
	b.WriteString("#  - name: other_tenant\n#    tenant: other\n#    header: Authorization\n#    value_env: PANDAWARD_ID_OTHER_TENANT\n")
	b.WriteString("#  - name: revoked\n#    header: Authorization\n#    value_env: PANDAWARD_ID_REVOKED\n#    revoked: true                 # a logged-out token that must be refused (B-004)\n")
	for _, r := range rls {
		fmt.Fprintf(&b, "# Note: %s; tenant isolation there needs identities in two tenants.\n", r.Source)
	}
	b.WriteString(`# identity_provisioning:            # optional: a project command creates the identities
#   provision: [node, scripts/pandaward-identities.mjs, create]
#   cleanup: [node, scripts/pandaward-identities.mjs, delete]
#   timeout_seconds: 60
`)
	b.WriteString("# Authorization checks: one read-only request to an object or function that\n# exists for the test; only \"allowed\" may succeed.\nauthorization_checks: []\n")
	if len(d.Routes) == 0 {
		b.WriteString("#  - name: acme invoice\n#    kind: object\n#    method: GET\n#    path: /api/invoices/inv_acme_1\n#    allowed: [owner]\n")
	} else {
		b.WriteString("# Readable routes found in code (replace <placeholders> with real test objects):\n")
		for _, r := range d.Routes {
			kind := "function"
			if strings.Contains(r.Path, "<") {
				kind = "object"
			}
			fmt.Fprintf(&b, "#  - name: %s %s\n#    kind: %s\n#    method: %s\n#    path: %s   # %s\n#    allowed: []\n", r.Method, r.Path, kind, r.Method, r.Path, r.File)
		}
	}
	return b.String()
}
