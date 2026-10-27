// Package inventory walks a repository read-only and builds the asset list.
//
// Safety: symlinks are never followed, files are size-capped, binary files
// are skipped, nothing in the repository is executed, and .env-style files
// are recorded by name only (their contents are never read).
package inventory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/model"
)

// File is a scanned text file.
type File struct {
	Path    string // slash-separated, relative to root
	SHA256  string
	Size    int64
	Lang    string
	Lines   []string
	Domains []string
}

// Inventory is the result of a walk.
type Inventory struct {
	Root           string
	Files          []*File
	Assets         []model.Asset
	Features       map[string][]string // feature -> provenance (asset IDs or paths)
	Skipped        []string            // path: reason
	Languages      map[string]int
	Tracked        map[string]bool // git-tracked paths (nil when not a git repo)
	GitCommit      string
	GitDirty       bool
	SensitiveNames []string // .env-like files found (content not read)
}

// Options control the walk.
type Options struct {
	Exclude      []string
	MaxFileBytes int64
	MaxFiles     int
}

var langByExt = map[string]string{
	".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
	".py": "python", ".go": "go", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
	".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".swift": "swift",
	".m": "objc", ".scala": "scala", ".ex": "elixir", ".exs": "elixir", ".dart": "dart",
	".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
	".vue": "vue", ".svelte": "svelte", ".html": "html", ".htm": "html",
	".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml", ".xml": "xml",
	".tf": "terraform", ".hcl": "hcl", ".sql": "sql", ".sh": "shell", ".ps1": "powershell",
	".plist": "plist", ".gradle": "gradle", ".properties": "properties", ".ini": "ini", ".cfg": "ini",
	".jinja": "template", ".j2": "template", ".erb": "template", ".ejs": "template", ".hbs": "template",
}

// CodeLangs are languages the code heuristics apply to.
var CodeLangs = map[string]bool{"javascript": true, "typescript": true, "python": true, "go": true, "java": true, "kotlin": true, "ruby": true, "php": true, "csharp": true, "rust": true, "swift": true, "scala": true, "elixir": true, "dart": true, "vue": true, "svelte": true, "objc": true, "c": true, "cpp": true, "template": true, "html": true}

// sensitive file names whose content is never read.
func isSensitiveName(name string) bool {
	l := strings.ToLower(name)
	if l == ".env" || (strings.HasPrefix(l, ".env.") && !strings.HasSuffix(l, ".example") && !strings.HasSuffix(l, ".sample") && !strings.HasSuffix(l, ".template")) {
		return true
	}
	switch l {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc", "credentials", ".git-credentials", "secrets.yml", "secrets.yaml":
		return true
	}
	return strings.HasSuffix(l, ".pem") || strings.HasSuffix(l, ".p12") || strings.HasSuffix(l, ".pfx") || strings.HasSuffix(l, ".key") || strings.HasSuffix(l, ".keystore") || strings.HasSuffix(l, ".jks")
}

// Walk builds the inventory.
func Walk(root string, opt Options) (*Inventory, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{Root: absRoot, Features: map[string][]string{}, Languages: map[string]int{}}
	inv.Tracked, inv.GitCommit, inv.GitDirty = gitInfo(absRoot)
	excl := map[string]bool{}
	for _, e := range opt.Exclude {
		excl[e] = true
	}
	count := 0
	err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, werr error) error {
		rel, _ := filepath.Rel(absRoot, p)
		rel = filepath.ToSlash(rel)
		if werr != nil {
			inv.Skipped = append(inv.Skipped, rel+": unreadable")
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			inv.Skipped = append(inv.Skipped, rel+": symlink not followed")
			return nil
		}
		if d.IsDir() {
			if excl[d.Name()] || excl[rel] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if isSensitiveName(d.Name()) {
			inv.SensitiveNames = append(inv.SensitiveNames, rel)
			return nil
		}
		count++
		if opt.MaxFiles > 0 && count > opt.MaxFiles {
			inv.Skipped = append(inv.Skipped, rel+": max_files limit reached")
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			inv.Skipped = append(inv.Skipped, rel+": stat failed")
			return nil
		}
		lang := langOf(d.Name())
		if lang == "" {
			return nil // not a type we analyze; not a coverage gap
		}
		if info.Size() > opt.MaxFileBytes {
			inv.Skipped = append(inv.Skipped, rel+": larger than max_file_bytes")
			return nil
		}
		f, err := readText(p, opt.MaxFileBytes)
		if err != nil {
			inv.Skipped = append(inv.Skipped, rel+": "+err.Error())
			return nil
		}
		if f == nil {
			return nil // binary
		}
		f.Path = rel
		f.Lang = lang
		f.Size = info.Size()
		inv.Files = append(inv.Files, f)
		inv.Languages[lang]++
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].Path < inv.Files[j].Path })
	inv.detect()
	return inv, nil
}

func langOf(name string) string {
	l := strings.ToLower(name)
	switch {
	case l == "dockerfile" || strings.HasPrefix(l, "dockerfile.") || strings.HasSuffix(l, ".dockerfile"):
		return "dockerfile"
	case l == "gemfile" || l == "podfile" || l == "makefile" || l == "procfile" || l == "jenkinsfile":
		return "manifest"
	case l == "requirements.txt" || (strings.HasPrefix(l, "requirements") && strings.HasSuffix(l, ".txt")):
		return "requirements"
	case l == "go.mod" || l == "go.sum" || l == "gemfile.lock" || l == "cargo.lock" || l == "poetry.lock" || l == "pipfile" || l == "pipfile.lock" || l == "yarn.lock" || l == "composer.lock" || l == "podfile.lock" || l == "uv.lock":
		return "manifest"
	}
	return langByExt[strings.ToLower(path.Ext(l))]
}

func readText(p string, max int64) (*File, error) {
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	head := b
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, nil
	}
	sum := sha256.Sum256(b)
	f := &File{SHA256: hex.EncodeToString(sum[:])}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		f.Lines = append(f.Lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return f, nil
}

// gitInfo reads tracked files and HEAD using git with fixed arguments.
// Repository hooks are disabled and no repository command is executed.
func gitInfo(root string) (map[string]bool, string, bool) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil, "", false
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, "", false
	}
	run := func(args ...string) ([]byte, error) {
		base := []string{"-C", root, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "safe.directory=" + filepath.ToSlash(root)}
		cmd := exec.Command(git, append(base, args...)...)
		cmd.Env = append(minimalEnv(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
		done := make(chan struct{})
		var out []byte
		var err error
		go func() { out, err = cmd.Output(); close(done) }()
		select {
		case <-done:
			return out, err
		case <-time.After(30 * time.Second):
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			return nil, os.ErrDeadlineExceeded
		}
	}
	tracked := map[string]bool{}
	if out, err := run("ls-files", "-z"); err == nil {
		for _, p := range bytes.Split(out, []byte{0}) {
			if len(p) > 0 {
				tracked[string(p)] = true
			}
		}
	} else {
		return nil, "", false
	}
	commit := ""
	if out, err := run("rev-parse", "HEAD"); err == nil {
		commit = strings.TrimSpace(string(out))
	}
	dirty := false
	if out, err := run("status", "--porcelain", "--untracked-files=no"); err == nil {
		dirty = len(bytes.TrimSpace(out)) > 0
	}
	return tracked, commit, dirty
}

// minimalEnv returns a scrubbed environment with no cloud or VCS tokens.
func minimalEnv() []string {
	keep := []string{"PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL"}
	var env []string
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// MinimalEnv is exported for adapters.
func MinimalEnv() []string { return minimalEnv() }

// ---- detection ----

var (
	routeRes = []struct {
		re        *regexp.Regexp
		framework string
		method    int
		path      int
	}{
		{regexp.MustCompile(`\b(?:app|router|server|api|routes)\.(get|post|put|patch|delete|all|options)\(\s*['"\x60]([^'"\x60]+)['"\x60]`), "express", 1, 2},
		{regexp.MustCompile(`@(?:app|router|api|bp|blueprint)\.(get|post|put|patch|delete|route)\(\s*['"]([^'"]+)['"]`), "flask/fastapi", 1, 2},
		{regexp.MustCompile(`\b(?:http\.)?HandleFunc\(\s*"([^"]+)"`), "go-net/http", 0, 1},
		{regexp.MustCompile(`\b\w+\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*"(/[^"]*)"`), "go-router", 1, 2},
		{regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?"([^"]*)"`), "spring", 1, 2},
		{regexp.MustCompile(`Route::(get|post|put|patch|delete|any|match)\(\s*['"]([^'"]+)['"]`), "laravel", 1, 2},
		{regexp.MustCompile(`\b(?:re_)?path\(\s*r?['"]([^'"]*)['"]\s*,`), "django", 0, 1},
		{regexp.MustCompile(`^\s*(get|post|put|patch|delete)\s+['"](/[^'"]*)['"]`), "rails/sinatra", 1, 2},
		{regexp.MustCompile(`\[(?:Http)?(Get|Post|Put|Patch|Delete)\(\s*"([^"]*)"\s*\)\]`), "aspnet", 1, 2},
	}
	nextRouteRe   = regexp.MustCompile(`(?:^|/)app/(.*)/route\.(?:js|ts|mjs)$`)
	nextPagesAPI  = regexp.MustCompile(`(?:^|/)pages/api/(.*)\.(?:js|ts|jsx|tsx)$`)
	nextMethodRe  = regexp.MustCompile(`export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b`)
	paramRe       = regexp.MustCompile(`(:[A-Za-z_]\w*|\{[^}]+\}|<[^>]+>|\[[^\]]+\])`)
	authPathRe    = regexp.MustCompile(`(?i)(login|logout|signin|sign-in|signup|register|auth|oauth|token|session|password|reset|mfa|2fa|otp|sso|callback)`)
	adminPathRe   = regexp.MustCompile(`(?i)(/admin|/internal|/manage|/staff|/superuser|/root)`)
	webhookPathRe = regexp.MustCompile(`(?i)(webhook|/hooks?/|callback|/notify|/ipn)`)
	paymentRe     = regexp.MustCompile(`(?i)(\bstripe\b|paypal|braintree|adyen|checkout\.sessions|paymentintent|payment_intent|mollie|razorpay|square\.(?:payments|client)|lemonsqueezy|paddle)`)
	llmRe         = regexp.MustCompile(`(?i)(@anthropic-ai/sdk|from anthropic import|import anthropic|\bopenai\b|@ai-sdk/|from ['"]ai['"]|langchain|llama_index|llamaindex|google\.generativeai|@google/genai|ollama|bedrock-runtime|cohere|mistralai)`)
	jwtLibRe      = regexp.MustCompile(`(?i)(jsonwebtoken|\bjwt\b|jose|passport|next-auth|auth\.js|@clerk/|firebase/auth|flask_login|django\.contrib\.auth|devise|golang-jwt|spring-security|express-session|cookie-session|iron-session|lucia|better-auth)`)
)

func (inv *Inventory) feature(name, prov string) {
	for _, p := range inv.Features[name] {
		if p == prov {
			return
		}
	}
	inv.Features[name] = append(inv.Features[name], prov)
}

// Has reports whether a feature has provenance.
func (inv *Inventory) Has(name string) bool {
	if name == "any" {
		return true
	}
	return len(inv.Features[name]) > 0
}

func (inv *Inventory) addAsset(a model.Asset) {
	inv.Assets = append(inv.Assets, a)
}

func (inv *Inventory) detect() {
	inv.feature("any", ".")
	if inv.Tracked != nil {
		inv.feature("git", ".git")
	}
	type routeInfo struct{ method, p, file string }
	var routes []routeInfo
	manifests := map[string]string{} // dir -> kind
	locks := map[string]bool{}
	for _, f := range inv.Files {
		base := path.Base(f.Path)
		lb := strings.ToLower(base)
		dir := path.Dir(f.Path)
		domains := map[string]bool{}
		if CodeLangs[f.Lang] {
			inv.feature("code", f.Path)
			domains["D"] = true
		}
		switch {
		case lb == "package.json":
			manifests[dir+"|npm"] = f.Path
			inv.feature("packages", f.Path)
			domains["I"] = true
			if bytes.Contains([]byte(strings.Join(f.Lines, "\n")), []byte(`"next"`)) || containsAny(f.Lines, `"express"`, `"fastify"`, `"koa"`, `"@nestjs/core"`, `"hono"`, `"react"`, `"vue"`, `"svelte"`, `"nuxt"`, `"@angular/core"`) {
				inv.feature("web", f.Path)
			}
		case lb == "package-lock.json" || lb == "npm-shrinkwrap.json" || lb == "yarn.lock" || lb == "pnpm-lock.yaml" || lb == "bun.lock" || lb == "bun.lockb":
			locks[dir+"|npm"] = true
			domains["I"] = true
			if lb == "package-lock.json" && containsAny(f.Lines, `"hasInstallScript": true`) {
				inv.feature("install_scripts", f.Path)
			}
			if lb == "package-lock.json" {
				inv.feature("npm_lock", f.Path)
			}
		case lb == "requirements.txt" || f.Lang == "requirements":
			manifests[dir+"|pip"] = f.Path
			inv.feature("packages", f.Path)
			inv.feature("python_reqs", f.Path)
			domains["I"] = true
			if containsAny(f.Lines, "django", "flask", "fastapi", "starlette", "Django", "Flask", "FastAPI") {
				inv.feature("web", f.Path)
			}
		case lb == "pyproject.toml" || lb == "pipfile":
			manifests[dir+"|py"] = f.Path
			inv.feature("packages", f.Path)
			domains["I"] = true
			if containsAny(f.Lines, "django", "flask", "fastapi", "Django", "Flask", "FastAPI") {
				inv.feature("web", f.Path)
			}
		case lb == "poetry.lock" || lb == "pipfile.lock" || lb == "uv.lock" || lb == "pdm.lock":
			locks[dir+"|py"] = true
		case lb == "go.mod":
			manifests[dir+"|go"] = f.Path
			inv.feature("packages", f.Path)
			domains["I"] = true
			if containsAny(f.Lines, "gin-gonic", "labstack/echo", "gofiber", "go-chi", "gorilla/mux") {
				inv.feature("web", f.Path)
			}
		case lb == "go.sum":
			locks[dir+"|go"] = true
		case lb == "gemfile":
			manifests[dir+"|ruby"] = f.Path
			inv.feature("packages", f.Path)
		case lb == "gemfile.lock":
			locks[dir+"|ruby"] = true
		case lb == "cargo.toml":
			manifests[dir+"|cargo"] = f.Path
			inv.feature("packages", f.Path)
		case lb == "cargo.lock":
			locks[dir+"|cargo"] = true
		case lb == "composer.json":
			manifests[dir+"|composer"] = f.Path
			inv.feature("packages", f.Path)
			inv.feature("web", f.Path)
		case lb == "composer.lock":
			locks[dir+"|composer"] = true
		case lb == "pom.xml" || lb == "build.gradle" || lb == "build.gradle.kts":
			inv.feature("packages", f.Path)
			if containsAny(f.Lines, "spring-boot", "springframework") {
				inv.feature("web", f.Path)
			}
		case f.Lang == "dockerfile":
			inv.feature("dockerfile", f.Path)
			inv.feature("deploy_config", f.Path)
			inv.feature("iac", f.Path)
			domains["J"] = true
		case lb == "docker-compose.yml" || lb == "docker-compose.yaml" || lb == "compose.yml" || lb == "compose.yaml":
			inv.feature("orchestration", f.Path)
			inv.feature("deploy_config", f.Path)
			domains["J"] = true
		case f.Lang == "terraform":
			inv.feature("terraform", f.Path)
			inv.feature("iac", f.Path)
			inv.feature("deploy_config", f.Path)
			domains["J"] = true
		case lb == "vercel.json" || lb == "vercel.ts" || lb == "netlify.toml" || lb == "fly.toml" || lb == "app.yaml" || lb == "serverless.yml" || lb == "wrangler.toml":
			inv.feature("deploy_config", f.Path)
			domains["J"] = true
		case lb == "androidmanifest.xml":
			inv.feature("android", f.Path)
			domains["K"] = true
		case lb == "info.plist":
			inv.feature("ios", f.Path)
			domains["L"] = true
		case lb == ".mcp.json" || lb == "mcp.json" || lb == "claude_desktop_config.json" || (strings.Contains(f.Path, ".cursor/") && lb == "mcp.json"):
			inv.feature("mcp_config", f.Path)
			domains["P"] = true
		}
		if f.Lang == "yaml" && strings.Contains(f.Path, ".github/workflows/") {
			inv.feature("github_workflows", f.Path)
			domains["N"] = true
			domains["I"] = true
			for _, l := range f.Lines {
				if m := usesRe.FindStringSubmatch(l); m != nil && !strings.HasPrefix(m[1], "./") && !strings.HasPrefix(m[1], "docker://") {
					inv.feature("third_party_actions", f.Path)
					break
				}
			}
		}
		if f.Lang == "yaml" && containsAny(f.Lines, "apiVersion:") && containsAny(f.Lines, "kind: Deployment", "kind: Pod", "kind: DaemonSet", "kind: StatefulSet", "kind: Job", "kind: CronJob") {
			inv.feature("orchestration", f.Path)
			inv.feature("iac", f.Path)
			inv.feature("deploy_config", f.Path)
			domains["J"] = true
		}
		if (f.Lang == "yaml" || f.Lang == "json") && (strings.Contains(lb, "openapi") || strings.Contains(lb, "swagger")) || (f.Lang == "yaml" || f.Lang == "json") && len(f.Lines) > 0 && (strings.HasPrefix(strings.TrimSpace(f.Lines[0]), "openapi:") || strings.HasPrefix(strings.TrimSpace(f.Lines[0]), "swagger:")) {
			inv.feature("openapi", f.Path)
			domains["G"] = true
			domains["A"] = true
			inv.addAsset(model.Asset{ID: "contract:" + f.Path, Kind: "api_contract", Locator: f.Path, ContentHash: f.SHA256, Domains: []string{"A", "G"}})
		}
		if CodeLangs[f.Lang] {
			joined := strings.Join(f.Lines, "\n")
			if paymentRe.MatchString(joined) {
				inv.feature("payments", f.Path)
				domains["F"] = true
			}
			if llmRe.MatchString(joined) {
				inv.feature("llm", f.Path)
				domains["P"] = true
			}
			if jwtLibRe.MatchString(joined) {
				inv.feature("auth", f.Path)
				domains["B"] = true
			}
			// routes
			for i, l := range f.Lines {
				for _, rr := range routeRes {
					m := rr.re.FindStringSubmatch(l)
					if m == nil {
						continue
					}
					method := "ANY"
					if rr.method > 0 {
						method = strings.ToUpper(m[rr.method])
						if method == "ROUTE" || method == "ALL" || method == "ANY" || method == "MATCH" || method == "REQUEST" {
							method = "ANY"
						}
					}
					p := m[rr.path]
					if rr.framework == "django" && !strings.Contains(f.Path, "urls") {
						continue
					}
					if !strings.HasPrefix(p, "/") && rr.framework != "django" {
						continue
					}
					routes = append(routes, routeInfo{method, p, f.Path})
					inv.addAsset(model.Asset{ID: "route:" + method + ":" + p + "@" + f.Path, Kind: "route", Locator: f.Path, Line: i + 1, ContentHash: f.SHA256,
						Domains: []string{"A", "B", "C", "D", "G"}, Meta: map[string]string{"method": method, "path": p, "framework": rr.framework, "confidence": "heuristic"}})
					break
				}
			}
			if m := nextRouteRe.FindStringSubmatch(f.Path); m != nil || nextPagesAPI.MatchString(f.Path) {
				var p string
				if m != nil {
					p = "/" + m[1]
				} else {
					p = "/api/" + nextPagesAPI.FindStringSubmatch(f.Path)[1]
				}
				p = regexp.MustCompile(`/\([^)]*\)`).ReplaceAllString(p, "")
				methods := []string{}
				for _, l := range f.Lines {
					if mm := nextMethodRe.FindStringSubmatch(l); mm != nil {
						methods = append(methods, mm[1])
					}
				}
				if len(methods) == 0 {
					methods = []string{"ANY"}
				}
				for _, method := range methods {
					routes = append(routes, routeInfo{method, p, f.Path})
					inv.addAsset(model.Asset{ID: "route:" + method + ":" + p + "@" + f.Path, Kind: "route", Locator: f.Path, Line: 1, ContentHash: f.SHA256,
						Domains: []string{"A", "B", "C", "D", "G"}, Meta: map[string]string{"method": method, "path": p, "framework": "nextjs", "confidence": "file-convention"}})
				}
				inv.feature("web", f.Path)
			}
		}
		for d := range domains {
			f.Domains = append(f.Domains, d)
		}
		sort.Strings(f.Domains)
		inv.addAsset(model.Asset{ID: "file:" + f.Path, Kind: "file:" + f.Lang, Locator: f.Path, ContentHash: f.SHA256, Domains: f.Domains})
	}
	for _, r := range routes {
		prov := "route:" + r.method + ":" + r.p + "@" + r.file
		inv.feature("routes", prov)
		inv.feature("web", r.file)
		if paramRe.MatchString(r.p) {
			inv.feature("param_routes", prov)
		}
		if authPathRe.MatchString(r.p) {
			inv.feature("auth_routes", prov)
			inv.feature("auth", prov)
		}
		if adminPathRe.MatchString(r.p) {
			inv.feature("admin_routes", prov)
		}
		if webhookPathRe.MatchString(r.p) {
			inv.feature("webhooks", prov)
		}
	}
	for k, p := range manifests {
		if !locks[k] {
			inv.feature("missing_lockfile", p)
		}
	}
	for _, s := range inv.SensitiveNames {
		inv.addAsset(model.Asset{ID: "sensitive:" + s, Kind: "sensitive_file", Locator: s, Domains: []string{"E"}, Meta: map[string]string{"content": "not read"}})
	}
	sort.Slice(inv.Assets, func(i, j int) bool { return inv.Assets[i].ID < inv.Assets[j].ID })
}

var usesRe = regexp.MustCompile(`^\s*-?\s*uses:\s*['"]?([^'"\s#]+)`)

// UsesRe matches a workflow `uses:` line.
func UsesRe() *regexp.Regexp { return usesRe }

func containsAny(lines []string, subs ...string) bool {
	for _, l := range lines {
		for _, s := range subs {
			if strings.Contains(l, s) {
				return true
			}
		}
	}
	return false
}

// RouteFiles returns the set of files that define routes.
func (inv *Inventory) RouteFiles() map[string]bool {
	out := map[string]bool{}
	for _, a := range inv.Assets {
		if a.Kind == "route" {
			out[a.Locator] = true
		}
	}
	return out
}

// FileByPath returns a scanned file.
func (inv *Inventory) FileByPath(p string) *File {
	i := sort.Search(len(inv.Files), func(i int) bool { return inv.Files[i].Path >= p })
	if i < len(inv.Files) && inv.Files[i].Path == p {
		return inv.Files[i]
	}
	return nil
}

// DomainsForPath classifies a path for invalidation when it was not part of
// the last inventory (new file).
func DomainsForPath(p string) []string {
	l := strings.ToLower(filepath.ToSlash(p))
	set := map[string]bool{"A": true}
	switch {
	case strings.Contains(l, ".github/workflows/"):
		set["N"], set["I"] = true, true
	case strings.HasSuffix(l, "package.json") || strings.HasSuffix(l, ".lock") || strings.HasSuffix(l, "go.mod") || strings.HasSuffix(l, "requirements.txt") || strings.HasSuffix(l, "lock.json") || strings.HasSuffix(l, "lock.yaml"):
		set["I"] = true
	case strings.Contains(l, "dockerfile") || strings.HasSuffix(l, ".tf") || strings.Contains(l, "compose"):
		set["J"] = true
	case strings.HasSuffix(l, "androidmanifest.xml"):
		set["K"] = true
	case strings.HasSuffix(l, "info.plist"):
		set["L"] = true
	default:
		set["B"], set["C"], set["D"], set["E"], set["G"], set["H"] = true, true, true, true, true, true
	}
	var out []string
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
