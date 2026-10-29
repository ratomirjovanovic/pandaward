// Package inventory walks a repository read-only and builds the asset list.
//
// Safety: symlinks are never followed, files are size-capped, binary files
// are skipped, nothing in the repository is executed, and .env-style files
// are recorded by name only (their contents are never read).
package inventory

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/ratomirjovanovic/pandaward/internal/model"
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
	".plist": "plist", ".entitlements": "plist", ".gradle": "gradle", ".properties": "properties", ".ini": "ini", ".cfg": "ini",
	".jinja": "template", ".j2": "template", ".erb": "template", ".ejs": "template", ".hbs": "template",
	".apk": "apk", ".ipa": "ipa", ".graphql": "graphql", ".gql": "graphql", ".proto": "proto",
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
	err = walkFiles(context.Background(), absRoot, opt, true, func(f *File) {
		inv.Files = append(inv.Files, f)
		inv.Languages[f.Lang]++
	}, func(rel, why string) {
		inv.Skipped = append(inv.Skipped, rel+": "+why)
	}, func(rel string) {
		inv.SensitiveNames = append(inv.SensitiveNames, rel)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].Path < inv.Files[j].Path })
	inv.detect()
	return inv, nil
}

// Hashes returns the SHA-256 of every file Walk would analyze, keyed by the
// same relative path, without reading lines or running detection. It is the
// cheap way to see which files changed since an assessment. When ctx ends
// first it returns ctx.Err().
func Hashes(ctx context.Context, root string, opt Options) (map[string]string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	err = walkFiles(ctx, absRoot, opt, false, func(f *File) { out[f.Path] = f.SHA256 }, func(string, string) {}, func(string) {})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// stateDirs hold PandaWard's own state (ledger, evidence, reports) at the
// project root. They are skipped whatever inventory.exclude says: a config
// from before the rename lists .pensec, and evidence read back as project
// files would show up as findings and make every scan look stale. Only the
// root is skipped, so a repository cannot hide code from the scan by naming
// a nested directory .pandaward.
var stateDirs = map[string]bool{".pandaward": true, ".pensec": true}

// excluder matches directories against inventory.exclude. Plain entries
// match a directory name or path exactly; entries with a * match directory
// names as a glob (".next-*").
type excluder struct {
	names map[string]bool
	globs []string
}

func newExcluder(exclude []string) excluder {
	x := excluder{names: map[string]bool{}}
	for _, e := range exclude {
		if strings.Contains(e, "*") {
			x.globs = append(x.globs, e)
			continue
		}
		x.names[e] = true
	}
	return x
}

// dir reports whether the directory at project-relative path rel, named
// name, is skipped.
func (x excluder) dir(rel, name string) bool {
	if stateDirs[rel] || x.names[name] || x.names[rel] {
		return true
	}
	for _, g := range x.globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// Excluded reports whether the project-relative file path rel (slash or
// OS separated) lies in a directory the inventory skips. Adapters that walk
// the tree themselves, such as gitleaks, can report files there; the engine
// drops those signals so every adapter honours inventory.exclude.
func Excluded(rel string, exclude []string) bool {
	rel = path.Clean(filepath.ToSlash(rel))
	x := newExcluder(exclude)
	dirs := strings.Split(rel, "/")
	for i := 1; i < len(dirs); i++ {
		if x.dir(strings.Join(dirs[:i], "/"), dirs[i-1]) {
			return true
		}
	}
	return false
}

// walkFiles applies the inventory rules (exclusions, no symlinks, sensitive
// names by name only, size cap, text files of known types) and reports each
// analyzable file to add. Lines are read only when withLines is set.
func walkFiles(ctx context.Context, absRoot string, opt Options, withLines bool, add func(*File), skip func(rel, why string), sensitive func(rel string)) error {
	skipDir := newExcluder(opt.Exclude).dir
	count := 0
	deadline, hasDeadline := ctx.Deadline()
	return filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, werr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Timers are coarse on Windows: an expired deadline must stop the
		// walk even before the context's timer has fired.
		if hasDeadline && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		rel, _ := filepath.Rel(absRoot, p)
		rel = filepath.ToSlash(rel)
		if werr != nil {
			skip(rel, "unreadable")
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			skip(rel, "symlink not followed")
			return nil
		}
		if d.IsDir() {
			if skipDir(rel, d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if isSensitiveName(d.Name()) {
			sensitive(rel)
			return nil
		}
		count++
		if opt.MaxFiles > 0 && count > opt.MaxFiles {
			skip(rel, "max_files limit reached")
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			skip(rel, "stat failed")
			return nil
		}
		lang := langOf(d.Name())
		if lang == "" {
			return nil // not a type we analyze; not a coverage gap
		}
		if lang == "apk" || lang == "ipa" {
			// Built Android and iOS packages are hashed, never read as
			// text; only the apktool and MobSF adapters open them.
			sum, err := hashFile(p)
			if err != nil {
				skip(rel, err.Error())
				return nil
			}
			add(&File{Path: rel, Lang: lang, Size: info.Size(), SHA256: sum})
			return nil
		}
		if info.Size() > opt.MaxFileBytes {
			skip(rel, "larger than max_file_bytes")
			return nil
		}
		f, err := readText(p, opt.MaxFileBytes, withLines)
		if err != nil {
			skip(rel, err.Error())
			return nil
		}
		if f == nil {
			return nil // binary
		}
		f.Path = rel
		f.Lang = lang
		f.Size = info.Size()
		add(f)
		return nil
	})
}

// LangOf returns the analysis language for a file name, or "" when PandaWard does
// not analyze that file type.
func LangOf(name string) string { return langOf(name) }

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

func hashFile(p string) (string, error) {
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readText(p string, max int64, withLines bool) (*File, error) {
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
	if !withLines {
		return f, nil
	}
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
// Windows tools that miss SystemDrive create a literal "%SystemDrive%"
// cache directory in their working directory, inside the scanned project.
func minimalEnv() []string {
	keep := []string{"PATH", "SYSTEMROOT", "SystemRoot", "SystemDrive", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL"}
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
	roots := serviceRoots(inv.Files)
	var entries []entry
	var mounts []mount
	nestGlobal := map[string]string{} // service root -> NestJS global prefix
	manifests := map[string]string{}  // dir -> kind
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
		case lb == "info.plist" || strings.HasSuffix(lb, ".entitlements"):
			inv.feature("ios", f.Path)
			domains["L"] = true
		case f.Lang == "apk":
			inv.feature("apk", f.Path)
			inv.feature("android", f.Path)
			domains["K"] = true
		case f.Lang == "ipa":
			inv.feature("ipa", f.Path)
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
			if jsLangs[f.Lang] {
				if m := nestGlobalRe.FindStringSubmatch(joined); m != nil {
					nestGlobal[serviceOf(roots, f.Path)] = m[1]
				}
			}
		}
		if f.Lang == "graphql" || f.Lang == "proto" {
			domains["A"], domains["G"] = true, true
		}
		es, ms := extractEntries(f, inv.resolveModule)
		entries = append(entries, es...)
		mounts = append(mounts, ms...)
		for d := range domains {
			f.Domains = append(f.Domains, d)
		}
		sort.Strings(f.Domains)
		inv.addAsset(model.Asset{ID: "file:" + f.Path, Kind: "file:" + f.Lang, Locator: f.Path, ContentHash: f.SHA256, Domains: f.Domains})
	}
	inv.addEntrypoints(applyMounts(entries, mounts), roots, nestGlobal)
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
