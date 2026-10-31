package inventory_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

func walk(t *testing.T, files map[string]string, opt inventory.Options) *inventory.Inventory {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if opt.MaxFileBytes == 0 {
		opt.MaxFileBytes = 1 << 20
	}
	inv, err := inventory.Walk(root, opt)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestLangOf(t *testing.T) {
	for name, want := range map[string]string{
		"app.ts": "typescript", "Main.java": "java", "main.go": "go", "x.py": "python", "Dockerfile": "dockerfile",
		"Dockerfile.prod": "dockerfile", "main.tf": "terraform", "ci.yml": "yaml", "page.vue": "vue", "README.md": "", "logo.png": "",
	} {
		if got := inventory.LangOf(name); got != want {
			t.Errorf("LangOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestWalkSkipsWhatItMustNotRead(t *testing.T) {
	inv := walk(t, map[string]string{
		"src/a.js":            "console.log(1);\n",
		"src/big.js":          strings.Repeat("x", 2048),
		"src/bin.js":          "\x00\x01\x02",
		"node_modules/x/i.js": "module.exports = 1;\n",
		".env":                "SECRET=1\n",
		"keys/server.pem":     "not read\n",
		"docs/notes.md":       "# notes\n",
	}, inventory.Options{Exclude: []string{"node_modules"}, MaxFileBytes: 1024})
	var paths []string
	for _, f := range inv.Files {
		paths = append(paths, f.Path)
	}
	if !slices.Equal(paths, []string{"src/a.js"}) {
		t.Fatalf("analyzed files = %v, want only src/a.js", paths)
	}
	if !slices.Contains(inv.Skipped, "src/big.js: larger than max_file_bytes") {
		t.Errorf("oversized file must be reported as skipped: %v", inv.Skipped)
	}
	slices.Sort(inv.SensitiveNames)
	if !slices.Equal(inv.SensitiveNames, []string{".env", "keys/server.pem"}) {
		t.Errorf("sensitive names = %v", inv.SensitiveNames)
	}
}

func TestWalkDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.js"), []byte("x\n"), 0o644)
	if err := os.Symlink(filepath.Join(outside, "secret.js"), filepath.Join(root, "link.js")); err != nil {
		t.Skip("symlinks not available:", err)
	}
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 0 || !slices.Contains(inv.Skipped, "link.js: symlink not followed") {
		t.Fatalf("symlink must be skipped: files=%d skipped=%v", len(inv.Files), inv.Skipped)
	}
}

func TestRouteDiscovery(t *testing.T) {
	inv := walk(t, map[string]string{
		"package.json":           `{"dependencies":{"express":"4"}}`,
		"src/server.js":          "app.get('/api/invoices/:id', h);\napp.post('/login', h);\napp.post('/webhooks/stripe', h);\n",
		"app.py":                 "@app.route('/admin/users')\ndef users(): pass\n",
		"main.go":                "http.HandleFunc(\"/health\", h)\n",
		"Ctl.java":               "@GetMapping(\"/orders/{id}\")\n",
		"app/api/users/route.ts": "export async function GET() {}\n",
		"src/notes.js":           "const s = 'app.get is not a route here';\n",
	}, inventory.Options{})
	for _, want := range []string{
		"route:GET:/api/invoices/:id@src/server.js", "route:POST:/login@src/server.js", "route:POST:/webhooks/stripe@src/server.js",
		"route:ANY:/admin/users@app.py", "route:ANY:/health@main.go", "route:GET:/orders/{id}@Ctl.java", "route:GET:/api/users@app/api/users/route.ts",
	} {
		if !slices.Contains(inv.Features["routes"], want) {
			t.Errorf("missing route %s in %v", want, inv.Features["routes"])
		}
	}
	if len(inv.Features["routes"]) != 7 {
		t.Errorf("unexpected extra routes: %v", inv.Features["routes"])
	}
	for feature, want := range map[string]string{
		"param_routes": "route:GET:/api/invoices/:id@src/server.js",
		"auth_routes":  "route:POST:/login@src/server.js",
		"webhooks":     "route:POST:/webhooks/stripe@src/server.js",
		"admin_routes": "route:ANY:/admin/users@app.py",
	} {
		if !slices.Contains(inv.Features[feature], want) {
			t.Errorf("%s does not contain %s: %v", feature, want, inv.Features[feature])
		}
	}
}

func TestFileDomains(t *testing.T) {
	inv := walk(t, map[string]string{
		"src/pay.js":               "const stripe = require('stripe');\n",
		"src/agent.py":             "from openai import OpenAI\n",
		"src/auth.js":              "const jwt = require('jsonwebtoken');\n",
		".github/workflows/ci.yml": "on: push\njobs: {}\n",
		"Dockerfile":               "FROM node:20\n",
		"package.json":             `{"name":"a"}`,
	}, inventory.Options{})
	for path, want := range map[string]string{
		"src/pay.js": "F", "src/agent.py": "P", "src/auth.js": "B", ".github/workflows/ci.yml": "N", "Dockerfile": "J", "package.json": "I",
	} {
		f := inv.FileByPath(path)
		if f == nil || !slices.Contains(f.Domains, want) {
			t.Errorf("%s: domains %v, want %s", path, f.Domains, want)
		}
	}
	if !slices.Contains(inv.Features["missing_lockfile"], "package.json") {
		t.Error("package.json without a lockfile must be reported")
	}
}

func TestDomainsForPath(t *testing.T) {
	for p, want := range map[string][]string{
		".github/workflows/x.yml":     {"A", "I", "N"},
		"web/package.json":            {"A", "I"},
		"deploy/Dockerfile":           {"A", "J"},
		"android/AndroidManifest.xml": {"A", "K"},
		"ios/Info.plist":              {"A", "L"},
		"src/handler.ts":              {"A", "B", "C", "D", "E", "G", "H"},
	} {
		if got := inventory.DomainsForPath(p); !slices.Equal(got, want) {
			t.Errorf("DomainsForPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestMinimalEnvKeepsSystemDrive(t *testing.T) {
	t.Setenv("SystemDrive", "C:")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "x")
	env := strings.Join(inventory.MinimalEnv(), "\n")
	if !strings.Contains(env, "SystemDrive=C:") {
		t.Error("SystemDrive must be kept so Windows tools do not create a %SystemDrive% directory in the project")
	}
	if strings.Contains(env, "AWS_SECRET_ACCESS_KEY") {
		t.Error("cloud credentials must be scrubbed")
	}
}

// PandaWard's own state at the root is never project input, even when a
// config from before the rename excludes only .pensec. A nested directory
// with the same name is scanned, so it cannot be used to hide code.
func TestWalkAlwaysSkipsStateDirectories(t *testing.T) {
	files := map[string]string{
		"src/a.js":                            "console.log(1);\n",
		".pandaward/private/evidence/e1.json": `{"snippet": "eval(x)"}`,
		".pandaward/config.yaml":              "schema_version: 1\n",
		".pensec/private/evidence/e2.json":    `{"snippet": "eval(x)"}`,
		"lib/.pandaward/hidden.js":            "eval(x);\n",
	}
	want := []string{"lib/.pandaward/hidden.js", "src/a.js"}
	inv := walk(t, files, inventory.Options{Exclude: []string{".pensec"}})
	var paths []string
	for _, f := range inv.Files {
		paths = append(paths, f.Path)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, want) {
		t.Fatalf("analyzed files = %v, want %v", paths, want)
	}
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	hs, err := inventory.Hashes(context.Background(), root, inventory.Options{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != len(want) || hs[want[0]] == "" || hs[want[1]] == "" {
		t.Errorf("Hashes saw %v, want %v", hs, want)
	}
}

// An exclude entry with a * matches directory names as a glob, so build
// output such as .next-e2e-main is skipped like .next.
func TestWalkExcludeGlobs(t *testing.T) {
	inv := walk(t, map[string]string{
		"src/a.js":                   "console.log(1);\n",
		".next/server/b.js":          "eval(x);\n",
		".next-e2e-main/server/c.js": "eval(x);\n",
		"lib/next-steps.js":          "console.log(2);\n",
		"docs/.next-steps/notes.js":  "console.log(3);\n",
	}, inventory.Options{Exclude: []string{".next", ".next-*"}})
	var paths []string
	for _, f := range inv.Files {
		paths = append(paths, f.Path)
	}
	slices.Sort(paths)
	if want := []string{"lib/next-steps.js", "src/a.js"}; !slices.Equal(paths, want) {
		t.Fatalf("analyzed files = %v, want %v", paths, want)
	}
}

func TestExcluded(t *testing.T) {
	ex := []string{"node_modules", ".next", ".next-*", "build", "web/out"}
	for rel, want := range map[string]bool{
		".next/cache/.rscinfo":                                           true,
		".next/server/preview-props.json":                                true,
		filepath.Join("apps", "web", ".next", "prerender-manifest.json"): true,
		".next-dev/trace":                                                true,
		"packages/ui/node_modules/x/index.js":                            true,
		"web/out/index.html":                                             true,
		".pandaward/private/state.db":                                    true,
		"src/.pandaward/notes.md":                                        false,
		"src/next.config.js":                                             false,
		"src/build.ts":                                                   false,
		"docs/out/index.html":                                            false,
		".env":                                                           false,
	} {
		if got := inventory.Excluded(rel, ex); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestIgnoredLocal(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	files := map[string]string{".gitignore": ".env.local\nsecrets/\n", ".env.local": "K=1\n", "secrets/a.json": "{}\n", "src/app.ts": "x\n", "new.ts": "y\n"}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", ".gitignore", "src/app.ts"}} {
		cmd := exec.Command(git, append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{".env.local": true, "secrets/a.json": true, "src/app.ts": false, "new.ts": false, ".gitignore": false} {
		if got := inv.IgnoredLocal(p); got != want {
			t.Errorf("IgnoredLocal(%s) = %v, want %v (ignored %v)", p, got, want, inv.Ignored)
		}
	}
	if (&inventory.Inventory{}).IgnoredLocal(".env.local") {
		t.Error("outside git nothing counts as ignored")
	}
}
