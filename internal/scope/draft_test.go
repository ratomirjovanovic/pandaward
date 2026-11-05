package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func nextFixture(t *testing.T) string {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"package.json":                   `{"name":"fx","scripts":{"dev":"next dev -p 3001","build":"next build"},"dependencies":{"next":"15.0.0"}}`,
		".env.example":                   "NEXT_PUBLIC_SITE_URL=http://localhost:3001\nNEXTAUTH_URL=http://127.0.0.1:3002\nAPP_URL=https://app.example.com\n",
		"app/api/invoices/[id]/route.ts": "export async function GET() { return Response.json({}) }\nexport async function DELETE() {}\n",
		"app/dashboard/page.tsx":         "export default function Page() { return null }\n",
		"app/docs/[...slug]/page.tsx":    "export default function Page() { return null }\n",
		"lib/auth.ts":                    "export type Role = 'owner' | 'member'\nexport function can(u: any) { return u.role === 'admin' }\n",
		"prisma/schema.prisma":           "enum TeamRole {\n  BILLING\n  SUPPORT\n}\n",
		"supabase/migrations/001.sql":    "create policy \"tenant read\" on public.invoices for select using (true);\n",
	})
	return root
}

func draftOf(t *testing.T, root string, opt DraftOptions) *Draft {
	t.Helper()
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	d, err := BuildDraft(inv, opt)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDraftFromNextJSProject(t *testing.T) {
	root := nextFixture(t)
	d := draftOf(t, root, DraftOptions{})
	var urls []string
	for _, tg := range d.Targets {
		urls = append(urls, tg.URL)
	}
	if got := strings.Join(urls, " "); got != "http://localhost:3001 http://127.0.0.1:3002" {
		t.Errorf("targets = %q; want only the local URLs, never app.example.com", got)
	}
	var routes []string
	for _, r := range d.Routes {
		routes = append(routes, r.Method+" "+r.Path)
	}
	if got := strings.Join(routes, ", "); got != "GET /api/invoices/<id>, GET /docs/<slug>, GET /dashboard" {
		t.Errorf("routes = %q; want readable routes, dynamic first, DELETE left out", got)
	}
	var roles []string
	rls := 0
	for _, r := range d.Roles {
		if r.Name == "" {
			rls++
		} else {
			roles = append(roles, r.Name)
		}
	}
	if got := strings.Join(roles, " "); !strings.Contains(got, "owner") || !strings.Contains(got, "member") || !strings.Contains(got, "admin") || !strings.Contains(got, "billing") {
		t.Errorf("roles = %q", got)
	}
	if rls != 1 {
		t.Errorf("RLS notes = %d, want 1", rls)
	}

	// The rendered draft parses with the strict decoder and is blocked only
	// by the authorization block a person must fill in.
	writeFiles(t, root, map[string]string{".pandaward/scope.yaml": d.Render()})
	m, err := Load(root)
	if err != nil {
		t.Fatalf("draft does not load: %v", err)
	}
	if m.Environment != "local" || !m.AllowPrivateAddresses {
		t.Errorf("a draft with only local targets should be environment local with private addresses allowed")
	}
	probs := strings.Join(m.Validate(time.Now()), "; ")
	for _, want := range []string{"authorization.owner is empty", "authorization.acknowledged is false"} {
		if !strings.Contains(probs, want) {
			t.Errorf("draft problems %q lack %q", probs, want)
		}
	}
	if strings.Contains(probs, "target") {
		t.Errorf("drafted targets are invalid: %s", probs)
	}
}

func TestDraftTargetFlagAndNoLocalURL(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"main.go": "package main\n"})
	d := draftOf(t, root, DraftOptions{})
	if len(d.Targets) != 0 {
		t.Fatalf("targets = %v, want none", d.Targets)
	}
	if !strings.Contains(d.Render(), "targets: []") {
		t.Error("an empty draft should keep targets: []")
	}
	d = draftOf(t, root, DraftOptions{Target: "https://staging.example.com/"})
	if len(d.Targets) != 1 || d.Targets[0].URL != "https://staging.example.com" {
		t.Fatalf("targets = %v", d.Targets)
	}
	if out := d.Render(); !strings.Contains(out, "environment: staging") || !strings.Contains(out, "allow_private_addresses: false") {
		t.Error("a non-local target must not be drafted as local")
	}
	inv, _ := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if _, err := BuildDraft(inv, DraftOptions{Target: "https://user:pw@example.com"}); err == nil {
		t.Error("a --target with credentials must be refused")
	}
}

func TestPlaceholder(t *testing.T) {
	for in, want := range map[string]string{
		"/invoices/[id]":         "/invoices/<id>",
		"/docs/[...slug]":        "/docs/<slug>",
		"/docs/[[...slug]]":      "/docs/<slug>",
		"/users/:userId/posts":   "/users/<userId>/posts",
		"/items/{id}":            "/items/<id>",
		"/items/{id:[0-9]+}/raw": "/items/<id>/raw",
	} {
		if got := Placeholder(in); got != want {
			t.Errorf("Placeholder(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProvisioningValidationAndBinding(t *testing.T) {
	root := t.TempDir()
	base := strings.NewReplacer(`owner: ""`, `owner: "o"`, `reference: ""`, `reference: "r"`, `purpose: ""`, `purpose: "p"`,
		"acknowledged: false", "acknowledged: true", "targets: []", "targets:\n  - url: https://staging.example.com",
		"identities: []\n", "identities:\n  - {name: alice, header: Authorization, value_env: PANDAWARD_ALICE}\n").Replace(Template)
	load := func(extra string) *Manifest {
		t.Helper()
		writeFiles(t, root, map[string]string{".pandaward/scope.yaml": base + extra})
		m, err := Load(root)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := load("")
	if m.BindHash() != m.Hash() {
		t.Fatal("without provisioning the approval must bind to the manifest hash, so existing approvals stay valid")
	}
	for extra, want := range map[string]string{
		"identity_provisioning:\n  provision: []\n":                             "provision must be a command",
		"identity_provisioning:\n  provision: [node]\n  timeout_seconds: 900\n": "timeout_seconds",
		"identity_provisioning:\n  provision: [node]\n  cleanup: [\"\"]\n":      "cleanup must start with a program",
	} {
		if got := strings.Join(load(extra).Validate(time.Now()), "; "); !strings.Contains(got, want) {
			t.Errorf("%q: problems %q lack %q", extra, got, want)
		}
	}
	prov := "identity_provisioning:\n  provision: [node, scripts/id.mjs]\n  cleanup: [node, scripts/id.mjs, delete]\n"
	missing := load(prov).BindHash()
	writeFiles(t, root, map[string]string{"scripts/id.mjs": "// one\n"})
	one := load(prov)
	if probs := one.Validate(time.Now()); len(probs) > 0 {
		t.Fatalf("valid provisioning rejected: %v", probs)
	}
	if one.BindHash() == missing || one.BindHash() == one.Hash() {
		t.Error("a script that appears must change what the approval binds")
	}
	writeFiles(t, root, map[string]string{"scripts/id.mjs": "// two\n"})
	if load(prov).BindHash() == one.BindHash() {
		t.Error("editing a bound script must change what the approval binds")
	}
	if files := one.ProvisionFiles(root); len(files) != 2 || !strings.HasPrefix(files[0], "scripts/id.mjs:") {
		t.Errorf("bound files = %v", files)
	}
}
