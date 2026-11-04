package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// secretsWithTracked runs the secrets adapter with the given files on disk
// and the given paths marked as tracked by git.
func secretsWithTracked(t *testing.T, files map[string]string, tracked ...string) []model.Signal {
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
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	inv.Tracked = map[string]bool{}
	for _, p := range tracked {
		inv.Tracked[p] = true
	}
	res, run := secretsAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("secrets adapter did not complete: %s %s", run.ExitClass, run.Detail)
	}
	return res.Signals
}

func trackedFiles(sigs []model.Signal) []string {
	var out []string
	for _, s := range sigs {
		if s.RuleID == "secret.tracked-sensitive-file" {
			out = append(out, s.File)
		}
	}
	return out
}

func TestTrackedToolLocalSettings(t *testing.T) {
	files := map[string]string{
		".claude/settings.local.json": "{}\n",
		".vscode/launch.local.json":   "{}\n",
		".cursor/mcp.local.json":      "{}\n",
		".claude/settings.json":       "{}\n",
		".mcp.json":                   "{}\n",
		"src/a.js":                    "x\n",
	}
	got := trackedFiles(secretsWithTracked(t, files, ".claude/settings.local.json", ".vscode/launch.local.json", ".claude/settings.json", ".mcp.json", "src/a.js"))
	want := []string{".claude/settings.local.json", ".vscode/launch.local.json"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tracked local settings reported = %v, want %v (untracked .cursor file, settings.json and .mcp.json must not fire)", got, want)
	}
}

func TestToolLocalSettingsNeedGit(t *testing.T) {
	sigs := secretsWithTracked(t, map[string]string{".claude/settings.local.json": "{}\n"})
	if got := trackedFiles(sigs); len(got) != 0 {
		t.Fatalf("an untracked file must not fire: %v", got)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.local.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	inv.Tracked = nil // not a git repository
	res, _ := secretsAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv})
	if got := trackedFiles(res.Signals); len(got) != 0 {
		t.Fatalf("without git there is no tracked-file finding: %v", got)
	}
}

// The content of a tool-local settings file is still scanned for secrets.
func TestToolLocalSettingsContentScanned(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("a1B2", 9)
	sigs := secretsWithTracked(t, map[string]string{".claude/settings.local.json": `{"env": {"GITHUB_TOKEN": "` + token + `"}}` + "\n"})
	if !fired(sigs, "secret.github-token") {
		t.Fatal("a secret in .claude/settings.local.json must still be reported by the content scan")
	}
}
