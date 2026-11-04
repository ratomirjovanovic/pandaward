package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// An RLS finding from SQL migrations is decided under C-004, not moved to
// another control of the code adapter.
func TestRLSFindingLandsOnC004(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"supabase/migrations/0001_init.sql": "create table public.profiles (id uuid primary key, display_name text, is_admin boolean default false);\n" +
			"alter table public.profiles enable row level security;\n" +
			"create policy p on public.profiles for update using (id = auth.uid());\n",
		"src/app.js": "export const x = 1;\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e, res := scan(t, root)
	defer e.Close()
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.RuleID == "sql.rls-update-privileged-column" {
			found = true
			if f.ControlID != "C-004" {
				t.Errorf("finding filed under %s, want C-004", f.ControlID)
			}
		}
	}
	if !found {
		t.Fatal("RLS finding missing")
	}
	cs := controlMap(t, e, res.AssessmentID)
	if cs["C-004"].Status != model.StatusSuspected {
		t.Errorf("C-004 = %s (%s), want SUSPECTED", cs["C-004"].Status, cs["C-004"].Reason)
	}
	if cs["B-001"].Status != model.StatusPass {
		t.Errorf("B-001 = %s (%s), want PASS", cs["B-001"].Status, cs["B-001"].Reason)
	}
}

// Without SQL migrations C-004 does not apply.
func TestC004NotApplicableWithoutMigrations(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "app.js"), []byte("export const x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, res := scan(t, root)
	defer e.Close()
	if st := controlMap(t, e, res.AssessmentID)["C-004"].Status; st != model.StatusNotApplicable {
		t.Errorf("C-004 = %s, want NOT_APPLICABLE", st)
	}
}
