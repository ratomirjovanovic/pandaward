package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

// Every profile the catalog knows, apart from the passive scan, is
// described for `pandaward test`, and every runtime control belongs to one.
func TestTestProfilesCoverTheCatalog(t *testing.T) {
	described := map[string]bool{}
	for _, p := range catalog.TestProfiles {
		described[p.Name] = true
		for id := range p.When {
			if c := catalog.ControlByID(id); c == nil || c.Profile != p.Name {
				t.Errorf("profile %s explains %s, which it does not decide", p.Name, id)
			}
		}
	}
	for _, n := range catalog.Profiles {
		if n != "local-passive" && !described[n] {
			t.Errorf("profile %s is not described in catalog.TestProfiles", n)
		}
	}
	for _, c := range catalog.Controls {
		if c.Method == catalog.MethodRuntime && !described[c.Profile] {
			t.Errorf("runtime control %s has profile %q, which is not described", c.ID, c.Profile)
		}
	}
}

func TestTestHelpListsProfilesControlsAndNeeds(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"test", "--help"}, nil, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	help := out.String()
	for _, p := range catalog.TestProfiles {
		i := strings.Index(help, "\n"+p.Name+"\n")
		if i < 0 {
			t.Fatalf("profile %s missing from help:\n%s", p.Name, help)
		}
		section := help[i+1:]
		if j := strings.Index(section, "\n\n"); j >= 0 {
			section = section[:j]
		}
		if p.Unsupported {
			continue
		}
		for _, want := range []string{"Covers:", "Decides:", "Needs:", "Local target:"} {
			if !strings.Contains(section, want) {
				t.Errorf("%s: help section has no %q", p.Name, want)
			}
		}
		if len(p.Decides()) == 0 {
			t.Errorf("profile %s decides nothing", p.Name)
		}
		for _, c := range p.Decides() {
			if !strings.Contains(section, c.ID+"  "+c.Title) {
				t.Errorf("%s: help does not list %s", p.Name, c.ID)
			}
		}
		for _, c := range p.NotAutomated() {
			if !strings.Contains(section, c.ID) {
				t.Errorf("%s: help does not list %s as not automated", p.Name, c.ID)
			}
		}
	}
}

// The README carries the same table the code renders, and the test skill
// names every profile and the controls it decides.
func TestProfileDocsMatchHelp(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if want := profilesMarkdown(); !strings.Contains(strings.ReplaceAll(string(readme), "\r\n", "\n"), want) {
		t.Errorf("README.md does not contain the current profile table; replace it with:\n%s", want)
	}
	skill, err := os.ReadFile(filepath.Join("..", "..", "skills", "test", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range catalog.TestProfiles {
		if !strings.Contains(string(skill), p.Name) {
			t.Errorf("skills/test/SKILL.md does not mention %s", p.Name)
		}
		for _, c := range p.Decides() {
			if !strings.Contains(string(skill), c.ID) {
				t.Errorf("skills/test/SKILL.md does not mention %s (%s)", c.ID, p.Name)
			}
		}
	}
}

func approvableProject(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	root := t.TempDir()
	if code := run(context.Background(), []string{"init", "--root", root}, nil, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("init exit %d", code)
	}
	y := strings.NewReplacer(
		`owner: ""`, `owner: "Fixture Owner"`,
		`reference: ""`, `reference: "TEST-263"`,
		`purpose: ""`, `purpose: "approval prompt test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: https://staging.example.com",
	).Replace(scope.Template)
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := scope.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if probs := m.Validate(time.Now()); len(probs) > 0 {
		t.Fatalf("fixture manifest invalid: %v", probs)
	}
	return root, "APPROVE " + m.Hash()[:8]
}

func approveWith(t *testing.T, root, input string) (int, string, string) {
	t.Helper()
	old := isInteractive
	isInteractive = func() bool { return true }
	defer func() { isInteractive = old }()
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"scope", "approve", "--by", "Jane", "--root", root}, strings.NewReader(input), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestScopeApproveShowsWhatToType(t *testing.T) {
	root, want := approvableProject(t)

	code, out, errOut := approveWith(t, root, "APPROVE\n")
	if code != 3 {
		t.Fatalf("bare APPROVE: exit %d, want 3", code)
	}
	if !strings.Contains(out, "\n    "+want+"\n") {
		t.Errorf("the prompt does not show the exact line to type %q:\n%s", want, out)
	}
	for _, s := range []string{`expected exactly "` + want + `"`, "without the code"} {
		if !strings.Contains(errOut, s) {
			t.Errorf("bare APPROVE: error %q does not say %q", errOut, s)
		}
	}

	code, _, errOut = approveWith(t, root, "\n")
	if code != 3 || !strings.Contains(errOut, "received nothing") {
		t.Errorf("empty input: exit %d, error %q", code, errOut)
	}

	// Input that is not the confirmation is shortened and redacted.
	secret := "ghp_" + strings.Repeat("A1b2C3d4", 6)
	code, _, errOut = approveWith(t, root, secret+"\n")
	if code != 3 || strings.Contains(errOut, secret) || !strings.Contains(errOut, `expected exactly "`+want+`"`) || !strings.Contains(errOut, "characters)") {
		t.Errorf("other input: exit %d, error %q", code, errOut)
	}

	code, out, errOut = approveWith(t, root, want+"\n")
	if code != 0 || !strings.Contains(out, "Approved apr_") {
		t.Fatalf("correct input: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestApproveMismatch(t *testing.T) {
	want := "APPROVE ab26dcf2"
	for got, has := range map[string]string{
		"":                 "received nothing",
		"APPROVE":          "without the code",
		"approve":          "without the code",
		"approve AB26DCF2": "different letter case",
		"APPROVE 12345678": `received "APPROVE 12345678" (16 characters)`,
		"yes I approve all of these targets for the test run today": `received "yes I approve all of these targe..." (57 characters)`,
	} {
		if m := approveMismatch(got, want); !strings.Contains(m, has) || !strings.Contains(m, `expected exactly "APPROVE ab26dcf2"`) {
			t.Errorf("approveMismatch(%q) = %q, want it to contain %q", got, m, has)
		}
	}
}
