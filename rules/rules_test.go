package rules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pensec/internal/catalog"
)

type rule struct {
	ID        string         `yaml:"id"`
	Languages []string       `yaml:"languages"`
	Severity  string         `yaml:"severity"`
	Message   string         `yaml:"message"`
	Metadata  map[string]any `yaml:"metadata"`
}

// TestSemgrepRulesAreMappedAndHaveFixtures checks every bundled rule without
// needing semgrep: a known control, a CWE, and a fixture with at least one
// positive (ruleid) and one negative (ok) case.
func TestSemgrepRulesAreMappedAndHaveFixtures(t *testing.T) {
	files, err := SemgrepFiles()
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		b, err := semgrepFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct{ Rules []rule }
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		base := strings.TrimSuffix(filepath.Base(f), ".yaml")
		fixtures, _ := filepath.Glob(filepath.Join("semgrep", base+".*"))
		var fixture string
		for _, x := range fixtures {
			if !strings.HasSuffix(x, ".yaml") {
				b, _ := os.ReadFile(x)
				fixture = strings.ReplaceAll(string(b), "\r", "")
			}
		}
		if fixture == "" {
			t.Fatalf("%s has no fixture file", f)
		}
		for _, r := range doc.Rules {
			if !strings.HasPrefix(r.ID, "pensec-") || seen[r.ID] {
				t.Errorf("%s: rule id %q must be unique and start with pensec-", f, r.ID)
			}
			seen[r.ID] = true
			if len(r.Languages) == 0 || r.Message == "" || (r.Severity != "ERROR" && r.Severity != "WARNING" && r.Severity != "INFO") {
				t.Errorf("%s: incomplete rule definition", r.ID)
			}
			ctl, _ := r.Metadata["pensec-control"].(string)
			if c := catalog.ControlByID(ctl); c == nil || c.Domain == "R" {
				t.Errorf("%s: pensec-control %q is not a catalog control", r.ID, ctl)
			}
			if cwe, _ := r.Metadata["cwe"].(string); !strings.HasPrefix(cwe, "CWE-") {
				t.Errorf("%s: missing CWE", r.ID)
			}
			if !strings.Contains(fixture, "ruleid: "+r.ID+"\n") || !strings.Contains(fixture, "ok: "+r.ID+"\n") {
				t.Errorf("%s: fixture needs both a ruleid and an ok case", r.ID)
			}
		}
	}
}

// TestSemgrepFixtures runs `semgrep --test` when semgrep is installed.
func TestSemgrepFixtures(t *testing.T) {
	bin, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not installed")
	}
	cmd := exec.Command(bin, "--test", "--metrics=off", "semgrep")
	cmd.Env = append(os.Environ(), "SEMGREP_SEND_METRICS=off", "PYTHONUTF8=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "All tests passed") {
		t.Fatalf("semgrep --test failed: %v\n%s", err, out)
	}
}

func TestWriteSemgrep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "stale.yaml"), []byte("rules: []"), 0o600)
	if _, err := WriteSemgrep(dir); err != nil {
		t.Fatal(err)
	}
	got, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	want, _ := SemgrepFiles()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d files", got, len(want))
	}
	if _, err := os.Stat(filepath.Join(dir, "stale.yaml")); err == nil {
		t.Fatal("old rule files must be removed")
	}
}
