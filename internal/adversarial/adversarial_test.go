package adversarial

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Release-blocking: PenSec must not be steered by repository content.
func TestHostileRepositoryCannotSteerPenSec(t *testing.T) {
	r, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Observations) < 8 {
		t.Fatalf("expected every case to run, got %d", len(r.Observations))
	}
	for _, o := range r.Observations {
		if !o.Passed {
			t.Errorf("%s (%d probes): %s", o.Case, o.Probes, o.Detail)
		}
	}
}

// The canary only proves something if the fixture's scripts really write it
// when executed; run one of them deliberately.
func TestCanaryDetectsExecution(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	canaryPath := filepath.Join(dir, canary)
	files := fixture(dir, filepath.ToSlash(canaryPath))
	script := filepath.Join(dir, "envrc.sh")
	if err := os.WriteFile(script, []byte(files[".envrc"]), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, script).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if _, err := os.Stat(canaryPath); err != nil {
		t.Fatal("running a fixture script must write the canary, otherwise the execution check is blind")
	}
}
