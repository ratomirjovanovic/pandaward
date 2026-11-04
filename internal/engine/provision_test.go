package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

// TestProvisionHelper is not a test: the provisioning tests run the test
// binary itself as the project's provision and cleanup command.
func TestProvisionHelper(t *testing.T) {
	mode := os.Getenv("PANDAWARD_PROVISION_HELPER")
	if mode == "" {
		t.Skip("helper process only")
	}
	switch mode {
	case "create":
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"credentials": map[string]string{
			"PANDAWARD_T_ALICE": tokAlice, "PANDAWARD_T_BOB": tokBob, "PANDAWARD_T_CAROL": tokCarol, "PANDAWARD_T_OLD": tokOld}})
	case "unknown":
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"credentials": map[string]string{"PANDAWARD_T_ALICE": tokAlice, "AWS_SECRET_ACCESS_KEY": "x"}})
	case "fail":
		fmt.Fprintln(os.Stderr, "could not create user, token was "+tokAlice)
		os.Exit(3)
	case "slow":
		time.Sleep(20 * time.Second)
	case "cleanup":
		in, _ := io.ReadAll(os.Stdin)
		got := "stdin without credentials"
		if strings.Contains(string(in), tokAlice) {
			got = "stdin with credentials"
		}
		_ = os.WriteFile(os.Getenv("PANDAWARD_PROVISION_MARK"), []byte(got), 0o600)
	}
	os.Exit(0)
}

// provisionYAML runs the test binary as provision and cleanup command.
func provisionYAML(mode string, timeout int) string {
	exe := strings.ReplaceAll(os.Args[0], `\`, `/`)
	return fmt.Sprintf(`identity_provisioning:
  provision: [%q, -test.run=^TestProvisionHelper$, %s]
  cleanup: [%q, -test.run=^TestProvisionHelper$, cleanup]
  timeout_seconds: %d
`, exe, mode, exe, timeout)
}

// helperMode makes the helper act out mode for provision and cleanup: the
// mode argument is informational, the environment decides.
func helperMode(t *testing.T, mode string) string {
	t.Helper()
	mark := filepath.Join(t.TempDir(), "cleanup")
	t.Setenv("PANDAWARD_PROVISION_MARK", mark)
	old := engine.ProvisionCommand
	t.Cleanup(func() { engine.ProvisionCommand = old })
	engine.ProvisionCommand = func(ctx context.Context, root string, argv []string, stdin []byte, timeout time.Duration) ([]byte, error) {
		m := mode
		if argv[len(argv)-1] == "cleanup" {
			m = "cleanup"
		}
		os.Setenv("PANDAWARD_PROVISION_HELPER", m)
		defer os.Unsetenv("PANDAWARD_PROVISION_HELPER")
		return old(ctx, root, argv, stdin, timeout)
	}
	return mark
}

func TestProvisionedIdentitiesDecideAuthzAndStayInMemory(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	mark := helperMode(t, "create")
	e := authzProject(t, app.URL, provisionYAML("create", 60))
	approveScope(t, e)

	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	for cid, want := range map[string]model.Status{"C-001": model.StatusFail, "C-002": model.StatusFail, "B-004": model.StatusFail} {
		if res.Controls[cid] != string(want) {
			t.Errorf("%s = %s, want %s (%v)", cid, res.Controls[cid], want, res.Notes)
		}
	}
	if b, err := os.ReadFile(mark); err != nil || string(b) != "stdin with credentials" {
		t.Errorf("cleanup did not run with the provision output on stdin: %q %v", b, err)
	}
	notes := strings.Join(res.Notes, "\n")
	if !strings.Contains(notes, "returned 4 credential(s)") || !strings.Contains(notes, "identity cleanup") {
		t.Errorf("notes do not record provisioning and cleanup: %s", notes)
	}
	for _, tok := range []string{tokAlice, "tok-alice"} {
		if strings.Contains(notes, tok) {
			t.Fatalf("a credential reached the notes")
		}
	}
	assertNoTokens(t, e)
}

func TestProvisioningFailuresStopBeforeAnyRequest(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"unknown", "AWS_SECRET_ACCESS_KEY, which no identity declares as value_env"},
		{"fail", "identity provisioning"},
		{"slow", "timed out after 1s"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
			var fixed atomic.Bool
			var hits atomic.Int64
			app := invoiceApp(&fixed, &hits)
			defer app.Close()
			noZAP(t)
			helperMode(t, tc.mode)
			e := authzProject(t, app.URL, provisionYAML(tc.mode, 1))
			approveScope(t, e)
			_, err := e.StagingActive(context.Background(), func(string) {})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "tok-alice") {
				t.Fatalf("the error leaks a credential: %v", err)
			}
			if hits.Load() != 0 {
				t.Fatalf("%d requests were sent after provisioning failed", hits.Load())
			}
		})
	}
}

func TestProvisioningNeedsApprovalAndBindsScripts(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	mark := helperMode(t, "create")
	e := authzProject(t, app.URL, "")
	// A project script named in the command binds the approval to its content.
	script := filepath.Join(e.Root, "scripts", "identities.mjs")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("// v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(scope.Path(e.Root))
	exe := strings.ReplaceAll(os.Args[0], `\`, `/`)
	y := string(b) + fmt.Sprintf("identity_provisioning:\n  provision: [%q, -test.run=^TestProvisionHelper$, scripts/identities.mjs]\n  cleanup: [%q, -test.run=^TestProvisionHelper$, cleanup]\n", exe, exe)
	if err := os.WriteFile(scope.Path(e.Root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil {
		t.Fatal("ran without an approval")
	}
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("cleanup ran without an approval")
	}
	approveScope(t, e)
	m, _ := scope.Load(e.Root)
	if files := m.ProvisionFiles(e.Root); len(files) != 1 || !strings.HasPrefix(files[0], "scripts/identities.mjs:") {
		t.Fatalf("bound files = %v", files)
	}
	if err := os.WriteFile(script, []byte("// v2, edited after the approval\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil {
		t.Fatal("an edited provisioning script kept the approval valid")
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests sent without a valid approval", hits.Load())
	}
}
