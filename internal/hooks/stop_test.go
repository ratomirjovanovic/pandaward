package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// assessed returns a scanned fixture project that only uses built-in
// adapters, so the test does not depend on installed scanners.
func assessed(t *testing.T, autoRetest bool) string {
	t.Helper()
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	cfg, _, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Scan.Adapters = []string{"builtin-inventory", "builtin-secrets", "builtin-code", "builtin-cicd", "builtin-infra", "builtin-supply", "builtin-mobile"}
	cfg.Hooks.AutoRetest = autoRetest
	if err := config.Write(root, cfg, true); err != nil {
		t.Fatal(err)
	}
	e, err = engine.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_PROJECT_DIR", root)
	return root
}

func runHook(t *testing.T, name, input string) string {
	t.Helper()
	var out bytes.Buffer
	if code := Run(name, strings.NewReader(input), &out); code != 0 {
		t.Fatalf("hook %s exited %d", name, code)
	}
	return out.String()
}

func edit(t *testing.T, root, rel, content string) {
	t.Helper()
	testfixture.Write(t, root, rel, content)
	b, _ := json.Marshal(map[string]any{"tool_name": "Write", "tool_input": map[string]string{"file_path": filepath.Join(root, rel)}})
	runHook(t, "post-edit", string(b))
}

func TestStopSilentWithoutEdits(t *testing.T) {
	assessed(t, true)
	if out := runHook(t, "stop", `{}`); out != "" {
		t.Fatalf("no edits must mean no output, got %q", out)
	}
}

func TestStopSilentWhenNothingNew(t *testing.T) {
	root := assessed(t, true)
	edit(t, root, "src/notes.js", "// nothing to see\n")
	if out := runHook(t, "stop", `{}`); out != "" {
		t.Fatalf("a clean retest must stay silent, got %q", out)
	}
	if out := runHook(t, "stop", `{}`); out != "" {
		t.Fatalf("the retest must clear the edited files, got %q", out)
	}
}

func TestStopReportsNewFindings(t *testing.T) {
	root := assessed(t, true)
	edit(t, root, "src/extra.js", "const t = Math.random().toString(36); // session token\n")
	var o stopOutput
	if err := json.Unmarshal([]byte(runHook(t, "stop", `{}`)), &o); err != nil {
		t.Fatal(err)
	}
	if o.Decision != "block" || !strings.Contains(o.Reason, "PW-") || !strings.Contains(o.Reason, "src/extra.js") {
		t.Fatalf("expected the new finding to reach Claude, got %+v", o)
	}
	if out := runHook(t, "stop", `{"stop_hook_active":true}`); out != "" {
		t.Fatalf("must not block again while Claude continues for this hook, got %q", out)
	}
}

func TestStopRespectsOptOut(t *testing.T) {
	root := assessed(t, false)
	edit(t, root, "src/extra.js", "const t = Math.random().toString(36); // session token\n")
	if out := runHook(t, "stop", `{}`); out != "" {
		t.Fatalf("auto_retest: false must disable the hook, got %q", out)
	}
}

func TestStopReportsSkippedRetest(t *testing.T) {
	root := assessed(t, true)
	edit(t, root, "src/extra.js", "const t = Math.random().toString(36); // session token\n")
	old := RetestBudget
	RetestBudget = time.Nanosecond
	defer func() { RetestBudget = old }()
	var o stopOutput
	if err := json.Unmarshal([]byte(runHook(t, "stop", `{}`)), &o); err != nil {
		t.Fatal(err)
	}
	if o.Decision != "" || !strings.Contains(o.SystemMessage, "STALE") && !strings.Contains(o.SystemMessage, "INCOMPLETE") {
		t.Fatalf("a retest over budget must be reported, never silent: %+v", o)
	}
}
