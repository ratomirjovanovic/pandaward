package adapters

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestTaintAdapterOnFixture(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	cfg := config.Default("x")
	inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
	if err != nil {
		t.Fatal(err)
	}
	res, run := taintAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv, Cfg: config.Default("x")})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("%s: %s", run.ExitClass, run.Detail)
	}
	var got []string
	for _, s := range res.Signals {
		got = append(got, s.RuleID+"@"+s.File+":"+strconv.Itoa(s.StartLine))
		if !strings.Contains(s.Message, "Flow: req.") {
			t.Errorf("%s: message lacks the flow: %s", s.RuleID, s.Message)
		}
		if s.Severity != model.SevHigh || s.Confidence != model.StronglySupported {
			t.Errorf("%s: request flow should be high and strongly supported", s.RuleID)
		}
	}
	sort.Strings(got)
	want := []string{
		"taint.js-code-injection@src/server.js:8",
		"taint.js-command-injection@src/server.js:8",
		"taint.js-sql-injection@src/server.js:6",
		"taint.js-xss@src/server.js:9",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestIsLibrary(t *testing.T) {
	for _, c := range []struct {
		pkg  string
		want bool
	}{
		{`{"name":"x","main":"index.js"}`, true},
		{`{"name":"x","exports":{".":"./a.js"}}`, true},
		{`{"name":"x","private":true,"main":"index.js"}`, false},
		{`{"name":"app","scripts":{"dev":"next dev"}}`, false},
		{`{"name":"x","version":"1.0.0"} + index.js`, true},
		{`{"name":"x"} + index.js`, false},
		{`{"name":"x","version":"1.0.0","private":true} + index.js`, false},
		{`{"name":"x","version":"1.0.0"}`, false},
	} {
		pkg, index, _ := strings.Cut(c.pkg, " + ")
		inv := &inventory.Inventory{Files: []*inventory.File{{Path: "package.json", Lines: strings.Split(pkg, "\n")}}}
		if index != "" {
			// Files are sorted by path.
			inv.Files = append([]*inventory.File{{Path: index, Lang: "javascript"}}, inv.Files...)
		}
		if got := isLibrary(inv); got != c.want {
			t.Errorf("%s: %v", c.pkg, got)
		}
	}
}

func TestTaintAdapterAcrossFiles(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tsconfig.json", `{
  // comments and trailing commas, as tsconfig allows
  "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"], }, },
}`)
	write("app/api/users/route.ts", `import { findUser } from '@/lib/db';
export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get('id');
  return Response.json(await findUser(id));
}`)
	write("src/lib/db.ts", `import { sql } from './pool';
export async function findUser(id: string | null) {
  return sql.query("SELECT * FROM users WHERE id = '" + id + "'");
}`)
	write("src/lib/pool.ts", `export const sql = makePool();`)
	cfg := config.Default("x")
	inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
	if err != nil {
		t.Fatal(err)
	}
	res, run := taintAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv, Cfg: cfg})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("%s: %s", run.ExitClass, run.Detail)
	}
	if len(res.Signals) != 1 {
		t.Fatalf("got %d signals: %+v", len(res.Signals), res.Signals)
	}
	s := res.Signals[0]
	if s.RuleID != "taint.js-sql-injection" || s.File != "src/lib/db.ts" || s.StartLine != 3 {
		t.Errorf("got %s at %s:%d", s.RuleID, s.File, s.StartLine)
	}
	if !strings.Contains(s.Message, "(app/api/users/route.ts line 3)") || !strings.Contains(s.Message, "findUser() (app/api/users/route.ts line 4)") {
		t.Errorf("the flow should name the caller's file: %s", s.Message)
	}
	if !strings.Contains(s.Snippet, "SELECT") {
		t.Errorf("snippet from the wrong file: %s", s.Snippet)
	}
}

func TestTaintSignalMessage(t *testing.T) {
	k := &taint.Sink{ID: "taint.js-command-injection", Control: "D-002", Title: "Shell command", Message: "Input reaches a shell."}
	var steps []taint.Step
	for i := 1; i <= 12; i++ {
		steps = append(steps, taint.Step{Line: i, What: "step" + strconv.Itoa(i), File: "app/api/some/long/route/path.ts"})
	}
	steps = append(steps, taint.Step{Line: 20, What: `password = "hunter2hunter2"`})
	f := &inventory.File{Path: "lib/x.js", Lines: make([]string, 20)}
	s := taintSignal(taint.Finding{Sink: k, File: "lib/x.js", Line: 20, Steps: steps}, f, TaintAdapter)
	if !strings.Contains(s.Message, "step12 (app/api/some/long/route/path.ts line 12)") || !strings.HasSuffix(s.Message, ".") {
		t.Errorf("long flow cut short: %s", s.Message)
	}
	if strings.Contains(s.Message, "hunter2") {
		t.Errorf("secret in a step not redacted: %s", s.Message)
	}
}
