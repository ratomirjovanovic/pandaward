package adapters

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
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
	} {
		inv := &inventory.Inventory{Files: []*inventory.File{{Path: "package.json", Lines: strings.Split(c.pkg, "\n")}}}
		if got := isLibrary(inv); got != c.want {
			t.Errorf("%s: %v", c.pkg, got)
		}
	}
}
