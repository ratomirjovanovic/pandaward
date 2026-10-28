package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pandaward/internal/bundle"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/mcp"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/report"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

var update = flag.Bool("update", false, "rewrite testdata/schemas.golden after a reviewed schema change")

const golden = "testdata/schemas.golden"

type section struct {
	name    string
	version int
	lines   []string
}

func current(t *testing.T) []section {
	t.Helper()
	var scopeDoc struct {
		SchemaVersion int `yaml:"schema_version"`
	}
	if err := yaml.Unmarshal([]byte(scope.Template), &scopeDoc); err != nil {
		t.Fatal(err)
	}
	var ledger []string
	for i, m := range store.Migrations() {
		sum := sha256.Sum256([]byte(m))
		ledger = append(ledger, fmt.Sprintf("migration %d %s", i+1, hex.EncodeToString(sum[:])))
	}
	raw, err := mcp.ToolsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var tools []map[string]any
	if err := json.Unmarshal(raw, &tools); err != nil {
		t.Fatal(err)
	}
	var mcpLines []string
	for _, tl := range tools {
		b, _ := json.Marshal(map[string]any{"input": StripDescriptions(tl["inputSchema"]), "annotations": tl["annotations"]})
		mcpLines = append(mcpLines, fmt.Sprintf("%v %s", tl["name"], b))
	}
	sort.Strings(mcpLines)
	csvHeader := strings.SplitN(report.CoverageCSV(&report.Report{}), "\n", 2)[0]
	return []section{
		{"report-json", model.SchemaVersion, Shape(report.Report{}, "json")},
		{"evidence-record", model.SchemaVersion, Shape(evidence.Record{}, "json")},
		{"bundle-manifest", model.SchemaVersion, Shape(bundle.Manifest{}, "json")},
		{"coverage-csv", model.SchemaVersion, []string{csvHeader}},
		{"mcp-tools", model.SchemaVersion, mcpLines},
		{"config-yaml", config.Default("x").SchemaVersion, Shape(config.Config{}, "yaml")},
		{"scope-yaml", scopeDoc.SchemaVersion, Shape(scope.Manifest{}, "yaml")},
		{"ledger", len(store.Migrations()), ledger},
	}
}

func render(ss []section) string {
	var b strings.Builder
	b.WriteString("# Frozen schemas. Do not edit by hand; see docs/SCHEMAS.md.\n")
	for _, s := range ss {
		fmt.Fprintf(&b, "\n## %s version %d\n", s.name, s.version)
		for _, l := range s.lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func parse(t *testing.T, text string) map[string]section {
	t.Helper()
	out := map[string]section{}
	var cur *section
	for _, l := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(l, "## "):
			var s section
			if _, err := fmt.Sscanf(l, "## %s version %d", &s.name, &s.version); err != nil {
				t.Fatalf("bad golden header %q", l)
			}
			out[s.name] = s
			cur = &s
		case l == "" || strings.HasPrefix(l, "#"):
		default:
			if cur == nil {
				t.Fatalf("golden line outside a section: %q", l)
			}
			cur.lines = append(cur.lines, l)
			out[cur.name] = *cur
		}
	}
	return out
}

func diff(old, cur []string) (removed, added []string) {
	in := func(xs []string, x string) bool {
		for _, y := range xs {
			if y == x {
				return true
			}
		}
		return false
	}
	for _, l := range old {
		if !in(cur, l) {
			removed = append(removed, l)
		}
	}
	for _, l := range cur {
		if !in(old, l) {
			added = append(added, l)
		}
	}
	return
}

// TestSchemasAreFrozen fails on any change to a pinned format. Additions are
// compatible but still need a reviewed golden update; removals and type or
// name changes also need a version bump (and, for the ledger, a new
// migration instead of an edited one).
func TestSchemasAreFrozen(t *testing.T) {
	cur := current(t)
	b, err := os.ReadFile(golden)
	if err != nil && !*update {
		t.Fatalf("%v (run: go test ./internal/schema -update)", err)
	}
	old := parse(t, string(b))
	var breaking, changed []string
	names := map[string]bool{}
	for _, s := range cur {
		names[s.name] = true
		g, ok := old[s.name]
		if !ok {
			changed = append(changed, s.name+": new schema")
			continue
		}
		removed, added := diff(g.lines, s.lines)
		switch {
		case s.version < g.version:
			breaking = append(breaking, fmt.Sprintf("%s: version went down from %d to %d", s.name, g.version, s.version))
		case s.name == "ledger" && len(removed) > 0:
			breaking = append(breaking, "ledger: a published migration was edited or removed; add a new migration instead: "+strings.Join(removed, "; "))
		case len(removed) > 0 && s.version == g.version:
			breaking = append(breaking, fmt.Sprintf("%s: fields removed or changed without a version bump: %s", s.name, strings.Join(removed, "; ")))
		}
		if len(removed)+len(added) > 0 || s.version != g.version {
			changed = append(changed, fmt.Sprintf("%s: +%v -%v", s.name, added, removed))
		}
	}
	for n := range old {
		if !names[n] {
			breaking = append(breaking, n+": schema removed")
		}
	}
	for _, m := range breaking {
		t.Error("breaking: " + m)
	}
	if len(breaking) > 0 {
		return
	}
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(render(cur)), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, m := range changed {
		t.Error("schema changed (compatible): " + m + "; review it, then run: go test ./internal/schema -update")
	}
}

// The shape helper must see renamed, retyped and removed fields.
func TestShapeDetectsChanges(t *testing.T) {
	type a struct {
		ID    string   `json:"id"`
		Count int      `json:"count"`
		Tags  []string `json:"tags"`
		Skip  string   `json:"-"`
	}
	type b struct {
		ID    string  `json:"ident"`
		Count float64 `json:"count"`
	}
	sa, sb := Shape(a{}, "json"), Shape(b{}, "json")
	if strings.Join(sa, "|") != "count int|id string|tags[] string" {
		t.Fatalf("shape a = %v", sa)
	}
	removed, added := diff(sa, sb)
	if len(removed) != 3 || len(added) != 2 {
		t.Fatalf("diff did not see the changes: -%v +%v", removed, added)
	}
}
