package report

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestReportsShowAttestedControls(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "package.json", `{"name":"shop","dependencies":{"express":"4.21.0"}}`)
	testfixture.Write(t, root, "src/server.js", "const app = require('express')();\napp.get('/orders/:id', requireOwner, getOrder);\n")
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Cfg.Scan.Adapters = []string{"builtin-inventory", "builtin-code"}
	if _, err := e.ProposeAttestation(engine.AttestationInput{ControlID: "C-003", Verdict: "PASS", Proposer: "pandaward:identity",
		Evidence: []engine.CitationInput{{File: "src/server.js", Line: 2, Why: "the order route runs requireOwner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DecideAttestation("C-003", true, "Ana", "reviewed with the team"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	r, err := Build(e)
	if err != nil {
		t.Fatal(err)
	}
	var c003 model.ControlResult
	for _, c := range r.Controls {
		if c.ID == "C-003" {
			c003 = c
		}
	}
	if c003.Status != model.StatusPass || c003.DecidedBy != model.DecidedAttested || c003.NextStep != "" {
		t.Fatalf("C-003 in the report: %+v", c003)
	}
	if r.Coverage.Attested != 1 {
		t.Errorf("coverage must count it as attested: %+v", r.Coverage)
	}
	for _, g := range r.PathTo100 {
		for _, id := range g.Controls {
			if id == "C-003" {
				t.Errorf("an attested control is decided and not on the path to 100%%: %+v", g)
			}
		}
	}
	md := Markdown(r)
	h, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(r)
	for name, out := range map[string]string{"markdown": md, "html": string(h), "json": string(j)} {
		for _, want := range []string{"Ana", "src/server.js", "the order route runs requireOwner", "pandaward:identity"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s report lacks %q", name, want)
			}
		}
	}
	if !strings.Contains(md, "## Attested controls") || !strings.Contains(md, "src/server.js:2 (the order route runs requireOwner)") {
		t.Errorf("markdown attested section missing:\n%s", md)
	}
}
