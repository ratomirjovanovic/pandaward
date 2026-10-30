package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// Closing a false positive says a report is ready, unless feedback is off.
func TestTriageFeedbackHint(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	fs, _ := e.St.Findings(e.ProjectID)
	e.Close()
	var ids []string
	for _, f := range fs {
		if f.Status.Active() && f.Collector != "manual-assisted" && len(ids) < 2 {
			ids = append(ids, f.ID)
		}
	}
	cli := func(args ...string) string {
		var out, errb bytes.Buffer
		if code := run(context.Background(), append(args, "--root", root), strings.NewReader(""), &out, &errb); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errb.String())
		}
		return out.String()
	}
	out := cli("findings", "false-positive", ids[0], "--by", "tester", "--note", "constant input")
	if !strings.Contains(out, "1 report(s) about wrong or missed findings can go to the PandaWard project: pandaward feedback pending") {
		t.Fatalf("no feedback hint after a false positive:\n%s", out)
	}
	cli("feedback", "mode", "off")
	if out := cli("findings", "false-positive", ids[1], "--by", "tester", "--note", "constant input"); strings.Contains(out, "feedback pending") {
		t.Fatalf("hint shown with feedback off:\n%s", out)
	}
}
