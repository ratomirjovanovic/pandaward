package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestAttestCommand(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	root := t.TempDir()
	testfixture.Write(t, root, "src/auth.js", "function requireOwner(req, res, next) {\n  if (req.order.userId !== req.user.id) return res.sendStatus(403);\n  next();\n}\n")
	pandaward := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), append(args, "--root", root), nil, &out, &errOut)
		return code, out.String() + errOut.String()
	}
	if code, out := pandaward("init"); code != 0 {
		t.Fatal(out)
	}
	for _, bad := range [][]string{{"attest"}, {"attest", "C-003"}, {"attest", "C-003", "--accept", "--reject", "--by", "x"}, {"attest", "--list", "C-003"}} {
		if code, _ := pandaward(bad...); code != 2 {
			t.Errorf("%v: exit %d, want a usage error", bad, code)
		}
	}
	if code, out := pandaward("attest", "--list"); code != 0 || !strings.Contains(out, "No attestations") {
		t.Fatalf("empty list: %d %s", code, out)
	}
	p := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(p, []byte(`{"verdict":"PASS","proposer":"pandaward:identity","evidence":[{"file":"src/auth.js","line":2,"why":"owner check returns 403"}]}`), 0o644)
	if code, out := pandaward("attest", "D-001", "--propose", "--file", p); code != 1 || !strings.Contains(out, "not a manual control") {
		t.Errorf("rule-based control: %d %s", code, out)
	}
	if code, out := pandaward("attest", "C-003", "--propose", "--file", p); code != 0 || !strings.Contains(out, "decides nothing") {
		t.Fatalf("propose: %d %s", code, out)
	}
	if code, out := pandaward("attest", "c-003", "--show"); code != 0 || !strings.Contains(out, "src/auth.js:2") || !strings.Contains(out, "pending") {
		t.Errorf("show: %d %s", code, out)
	}
	if code, out := pandaward("attest", "C-003", "--accept"); code != 1 || !strings.Contains(out, "--by") {
		t.Errorf("accept without --by: %d %s", code, out)
	}
	if code, out := pandaward("attest", "C-003", "--accept", "--by", "Ana", "--note", "reviewed"); code != 0 || !strings.Contains(out, "Accepted") {
		t.Fatalf("accept: %d %s", code, out)
	}
	if code, out := pandaward("attest", "--list"); code != 0 || !strings.Contains(out, "accepted by Ana") {
		t.Errorf("list after accept: %d %s", code, out)
	}
}
