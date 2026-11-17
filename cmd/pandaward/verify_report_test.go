package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestVerifyReportCommand(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	if err := cmdAssess(context.Background(), []string{"--root", root, "--ascii"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	run := func(stdin string, args ...string) (string, error) {
		var out bytes.Buffer
		err := cmdVerifyReport(append([]string{"--root", root}, args...), strings.NewReader(stdin), &out)
		return out.String(), err
	}
	// The fixture has hardcoded secrets: E-001 is FAIL in the ledger.
	if out, err := run("E-001: FAIL, a token is committed.\n"); err != nil || !strings.Contains(out, "OK:") {
		t.Fatalf("an honest report verifies: %v\n%s", err, out)
	}
	out, err := run("E-001: PASS\n")
	if e, ok := err.(exitErr); !ok || e.code != 1 || !strings.Contains(out, "FALSE ASSURANCE") || !strings.Contains(out, "unsupported_pass") {
		t.Fatalf("a false PASS must exit 1: %v\n%s", err, out)
	}
	if _, err := run("Everything is secure and all controls passed.\n"); err == nil {
		t.Fatal("an all-clear claim must exit 1")
	}
	// JSON output and a file argument.
	file := filepath.Join(t.TempDir(), "report.md")
	if err := os.WriteFile(file, []byte("E-001: PASS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = run("", "--json", file)
	if err == nil {
		t.Fatal("exit 1 expected")
	}
	var res struct {
		Unsupported bool `json:"unsupported"`
		Mismatches  []struct {
			Kind string `json:"kind"`
		} `json:"mismatches"`
	}
	if json.Unmarshal([]byte(out), &res) != nil || !res.Unsupported || len(res.Mismatches) == 0 {
		t.Fatalf("%s", out)
	}
	// A report about one fix is not a full review, unless it says it is.
	if _, err := run("E-001: FAIL\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("E-001: FAIL\n", "--complete"); err == nil {
		t.Fatal("a full review that leaves out the other open findings must exit 1")
	}
	if _, err := run("", "a", "b"); err == nil {
		t.Fatal("two files are a usage error")
	}
	// Without a ledger there is nothing to check against.
	empty := t.TempDir()
	if err := cmdVerifyReport([]string{"--root", empty}, strings.NewReader("E-001: PASS"), &bytes.Buffer{}); err == nil {
		t.Fatal("no project, no check")
	}
}
