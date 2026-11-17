package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLabValidateShippedCorpus(t *testing.T) {
	var out bytes.Buffer
	if err := cmdLab([]string{"validate", "--corpus", filepath.Join("..", "..", "research", "agent-safety", "corpus", "v1")}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "OK:") {
		t.Fatal(out.String())
	}
}

func TestLabValidateRejectsHashMismatch(t *testing.T) {
	src := filepath.Join("..", "..", "research", "agent-safety", "corpus", "v1")
	dir := t.TempDir()
	for _, f := range []string{"corpus.json", filepath.Join("F06", "F06-A01.json")} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f, "A01.json") {
			b = bytes.Replace(b, []byte("Release notes."), []byte("Release notes, edited."), 1)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	err := cmdLab([]string{"validate", "--corpus", dir}, &out)
	if err == nil || !strings.Contains(out.String(), "fixture sha256") {
		t.Fatalf("a changed fixture must fail validation: %v\n%s", err, out.String())
	}
	// seal repairs it
	if err := cmdLab([]string{"seal", filepath.Join(dir, "F06", "F06-A01.json")}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdLab([]string{"validate", "--corpus", dir}, &out); err != nil {
		t.Fatalf("after seal: %v\n%s", err, out.String())
	}
}

func TestLabUnknownCommand(t *testing.T) {
	if err := cmdLab([]string{"run"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown lab command must fail")
	}
}

func TestLabRunScoreReportMock(t *testing.T) {
	corpus := filepath.Join("..", "..", "research", "agent-safety", "corpus", "v1")
	out := t.TempDir()
	var w bytes.Buffer
	if err := cmdLab([]string{"run", "--corpus", corpus, "--out", out, "--run", "m1", "--mock", "unsafe", "--reps", "2"}, &w); err != nil {
		t.Fatalf("%v\n%s", err, w.String())
	}
	if !strings.Contains(w.String(), "Mock run: scripted agents, no model, no cost") || !strings.Contains(w.String(), "16 planned") {
		t.Fatal(w.String())
	}
	// A second invocation has nothing left to do.
	w.Reset()
	if err := cmdLab([]string{"run", "--corpus", corpus, "--out", out, "--run", "m1", "--mock", "unsafe", "--reps", "2"}, &w); err != nil || !strings.Contains(w.String(), "16 already done, 0 run now") {
		t.Fatalf("%v\n%s", err, w.String())
	}
	w.Reset()
	if err := cmdLab([]string{"score", "--run", filepath.Join(out, "m1")}, &w); err != nil || !strings.Contains(w.String(), "MOCK results") || !strings.Contains(w.String(), "attack success") {
		t.Fatalf("%v\n%s", err, w.String())
	}
	w.Reset()
	file := filepath.Join(out, "report.md")
	if err := cmdLab([]string{"report", "--run", filepath.Join(out, "m1"), "--public", "--out", file}, &w); err != nil {
		t.Fatalf("%v\n%s", err, w.String())
	}
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), "MOCK: scripted agents") {
		t.Fatal("the report must label mock results")
	}
}

func TestLabRunLiveGuards(t *testing.T) {
	corpus := filepath.Join("..", "..", "research", "agent-safety", "corpus", "v1")
	for name, args := range map[string][]string{
		"no live flag": {"run", "--corpus", corpus, "--out", t.TempDir(), "--run", "x", "--provider", "api"},
		"no run id":    {"run", "--corpus", corpus},
		"bad arm":      {"run", "--corpus", corpus, "--run", "x", "--arms", "E"},
	} {
		if err := cmdLab(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	if err := cmdLab([]string{"run", "--corpus", corpus, "--out", t.TempDir(), "--run", "x", "--provider", "api", "--live"}, &bytes.Buffer{}); err == nil {
		t.Error("no key, no live run")
	}
}
