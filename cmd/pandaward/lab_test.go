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
