package bundle

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/report"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

func exported(t *testing.T) (string, *engine.Engine) {
	t.Helper()
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	e.Cfg.Scan.Adapters = []string{"builtin-inventory", "builtin-secrets", "builtin-code", "builtin-cicd", "builtin-infra", "builtin-supply", "builtin-mobile"}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	r, err := report.Build(e)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle.zip")
	sum, n, err := Export(r, e.Private(), out)
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 || len(sum) != 64 {
		t.Fatalf("unexpected export result: %d files, manifest %q", n, sum)
	}
	if _, _, err := Export(r, e.Private(), out); err == nil {
		t.Fatal("export must not overwrite an existing file")
	}
	return out, e
}

// rewrite copies a bundle, letting change edit or drop entries and add new ones.
func rewrite(t *testing.T, src string, change func(name string, b []byte) ([]byte, bool), extra map[string]string) string {
	t.Helper()
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, _ := f.Open()
		var b bytes.Buffer
		b.ReadFrom(rc)
		rc.Close()
		nb, keep := change(f.Name, b.Bytes())
		if !keep {
			continue
		}
		w, _ := zw.Create(f.Name)
		w.Write(nb)
	}
	for n, c := range extra {
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	out := filepath.Join(t.TempDir(), "changed.zip")
	os.WriteFile(out, buf.Bytes(), 0o600)
	return out
}

func TestExportedBundleVerifies(t *testing.T) {
	out, _ := exported(t)
	m, sum, err := Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 64 || m.Assessment.ID == "" {
		t.Fatalf("manifest: %+v %s", m, sum)
	}
	zr, _ := zip.OpenReader(out)
	defer zr.Close()
	for _, f := range zr.File {
		ok := f.Name == ManifestName || f.Name == "report.json" || f.Name == "report.md" || (strings.HasPrefix(f.Name, "evidence/") && strings.HasSuffix(f.Name, ".json"))
		if !ok {
			t.Errorf("unexpected entry %s (raw tool output and the ledger must never be bundled)", f.Name)
		}
		rc, _ := f.Open()
		var b bytes.Buffer
		b.ReadFrom(rc)
		rc.Close()
		for _, secret := range []string{testfixture.FakeStripe, testfixture.FakeGitHub} {
			if strings.Contains(b.String(), secret) {
				t.Errorf("%s contains an unredacted secret", f.Name)
			}
		}
	}
}

func TestTamperingFailsVerification(t *testing.T) {
	out, _ := exported(t)
	zr, _ := zip.OpenReader(out)
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	zr.Close()
	for _, target := range names {
		if target == ManifestName {
			continue
		}
		changed := rewrite(t, out, func(n string, b []byte) ([]byte, bool) {
			if n == target {
				return append(b, ' '), true
			}
			return b, true
		}, nil)
		if _, _, err := Verify(changed); err == nil {
			t.Errorf("changing %s was not detected", target)
		}
	}
	missing := rewrite(t, out, func(n string, b []byte) ([]byte, bool) { return b, n != "report.json" }, nil)
	if _, _, err := Verify(missing); err == nil || !strings.Contains(err.Error(), "report.json: missing") {
		t.Errorf("a removed file must fail verification: %v", err)
	}
	added := rewrite(t, out, func(n string, b []byte) ([]byte, bool) { return b, true }, map[string]string{"evidence/extra.json": "{}"})
	if _, _, err := Verify(added); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Errorf("an added file must fail verification: %v", err)
	}
	unsafe := rewrite(t, out, func(n string, b []byte) ([]byte, bool) { return b, true }, map[string]string{"../escape.txt": "x"})
	if _, _, err := Verify(unsafe); err == nil || !strings.Contains(err.Error(), "unsafe entry") {
		t.Errorf("a path-traversal entry must be rejected: %v", err)
	}
	// Editing the manifest changes its SHA-256, which the recipient compares
	// out of band; the edited manifest still has to match the files.
	_, orig, _ := Verify(out)
	edited := rewrite(t, out, func(n string, b []byte) ([]byte, bool) {
		if n == ManifestName {
			return bytes.Replace(b, []byte(`"project"`), []byte(`"project" `), 1), true
		}
		return b, true
	}, nil)
	if _, sum, _ := Verify(edited); sum == orig {
		t.Error("an edited manifest must have a different SHA-256")
	}
}

func TestExportRefusesTamperedEvidence(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, _ := engine.Init(root, false)
	defer e.Close()
	e.Cfg.Scan.Adapters = []string{"builtin-secrets", "builtin-code"}
	e.Scan(context.Background(), nil)
	r, err := report.Build(e)
	if err != nil || len(r.EvidenceIndex) == 0 {
		t.Fatal(err)
	}
	p := filepath.Join(e.Private(), "evidence", r.EvidenceIndex[0].Path)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, ' '), 0o600)
	if _, _, err := Export(r, e.Private(), filepath.Join(t.TempDir(), "b.zip")); err == nil {
		t.Fatal("evidence that fails its integrity check must not be exported")
	}
}

func TestExportRefusesUnredactedText(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, _ := engine.Init(root, false)
	defer e.Close()
	e.Cfg.Scan.Adapters = []string{"builtin-secrets"}
	e.Scan(context.Background(), nil)
	r, err := report.Build(e)
	if err != nil || len(r.Findings) == 0 {
		t.Fatal(err)
	}
	r.Findings[0].Message = "leaked " + testfixture.FakeStripe
	if _, _, err := Export(r, e.Private(), filepath.Join(t.TempDir(), "b.zip")); err == nil || !strings.Contains(err.Error(), "redaction") {
		t.Fatalf("a report with an unredacted secret must not be exported: %v", err)
	}
}
