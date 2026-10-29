package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
)

// FuzzParseSARIF feeds arbitrary bytes to the SARIF importer, which reads
// files supplied by the scanned project. It must never panic.
func FuzzParseSARIF(f *testing.F) {
	f.Add([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r"}]}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":1}}}]}]}]}`))
	f.Add([]byte(`{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"../../etc/passwd"},"region":{"startLine":-5}}}]}]}]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		root := t.TempDir()
		c := &Context{Root: root, Cfg: config.Default("f")}
		res, err := parseSARIF(c, "f.sarif", raw)
		if err != nil {
			return
		}
		for _, s := range res.signals {
			if strings.HasPrefix(s.File, "..") || strings.HasPrefix(s.File, "/") {
				t.Fatalf("signal points outside the project: %q", s.File)
			}
		}
	})
}

// FuzzMobSFScorecard feeds arbitrary bytes to the MobSF scorecard parser,
// the signal mapping and the raw-output cleaner. None may panic, and the
// saved output never holds the API key.
func FuzzMobSFScorecard(f *testing.F) {
	f.Add([]byte(`{"high":[{"title":"t","description":"d\nFiles:\na/b.java, line(s) 1","section":"code"}],"hash":"h","version":"v4.5.3"}`), "com.example.app")
	f.Add([]byte(`{"warning":[{"title":"s","description":"k","section":"secrets"}],"hash":"h"}`), "")
	f.Fuzz(func(t *testing.T, raw []byte, pkg string) {
		const key = "0123456789abcdef0123456789abcdef"
		if out := mobsfRaw(append(raw, []byte(key)...), key); strings.Contains(string(out), key) {
			t.Fatal("the API key survived in the saved scorecard")
		}
		card, err := parseMobSFScorecard(raw)
		if err != nil {
			return
		}
		card.Package = pkg
		_ = mobsfSignals(card, "app.apk", "K-006", "mobsf")
	})
}
