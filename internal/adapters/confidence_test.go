package adapters

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// Synthetic values in real formats; none was ever a credential.
var (
	fakeKeyBody = strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", 2)[:64]
	fakeStripe  = "sk_" + "live_" + strings.Repeat("Q7", 12)
)

func confidenceOf(t *testing.T, sigs []model.Signal, rule, file string) (model.Confidence, model.Severity) {
	t.Helper()
	for _, s := range sigs {
		if s.RuleID == rule && s.File == file {
			return s.Confidence, s.Severity
		}
	}
	t.Fatalf("%s did not fire on %s: %+v", rule, file, sigs)
	return "", ""
}

// A PEM header proves nothing on its own; a key body does. Matches in test
// fixtures are still reported, but never as confirmed.
func TestSecretConfidence(t *testing.T) {
	sigs := runOn(t, &secretsAdapter{}, map[string]string{
		"src/header-only.js":    "const k = `-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----`;\n",
		"src/real.js":           "const k = `-----BEGIN " + "PRIVATE KEY-----\n" + fakeKeyBody + "\n" + fakeKeyBody + "\n-----END PRIVATE KEY-----`;\n",
		"src/embedded.json":     `{"key": "-----BEGIN ` + `PRIVATE KEY-----\n` + fakeKeyBody + `\n-----END PRIVATE KEY-----"}` + "\n",
		"src/pay.js":            "const key = \"" + fakeStripe + "\";\n",
		"test/unit/pay.test.js": "const key = \"" + fakeStripe + "\";\n",
	})
	for _, c := range []struct {
		rule, file string
		conf       model.Confidence
		sev        model.Severity
	}{
		{"secret.private-key", "src/header-only.js", model.Hypothesis, model.SevMedium},
		{"secret.private-key", "src/real.js", model.Confirmed, model.SevCritical},
		{"secret.private-key", "src/embedded.json", model.Confirmed, model.SevCritical},
		{"secret.stripe-live-key", "src/pay.js", model.Confirmed, model.SevHigh},
		{"secret.stripe-live-key", "test/unit/pay.test.js", model.Hypothesis, model.SevLow},
	} {
		conf, sev := confidenceOf(t, sigs, c.rule, c.file)
		if conf != c.conf || sev != c.sev {
			t.Errorf("%s on %s: %s %s, want %s %s", c.rule, c.file, conf, sev, c.conf, c.sev)
		}
	}
}

// Generic gitleaks rules and matches in test fixtures are hypotheses; a
// specific format in source stays a strong signal. Paths are made relative
// first, so a project under a directory named fixture keeps its signals.
func TestGitleaksConfidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture", "app")
	item := func(rule, rel string) map[string]any {
		return map[string]any{"RuleID": rule, "Description": rule, "File": filepath.Join(root, filepath.FromSlash(rel)), "StartLine": 1, "EndLine": 1, "Match": "REDACTED"}
	}
	raw, _ := json.Marshal([]any{
		item("stripe-access-token", "src/pay.ts"),
		item("stripe-access-token", "test/adapters/stripe.test.ts"),
		item("generic-api-key", "src/config.ts"),
	})
	sigs, err := gitleaks().(*externalTool).normalize(&Context{Root: root}, raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		conf model.Confidence
		sev  model.Severity
	}{{model.StronglySupported, model.SevHigh}, {model.Hypothesis, model.SevLow}, {model.Hypothesis, model.SevMedium}}
	if len(sigs) != len(want) {
		t.Fatalf("signals %+v", sigs)
	}
	for i, w := range want {
		if sigs[i].Confidence != w.conf || sigs[i].Severity != w.sev {
			t.Errorf("signal %d (%s): %s %s, want %s %s", i, sigs[i].RuleID, sigs[i].Confidence, sigs[i].Severity, w.conf, w.sev)
		}
	}
}
