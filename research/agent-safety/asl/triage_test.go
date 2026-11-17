package asl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeldSplitIsFixedAndRoughlyOneInFive(t *testing.T) {
	n := 0
	for i := 0; i < 2000; i++ {
		name := "BenchmarkTest" + strings.Repeat("0", 5-len(itoa(i))) + itoa(i)
		if Held(name) != Held(name) {
			t.Fatal("not deterministic")
		}
		if Held(name) {
			n++
		}
	}
	if n < 300 || n > 500 {
		t.Fatalf("held-out share %d of 2000, want about 400", n)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestParseVerdictAndEvidenceGate(t *testing.T) {
	src := "line one\n  String sql = \"select \" + p;\nreturn x;"
	v, ok := ParseVerdict("Thinking...\n{\"verdict\":\"true_positive\",\"line\":2,\"quote\":\"String sql = \\\"select \\\" + p;\",\"reason\":\"concat\"}")
	if !ok || v.Verdict != "true_positive" || v.Line != 2 {
		t.Fatalf("%+v %v", v, ok)
	}
	if !EvidenceOK(v, src) {
		t.Error("a real line with its text must pass the gate")
	}
	for _, bad := range []TriageVerdict{{Verdict: "false_positive", Line: 9, Quote: "x"}, {Verdict: "false_positive", Line: 2, Quote: "never written"}, {Verdict: "false_positive", Line: 2}, {Verdict: "false_positive", Line: 0, Quote: "x"}} {
		if EvidenceOK(bad, src) {
			t.Errorf("must fail the gate: %+v", bad)
		}
	}
	if _, ok := ParseVerdict("no json here"); ok {
		t.Error("no verdict expected")
	}
	if _, ok := ParseVerdict(`{"verdict":"maybe"}`); ok {
		t.Error("an unknown verdict is not a verdict")
	}
}

func TestScoreTriageCountsCostAndKeepsInvalid(t *testing.T) {
	rec := func(label, verdict string, gate bool, status string) TriageRecord {
		return TriageRecord{TriageSample: TriageSample{Label: label}, Verdict: TriageVerdict{Verdict: verdict}, GateOK: gate, Status: status}
	}
	recs := []TriageRecord{
		rec("true", "true_positive", true, StatusValid),
		rec("true", "false_positive", true, StatusValid), // a true finding wrongly dismissed
		rec("false_positive", "false_positive", true, StatusValid),
		rec("false_positive", "false_positive", false, StatusValid), // dismissed without real evidence
		rec("false_positive", "true_positive", true, StatusValid),
		rec("true", "", false, StatusInvalid),
	}
	arms, invalid := ScoreTriage(recs)
	if invalid != 1 {
		t.Fatalf("invalid %d", invalid)
	}
	raw, tri, gate := arms[0], arms[1], arms[2]
	if raw.TrueKept != 2 || raw.FPKept != 3 || raw.TrueDismissed+raw.FPDismissed != 0 {
		t.Errorf("raw %+v", raw)
	}
	if tri.TrueDismissed != 1 || tri.FPDismissed != 2 || tri.FPKept != 1 || tri.TrueKept != 1 {
		t.Errorf("triage %+v", tri)
	}
	if gate.FPDismissed != 1 || gate.FPKept != 2 || gate.TrueDismissed != 1 {
		t.Errorf("gate %+v", gate)
	}
}

func TestRunTriageResumesAndStopsAtUsageLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A.java"), []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mk := func(n string) TriageSample {
		return TriageSample{Engine: "e", TestCase: n, File: "A.java", Line: 2, Rule: "r", Label: "true"}
	}
	samples := []TriageSample{mk("c1"), mk("c2"), mk("c3")}
	calls := 0
	reply := `{"result":"{\"verdict\":\"false_positive\",\"line\":2,\"quote\":\"b\",\"reason\":\"x\"}"}`
	c := TriageConfig{Checkout: dir, Out: filepath.Join(dir, "out.jsonl"), Parallel: 1, CC: CCConfig{Claude: "claude", Model: "m", Launch: func(_ context.Context, _ string, args, env []string, _ string) ([]byte, error) {
		calls++
		for _, kv := range env {
			if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") {
				t.Error("an API key reached the child")
			}
		}
		if calls == 3 {
			return []byte(`{"result":"usage limit reached","is_error":true}`), nil
		}
		return []byte(reply), nil
	}}}
	if err := RunTriage(context.Background(), c, samples); err != ErrUsageLimit {
		t.Fatalf("want the usage limit, got %v", err)
	}
	recs, _ := LoadTriageRecords(c.Out)
	if len(recs) != 2 || !recs[0].GateOK {
		t.Fatalf("%d records %+v", len(recs), recs)
	}
	c.CC.Launch = func(context.Context, string, []string, []string, string) ([]byte, error) {
		calls++
		return []byte(reply), nil
	}
	before := calls
	if err := RunTriage(context.Background(), c, samples); err != nil {
		t.Fatal(err)
	}
	if calls-before != 1 {
		t.Fatalf("a resume must only run the unfinished finding, ran %d", calls-before)
	}
}
