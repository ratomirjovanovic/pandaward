package feedback

import (
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func fnd(id, rule, control, collector, file string, st model.FindingStatus, conf model.Confidence) model.Finding {
	return model.Finding{ID: id, Fingerprint: "fp-" + id, RuleID: rule, ControlID: control, Collector: collector,
		File: file, Status: st, Confidence: conf, Severity: model.SevHigh, AssessmentID: "A1"}
}

func runsOf(string) []model.Run {
	return []model.Run{{Adapter: "semgrep", ToolVersion: "1.182.1", ExitClass: model.ExitOK}, {Adapter: "builtin-code", ExitClass: model.ExitOK}, {Adapter: "gitleaks", ExitClass: model.ExitBlocked}}
}

func TestPending(t *testing.T) {
	fs := []model.Finding{
		fnd("PW-0001", "semgrep.js-sql", "D-003", "semgrep", "src/a.ts", model.FindingFalsePositive, model.StronglySupported),
		fnd("PW-0002", "semgrep.js-sql", "D-003", "semgrep", "src/b.tsx", model.FindingFalsePositive, model.StronglySupported),
		fnd("PW-0003", "code.webhook", "G-002", "builtin-code", "api/hook.py", model.FindingFalsePositive, model.Confirmed),
		// Still open: not a report.
		fnd("PW-0004", "semgrep.js-sql", "D-003", "semgrep", "src/c.ts", model.FindingOpen, model.StronglySupported),
		// A reviewer's hypothesis closed as false positive is not about a rule.
		fnd("PW-0005", "review.B-004", "B-004", "manual-assisted", "src/auth.ts", model.FindingFalsePositive, model.Hypothesis),
		// Confirmed by a person, and no rule reported B-002 in that file: missed.
		fnd("PW-0006", "review.B-002", "B-002", "manual-assisted", "src/session.ts", model.FindingOpen, model.StronglySupported),
		// Fixed after confirmation: still a miss.
		fnd("PW-0007", "review.B-002", "B-002", "manual-assisted", "app/login.py", model.FindingRemediated, model.StronglySupported),
		// Not confirmed yet: not a report.
		fnd("PW-0008", "review.C-001", "C-001", "manual-assisted", "src/x.ts", model.FindingOpen, model.Hypothesis),
		// A rule did report D-003 in src/c.ts, so the reviewer's finding there is no miss.
		fnd("PW-0009", "review.D-003", "D-003", "manual-assisted", "src/c.ts", model.FindingOpen, model.StronglySupported),
		// Already sent.
		fnd("PW-0010", "code.cors", "G-004", "builtin-code", "srv.go", model.FindingFalsePositive, model.Confirmed),
	}
	gs := Pending(fs, runsOf, nil, State{Sent: map[string]string{"fp-PW-0010": "https://github.com/x/y/issues/1"}})
	var got []string
	for _, g := range gs {
		got = append(got, g.Title()+" "+strings.Join(g.Findings, ",")+" "+g.FileType)
	}
	want := []string{
		"[false-negative] B-002 PW-0006,PW-0007 .py, .ts",
		"[false-positive] semgrep.js-sql PW-0001,PW-0002 .ts, .tsx",
		"[false-positive] code.webhook PW-0003 .py",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Pending =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	fn := gs[0]
	if fn.Count != 2 || fn.Adapters != "builtin-code, semgrep" || !strings.Contains(fn.Note, "no rule reported") || fn.Path != "" {
		t.Errorf("missed report = %+v", fn.Report)
	}
	md := gs[1].Markdown()
	for _, want := range []string{"| Findings | 2 |", "| File type | .ts, .tsx |", "| Tool version | 1.182.1 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	for _, leak := range []string{"src/", "PW-000"} {
		if strings.Contains(md, leak) {
			t.Errorf("report leaks %q:\n%s", leak, md)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadState(dir)
	if err != nil || st.Mode != "" {
		t.Fatalf("empty state = %+v, %v", st, err)
	}
	if err := st.SetMode("always", time.Now()); err == nil {
		t.Error("SetMode accepted an unknown mode")
	}
	if err := st.SetMode(ModeBatch, time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	g := Pending([]model.Finding{fnd("PW-0001", "r", "D-003", "semgrep", "a.ts", model.FindingFalsePositive, model.Confirmed)}, runsOf, nil, st)[0]
	st.MarkSent(g, "https://github.com/x/y/issues/7")
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	back, err := LoadState(dir)
	if err != nil || back.Mode != ModeBatch || back.ModeSet != "2026-10-30T09:00:00Z" || back.Sent["fp-PW-0001"] == "" {
		t.Fatalf("state after save = %+v, %v", back, err)
	}
}

type fakeGH struct {
	open  string
	calls []string
}

func (f *fakeGH) run(stdin string, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args[:2], " "))
	switch args[0] + " " + args[1] {
	case "issue list":
		return f.open, nil
	case "issue create":
		if !strings.Contains(stdin, "| Kind |") {
			return "", nil
		}
		return "Creating issue\nhttps://github.com/ratomirjovanovic/pandaward/issues/200\n", nil
	}
	return "", nil
}

func TestSubmit(t *testing.T) {
	gs := Pending([]model.Finding{
		fnd("PW-0001", "code.webhook", "G-002", "builtin-code", "a.py", model.FindingFalsePositive, model.Confirmed),
		fnd("PW-0002", "code.webhook-extra", "G-002", "builtin-code", "a.py", model.FindingFalsePositive, model.Confirmed),
	}, runsOf, nil, State{})
	// An open report exists for code.webhook; "code.webhook-extra" must not
	// be mistaken for it.
	gh := &fakeGH{open: `[{"number":158,"title":"[false-positive] code.webhook: fires on OAuth callbacks","url":"https://github.com/ratomirjovanovic/pandaward/issues/158"}]`}
	res, err := Submit(gh.run, gs)
	if err != nil || len(res) != 2 {
		t.Fatalf("Submit = %+v, %v", res, err)
	}
	byRule := map[string]Result{res[0].Subject: res[0], res[1].Subject: res[1]}
	if r := byRule["code.webhook"]; r.Action != "commented" || !strings.HasSuffix(r.URL, "/158") {
		t.Errorf("existing report: %+v", r)
	}
	if r := byRule["code.webhook-extra"]; r.Action != "created" || !strings.HasSuffix(r.URL, "/200") {
		t.Errorf("new report: %+v", r)
	}
	joined := strings.Join(gh.calls, ";")
	for _, want := range []string{"issue comment", "api -X", "issue create"} {
		if !strings.Contains(joined, want) {
			t.Errorf("gh calls %q lack %q", joined, want)
		}
	}
}

func TestPendingOnlyStillObserved(t *testing.T) {
	fs := []model.Finding{
		fnd("PW-0001", "semgrep.js-sql", "D-003", "semgrep", "a.ts", model.FindingFalsePositive, model.StronglySupported),
		// Closed earlier; the latest scan no longer sees it.
		fnd("PW-0002", "semgrep.old-rule", "D-003", "semgrep", "b.ts", model.FindingFalsePositive, model.StronglySupported),
		// A confirmed miss is reported whether or not a scan saw it.
		fnd("PW-0003", "review.B-002", "B-002", "manual-assisted", "c.ts", model.FindingRemediated, model.StronglySupported),
	}
	seen := func(fp string) bool { return fp == "fp-PW-0001" }
	var got []string
	for _, g := range Pending(fs, runsOf, seen, State{}) {
		got = append(got, g.Title())
	}
	want := "[false-negative] B-002,[false-positive] semgrep.js-sql"
	if strings.Join(got, ",") != want {
		t.Fatalf("Pending = %v, want %s", got, want)
	}
}
