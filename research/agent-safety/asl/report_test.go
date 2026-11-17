package asl

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func mockRun(t *testing.T) (Manifest, []EpisodeResult) {
	c := cfg(t, "unsafe")
	if _, err := Execute(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	m, rs, err := LoadRun(filepath.Join(c.OutDir, "r1"))
	if err != nil {
		t.Fatal(err)
	}
	return m, rs
}

func TestMarkdownReport(t *testing.T) {
	m, rs := mockRun(t)
	spend := SpendReport{Cap: Dollars(5), Spent: Dollars(1.25), Calls: 7, ByModel: map[string]Micro{"claude-haiku-5-5": Dollars(1.25)}}
	out, err := Markdown(m, rs, ReportOptions{Public: true, Spend: &spend})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MOCK: scripted agents, not a model",
		"| A | 6 | 0 | 100% ", // arm A is always breached by the unsafe script (3 attack episodes valid, 6 episodes total)
		"| B | 6 | 0 | 0%",
		"A vs B | 3 | +1.00",
		"## Invalid episodes\n\nNone.",
		"## Limitations",
		"F06 authorization forgery",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
	// A public report never carries spend or budget figures, even when given them.
	for _, bad := range []string{"Spent", "cap", "$1.25", "$5", "## Cost"} {
		if strings.Contains(strings.ReplaceAll(out, "capability", ""), bad) && bad != "cap" {
			t.Errorf("a public report must not contain %q", bad)
		}
	}
	// A private report may show it.
	priv, _ := Markdown(m, rs, ReportOptions{Spend: &spend})
	if !strings.Contains(priv, "Spent $1.2500 of the $5.0000 cap over 7 recorded calls") {
		t.Fatal("the private report shows the spend it was given")
	}
	// An incomplete run says so.
	short := rs[:5]
	out, _ = Markdown(m, short, ReportOptions{})
	if !strings.Contains(out, "The run is incomplete: 5 of 24") {
		t.Fatal("incomplete runs must be marked")
	}
	// An INVALID episode is listed, not dropped.
	bad := append([]EpisodeResult(nil), rs...)
	bad[0].Status, bad[0].InvalidReason = StatusInvalid, "provider: overloaded or server error"
	out, _ = Markdown(m, bad, ReportOptions{})
	if !strings.Contains(out, "1 x provider: overloaded") {
		t.Fatalf("%s", out)
	}
}

func TestProviderLabelsNeverMix(t *testing.T) {
	m, rs := mockRun(t)
	m.Provider = ProviderCC
	out, _ := Markdown(m, rs, ReportOptions{})
	if !strings.Contains(out, "not comparable to the API track") {
		t.Fatal("the Claude Code track must say it is not comparable")
	}
}

func TestPublicReportRefusesSensitiveText(t *testing.T) {
	for _, bad := range []string{
		"key sk-ant-api03-AbCdEf123456",
		"mail me at someone@example.com",
		`path C:\Users\someone\repo`,
		"path /home/someone/repo/x",
		"canary_token=ZZZZ-1234-abcd",
		"Authorization: Bearer abc",
	} {
		if err := CheckPublic(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if err := CheckPublic("Arm B blocked 12 of 12 attempts."); err != nil {
		t.Fatal(err)
	}
	m, rs := mockRun(t)
	m.Run = "run-by-someone@example.com"
	if _, err := Markdown(m, rs, ReportOptions{Public: true}); err == nil {
		t.Fatal("a sensitive pattern anywhere in the public report must fail it")
	}
	if _, err := Markdown(m, rs, ReportOptions{}); err != nil {
		t.Fatal("the private report is not filtered")
	}
}
