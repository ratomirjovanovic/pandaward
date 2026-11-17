package asl

import (
	"strings"
	"testing"
)

func TestHTMLPageRendersAReportAndEscapesEverything(t *testing.T) {
	m, rs := mockRun(t)
	md, err := Markdown(m, rs, ReportOptions{Public: true})
	if err != nil {
		t.Fatal(err)
	}
	page := HTMLPage("Report", md, "../style.css", "../")
	for _, want := range []string{"<!doctype html>", "<h1>Agent Safety Lab report: run r1</h1>", "<table>", "<th>Arm</th>", "<h2>Per arm</h2>", "<p class=\"note\"><b>MOCK:", "<ul>", "href=\"../style.css\""} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(page, "|---") {
		t.Error("table separator rows must not be rendered")
	}
	hostile := "# <script>alert(1)</script>\n\n| a | b |\n|---|---|\n| <img src=x onerror=1> | [x](https://example.com) |\n"
	out := HTMLPage("<b>t</b>", hostile, "x.css", "/")
	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") || strings.Contains(out, "<b>t</b>") {
		t.Fatalf("input must be escaped:\n%s", out)
	}
	if !strings.Contains(out, `<a href="https://example.com">x</a>`) {
		t.Fatal("https links are kept")
	}
}
