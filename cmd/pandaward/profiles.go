package main

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// testHelp prints `pandaward test --help`: every profile with what it
// covers, the controls it decides (from the catalog), what it needs and
// whether it may run against a local target.
func testHelp(w io.Writer) {
	fmt.Fprint(w, `Usage: pandaward test --profile <name> [--json] [--root <dir>]

Runs one runtime profile. A profile decides only the controls listed under
it; every other control keeps what the passive scan decided. Only PASS and
FAIL count as decided.

`)
	for _, p := range catalog.TestProfiles {
		fmt.Fprintln(w, p.Name)
		wrapField(w, "Covers:", p.Covers)
		if p.Unsupported {
			fmt.Fprintln(w)
			continue
		}
		fmt.Fprintln(w, "  Decides:")
		for _, c := range p.Decides() {
			fmt.Fprintf(w, "    %s  %s\n", c.ID, c.Title)
			if when := p.When[c.ID]; when != "" {
				fmt.Fprintf(w, "           needs %s\n", when)
			}
		}
		if na := p.NotAutomated(); len(na) > 0 {
			var ids []string
			for _, c := range na {
				ids = append(ids, c.ID)
			}
			wrapField(w, "Not automated yet:", strings.Join(ids, ", ")+" stay UNSUPPORTED; use /pandaward:review")
		}
		wrapField(w, "Needs:", p.Needs)
		wrapField(w, "Local target:", p.Local)
		fmt.Fprintln(w)
	}
	fmt.Fprint(w, `Flags:
  --profile <name>  one of the profiles above (required)
  --json            print the result as JSON
  --root <dir>      project directory
`)
}

// wrapField prints "  label text" wrapped at 78 columns, continuation lines
// indented under the text.
func wrapField(w io.Writer, label, text string) {
	const width = 78
	indent := strings.Repeat(" ", 4)
	line := "  " + label
	for _, word := range strings.Fields(text) {
		if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width && strings.TrimSpace(line) != label {
			fmt.Fprintln(w, line)
			line = indent + word
			continue
		}
		line += " " + word
	}
	fmt.Fprintln(w, line)
}

// profilesMarkdown renders the profile table the README carries; a test
// keeps the two identical.
func profilesMarkdown() string {
	var b strings.Builder
	b.WriteString("| Profile | Covers | Decides | Needs | Local target |\n|---|---|---|---|---|\n")
	for _, p := range catalog.TestProfiles {
		decides := "nothing"
		if !p.Unsupported {
			var ids []string
			for _, c := range p.Decides() {
				id := c.ID
				if when := p.When[c.ID]; when != "" {
					id += " (needs " + when + ")"
				}
				ids = append(ids, id)
			}
			decides = strings.Join(ids, "<br>")
			if na := p.NotAutomated(); len(na) > 0 {
				var n []string
				for _, c := range na {
					n = append(n, c.ID)
				}
				decides += "<br>not automated yet: " + strings.Join(n, ", ")
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", p.Name, p.Covers, decides, p.Needs, p.Local)
	}
	return b.String()
}

// approveMismatch explains a rejected scope approval: what to type and what
// was typed, shortened and redacted so a pasted secret is not echoed.
func approveMismatch(got, want string) string {
	msg := fmt.Sprintf("not approved: expected exactly %q (the word APPROVE, one space, then the 8-character code shown above, which ties the approval to this manifest's SHA-256)", want)
	switch {
	case got == "":
		return msg + "; received nothing"
	case got == "APPROVE" || strings.EqualFold(got, "approve"):
		return msg + "; received APPROVE without the code"
	case strings.EqualFold(got, want):
		return msg + "; received it in different letter case"
	}
	shown := redact.Line(got)
	if utf8.RuneCountInString(shown) > 32 {
		shown = string([]rune(shown)[:32]) + "..."
	}
	return fmt.Sprintf("%s; received %q (%d characters)", msg, shown, utf8.RuneCountInString(got))
}
