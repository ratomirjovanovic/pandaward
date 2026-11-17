package asl

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

var (
	boldRe = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	codeRe = regexp.MustCompile("`([^`]+)`")
	linkRe = regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)\s]+)\)`)
)

func inline(s string) string {
	s = html.EscapeString(s)
	s = codeRe.ReplaceAllString(s, "<code>$1</code>")
	s = boldRe.ReplaceAllString(s, "<b>$1</b>")
	s = linkRe.ReplaceAllString(s, `<a href="$2">$1</a>`)
	return s
}

// HTMLPage renders the Markdown of a report as a standalone page that uses the
// site's stylesheet. It handles only what Markdown() produces: headings,
// tables, bullet lists, block quotes and paragraphs. Nothing in the input is
// trusted as HTML: everything is escaped first.
func HTMLPage(title, md, cssHref, backHref string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>%s</title>\n<link rel=\"stylesheet\" href=\"%s\">\n</head>\n<body>\n<main class=\"wrap\">\n<p><a href=\"%s\">PandaWard</a></p>\n", html.EscapeString(title), html.EscapeString(cssHref), html.EscapeString(backHref))
	lines := strings.Split(md, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "# "):
			fmt.Fprintf(&b, "<h1>%s</h1>\n", inline(l[2:]))
		case strings.HasPrefix(l, "## "):
			fmt.Fprintf(&b, "<h2>%s</h2>\n", inline(l[3:]))
		case strings.HasPrefix(l, "> "):
			fmt.Fprintf(&b, "<p class=\"note\">%s</p>\n", inline(strings.TrimPrefix(l, "> ")))
		case strings.HasPrefix(l, "|"):
			var rows []string
			for i < len(lines) && strings.HasPrefix(lines[i], "|") {
				rows = append(rows, lines[i])
				i++
			}
			i--
			b.WriteString("<div class=\"tablewrap\"><table>\n")
			for r, row := range rows {
				cells := strings.Split(strings.Trim(row, "|"), "|")
				if r == 1 && strings.Contains(row, "---") {
					continue
				}
				tag := "td"
				if r == 0 && len(rows) > 1 && strings.Contains(rows[1], "---") && strings.TrimSpace(cells[0]) != "" {
					tag = "th"
				}
				b.WriteString("<tr>")
				for _, c := range cells {
					fmt.Fprintf(&b, "<%s>%s</%s>", tag, inline(strings.TrimSpace(c)), tag)
				}
				b.WriteString("</tr>\n")
			}
			b.WriteString("</table></div>\n")
		case strings.HasPrefix(l, "- "):
			b.WriteString("<ul>\n")
			for i < len(lines) && strings.HasPrefix(lines[i], "- ") {
				fmt.Fprintf(&b, "<li>%s</li>\n", inline(lines[i][2:]))
				i++
			}
			i--
			b.WriteString("</ul>\n")
		case strings.TrimSpace(l) == "":
		default:
			fmt.Fprintf(&b, "<p>%s</p>\n", inline(l))
		}
	}
	b.WriteString("</main>\n</body>\n</html>\n")
	return b.String()
}
