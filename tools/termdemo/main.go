// Command termdemo records a real Pandaward session on the demo fixture and
// writes it as an animated SVG terminal for the README:
//
//	go build -o /tmp/pandaward ./cmd/pandaward
//	go run ./tools/termdemo --pandaward /tmp/pandaward --out docs/media/demo.svg
//
// Every screen is the actual output of the command shown, shortened to fit.
package main

import (
	"flag"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type screen struct {
	cmd   string
	lines []string
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

const (
	maxLines = 20
	maxCols  = 96
	lineH    = 19
	padX     = 16
	padTop   = 44
	seconds  = 6
)

func main() {
	bin := flag.String("pandaward", "", "path to a pandaward binary")
	out := flag.String("out", "docs/media/demo.svg", "SVG file to write")
	flag.Parse()
	if *bin == "" {
		fmt.Fprintln(os.Stderr, "usage: termdemo --pandaward <binary> [--out file.svg]")
		os.Exit(2)
	}
	abs, err := filepath.Abs(*bin)
	check(err)
	work, err := os.MkdirTemp("", "termdemo")
	check(err)
	defer os.RemoveAll(work)
	fx := filepath.Join(work, "acme-shop")
	gen := exec.Command("go", "run", "./tools/demofixture", fx)
	gen.Stderr = os.Stderr
	check(gen.Run())

	steps := []struct{ args, show string }{
		{"init", "pandaward init"},
		{"scan --quiet", "pandaward scan"},
		{"findings", "pandaward findings"},
		{"graph", "pandaward graph"},
		{"fix-plan", "pandaward fix-plan"},
	}
	var screens []screen
	for _, s := range steps {
		c := exec.Command(abs, strings.Fields(s.args)...)
		c.Dir = fx
		b, _ := c.CombinedOutput()
		text := strings.ReplaceAll(ansi.ReplaceAllString(string(b), ""), "\r", "")
		text = strings.ReplaceAll(text, filepath.ToSlash(fx), "~/acme-shop")
		text = slashPaths(strings.ReplaceAll(text, fx, "~/acme-shop"))
		screens = append(screens, screen{cmd: s.show, lines: fit(text)})
	}
	check(os.WriteFile(*out, []byte(render(screens)), 0o644))
	fmt.Println("wrote", *out)
}

// slashPaths shows paths under the fixture with forward slashes, so the
// demo looks the same whichever system generated it.
func slashPaths(text string) string {
	return projectPath.ReplaceAllStringFunc(text, filepath.ToSlash)
}

var projectPath = regexp.MustCompile(`~/acme-shop[^\s]*`)

// fit keeps the first lines of the output, cut to the terminal width.
func fit(text string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if r := []rune(l); len(r) > maxCols {
			l = string(r[:maxCols-3]) + "..."
		}
		lines = append(lines, l)
	}
	if len(lines) > maxLines {
		more := len(lines) - maxLines + 1
		lines = append(lines[:maxLines-1], fmt.Sprintf("... %d more lines", more))
	}
	return lines
}

func render(screens []screen) string {
	w := padX*2 + maxCols*42/5 // a 14px monospace cell is about 8.4px wide
	h := padTop + lineH*(maxLines+1) + 16
	total := seconds * len(screens)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="Pandaward terminal session: init, scan, findings, graph and fix-plan on a demo project">`+"\n", w, h, w, h)
	b.WriteString("<style>\n")
	b.WriteString(`text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:14px;white-space:pre;fill:#d4d4d8}` + "\n")
	b.WriteString(".p{fill:#4ade80}.c{fill:#fafafa;font-weight:600}.f{opacity:0}\n")
	for i := range screens {
		from := float64(i*seconds) / float64(total) * 100
		to := float64((i+1)*seconds) / float64(total) * 100
		fmt.Fprintf(&b, "@keyframes s%d{0%%,%.3f%%{opacity:0}%.3f%%,%.3f%%{opacity:1}%.3f%%,100%%{opacity:0}}\n", i, from, from+0.01, to-0.01, to)
		fmt.Fprintf(&b, ".s%d{animation:s%d %ds step-end infinite}\n", i, i, total)
	}
	b.WriteString("@media (prefers-reduced-motion:reduce){.f{animation:none}.s1{opacity:1}}\n")
	b.WriteString("</style>\n")
	fmt.Fprintf(&b, `<rect width="%d" height="%d" rx="10" fill="#18181b"/>`+"\n", w, h)
	for i, c := range []string{"#ef4444", "#eab308", "#22c55e"} {
		fmt.Fprintf(&b, `<circle cx="%d" cy="18" r="6" fill="%s"/>`+"\n", 20+i*20, c)
	}
	for i, s := range screens {
		fmt.Fprintf(&b, `<g class="f s%d">`+"\n", i)
		y := padTop
		fmt.Fprintf(&b, `<text x="%d" y="%d"><tspan class="p">$ </tspan><tspan class="c">%s</tspan></text>`+"\n", padX, y, html.EscapeString(s.cmd))
		for _, l := range s.lines {
			y += lineH
			fmt.Fprintf(&b, `<text x="%d" y="%d">%s</text>`+"\n", padX, y, html.EscapeString(l))
		}
		b.WriteString("</g>\n")
	}
	b.WriteString("</svg>\n")
	return b.String()
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
