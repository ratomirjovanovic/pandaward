package main

import (
	"context"
	"flag"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// subcommands are the words that may follow a command. Keep them in step
// with the switch statements of the commands.
var subcommands = map[string][]string{
	"findings":  {"list", "show", "add", "false-positive", "accept-risk", "reopen", "confirm", "apply"},
	"evidence":  {"show", "verify"},
	"scope":     {"init", "show", "validate", "approve", "revoke"},
	"telemetry": {"status", "on", "off", "send", "show"},
	"feedback":  {"false-positive", "false-negative", "summary"},
	"hook":      {"session-start", "post-edit", "pre-tool", "pre-compact", "stop", "subagent-start", "subagent-stop", "reviewer-tool"},
}

var (
	usageCmd = regexp.MustCompile(`(?m)^  ([a-z][a-z-]+)(?: |$)`)
	// A reference is "pandaward" and the words after it, one space apart;
	// two spaces end it, as in the columns of help text.
	refRe   = regexp.MustCompile("(?:^|[^\\w.-])pandaward(?:\\.exe)?\"? ((?:[^ `\"'|;,()\\n]+ ?)+)")
	wordRe  = regexp.MustCompile(`^[a-z][a-z-]*$`)
	flagRe  = regexp.MustCompile(`^--?([a-z][a-z0-9-]*)(?:=.*)?$`)
	codeTag = regexp.MustCompile(`</?code>`)
	htmlTag = regexp.MustCompile(`<[^>]+>`)
)

// cliSurface lists every command and the flags it accepts, read from the
// usage text and from the flag sets the commands build.
func cliSurface(t *testing.T) map[string]map[string]bool {
	cmds := map[string]map[string]bool{"hook": {}, "version": {}, "help": {}}
	for _, m := range usageCmd.FindAllStringSubmatch(usage, -1) {
		cmds[m[1]] = map[string]bool{}
	}
	var sets []*flag.FlagSet
	seenFlags = func(fs *flag.FlagSet) { fs.SetOutput(io.Discard); sets = append(sets, fs) }
	defer func() { seenFlags = nil }()
	for c := range cmds {
		if c == "hook" || c == "version" || c == "help" || c == "telemetry" {
			continue
		}
		runs := [][]string{{c, "-h"}}
		for _, s := range subcommands[c] {
			runs = append(runs, []string{c, s, "-h"})
		}
		for _, args := range runs {
			sets = nil
			run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard)
			for _, fs := range sets {
				fs.VisitAll(func(f *flag.Flag) { cmds[c][f.Name] = true })
			}
		}
	}
	if len(cmds) < 20 || len(cmds["assess"]) == 0 {
		t.Fatalf("could not read the CLI: %v", cmds)
	}
	return cmds
}

// strictBefore reports whether the text before "pandaward" starts a
// command, so the word after it must be a command. Elsewhere "pandaward"
// may be prose ("an older pandaward without ...") and only known commands
// are checked.
func strictBefore(prefix string) bool {
	p := strings.TrimRight(prefix, " ")
	if p == "" {
		return true
	}
	for _, s := range []string{"`", "$", "!", "&&", ";", "(", "/bin/", "bin/pandaward\""} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

func checkLine(cmds map[string]map[string]bool, line string) []string {
	var problems []string
	for _, m := range refRe.FindAllStringSubmatchIndex(line, -1) {
		start := strings.Index(line[m[0]:], "pandaward") + m[0]
		toks := strings.Fields(line[m[2]:m[3]])
		if len(toks) == 0 || !wordRe.MatchString(toks[0]) {
			continue
		}
		c := toks[0]
		flags, ok := cmds[c]
		if !ok {
			if strictBefore(line[:start]) {
				problems = append(problems, "unknown command "+strconv.Quote(c))
			}
			continue
		}
		for i, tok := range toks[1:] {
			if fm := flagRe.FindStringSubmatch(tok); fm != nil {
				if !flags[fm[1]] && fm[1] != "h" && fm[1] != "help" {
					problems = append(problems, "pandaward "+c+" has no flag --"+fm[1])
				}
				continue
			}
			if subs, has := subcommands[c]; has && i == 0 && wordRe.MatchString(tok) {
				found := false
				for _, s := range subs {
					found = found || s == tok
				}
				if !found {
					problems = append(problems, "pandaward "+c+" has no subcommand "+strconv.Quote(tok))
				}
			}
		}
	}
	return problems
}

type textLine struct {
	n    int
	text string
}

// textLines returns the lines of a file that may hold command references:
// every line of documents, and each line of the string literals of Go code.
func textLines(t *testing.T, path string) []textLine {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []textLine
	switch filepath.Ext(path) {
	case ".go":
		fset := token.NewFileSet()
		f := fset.AddFile(path, -1, len(b))
		var s scanner.Scanner
		s.Init(f, b, nil, 0)
		for {
			pos, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			if tok != token.STRING {
				continue
			}
			v := lit
			if u, err := strconv.Unquote(lit); err == nil {
				v = u
			}
			for i, l := range strings.Split(v, "\n") {
				out = append(out, textLine{fset.Position(pos).Line + i, l})
			}
		}
	case ".html":
		for i, l := range strings.Split(string(b), "\n") {
			out = append(out, textLine{i + 1, htmlTag.ReplaceAllString(codeTag.ReplaceAllString(l, "`"), " ")})
		}
	default:
		for i, l := range strings.Split(string(b), "\n") {
			out = append(out, textLine{i + 1, l})
		}
	}
	return out
}

// TestCommandReferences fails when the skills, agents, MCP descriptions,
// CLI messages, README, docs or site mention a pandaward command,
// subcommand or flag the CLI does not have, so an assistant never runs a
// command that no longer exists. Set PANDAWARD_WIKI to a wiki checkout to
// check the wiki as well.
func TestCommandReferences(t *testing.T) {
	cmds := cliSurface(t)
	dirs := []string{filepath.Join("..", "..")}
	if w := os.Getenv("PANDAWARD_WIKI"); w != "" {
		dirs = append(dirs, w)
	}
	skip := map[string]bool{".git": true, "bin": true, "node_modules": true, "testdata": true, ".pandaward": true, ".claude": true, "_out": true}
	var bad []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skip[d.Name()] || strings.HasPrefix(d.Name(), "brag-output") {
					return filepath.SkipDir
				}
				return nil
			}
			switch filepath.Ext(p) {
			case ".md", ".html", ".go", ".yml", ".yaml", ".json", ".rb":
			default:
				return nil
			}
			if strings.HasSuffix(p, "_test.go") {
				return nil
			}
			for _, l := range textLines(t, p) {
				for _, pr := range checkLine(cmds, l.text) {
					bad = append(bad, filepath.ToSlash(p)+":"+strconv.Itoa(l.n)+": "+pr)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

func TestCheckLine(t *testing.T) {
	cmds := map[string]map[string]bool{"progress": {"watch": true, "root": true}, "feedback": {"note": true}}
	for line, want := range map[string]int{
		"run `pandaward progress --watch`":                           0,
		"run `pandaward progress --follow`":                          1,
		"`\"${CLAUDE_PLUGIN_ROOT}/bin/pandaward\" progress --watch`": 0,
		"pandaward progres":                                          1,
		"recorded by an older pandaward without tracking":            0,
		"pandaward feedback false-positive PW-0001 --note x":         0,
		"pandaward feedback false-alarm":                             1,
		"    pandaward feedback    tell us about a wrong finding":    0,
		"scoop bucket add pandaward https://github.com/x/y":          0,
		"Usage: pandaward <command> [flags]":                         0,
	} {
		if got := checkLine(cmds, line); len(got) != want {
			t.Errorf("checkLine(%q) = %q, want %d problem(s)", line, got, want)
		}
	}
}
