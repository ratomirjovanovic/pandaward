package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// ---- agent instructions and MCP tool descriptions: P-004 ----
//
// Coding agents load instruction files (AGENTS.md, CLAUDE.md, skills, MCP
// configs) and MCP tool descriptions into the model's context. Two checks
// run over that text, both tuned for precision:
//
//   - prompt.hidden-unicode: characters a person reviewing the file cannot
//     see but a model reads (Unicode tags, bidi overrides and isolates,
//     zero-width characters, a byte order mark after the start of the file).
//   - prompt.tool-description-injection: a tool description that tells the
//     model to ignore its instructions, hide something from the user, read or
//     send credential files, or prefer this tool over every other one. Only
//     tool descriptions are checked: instruction files such as CLAUDE.md
//     legitimately tell the agent what to do.

var hiddenUnicodeRule = lineRule{ID: "prompt.hidden-unicode", Control: "P-004", Title: "Invisible Unicode characters in agent instructions or a tool description",
	Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-1427",
	Fix: "Remove the invisible characters (for example with a hex editor or `grep -nP '[\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}\\x{E0000}-\\x{E007F}]'`), find out who added them, and review the visible text again."}

var toolInjectionRule = lineRule{ID: "prompt.tool-description-injection", Control: "P-004", Title: "MCP tool description contains instructions aimed at the model",
	Severity: model.SevHigh, Confidence: model.Hypothesis, CWE: "CWE-1427",
	Fix: "Keep tool descriptions to what the tool does and what its parameters mean. Remove the instruction; if the server comes from a third party, stop using it until the description is explained."}

// hiddenRune reports whether r is one of the invisible characters the check
// looks for.
func hiddenRune(r rune) bool {
	switch {
	case r >= 0xE0000 && r <= 0xE007F: // tags
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069: // bidi embeddings, overrides, isolates
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF: // zero-width, word joiner, BOM
		return true
	}
	return false
}

// joinable reports whether r can legitimately sit on either side of a zero
// width joiner or non-joiner: emoji and their modifiers, or letters and marks
// of non-Latin scripts (Persian, Indic) that use them in ordinary text.
func joinable(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF, r >= 0x2300 && r <= 0x23FF, r >= 0x2600 && r <= 0x27BF, r >= 0x2B00 && r <= 0x2BFF:
		return true
	case r == 0xFE0F || r == 0x20E3:
		return true
	}
	return r > 0x7F && (unicode.IsLetter(r) || unicode.IsMark(r))
}

// hiddenAt returns the indexes of the suspicious runes in rs. Joiners
// between joinable characters and tag sequences of subdivision flags (a black
// flag followed by tag letters and a cancel tag) are allowed. When atStart
// is set, a byte order mark at index 0 is allowed.
func hiddenAt(rs []rune, atStart bool) []int {
	var out []int
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if !hiddenRune(r) {
			continue
		}
		if r == 0xFEFF && i == 0 && atStart {
			continue
		}
		if (r == 0x200C || r == 0x200D) && i > 0 && i+1 < len(rs) && joinable(rs[i-1]) && joinable(rs[i+1]) {
			continue
		}
		if r >= 0xE0000 && r <= 0xE007F && i > 0 && rs[i-1] == 0x1F3F4 {
			if j := flagTagEnd(rs, i); j > 0 {
				i = j
				continue
			}
		}
		out = append(out, i)
	}
	return out
}

// flagTagEnd returns the index of the cancel tag that ends a subdivision
// flag tag sequence starting at i, or 0 when rs[i:] is not one.
func flagTagEnd(rs []rune, i int) int {
	for j := i; j < len(rs) && j-i <= 8; j++ {
		switch r := rs[j]; {
		case r == 0xE007F:
			if j > i {
				return j
			}
			return 0
		case r >= 0xE0030 && r <= 0xE0039, r >= 0xE0061 && r <= 0xE007A:
		default:
			return 0
		}
	}
	return 0
}

// codePoints lists the distinct code points at idx in order of appearance.
func codePoints(rs []rune, idx []int) string {
	seen := map[rune]bool{}
	var list []string
	more := 0
	for _, i := range idx {
		if seen[rs[i]] {
			continue
		}
		seen[rs[i]] = true
		if len(list) == 8 {
			more++
			continue
		}
		list = append(list, fmt.Sprintf("U+%04X", rs[i]))
	}
	s := strings.Join(list, ", ")
	if more > 0 {
		s += fmt.Sprintf(" and %d more", more)
	}
	return s
}

// visibleSnippet replaces every run of invisible characters in a line with a
// marker, so the snippet never carries the hidden text.
func visibleSnippet(line string) string {
	var b strings.Builder
	run := 0
	flush := func() {
		if run > 0 {
			fmt.Fprintf(&b, "[%d hidden]", run)
			run = 0
		}
	}
	for _, r := range line {
		if hiddenRune(r) {
			run++
			continue
		}
		flush()
		b.WriteRune(r)
	}
	flush()
	return redact.Line(strings.TrimSpace(b.String()))
}

func hiddenSignal(f *inventory.File, line int, rs []rune, idx []int, where, collector string) model.Signal {
	s := sig(hiddenUnicodeRule, f, line, collector)
	s.Snippet = visibleSnippet(f.Lines[line-1])
	s.Message = fmt.Sprintf("%s contains %d invisible character(s) (%s). Editors and diffs do not show them, but a language model reads them, so they can carry instructions that a reviewer cannot see. The hidden text is not reproduced here.",
		where, len(idx), codePoints(rs, idx))
	return s
}

// skipAgentText reports whether a path is test, fixture or adversarial
// probe content, where hostile text is expected.
func skipAgentText(p string) bool {
	if IsTestPath(p) {
		return true
	}
	for _, seg := range strings.Split(strings.ToLower(p), "/") {
		if seg == "adversarial" {
			return true
		}
	}
	return false
}

// agentTextSignals runs both checks over the inventory's agent_text files.
func agentTextSignals(inv *inventory.Inventory, collector string) []model.Signal {
	var out []model.Signal
	for _, p := range inv.Features["agent_text"] {
		f := inv.FileByPath(p)
		if f == nil || skipAgentText(f.Path) {
			continue
		}
		seen := map[string]bool{}
		add := func(s model.Signal) {
			k := fmt.Sprintf("%s|%d", s.RuleID, s.StartLine)
			if !seen[k] {
				seen[k] = true
				out = append(out, s)
			}
		}
		var descs []toolDesc
		switch {
		case inventory.IsMCPConfig(f.Path):
			descs = jsonDescriptions(f)
			fallthrough
		case inventory.IsAgentInstructions(f.Path):
			// The whole file is read by the agent.
			for i, l := range f.Lines {
				rs := []rune(l)
				if idx := hiddenAt(rs, i == 0); len(idx) > 0 {
					add(hiddenSignal(f, i+1, rs, idx, fmt.Sprintf("Line %d", i+1), collector))
				}
			}
		default:
			descs = codeDescriptions(f)
		}
		lineStarts := lineOffsets(f.Lines)
		for _, d := range descs {
			rs := d.runes
			if idx := hiddenAt(rs, false); len(idx) > 0 {
				// Report each source line that holds hidden characters.
				byLine := map[int][]int{}
				var lines []int
				for _, i := range idx {
					ln := lineAt(lineStarts, d.offs[i])
					if byLine[ln] == nil {
						lines = append(lines, ln)
					}
					byLine[ln] = append(byLine[ln], i)
				}
				for _, ln := range lines {
					add(hiddenSignal(f, ln, rs, byLine[ln], "The MCP tool description on line "+fmt.Sprint(ln), collector))
				}
			}
			text := string(rs)
			if kind, at := toolInjection(text); kind != "" {
				ln := lineAt(lineStarts, d.offs[utf8.RuneCountInString(text[:at])])
				s := sig(toolInjectionRule, f, ln, collector)
				s.Message = "This MCP tool description " + kind + ". Tool descriptions are read by the model on every request, and an instruction in one can make the agent act against the user without being asked (tool poisoning). Confirm who wrote it and why."
				add(s)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].File < out[j].File || out[i].File == out[j].File && out[i].StartLine < out[j].StartLine
	})
	return out
}

// ---- tool description injection patterns ----

var (
	ignoreInstrRe = regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts?)\b`)
	concealRe     = regexp.MustCompile(`(?i)\b(?:do\s+not|don['\x{2019}]t|never)\s+(?:(?:tell|inform|notify)\s+the\s+user|mention\s+(?:this\s+|it\s+|that\s+|anything\s+)?(?:to\s+)?the\s+user)(?:$|[^'\x{2019}\w])`)
	pseudoTagRe   = regexp.MustCompile(`(?i)<\s*/?\s*(?:important|system)\s*>`)
	shadowRe      = regexp.MustCompile(`(?i)\b(?:before|instead\s+of)\s+(?:using|calling|invoking)\s+(?:any\s+other|other|another|any)\s+(?:mcp\s+)?(?:tools?|servers?)\b|\binstead\s+of\s+(?:any\s+other|other|another)\s+(?:mcp\s+)?(?:tools?|servers?)\b`)
	sentenceRe    = regexp.MustCompile(`[.!?](?:\s+|$)|\n`)
	// Credential locations nobody needs a model to read for a tool call.
	strongCredRe = regexp.MustCompile(`(?i)(?:~/\.ssh\b|\.ssh/|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bmcp\.json\b|claude_desktop_config\.json|\.aws/|\.git-credentials|credentials\.json|/credentials\b|\.netrc\b)`)
	// .env files are also read by ordinary dotenv tools, so they count only
	// when the description asks for their content to be passed on.
	envFileRe  = regexp.MustCompile(`(?i)(?:^|[\s/'"(\x60~])\.env\b`)
	readSendRe = regexp.MustCompile(`(?i)\b(?:read|cat|open|send|pass|include|attach|provide|upload|forward|append|embed|exfiltrate|share|copy)\b`)
	sendRe     = regexp.MustCompile(`(?i)\b(?:send|pass|include|attach|provide|upload|forward|append|embed|exfiltrate)\b`)
	contentRe  = regexp.MustCompile(`(?i)\bcontents?\b`)
	negationRe = regexp.MustCompile(`(?i)\b(?:not|never|don['\x{2019}]t|without|avoid|except|excluding)\b`)
)

// toolInjection returns what the description asks for and the byte offset in
// d where the evidence starts, or "" when no pattern matches.
func toolInjection(d string) (string, int) {
	type pat struct {
		re   *regexp.Regexp
		kind string
	}
	for _, p := range []pat{
		{ignoreInstrRe, "tells the model to ignore its previous instructions"},
		{concealRe, "tells the model to keep something from the user"},
		{pseudoTagRe, "wraps text in an <IMPORTANT> or <SYSTEM> style tag to make it look like a system instruction"},
		{shadowRe, "tells the model to call it before, or instead of, other tools or servers"},
	} {
		if loc := p.re.FindStringIndex(d); loc != nil {
			return p.kind, loc[0]
		}
	}
	// Credential files: judged per sentence, and only without a negation.
	for _, loc := range sentenceSpans(d) {
		s := d[loc[0]:loc[1]]
		if negationRe.MatchString(s) {
			continue
		}
		if m := strongCredRe.FindStringIndex(s); m != nil && readSendRe.MatchString(s) {
			return "asks the model to read or send a credential or agent configuration file", loc[0] + m[0]
		}
		if m := envFileRe.FindStringIndex(s); m != nil && sendRe.MatchString(s) && contentRe.MatchString(s) {
			return "asks the model to pass on the content of a .env file", loc[0] + m[0]
		}
	}
	return "", 0
}

// sentenceSpans splits d into sentences; dots inside paths such as ~/.ssh do
// not end a sentence because no space follows them.
func sentenceSpans(d string) [][2]int {
	var out [][2]int
	start := 0
	for _, m := range sentenceRe.FindAllStringIndex(d, -1) {
		out = append(out, [2]int{start, m[0] + 1})
		start = m[1]
	}
	if start < len(d) {
		out = append(out, [2]int{start, len(d)})
	}
	for i := range out {
		if out[i][1] > len(d) {
			out[i][1] = len(d)
		}
	}
	return out
}

// ---- extracting tool descriptions ----

// toolDesc is the decoded text of one description with the source offset
// (in the file's lines joined by "\n") of every rune.
type toolDesc struct {
	runes []rune
	offs  []int
}

func (d *toolDesc) add(r rune, off int) {
	d.runes = append(d.runes, r)
	d.offs = append(d.offs, off)
}

func lineOffsets(lines []string) []int {
	out := make([]int, len(lines))
	off := 0
	for i, l := range lines {
		out[i] = off
		off += len(l) + 1
	}
	return out
}

// lineAt returns the 1-based line of a byte offset.
func lineAt(starts []int, off int) int {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] > off })
	if i < 1 {
		return 1
	}
	return i
}

// jsonDescriptions returns every string value stored under a "description"
// key in an MCP JSON config. A file that does not parse yields nothing.
func jsonDescriptions(f *inventory.File) []toolDesc {
	text := strings.Join(f.Lines, "\n")
	dec := json.NewDecoder(strings.NewReader(text))
	type frame struct {
		object, expectKey bool
		key               string
	}
	var stack []*frame
	var out []toolDesc
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			return out
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expectKey {
			if k, ok := tok.(string); ok {
				top.key, top.expectKey = k, false
				continue
			}
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if top != nil && top.object {
					top.expectKey = true
				}
				stack = append(stack, &frame{object: v == '{', expectKey: v == '{'})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		case string:
			if top != nil && top.object && strings.EqualFold(top.key, "description") {
				end := int(dec.InputOffset())
				var d toolDesc
				for _, r := range v {
					d.add(r, end-1)
				}
				out = append(out, d)
			}
		}
		if top != nil && top.object {
			top.expectKey = true
		}
	}
}

var (
	jsToolCallRe    = regexp.MustCompile(`\.(tool|registerTool|addTool)\s*\(`)
	jsDescPropRe    = regexp.MustCompile(`\bdescription\s*:\s*`)
	pyToolDecoRe    = regexp.MustCompile(`(?m)^[ \t]*@\w+\.tool\b`)
	pyDescKwRe      = regexp.MustCompile(`\bdescription\s*=\s*`)
	pyDefRe         = regexp.MustCompile(`(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+\w+`)
	goNewToolRe     = regexp.MustCompile(`\bmcp\.NewTool\s*\(`)
	goWithDescRe    = regexp.MustCompile(`\bmcp\.WithDescription\s*\(\s*`)
	pyStringStartRe = regexp.MustCompile(`^[rRuUbBfF]{0,2}("""|'''|"|')`)
)

// codeDescriptions extracts the description strings of MCP tools defined in
// a source file. Only literal text is taken; computed parts are skipped.
func codeDescriptions(f *inventory.File) []toolDesc {
	text := strings.Join(f.Lines, "\n")
	var out []toolDesc
	switch f.Lang {
	case "javascript", "typescript":
		for _, m := range jsToolCallRe.FindAllStringSubmatchIndex(text, -1) {
			open := m[1] - 1
			end := matchingParen(text, open, "js")
			call := text[m[2]:m[3]]
			if call == "tool" {
				// server.tool(name, description, ...): the second argument.
				if args := splitArgs(text, open+1, end, "js"); len(args) >= 3 {
					if d, ok := literalExpr(text, args[1], end, "js"); ok {
						out = append(out, d)
					}
				}
			}
			for _, p := range jsDescPropRe.FindAllStringIndex(text[open:end], -1) {
				if d, ok := literalExpr(text, open+p[1], end, "js"); ok {
					out = append(out, d)
				}
			}
		}
	case "python":
		for _, m := range pyToolDecoRe.FindAllStringIndex(text, -1) {
			at := m[1]
			if rest := strings.TrimLeft(text[at:], " \t"); strings.HasPrefix(rest, "(") {
				open := at + strings.Index(text[at:], "(")
				end := matchingParen(text, open, "py")
				for _, p := range pyDescKwRe.FindAllStringIndex(text[open:end], -1) {
					if d, ok := literalExpr(text, open+p[1], end, "py"); ok {
						out = append(out, d)
					}
				}
				at = end
			}
			// The docstring of the decorated function.
			def := pyDefRe.FindStringIndex(text[at:])
			if def == nil {
				continue
			}
			sigStart := at + def[1]
			colon := pyDefColon(text, sigStart)
			if colon < 0 {
				continue
			}
			body := skipSpace(text, colon+1, "py")
			if d, ok := literalExpr(text, body, len(text), "py"); ok {
				out = append(out, d)
			}
		}
	case "go":
		for _, m := range goNewToolRe.FindAllStringIndex(text, -1) {
			open := m[1] - 1
			end := matchingParen(text, open, "go")
			for _, p := range goWithDescRe.FindAllStringIndex(text[open:end], -1) {
				if d, ok := literalExpr(text, open+p[1], end, "go"); ok {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// pyDefColon returns the offset of the colon that ends a def signature
// starting at i (after the function name), or -1.
func pyDefColon(text string, i int) int {
	depth := 0
	for i < len(text) {
		switch c := text[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '"', '\'':
			i = skipString(text, i, "py")
			continue
		case ':':
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

// skipSpace skips whitespace and comments.
func skipSpace(text string, i int, lang string) int {
	for i < len(text) {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case lang == "py" && c == '#', lang != "py" && strings.HasPrefix(text[i:], "//"):
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case lang != "py" && strings.HasPrefix(text[i:], "/*"):
			if j := strings.Index(text[i+2:], "*/"); j >= 0 {
				i += j + 4
			} else {
				return len(text)
			}
		case lang == "py" && c == '\\' && i+1 < len(text) && text[i+1] == '\n':
			i += 2
		default:
			return i
		}
	}
	return i
}

// matchingParen returns the offset of the parenthesis that closes the one at
// open, skipping strings and comments, or len(text).
func matchingParen(text string, open int, lang string) int {
	depth := 0
	for i := open; i < len(text); {
		if j := skipSpace(text, i, lang); j != i {
			i = j
			continue
		}
		switch c := text[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		case '"', '\'', '`':
			i = skipString(text, i, lang)
			continue
		}
		i++
	}
	return len(text)
}

// splitArgs returns the start offsets of the top-level arguments between
// from and end.
func splitArgs(text string, from, end int, lang string) []int {
	out := []int{skipSpace(text, from, lang)}
	depth := 0
	for i := from; i < end; {
		if j := skipSpace(text, i, lang); j != i {
			i = j
			continue
		}
		switch c := text[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '"', '\'', '`':
			i = skipString(text, i, lang)
			continue
		case ',':
			if depth == 0 {
				out = append(out, skipSpace(text, i+1, lang))
			}
		}
		i++
	}
	return out
}

// skipString returns the offset just past the string literal at i.
func skipString(text string, i int, lang string) int {
	_, j, ok := readString(text, i, lang, nil)
	if !ok {
		return i + 1
	}
	return j
}

// literalExpr decodes a string literal at i, joined with following literals
// by + (or by adjacency in Python), stopping at the first operand that is
// not a literal. It reports false when no literal starts at i.
func literalExpr(text string, i, end int, lang string) (toolDesc, bool) {
	var d toolDesc
	i = skipSpace(text, i, lang)
	found := false
	for i < end {
		_, j, ok := readString(text, i, lang, &d)
		if !ok {
			break
		}
		found = true
		i = skipSpace(text, j, lang)
		if i < end && text[i] == '+' {
			i = skipSpace(text, i+1, lang)
			continue
		}
		if lang == "py" && i < end && pyStringStartRe.MatchString(text[i:min(end, i+5)]) {
			continue
		}
		break
	}
	return d, found
}

// readString reads the string literal at i. It decodes the literal into d
// when d is not nil and returns the offset past the literal. In template
// literals the ${...} parts are skipped.
func readString(text string, i int, lang string, d *toolDesc) (string, int, bool) {
	start := i
	raw := false
	if lang == "py" {
		m := pyStringStartRe.FindStringSubmatchIndex(text[i:min(len(text), i+6)])
		if m == nil {
			return "", i, false
		}
		raw = strings.ContainsAny(text[i:i+m[2]], "rR")
		i += m[2]
		q := text[i : i+m[3]-m[2]]
		i += len(q)
		for i < len(text) {
			if strings.HasPrefix(text[i:], q) {
				return text[start:i], i + len(q), true
			}
			if len(q) == 1 && text[i] == '\n' {
				return "", i, false
			}
			i = decodeChar(text, i, raw, lang, d)
		}
		return "", i, false
	}
	if i >= len(text) {
		return "", i, false
	}
	q := text[i]
	if q != '"' && q != '\'' && q != '`' {
		return "", i, false
	}
	raw = q == '`' && lang == "go"
	i++
	for i < len(text) {
		c := text[i]
		if c == q {
			return text[start:i], i + 1, true
		}
		if c == '\n' && q != '`' {
			return "", i, false
		}
		if q == '`' && lang == "js" && strings.HasPrefix(text[i:], "${") {
			// Skip the substitution.
			depth := 0
			for i < len(text) {
				if text[i] == '{' {
					depth++
				} else if text[i] == '}' {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				i++
			}
			continue
		}
		i = decodeChar(text, i, raw, lang, d)
	}
	return "", i, false
}

// decodeChar decodes one character or escape sequence at i into d and
// returns the next offset.
func decodeChar(text string, i int, raw bool, lang string, d *toolDesc) int {
	if raw || text[i] != '\\' || i+1 >= len(text) {
		r, n := utf8.DecodeRuneInString(text[i:])
		if d != nil {
			d.add(r, i)
		}
		return i + n
	}
	at := i
	c := text[i+1]
	put := func(r rune, next int) int {
		if d != nil {
			d.add(r, at)
		}
		return next
	}
	hex := func(from, n int) (rune, bool) {
		if from+n > len(text) {
			return 0, false
		}
		var v rune
		for _, h := range text[from : from+n] {
			switch {
			case h >= '0' && h <= '9':
				v = v*16 + h - '0'
			case h >= 'a' && h <= 'f':
				v = v*16 + h - 'a' + 10
			case h >= 'A' && h <= 'F':
				v = v*16 + h - 'A' + 10
			default:
				return 0, false
			}
		}
		return v, true
	}
	switch c {
	case 'n':
		return put('\n', i+2)
	case 't':
		return put('\t', i+2)
	case 'r':
		return put('\r', i+2)
	case '\n':
		return i + 2 // line continuation
	case 'x':
		if v, ok := hex(i+2, 2); ok {
			return put(v, i+4)
		}
	case 'U':
		if lang != "js" {
			if v, ok := hex(i+2, 8); ok {
				return put(v, i+10)
			}
		}
	case 'u':
		if lang == "js" && i+2 < len(text) && text[i+2] == '{' {
			if j := strings.IndexByte(text[i+3:], '}'); j > 0 && j <= 6 {
				if v, ok := hex(i+3, j); ok {
					return put(v, i+4+j)
				}
			}
			break
		}
		if v, ok := hex(i+2, 4); ok {
			next := i + 6
			// A surrogate pair written as two escapes.
			if v >= 0xD800 && v <= 0xDBFF && strings.HasPrefix(text[next:], `\u`) {
				if lo, ok := hex(next+2, 4); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					return put((v-0xD800)<<10+(lo-0xDC00)+0x10000, next+6)
				}
			}
			return put(v, next)
		}
	}
	r, n := utf8.DecodeRuneInString(text[i+1:])
	return put(r, i+1+n)
}
