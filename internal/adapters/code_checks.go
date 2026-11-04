package adapters

import (
	"regexp"
	"strings"
)

// Structural checks that narrow the line rules in builtin_code.go. Each one
// only drops a match when the code itself shows the value cannot carry
// attacker input; anything it cannot prove keeps firing.

// ---- code.js-shell ----

var jsShellExecRe = regexp.MustCompile(`\b(exec|execSync)\s*\(\s*(\x60[^\x60]*\$\{|['"][^'"]*['"]\s*\+|[a-zA-Z_]\w*\s*[,)])`)

var (
	interpRe      = regexp.MustCompile(`\$\{([^}]*)\}`)
	constInterpRe = regexp.MustCompile(`^([A-Z][A-Z0-9_]*|[A-Za-z_$][\w$]*\.pid)$`)
)

// jsShellDynamic reports whether some exec call on the line builds its
// command from something other than a template literal whose every
// interpolation is an UPPER_CASE constant or a process id.
func jsShellDynamic(l, _ string) bool {
	for _, m := range jsShellExecRe.FindAllStringSubmatchIndex(l, -1) {
		start := m[4]
		if l[start] != '`' {
			return true
		}
		tpl := l[start+1:]
		if end := strings.IndexByte(tpl, '`'); end >= 0 {
			tpl = tpl[:end]
		}
		ins := interpRe.FindAllStringSubmatch(tpl, -1)
		if len(ins) == 0 || len(ins) != strings.Count(tpl, "${") {
			return true
		}
		for _, in := range ins {
			if !constInterpRe.MatchString(strings.TrimSpace(in[1])) {
				return true
			}
		}
	}
	return false
}

var (
	ownExecRe   = regexp.MustCompile(`(?m)(^|[^.\w$])(function\s*\*?\s*exec\s*[<(]|(const|let|var)\s+exec\s*(:[^=]+)?=\s*(async\s+)?(function\b|\([^)]*\)\s*(:[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>))`)
	childProcRe = regexp.MustCompile(`child_process|shelljs`)
)

// definesOwnExec reports whether the file declares its own exec function
// and never references child_process or shelljs, so a bare exec(...) call
// in it cannot be the shell API. An imported exec does not count.
func definesOwnExec(text string) bool {
	return ownExecRe.MatchString(text) && !childProcRe.MatchString(text)
}

// ---- code.html-sink ----

var (
	htmlSinkRe   = regexp.MustCompile(`dangerouslySetInnerHTML|\.(inner|outer)HTML\s*=[^=]|document\.write(ln)?\s*\(|\bv-html\s*=|\bmark_safe\s*\(|\bhtml_safe\b|bypassSecurityTrust\w+\(`)
	htmlSinkNot  = regexp.MustCompile(`(?i)DOMPurify|sanitize|escape|innerHTML\s*=\s*['"\x60]{2}|innerHTML\s*=\s*['"]\s*['"]|JSON\.stringify\(.*\)\s*\.replace\(\s*/</g\s*,`)
	htmlAssignRe = regexp.MustCompile(`\.(inner|outer)HTML\s*=([^=].*)$`)
	constRHSRe   = regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]*|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60$]*\x60)\s*;?\s*(//.*)?$`)
	literalRe    = regexp.MustCompile(`^('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60)\s*(as\s+const\s*)?(;|\r?\n|$)`)
)

// htmlSinkDynamic drops an innerHTML/outerHTML assignment whose right-hand
// side is a string literal, a template without interpolation, or an
// UPPER_CASE constant the same file declares with such a literal.
func htmlSinkDynamic(l, text string) bool {
	m := htmlAssignRe.FindStringSubmatchIndex(l)
	if m == nil {
		return true
	}
	rhs := constRHSRe.FindStringSubmatch(l[m[4]:m[5]])
	if rhs == nil {
		return true
	}
	if c := rhs[1]; c[0] >= 'A' && c[0] <= 'Z' && !constLiteralDefined(c, text) {
		return true
	}
	return htmlSinkRe.MatchString(l[:m[0]])
}

// constLiteralDefined reports whether text declares `const name = <literal>`
// with a plain string or an interpolation-free template.
func constLiteralDefined(name, text string) bool {
	re := regexp.MustCompile(`(?:^|[^.\w$])const\s+` + regexp.QuoteMeta(name) + `(?:\s*:\s*string)?\s*=\s*`)
	loc := re.FindStringIndex(text)
	if loc == nil {
		return false
	}
	lit := literalRe.FindStringSubmatch(text[loc[1]:])
	return lit != nil && !strings.Contains(lit[1], "${")
}

// ---- code.secret-logged ----

var (
	labelRe       = regexp.MustCompile(`(?i)\b(password|passwd|secret|api_?key|access_?token|refresh_?token|authorization|private_?key)\b\s*[:=]\s*(%[-+#0-9.]*[a-zA-Z]|\{\d*\})?\s*$`)
	proseInterpRe = regexp.MustCompile(`\$?\{[^}]*\}|#\{[^}]*\}|\$[A-Za-z_]\w*`)
)

// blankProse empties the prose inside string literals so words in a log
// message do not count as logged values. Interpolations are kept, and so is
// a literal (or the text right before an interpolation) that ends in a
// label such as "password:" or "secret=%s", because a value follows it.
func blankProse(l string) string {
	var b strings.Builder
	for i := 0; i < len(l); {
		q := l[i]
		if q != '"' && q != '\'' && q != '`' {
			b.WriteByte(q)
			i++
			continue
		}
		j := i + 1
		for j < len(l) && l[j] != q {
			if l[j] == '\\' {
				j++
			}
			j++
		}
		end := min(j, len(l))
		body := l[i+1 : end]
		next := strings.TrimLeft(l[min(end+1, len(l)):], " \t")
		b.WriteByte(q)
		if labelRe.MatchString(body) && next != "" && strings.ContainsRune(",+%.", rune(next[0])) {
			b.WriteString(body)
		} else {
			b.WriteString(keepInterpolations(body))
		}
		if j < len(l) {
			b.WriteByte(q)
		}
		i = j + 1
	}
	return b.String()
}

func keepInterpolations(body string) string {
	var parts []string
	prev := 0
	for _, m := range proseInterpRe.FindAllStringIndex(body, -1) {
		if labelRe.MatchString(body[prev:m[0]]) {
			parts = append(parts, body[prev:m[0]])
		}
		parts = append(parts, body[m[0]:m[1]])
		prev = m[1]
	}
	return strings.Join(parts, " ")
}

// ---- code.llm-output-exec ----

var (
	llmSinkRe = regexp.MustCompile(`(?i)(\beval|\bexec|\bexecSync|\bsubprocess\.\w+|\bos\.system|\bnew\s+Function)\s*\(`)
	llmWordRe = regexp.MustCompile(`(?i)\b(completion|response|output|message|content|choices|generated|llm|model|answer|result\.text)\b`)
)

// llmOutputExec reports whether model output appears inside the argument
// list of an execution sink on the line. A method call such as re.exec(...)
// counts only in files that use child_process or shelljs, since elsewhere
// .exec is a RegExp or library method rather than a shell.
func llmOutputExec(l, text string) bool {
	for _, m := range llmSinkRe.FindAllStringSubmatchIndex(l, -1) {
		name := strings.ToLower(l[m[2]:m[3]])
		if m[2] > 0 && l[m[2]-1] == '.' {
			if name == "eval" || !childProcRe.MatchString(text) {
				continue
			}
		}
		if llmWordRe.MatchString(callArgs(l[m[1]:])) {
			return true
		}
	}
	return false
}

// callArgs returns the text up to the parenthesis that closes a call whose
// opening parenthesis was just consumed, or the rest of the line.
func callArgs(s string) string {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// ---- code.sql-concat ----

// sqlConcatRe pairs each opening quote with the same closing quote.
var sqlConcatRe = regexp.MustCompile(`(?i)("\s*` + sqlIn(`[^"]`) + `[^"]*"|'\s*` + sqlIn(`[^']`) + `[^']*'|\x60\s*` + sqlIn(`[^\x60]`) + `[^\x60]*\x60)\s*(\+|\.\s*\$|%\s*[\w(]|\.format\()`)

// sqlIn is the statement start; class keeps "select ... from" inside one
// literal.
func sqlIn(class string) string {
	return `(select\s` + class + `+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b`
}

// ---- code.weak-hash-password ----

// weakHashCall matches an MD5 or SHA-1 hashing call in common languages,
// including the md5sum/sha1sum command line tools.
const weakHashCall = `(\b(md5|sha1)(hex|_hex|digest)?\s*\(|\b(md5|sha1)sum\b` +
	`|\b(md5|sha1)\.(sum|new)\w*\s*\(` +
	`|\bhashlib\.(md5|sha1)\b` +
	`|(createHash|\bhash|hashlib\.new|\bdigest|getInstance|Digest\.new)\s*\(\s*['"\x60](md5|sha-?1)['"\x60]` +
	`|DigestUtils\.(md5|sha1|sha)\w*\s*\(` +
	`|Digest::(md5|sha1)\b` +
	`|\b(md5|sha1)(\.create\s*\(|managed\b|cryptoserviceprovider\b)` +
	`|:crypto\.hash\(\s*:(md5|sha)\b)`

var weakHashPasswordRe = regexp.MustCompile(`(?i)(` + weakHashCall + `.*\b(password|passwd|pwd)\b|\b(password|passwd|pwd)\b.*` + weakHashCall + `)`)
