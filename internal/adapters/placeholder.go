package adapters

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Gitleaks runs with --redact, so its report never holds the matched value.
// To tell a placeholder from a credential, the adapter re-reads the one
// reported line from the project, slices the match in memory and judges it
// here. The value is never stored, logged or copied into a signal, note or
// error.

var (
	placeholderWordRe = regexp.MustCompile(`(?i)dummy|example|placeholder|fake|changeme|your[_-]|redacted`)
	jwtSegRe          = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	testPrefixRe      = regexp.MustCompile(`(?i)^test[_-]`)
)

// placeholderSecret reports whether value, matched by a secret rule in file
// on the given line, is shaped like a placeholder rather than a credential:
//
//   - a run of at least 8 sequential (abcdefgh, 01234567) or repeated
//     (xxxxxxxx) characters;
//   - a placeholder word (dummy, example, placeholder, fake, changeme, your_,
//     redacted), or a value that starts with test_ or test-;
//   - a JWT whose signature is shorter than 16 characters or whose payload
//     claims say dummy or example;
//   - the fallback literal of `secrets.NAME || '...'` inside `${{ }}` in a
//     GitHub Actions workflow.
//
// A JWT that claims the service_role role is never a placeholder.
func placeholderSecret(value, file, line string) bool {
	if len(value) < 8 {
		return false
	}
	isJWT, claims, sig := parseJWT(value)
	if isJWT && claimsHaveRole(claims, "service_role") {
		return false
	}
	if hasRun(value, 8) {
		return true
	}
	if placeholderWordRe.MatchString(value) || testPrefixRe.MatchString(value) {
		return true
	}
	if isJWT && (len(sig) < 16 || claimsMention(claims, "dummy", "example")) {
		return true
	}
	if workflowFallback(value, file, line) {
		return true
	}
	return false
}

// hasRun reports a run of n characters that repeat or ascend by one within
// lower case letters, upper case letters or digits.
func hasRun(s string, n int) bool {
	rep, seq := 1, 1
	for i := 1; i < len(s); i++ {
		a, b := s[i-1], s[i]
		if b == a {
			rep++
		} else {
			rep = 1
		}
		if b == a+1 && charClass(a) != 0 && charClass(a) == charClass(b) {
			seq++
		} else {
			seq = 1
		}
		if rep >= n || seq >= n {
			return true
		}
	}
	return false
}

func charClass(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return 1
	case c >= 'A' && c <= 'Z':
		return 2
	case c >= '0' && c <= '9':
		return 3
	}
	return 0
}

// parseJWT splits a compact JWT. It returns the payload claims when they
// decode as a JSON object, and the signature segment.
func parseJWT(v string) (bool, map[string]any, string) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") || !strings.HasPrefix(parts[1], "eyJ") {
		return false, nil, ""
	}
	for _, p := range parts {
		if !jwtSegRe.MatchString(strings.TrimRight(p, "=")) {
			return false, nil, ""
		}
	}
	var claims map[string]any
	if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "=")); err == nil {
		_ = json.Unmarshal(raw, &claims)
	}
	return true, claims, strings.TrimRight(parts[2], "=")
}

func claimsHaveRole(claims map[string]any, role string) bool {
	for _, k := range []string{"role", "roles"} {
		switch v := claims[k].(type) {
		case string:
			if strings.EqualFold(v, role) {
				return true
			}
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok && strings.EqualFold(s, role) {
					return true
				}
			}
		}
	}
	return false
}

func claimsMention(claims map[string]any, words ...string) bool {
	for _, v := range claims {
		s, ok := v.(string)
		if !ok {
			continue
		}
		l := strings.ToLower(s)
		for _, w := range words {
			if strings.Contains(l, w) {
				return true
			}
		}
	}
	return false
}

// workflowFallback reports whether value is the literal after
// `secrets.NAME ||` inside a `${{ }}` expression of a workflow file.
func workflowFallback(value, file, line string) bool {
	f := filepath.ToSlash(file)
	if !strings.HasPrefix(f, ".github/workflows/") || strings.Contains(strings.TrimPrefix(f, ".github/workflows/"), "/") {
		return false
	}
	re, err := regexp.Compile(`\$\{\{[^}]*\bsecrets\.[A-Za-z0-9_-]+\s*\|\|\s*(['"]?)` + regexp.QuoteMeta(value) + `(['"]?)\s*\}\}`)
	if err != nil {
		return false
	}
	return re.MatchString(line)
}

// matchedValue re-reads line n of rel under root and returns the token gitleaks
// matched between the 1-based columns start and end, with the whole line.
// Paths that leave the root, also through symlinks, are refused. ok is false
// when the line cannot be read or the columns do not fit it.
func matchedValue(root, rel string, n, start, end int) (value, line string, ok bool) {
	if root == "" || rel == "" || rel == "(outside-root)" || n < 1 || start < 1 || end < start {
		return "", "", false
	}
	rootAbs, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", false
	}
	abs, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", "", false
	}
	if r, err := filepath.Rel(rootAbs, abs); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", "", false
	}
	fh, err := os.Open(abs)
	if err != nil {
		return "", "", false
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for i := 1; sc.Scan(); i++ {
		if i < n {
			continue
		}
		line = strings.TrimRight(sc.Text(), "\r")
		// One character of slack on the left: gitleaks columns are not
		// always 1-based on lines after the first. The token is cut out of
		// the slice, so an extra delimiter does not matter.
		s, e := start-2, end
		if s < 0 {
			s = 0
		}
		if e > len(line) {
			e = len(line)
		}
		if s >= e {
			return "", "", false
		}
		value = lastToken(line[s:e])
		return value, line, value != ""
	}
	return "", "", false
}

// lastToken returns the last run of secret-like characters in s. For a rule
// that matches `key = "value"` that is the value; a `name=` prefix glued to
// it is cut off.
func lastToken(s string) string {
	isTok := func(c byte) bool {
		return charClass(c) != 0 || strings.IndexByte("_-.+/~=", c) >= 0
	}
	e := len(s)
	for e > 0 && !isTok(s[e-1]) {
		e--
	}
	b := e
	for b > 0 && isTok(s[b-1]) {
		b--
	}
	tok := s[b:e]
	if i := strings.LastIndexByte(strings.TrimRight(tok, "="), '='); i >= 0 {
		tok = tok[i+1:]
	}
	return tok
}
