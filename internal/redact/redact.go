// Package redact removes secret-like and personal values before anything is
// persisted, printed or handed to a model.
package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxSnippet is the maximum length of a stored snippet.
const MaxSnippet = 240

// SecretRule is a high-specificity secret format.
type SecretRule struct {
	ID    string
	Title string
	Re    *regexp.Regexp
	// Group is the submatch index that holds the secret value (0 = whole match).
	Group int
}

// SecretRules are formats with a low false-positive rate.
var SecretRules = []SecretRule{
	{"aws-access-key-id", "AWS access key ID", regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`), 1},
	{"github-token", "GitHub token", regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b`), 1},
	{"github-fine-grained-pat", "GitHub fine-grained token", regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{60,})\b`), 1},
	{"gitlab-token", "GitLab personal access token", regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,})\b`), 1},
	{"slack-token", "Slack token", regexp.MustCompile(`\b(xox[abpors]-[A-Za-z0-9-]{10,})\b`), 1},
	{"slack-webhook", "Slack webhook URL", regexp.MustCompile(`(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})`), 1},
	{"stripe-live-key", "Stripe live secret key", regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b`), 1},
	{"google-api-key", "Google API key", regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1},
	{"anthropic-api-key", "Anthropic API key", regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_\-]{20,})\b`), 1},
	{"openai-api-key", "OpenAI API key", regexp.MustCompile(`\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b`), 1},
	{"npm-token", "npm access token", regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), 1},
	{"sendgrid-key", "SendGrid API key", regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`), 1},
	{"twilio-key", "Twilio API key", regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), 1},
	{"private-key", "Private key block", regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)`), 1},
	{"jwt", "JSON Web Token", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), 1},
	{"db-url-password", "Database URL with inline password", regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/'"]+:([^@\s'"]{3,})@`), 1},
}

var (
	// key = "value" assignments for sensitive-looking names.
	assignRe = regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_\-]*\s*[:=]\s*)(["'\x60]?)([^"'\x60\s,;]{4,})`)
	bearerRe = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9_\-\.=]{8,})`)
	basicRe  = regexp.MustCompile(`(?i)(basic\s+)([A-Za-z0-9+/=]{8,})`)
	cookieRe = regexp.MustCompile(`(?i)((?:set-)?cookie\s*:\s*[^=;\s]+=)([^;\s]+)`)
	emailRe  = regexp.MustCompile(`\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
)

// Mask returns a non-reversible display form of a secret value.
func Mask(v string) string {
	n := utf8.RuneCountInString(v)
	if n <= 8 {
		return "[REDACTED]"
	}
	r := []rune(v)
	return string(r[:4]) + "…[REDACTED " + itoa(n) + " chars]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// placeholder values that are clearly not real secrets.
func isPlaceholder(v string) bool {
	l := strings.ToLower(strings.Trim(v, `"'`))
	if strings.HasPrefix(l, "${") || strings.HasPrefix(l, "process.env") || strings.HasPrefix(l, "os.") || strings.HasPrefix(l, "env.") || strings.HasPrefix(l, "$") {
		return true
	}
	switch l {
	case "true", "false", "null", "none", "nil", "undefined", "required", "string", "changeme", "example", "xxxx", "****", "<redacted>":
		return true
	}
	return false
}

// Line redacts one line of text. It is safe to call repeatedly.
func Line(s string) string {
	s = Sanitize(s)
	for _, r := range SecretRules {
		s = r.Re.ReplaceAllStringFunc(s, func(m string) string {
			sub := r.Re.FindStringSubmatch(m)
			if r.ID == "private-key" {
				return m // the header itself is not secret; key bodies are dropped below
			}
			if len(sub) > r.Group {
				return strings.Replace(m, sub[r.Group], Mask(sub[r.Group]), 1)
			}
			return Mask(m)
		})
	}
	s = bearerRe.ReplaceAllString(s, "${1}[REDACTED]")
	s = basicRe.ReplaceAllString(s, "${1}[REDACTED]")
	s = assignRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := assignRe.FindStringSubmatch(m)
		if isPlaceholder(sub[3]) || strings.Contains(sub[3], "REDACTED") || strings.EqualFold(sub[3], "bearer") || strings.EqualFold(sub[3], "basic") {
			return m
		}
		return sub[1] + sub[2] + Mask(sub[3])
	})
	s = cookieRe.ReplaceAllString(s, "${1}[REDACTED]")
	s = emailRe.ReplaceAllString(s, "${1}***@${2}")
	if looksLikeKeyBody(s) {
		return "[REDACTED key material]"
	}
	return truncate(s, MaxSnippet)
}

// Text redacts multi-line text line by line.
func Text(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = Line(lines[i])
	}
	return strings.Join(lines, "\n")
}

// Sanitize strips terminal escapes and control characters so untrusted
// repository text cannot manipulate a terminal or a report.
func Sanitize(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || r == '‮' || r == '‭' || r == '⁦' || r == '⁧' || r == '⁨' || r == '⁩' {
			return -1
		}
		return r
	}, s)
}

func looksLikeKeyBody(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 60 || strings.ContainsAny(t, " :=\"'(){}<>,;") {
		return false
	}
	for _, r := range t {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}
