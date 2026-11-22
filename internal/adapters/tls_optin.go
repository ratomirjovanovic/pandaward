package adapters

import (
	"regexp"
	"strings"
)

// Certificate verification that an operator switches off.
//
// A TLS client that skips verification only when a setting says so
// (`if conf.InsecureSkipVerify {`, `if (!this.rejectUnauthorized)`, an
// environment variable read in the condition) is an opt-in for a private or
// self-signed certificate, which is how many servers let an administrator
// reach an internal SMTP, LDAP or database host. It is still worth a look,
// so it is listed as information instead of high. A call that disables
// verification with no such condition stays high.

var (
	tlsOptInIfRe   = regexp.MustCompile(`\b(if|elif|else\s+if|unless|when)\b|\?\s*$|&&\s*$`)
	tlsOptInNameRe = regexp.MustCompile(`(?i)skip[_ -]?(tls|ssl|cert|verif)|insecure|reject_?unauth|unauthori[sz]ed|verify_?(tls|ssl|cert)|tls_?verify|ssl_?verify|self_?signed|allow_?invalid|ignore_?(tls|ssl|cert)|no_?verify|trust_?all|process\.env|os\.Getenv|getenv|environ`)
)

func tlsOptInDemote(c lineCtx) *demotion {
	if c.File == nil || c.Index < 0 || c.Index >= len(c.File.Lines) {
		return nil
	}
	lo := c.Index - 8
	if lo < 0 {
		lo = 0
	}
	// The nearest condition above the line, and everything up to the line.
	start := -1
	for i := c.Index - 1; i >= lo; i-- {
		l := c.File.Lines[i]
		if tlsOptInIfRe.MatchString(l) {
			start = i
			break
		}
		// A function boundary ends the search: the condition belongs to
		// another block.
		if funcStartRe.MatchString(l) {
			return nil
		}
	}
	if start < 0 {
		return nil
	}
	cond := strings.Join(c.File.Lines[start:c.Index], "\n")
	if !tlsOptInNameRe.MatchString(cond) {
		return nil
	}
	// The condition's block must still be open at the line: an earlier
	// sibling `if` whose block has closed does not guard it.
	if c.File.Lang == "python" {
		if indentOf(c.File.Lines[c.Index]) <= indentOf(c.File.Lines[start]) {
			return nil
		}
	} else if strings.Count(cond, "{")-strings.Count(cond, "}") <= 0 {
		return nil
	}
	return &demotion{Title: "TLS verification switched off by a setting",
		Message: "The call turns certificate verification off only inside a condition that reads a configuration value, so an operator chooses it, for example to reach a host with a private certificate. It is listed because the setting is still an exposure when it is on.",
		Fix:     "Make verification the default, trust a specific CA bundle for private certificates, and document the risk of the setting."}
}

var funcStartRe = regexp.MustCompile(`^\s*(func\b|def\b|(async\s+)?function\b|(export\s+)?(const|let)\s+\w+\s*=\s*(async\s*)?\(?[\w,\s]*\)?\s*=>\s*\{?\s*$)`)

func indentOf(l string) int {
	return len(l) - len(strings.TrimLeft(l, " 	"))
}
