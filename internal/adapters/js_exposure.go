package adapters

import (
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// ---- D-006: a checked address is not the one connected to ----
//
// A server-side fetch of a user-supplied URL that resolves the host with
// dns.lookup, checks the addresses and then calls fetch (or another client)
// with the URL resolves the name a second time. A host that answers with a
// public address for the check and a private one for the connection (DNS
// rebinding) reaches internal addresses. The fix is to connect through a
// lookup that validates the addresses it returns. The rule reads one file:
// a lookup that is checked, followed within 40 lines by a request that takes
// the same host, in a file with no connection-time lookup of its own.

var (
	dnsLookupRe    = regexp.MustCompile(`\b(?:lookup|resolve4|resolve6|resolve)\s*\(\s*([A-Za-z_$][\w$]*(?:\.(?:hostname|host))?)`)
	dnsImportRe    = regexp.MustCompile(`(?:from\s+['"](?:node:)?dns(?:/promises)?['"]|require\(\s*['"](?:node:)?dns(?:/promises)?['"]\s*\)|\bdns\.(?:promises\.)?(?:lookup|resolve))`)
	addrCheckRe    = regexp.MustCompile(`(?i)private|public|internal|loopback|reserved|isIP|blocked|forbidden|169\.254|127\.|10\.|192\.168`)
	requestCallRe  = regexp.MustCompile(`\b(?:fetch|axios(?:\.(?:get|post|request))?|got|request|http\.get|https\.get|http\.request|https\.request)\s*\(\s*([A-Za-z_$][\w$]*(?:\.[\w$]+)?)`)
	connectLookup  = regexp.MustCompile(`\blookup\s*:|createConnection|ssrf-req-filter|ssrfFilter|safeFetch|safe-fetch|useAgent|new\s+Agent\s*\(|setGlobalDispatcher`)
	rebindWindow   = 40
	rebindBaseRoot = regexp.MustCompile(`^([A-Za-z_$][\w$]*)`)
)

func dnsRebindSignals(f *inventory.File, text, collector string) []model.Signal {
	if !dnsImportRe.MatchString(text) || connectLookup.MatchString(text) {
		return nil
	}
	var out []model.Signal
	reported := map[int]bool{}
	for i, l := range f.Lines {
		m := dnsLookupRe.FindStringSubmatch(l)
		if m == nil || commentRe.MatchString(l) {
			continue
		}
		host := rebindBaseRoot.FindString(m[1])
		end := min(i+rebindWindow, len(f.Lines))
		checked := false
		for j := i; j < end; j++ {
			if j > i && addrCheckRe.MatchString(f.Lines[j]) {
				checked = true
			}
			rm := requestCallRe.FindStringSubmatch(f.Lines[j])
			if rm == nil || j <= i || !checked || reported[j] {
				continue
			}
			// The request takes the URL or the host that was resolved: a
			// variable of the lookup's own name, or one built from it.
			arg := rebindBaseRoot.FindString(rm[1])
			if arg == "" || !relatedTo(f.Lines[i:j], host, arg) {
				continue
			}
			reported[j] = true
			out = append(out, model.Signal{
				RuleID: "code.dns-rebinding-check", ControlID: "D-006", Title: "Checked address is not the address connected to",
				Severity: model.SevLow, Confidence: model.Hypothesis, CWE: "CWE-367",
				File: f.Path, StartLine: j + 1, EndLine: j + 1, Snippet: redact.Line(strings.TrimSpace(f.Lines[j])),
				Message: "The host is resolved and its addresses are checked, then the request resolves the name again. A host that answers with a public address for the check and a private one for the connection (DNS rebinding) reaches internal addresses.",
				Fix:     "Connect through a lookup that validates the addresses it returns (an agent or dispatcher with a `lookup` option), or connect to the address that was checked and send the original host name in the Host header.",
				Retest:  "Re-run `pandaward scan`.", Collector: collector, Key: "dns-rebinding",
			})
			break
		}
	}
	return out
}

// relatedTo reports that name arg is the resolved host, or is assigned from
// an expression that mentions it, within the lines given.
func relatedTo(lines []string, host, arg string) bool {
	if arg == host {
		return true
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(arg) + `\s*=[^=][^\n]*\b` + regexp.QuoteMeta(host) + `\b`)
	for _, l := range lines {
		if re.MatchString(l) {
			return true
		}
	}
	// A URL parsed from the same input as the host: new URL(x) in the lines.
	return strings.Contains(strings.Join(lines, "\n"), arg+" = new URL(") || strings.Contains(strings.Join(lines, "\n"), "const "+arg+" = new URL(")
}

// ---- G-003: whole rows returned to the client ----
//
// An ORM find without a field list whose result is serialised straight into a
// response returns every column, including internal ones (cost, metadata,
// flags). The rule reads one file: `x = await db.model.findMany(...)` with no
// `select` or `omit`, and `json(... x ...)` or `res.send/json(x)` within 15
// lines. It is a hypothesis: the schema may hold nothing internal.

var (
	ormFindRe      = regexp.MustCompile(`\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[\w$.]*\.(?:findMany|findFirst|findUnique|findFirstOrThrow|findUniqueOrThrow)\s*\(`)
	ormFieldListRe = regexp.MustCompile(`\b(?:select|omit)\s*:`)
	respJSONRe     = regexp.MustCompile(`(?:\.json|\.send|Response\.json|NextResponse\.json)\s*\(`)
)

func excessiveExposureSignals(f *inventory.File, collector string) []model.Signal {
	var out []model.Signal
	for i, l := range f.Lines {
		m := ormFindRe.FindStringSubmatch(l)
		if m == nil || commentRe.MatchString(l) || strings.HasPrefix(m[1], "{") {
			continue
		}
		v := m[1]
		// The call's arguments: up to the line that closes it, at most 12.
		call, depth := "", 0
		for j := i; j < min(i+12, len(f.Lines)); j++ {
			call += f.Lines[j] + "\n"
			depth += strings.Count(f.Lines[j], "(") - strings.Count(f.Lines[j], ")")
			if depth <= 0 {
				break
			}
		}
		if depth > 0 || ormFieldListRe.MatchString(call) {
			continue
		}
		use := regexp.MustCompile(`\b` + regexp.QuoteMeta(v) + `\b`)
		for j := i + 1; j < min(i+16, len(f.Lines)); j++ {
			if !respJSONRe.MatchString(f.Lines[j]) {
				continue
			}
			arg := f.Lines[j][respJSONRe.FindStringIndex(f.Lines[j])[1]:]
			// A projection (map, pick, a call) between the row and the
			// response is not judged: only the variable itself, alone or as
			// a property of the response object.
			if !use.MatchString(arg) || strings.Contains(arg, v+".map(") || strings.Contains(arg, "pick(") || strings.Contains(arg, "omit(") {
				continue
			}
			out = append(out, model.Signal{
				RuleID: "code.excessive-data-exposure", ControlID: "G-003", Title: "Whole database rows may be returned to the client",
				Severity: model.SevLow, Confidence: model.Hypothesis, CWE: "CWE-213",
				File: f.Path, StartLine: i + 1, EndLine: i + 1, Snippet: redact.Line(strings.TrimSpace(f.Lines[i])),
				Message: "A query without a field list (`select` or `omit`) is serialised into a response on line " + itoa(j+1) + ", so every column is returned, including internal ones such as cost, metadata or flags.",
				Fix:     "Select the fields the client needs (`select: { id: true, type: true }`) or map the rows to a response type before returning them.",
				Retest:  "Re-run `pandaward scan`.", Collector: collector, Key: "excessive-data-exposure",
			})
			break
		}
	}
	return out
}
