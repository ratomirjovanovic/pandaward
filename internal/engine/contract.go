package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// G-002 compares the deployed API with the authorization its OpenAPI
// contract declares. Every GET or HEAD operation that requires security
// and needs no parameter value is sent once without credentials; the
// contract says it must be refused.

// contractOp is one operation the contract declares as secured.
type contractOp struct {
	Doc    string
	Method string
	Path   string   // request path, with the server base path
	Types  []string // media types the contract declares for 2xx answers
}

// contractSkip counts operations that were not sent, by reason.
type contractSkip map[string]int

// contractOps reads every OpenAPI document of the inventory and returns the
// secured operations that can be sent without inventing a value, with the
// documents that could not be read.
func contractOps(inv *inventory.Inventory) ([]contractOp, contractSkip, []string) {
	skip := contractSkip{}
	var ops []contractOp
	var bad []string
	for _, p := range inv.Features["openapi"] {
		f := inv.FileByPath(p)
		if f == nil {
			continue
		}
		var doc map[string]any
		text := strings.Join(f.Lines, "\n")
		var err error
		if strings.HasSuffix(strings.ToLower(p), ".json") {
			err = json.Unmarshal([]byte(text), &doc)
		} else {
			err = yaml.Unmarshal([]byte(text), &doc)
		}
		paths, _ := doc["paths"].(map[string]any)
		if err != nil || paths == nil {
			bad = append(bad, p)
			continue
		}
		base, ok := contractBase(doc)
		if !ok {
			skip["server URL with variables"] += len(paths)
			continue
		}
		global, _ := securityOf(doc)
		produces := stringList(doc["produces"])
		for rawPath, item := range paths {
			pi, _ := item.(map[string]any)
			for _, method := range []string{"get", "head"} {
				op, ok := pi[method].(map[string]any)
				if !ok {
					continue
				}
				secured := global
				if s, set := securityOf(op); set {
					secured = s
				}
				switch {
				case !secured:
					skip["public in the contract"]++
				case strings.Contains(rawPath, "{"):
					skip["path parameter"]++
				case requiredQuery(pi["parameters"]) || requiredQuery(op["parameters"]):
					skip["required query or header parameter"]++
				default:
					ops = append(ops, contractOp{Doc: p, Method: strings.ToUpper(method), Path: joinPath(base, rawPath), Types: okTypes(op, produces)})
				}
			}
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
	return ops, skip, bad
}

// contractBase returns the base path requests get: the path of the first
// OpenAPI 3 server, or the Swagger 2 basePath. A server URL with variables
// cannot be resolved.
func contractBase(doc map[string]any) (string, bool) {
	if bp, ok := doc["basePath"].(string); ok {
		return strings.TrimSuffix(bp, "/"), true
	}
	servers, _ := doc["servers"].([]any)
	if len(servers) == 0 {
		return "", true
	}
	s, _ := servers[0].(map[string]any)
	raw, _ := s["url"].(string)
	if strings.Contains(raw, "{") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(u.Path, "/"), true
}

// securityOf reports whether a security list requires credentials and
// whether the object sets one at all. An empty list or an empty
// requirement object ({}) makes credentials optional.
func securityOf(obj map[string]any) (secured, set bool) {
	v, ok := obj["security"]
	if !ok {
		return false, false
	}
	list, _ := v.([]any)
	if len(list) == 0 {
		return false, true
	}
	for _, req := range list {
		if m, _ := req.(map[string]any); len(m) == 0 {
			return false, true
		}
	}
	return true, true
}

func requiredQuery(v any) bool {
	list, _ := v.([]any)
	for _, p := range list {
		m, _ := p.(map[string]any)
		in, _ := m["in"].(string)
		req, _ := m["required"].(bool)
		if req && in != "path" {
			return true
		}
		if _, ref := m["$ref"]; ref {
			return true // a shared parameter that may be required
		}
	}
	return false
}

// okTypes lists the media types declared for 2xx answers.
func okTypes(op map[string]any, produces []string) []string {
	out := stringList(op["produces"])
	if len(out) == 0 {
		out = produces
	}
	resps, _ := op["responses"].(map[string]any)
	for code, r := range resps {
		if !strings.HasPrefix(code, "2") {
			continue
		}
		rm, _ := r.(map[string]any)
		content, _ := rm["content"].(map[string]any)
		for t := range content {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func stringList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func joinPath(base, p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

// contractAnswer is one request as recorded in evidence: no body.
type contractAnswer struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
	Type   string `json:"content_type,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	Error  string `json:"error,omitempty"`
}

// runContract sends every secured operation without credentials and
// decides G-002.
func (e *Engine) runContract(ctx context.Context, a *store.Assessment, m *scope.Manifest, ap *store.Approval, rr runtimeRun, g *scope.Guard, res *StagingResult, progress func(string)) error {
	inv := rr.inv
	if inv == nil {
		var err error
		if inv, err = e.Inventory(); err != nil {
			return err
		}
	}
	set := func(st model.Status, reason string) error {
		res.Controls["G-002"] = string(st)
		return e.setRuntime(a, rr, "G-002", st, reason)
	}
	if !inv.Has("openapi") {
		return set(model.StatusBlocked, "contract.check is on, but the repository has no OpenAPI document to compare the API with")
	}
	ops, skip, bad := contractOps(inv)
	if len(bad) > 0 {
		res.Notes = append(res.Notes, "OpenAPI documents that could not be read: "+strings.Join(bad, ", "))
	}
	skipped := skipText(skip)
	if len(ops) == 0 {
		return set(model.StatusInconclusive, "the OpenAPI contract declares no secured GET/HEAD operation that can be sent without a parameter value"+skipped)
	}
	base, err := m.CheckURL(scope.AuthCheck{Path: "/"})
	if err != nil {
		return err
	}
	client := g.Client()
	var answers []contractAnswer
	var sigs []model.Signal
	fail, suspect, unclear, passed := 0, 0, 0, 0
	for _, op := range ops {
		u := *base
		u.Path, u.RawPath = op.Path, ""
		target := redact.Line(op.Method + " " + u.Redacted())
		progress("contract check: " + target + " without credentials")
		ans := contractAnswer{Method: op.Method, Path: op.Path}
		req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), nil)
		if err == nil {
			req.Header.Set("User-Agent", "pandaward-contract/1 (authorized contract test)")
			var resp *http.Response
			if resp, err = client.Do(req); err == nil {
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				ans.Status, ans.Bytes, ans.Type = resp.StatusCode, int(n), redact.Line(resp.Header.Get("Content-Type"))
			}
		}
		if err != nil {
			ans.Error = redact.Line(err.Error())
		}
		answers = append(answers, ans)
		switch {
		case ans.Error != "" || ans.Status == http.StatusTooManyRequests || ans.Status >= 500:
			unclear++
		case ans.Status >= 200 && ans.Status < 300:
			s := contractSignal(op, target, ans)
			sigs = append(sigs, s)
			if s.Confidence == model.Confirmed {
				fail++
			} else {
				suspect++
			}
		case ans.Status == http.StatusUnauthorized || ans.Status == http.StatusForbidden || ans.Status >= 300 && ans.Status < 400:
			passed++
		default: // 400, 404, 405 and the like say nothing about authorization
			unclear++
		}
	}
	ev, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "contract-differential", Collector: "contract", File: "OpenAPI contract",
		Observation: fmt.Sprintf("%d secured operation(s) of the OpenAPI contract sent once without credentials; bodies not recorded", len(ops)),
		Data:        map[string]any{"answers": answers, "skipped": skip, "approval_id": ap.ID}})
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range sigs {
		fp := fingerprint(s.RuleID+"|"+s.File+"|"+s.Key, 1)
		seen[fp] = true
		if _, _, err := e.upsertFinding(a.ID, fp, s, ev); err != nil {
			return err
		}
	}
	res.Findings += len(sigs)
	complete := g.Halted() == "" && unclear == 0
	if complete {
		listed := map[string]bool{}
		for _, op := range ops {
			u := *base
			u.Path, u.RawPath = op.Path, ""
			listed[redact.Line(op.Method+" "+u.Redacted())] = true
		}
		fs, _ := e.St.Findings(e.ProjectID)
		for _, f := range fs {
			if f.Collector == "contract" && f.Status.Active() && !seen[f.Fingerprint] && listed[f.File] {
				old := f.Status
				f.Status = model.FindingRemediated
				f.AssessmentID = a.ID
				_ = e.St.UpsertFinding(e.ProjectID, f)
				_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "refused without credentials on re-test")
			}
		}
	}
	switch {
	case fail > 0:
		return set(model.StatusFail, fmt.Sprintf("%d secured operation(s) answered 2xx without credentials%s", fail, plus(suspect, " suspected")))
	case suspect > 0:
		return set(model.StatusSuspected, fmt.Sprintf("%d secured operation(s) answered 2xx without credentials with a media type the contract does not declare; review them", suspect))
	case unclear > 0 || g.Halted() != "":
		reason := fmt.Sprintf("%d of %d operation(s) could not be judged (error, 429, 5xx or a status such as 400 or 404 that says nothing about authorization)", unclear, len(ops))
		if h := g.Halted(); h != "" {
			reason += "; " + h
		}
		return set(model.StatusInconclusive, reason)
	}
	return set(model.StatusPass, fmt.Sprintf("%d secured operation(s) refused without credentials as the contract declares%s; PASS applies to these operations only", passed, skipped))
}

func skipText(skip contractSkip) string {
	if len(skip) == 0 {
		return ""
	}
	var parts []string
	for why, n := range skip {
		parts = append(parts, fmt.Sprintf("%d %s", n, why))
	}
	sort.Strings(parts)
	return " (not sent: " + strings.Join(parts, ", ") + ")"
}

func contractSignal(op contractOp, target string, ans contractAnswer) model.Signal {
	conf, how := model.Confirmed, "with a media type the contract declares"
	if !typeDeclared(ans.Type, op.Types) {
		conf, how = model.StronglySupported, "but as "+orNone(ans.Type)+", which the contract does not declare; it may be a fallback page rather than the API"
	}
	return model.Signal{RuleID: "contract.unauthenticated-access", ControlID: "G-002", Title: "Secured API operation answers without credentials", Severity: model.SevHigh, Confidence: conf, CWE: "CWE-306",
		File:      target,
		Message:   redact.Line(fmt.Sprintf("%s declares security for %s %s, but it answered %d without credentials %s.", op.Doc, op.Method, op.Path, ans.Status, how)),
		Fix:       "Enforce authentication on the server for this operation, or mark it public in the contract (security: []) if that is intended.",
		Collector: "contract", Key: op.Method + " " + op.Path,
		Retest: "Deploy the fix to the approved target, then run `pandaward test --profile staging-active` again (needs a valid approval)."}
}

// typeDeclared reports whether a response Content-Type matches a declared
// media type. Without declared types any non-HTML answer counts, since an
// HTML page is what a framework fallback usually serves.
func typeDeclared(ct string, declared []string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(ct))
	}
	if len(declared) == 0 {
		return mt != "" && mt != "text/html"
	}
	for _, d := range declared {
		d = strings.ToLower(d)
		if d == mt || d == "*/*" || strings.HasSuffix(d, "/*") && strings.HasPrefix(mt, strings.TrimSuffix(d, "*")) {
			return true
		}
	}
	return false
}

func orNone(s string) string {
	if s == "" {
		return "no content type"
	}
	return s
}
