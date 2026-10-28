package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// ApprovalKind binds approvals for network-active tests to the scope hash.
const ApprovalKind = "scope-network"

// ObserveResult summarizes a production-observe run.
type ObserveResult struct {
	AssessmentID string   `json:"assessment_id"`
	Requests     int      `json:"requests_sent"`
	Budget       int      `json:"request_budget"`
	Targets      []string `json:"targets"`
	Findings     int      `json:"findings"`
	Status       string   `json:"control_status"`
	Errors       []string `json:"errors,omitempty"`
}

// CheckScope validates the manifest and its approval. It is called before
// any network activity and fails closed.
func (e *Engine) CheckScope(now time.Time) (*scope.Manifest, *store.Approval, error) {
	m, err := scope.Load(e.Root)
	if err != nil {
		return nil, nil, err
	}
	if probs := m.Validate(now); len(probs) > 0 {
		return m, nil, fmt.Errorf("scope manifest is not valid for network tests:\n  - %s", strings.Join(probs, "\n  - "))
	}
	subject, err := e.ApprovalSubject(m, false)
	if errors.Is(err, os.ErrNotExist) {
		subject, err = "", nil // no key on this machine: nothing was approved here
	}
	if err != nil {
		return m, nil, err
	}
	var ap *store.Approval
	if subject != "" {
		if ap, err = e.St.ValidApproval(e.ProjectID, ApprovalKind, subject, now); err != nil {
			return m, nil, err
		}
	}
	if ap == nil {
		return m, nil, errors.New("no valid approval for this exact scope manifest; a human must run `pandaward scope approve --by \"<name>\"` in an interactive terminal (editing scope.yaml invalidates earlier approvals)")
	}
	return m, ap, nil
}

// Observe runs the production-observe profile: one GET per approved target
// origin, no redirects followed, no payloads, and a hard request budget.
func (e *Engine) Observe(ctx context.Context, progress func(string)) (*ObserveResult, error) {
	m, ap, err := e.CheckScope(time.Now())
	if err != nil {
		return nil, err
	}
	if !m.MethodAllowed("GET") {
		return nil, errors.New("scope allowed_methods does not include GET")
	}
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("run `pandaward scan` first; runtime observations attach to the latest assessment")
	}
	// The guard enforces scope, methods, the budget, the rate limit and
	// address checks, and never follows redirects.
	g := scope.NewGuard(m, guardRoots)
	client := g.Client()
	res := &ObserveResult{AssessmentID: a.ID, Budget: m.Limits.MaxRequestsTotal}
	_ = e.St.Event(e.ProjectID, a.ID, "", "NETWORK_TEST_STARTED", fmt.Sprintf("production-observe under approval %s by %s", ap.ID, ap.ApprovedBy))

	var sigs []model.Signal
	var evIDs []string
	decided := 0
	for _, t := range m.Targets {
		if ctx.Err() != nil {
			res.Errors = append(res.Errors, "cancelled")
			break
		}
		u, err := scope.ParseTarget(t.URL)
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		if err := m.InScope(u); err != nil {
			res.Errors = append(res.Errors, "scope guard: "+err.Error())
			continue
		}
		progress("GET " + u.Redacted())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		req.Header.Set("User-Agent", "pandaward-observe/1 (authorized passive header review)")
		resp, err := client.Do(req)
		res.Requests = g.Sent()
		if err != nil {
			res.Errors = append(res.Errors, redact.Line(err.Error()))
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		res.Targets = append(res.Targets, u.Redacted())
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if lu, err := url.Parse(loc); err == nil {
				lu = u.ResolveReference(lu)
				if m.InScope(lu) != nil {
					res.Errors = append(res.Errors, "redirect to out-of-scope location not followed: "+lu.Redacted())
				}
			}
		}
		hdrs := map[string]string{}
		var names []string
		for k := range resp.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			v := strings.Join(resp.Header.Values(k), " | ")
			if strings.EqualFold(k, "Set-Cookie") {
				v = cookieAttrsOnly(resp.Header.Values(k))
			}
			hdrs[k] = redact.Line(v)
		}
		evID, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "http-response-headers", Collector: "observe-headers", File: u.Redacted(),
			Observation: fmt.Sprintf("GET %s -> %d (redirects not followed)", u.Redacted(), resp.StatusCode), Data: map[string]any{"status": resp.StatusCode, "headers": hdrs, "approval_id": ap.ID}})
		if err != nil {
			return nil, err
		}
		for _, s := range headerSignals(u, resp) {
			sigs = append(sigs, s)
			evIDs = append(evIDs, evID)
		}
		decided++
	}
	_ = e.St.Event(e.ProjectID, a.ID, "NETWORK_TEST_STARTED", "NETWORK_TEST_FINISHED", fmt.Sprintf("%d requests of budget %d", res.Requests, res.Budget))

	seen := map[string]bool{}
	for i, s := range sigs {
		fp := fingerprint(s.RuleID+"|"+s.File+"|"+s.Key, 1)
		seen[fp] = true
		if _, _, err := e.upsertFinding(a.ID, fp, s, evIDs[i]); err != nil {
			return nil, err
		}
	}
	res.Findings = len(sigs)
	status, reason := model.StatusInconclusive, "no target answered: "+strings.Join(res.Errors, "; ")
	if decided > 0 {
		status, reason = decide(sigs, "H-003", fmt.Sprintf("%d target(s) observed", decided))
		if len(res.Errors) > 0 {
			status, reason = model.StatusInconclusive, reason+"; errors: "+strings.Join(res.Errors, "; ")
		}
		fs, _ := e.St.Findings(e.ProjectID)
		for _, f := range fs {
			if f.Collector == "observe-headers" && f.Status.Active() && !seen[f.Fingerprint] && containsStr(res.Targets, f.File) {
				old := f.Status
				f.Status = model.FindingRemediated
				f.AssessmentID = a.ID
				_ = e.St.UpsertFinding(e.ProjectID, f)
				_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "header present on re-observation")
			}
		}
	}
	res.Status = string(status)
	if err := e.St.SetControlStatus(e.ProjectID, a.ID, "H-003", status, reason); err != nil {
		return nil, err
	}
	if inv, err := e.Inventory(); err == nil {
		if cs, err := e.St.Controls(a.ID); err == nil {
			_ = e.St.PutEdges(a.ID, BuildEdges(inv, cs))
		}
	}
	return res, nil
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// cookieAttrsOnly keeps cookie names and attributes, never values.
func cookieAttrsOnly(vals []string) string {
	var out []string
	for _, v := range vals {
		parts := strings.Split(v, ";")
		name := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)[0]
		attrs := []string{name + "=[REDACTED]"}
		for _, p := range parts[1:] {
			k := strings.SplitN(strings.TrimSpace(p), "=", 2)[0]
			attrs = append(attrs, k)
		}
		out = append(out, strings.Join(attrs, "; "))
	}
	return strings.Join(out, " | ")
}

func headerSignals(u *url.URL, resp *http.Response) []model.Signal {
	var out []model.Signal
	h := resp.Header
	add := func(id, title string, sev model.Severity, cwe, msg, fix string) {
		out = append(out, model.Signal{RuleID: "observe." + id, ControlID: "H-003", Title: title, Severity: sev, Confidence: model.Confirmed, CWE: cwe, File: u.Redacted(),
			Message: msg, Fix: fix, Collector: "observe-headers", Key: id, Retest: "Deploy the change, then run `pandaward test --profile production-observe` again (needs a valid approval)."})
	}
	if u.Scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		add("missing-hsts", "Missing Strict-Transport-Security", model.SevMedium, "CWE-319", "HTTPS response without HSTS; first visits can be downgraded.", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.")
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		add("missing-csp", "Missing Content-Security-Policy", model.SevMedium, "CWE-693", "No CSP limits script sources, so any XSS has full effect.", "Define a CSP (start with default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none').")
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		add("missing-nosniff", "Missing X-Content-Type-Options: nosniff", model.SevLow, "CWE-693", "Browsers may MIME-sniff responses.", "Send X-Content-Type-Options: nosniff.")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		add("missing-frame-protection", "No clickjacking protection", model.SevLow, "CWE-1021", "Neither X-Frame-Options nor CSP frame-ancestors is set.", "Send CSP frame-ancestors 'none' (or 'self').")
	}
	if h.Get("Referrer-Policy") == "" {
		add("missing-referrer-policy", "Missing Referrer-Policy", model.SevLow, "CWE-200", "Full URLs may leak to third parties via Referer.", "Send Referrer-Policy: strict-origin-when-cross-origin.")
	}
	for _, k := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if v := h.Get(k); v != "" && strings.IndexAny(v, "0123456789") >= 0 {
			add("version-disclosure-"+strings.ToLower(k), "Software version disclosed in "+k, model.SevLow, "CWE-200", k+" header reveals a version ("+redact.Line(v)+").", "Remove or genericize the header.")
		}
	}
	for _, c := range h.Values("Set-Cookie") {
		l := strings.ToLower(c)
		name := strings.SplitN(strings.TrimSpace(strings.SplitN(c, ";", 2)[0]), "=", 2)[0]
		if (u.Scheme == "https" && !strings.Contains(l, "; secure")) || !strings.Contains(l, "httponly") {
			out = append(out, model.Signal{RuleID: "observe.cookie-flags", ControlID: "H-003", Title: "Cookie without Secure/HttpOnly", Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-1004",
				File: u.Redacted(), Message: "Cookie " + redact.Line(name) + " lacks Secure and/or HttpOnly (value not recorded).", Fix: "Set Secure, HttpOnly and SameSite on session cookies.", Collector: "observe-headers", Key: "cookie:" + name})
		}
	}
	return out
}
