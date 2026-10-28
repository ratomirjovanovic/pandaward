package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/internal/scope"
	"github.com/ratomirjovanovic/pensec/internal/store"
)

// authzControls maps check kinds to the controls they decide. Revoked
// identities decide B-004 on every check.
var authzControls = map[string]string{"object": "C-001", "function": "C-002"}

// authzAnswer is one request of a check, as recorded in evidence: no
// headers and no body, only what is needed to compare the answers.
type authzAnswer struct {
	Identity string `json:"identity"`
	Tenant   string `json:"tenant,omitempty"`
	Role     string `json:"role"` // allowed, denied or revoked
	Status   int    `json:"status,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	BodyHash string `json:"body_sha256,omitempty"`
	Type     string `json:"content_type,omitempty"`
	Redirect string `json:"redirect,omitempty"`
	Error    string `json:"error,omitempty"`
}

type authzCred struct {
	id     scope.Identity
	header string
	value  string
}

// credentials reads every identity's credential from the environment
// before any request is sent; a missing one stops the whole run.
func credentials(m *scope.Manifest) (map[string]authzCred, error) {
	out := map[string]authzCred{}
	for _, id := range m.Identities {
		v := os.Getenv(id.ValueEnv)
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("identity %s: environment variable %s is empty; set it to the full %s header value before the test", id.Name, id.ValueEnv, id.Header)
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("identity %s: %s contains a line break", id.Name, id.ValueEnv)
		}
		out[id.Name] = authzCred{id: id, header: id.Header, value: v}
	}
	return out, nil
}

// runAuthz sends every authorization check as each identity and without
// credentials and decides C-001, C-002 and B-004 from the differences.
func (e *Engine) runAuthz(ctx context.Context, a *store.Assessment, m *scope.Manifest, ap *store.Approval, g *scope.Guard, creds map[string]authzCred, res *StagingResult, progress func(string)) error {
	client := g.Client()
	type outcome struct{ fail, suspect, unclear, passed int }
	out := map[string]*outcome{}
	note := func(cid string) *outcome {
		if out[cid] == nil {
			out[cid] = &outcome{}
		}
		return out[cid]
	}
	var sigs []model.Signal
	var evIDs []string
	for _, c := range m.AuthorizationChecks {
		cid := authzControls[c.Kind]
		u, err := m.CheckURL(c)
		if err != nil {
			return err
		}
		target := redact.Line(c.Method + " " + u.Redacted())
		progress("authorization check " + c.Name + ": " + target)
		allowed := map[string]bool{}
		for _, n := range c.Allowed {
			allowed[n] = true
		}
		send := func(name string) authzAnswer {
			ans := authzAnswer{Identity: name, Role: "denied"}
			req, err := http.NewRequestWithContext(ctx, c.Method, u.String(), nil)
			if err != nil {
				ans.Error = err.Error()
				return ans
			}
			req.Header.Set("User-Agent", "pensec-authz/1 (authorized authorization test)")
			if cr, ok := creds[name]; ok {
				req.Header.Set(cr.header, cr.value)
				ans.Tenant = cr.id.Tenant
				if cr.id.Revoked {
					ans.Role = "revoked"
				}
			}
			if allowed[name] {
				ans.Role = "allowed"
			}
			resp, err := client.Do(req)
			if err != nil {
				ans.Error = redact.Line(err.Error())
				return ans
			}
			defer resp.Body.Close()
			h := sha256.New()
			n, _ := io.Copy(h, resp.Body)
			ans.Status, ans.Bytes, ans.Type = resp.StatusCode, int(n), redact.Line(resp.Header.Get("Content-Type"))
			ans.BodyHash = hex.EncodeToString(h.Sum(nil))[:16]
			if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				ans.Redirect = "not followed"
				if lu, err := u.Parse(loc); err == nil && m.InScope(lu) != nil {
					ans.Redirect = "to an out-of-scope location, not followed"
				}
			}
			return ans
		}
		var answers []authzAnswer
		baseline := map[string]bool{} // body hashes of allowed identities
		baselineOK := true
		for _, n := range append(identityNames(m), scope.Anonymous) {
			if !allowed[n] {
				continue
			}
			ans := send(n)
			answers = append(answers, ans)
			if ans.Status >= 200 && ans.Status < 300 {
				baseline[ans.BodyHash] = true
			} else {
				baselineOK = false
			}
		}
		for _, n := range append(identityNames(m), scope.Anonymous) {
			if !allowed[n] {
				answers = append(answers, send(n))
			}
		}
		ev, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "authz-differential", Collector: "authz", File: target,
			Observation: fmt.Sprintf("authorization check %q sent as %d identities and anonymously; credentials and bodies not recorded", c.Name, len(m.Identities)),
			Data:        map[string]any{"check": c.Name, "kind": c.Kind, "allowed": c.Allowed, "answers": answers, "approval_id": ap.ID}})
		if err != nil {
			return err
		}
		if !baselineOK {
			note(cid).unclear++
			for _, ans := range answers {
				if ans.Role == "revoked" {
					note("B-004").unclear++
				}
			}
			res.Notes = append(res.Notes, fmt.Sprintf("check %q: an allowed identity did not get a 2xx answer, so the denials cannot be judged; fix the check or the fixture", c.Name))
			continue
		}
		for _, ans := range answers {
			if ans.Role == "allowed" {
				continue
			}
			ctl := cid
			if ans.Role == "revoked" {
				ctl = "B-004"
			}
			switch {
			case ans.Error != "" || ans.Status == http.StatusTooManyRequests || ans.Status >= 500:
				note(ctl).unclear++
			case ans.Status >= 200 && ans.Status < 300:
				s := authzSignal(c, ctl, target, ans, baseline[ans.BodyHash])
				sigs, evIDs = append(sigs, s), append(evIDs, ev)
				if s.Confidence == model.Confirmed {
					note(ctl).fail++
				} else {
					note(ctl).suspect++
				}
			default: // 401, 403, 404, other 4xx, or a redirect that was not followed
				note(ctl).passed++
			}
		}
	}

	seen := map[string]bool{}
	for i, s := range sigs {
		fp := fingerprint(s.RuleID+"|"+s.File+"|"+s.Key, 1)
		seen[fp] = true
		if _, _, err := e.upsertFinding(a.ID, fp, s, evIDs[i]); err != nil {
			return err
		}
	}
	res.Findings += len(sigs)
	complete := g.Halted() == ""
	if complete {
		fs, _ := e.St.Findings(e.ProjectID)
		for _, f := range fs {
			if f.Collector == "authz" && f.Status.Active() && !seen[f.Fingerprint] && checkStillListed(m, f.File) {
				old := f.Status
				f.Status = model.FindingRemediated
				f.AssessmentID = a.ID
				_ = e.St.UpsertFinding(e.ProjectID, f)
				_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "access denied on re-test")
			}
		}
	}
	for cid, o := range out {
		st, reason := model.StatusPass, fmt.Sprintf("%d denial(s) observed as expected; PASS applies to the listed checks only", o.passed)
		switch {
		case o.fail > 0:
			st, reason = model.StatusFail, fmt.Sprintf("%d confirmed unauthorized access(es)%s", o.fail, plus(o.suspect, " suspected"))
		case o.suspect > 0:
			st, reason = model.StatusSuspected, fmt.Sprintf("%d unexpected 2xx answer(s) with a different body; review them", o.suspect)
		case o.unclear > 0 || !complete:
			st, reason = model.StatusInconclusive, fmt.Sprintf("%d request(s) could not be judged (baseline failed, error, 429 or 5xx)", o.unclear)
			if !complete {
				reason += "; " + g.Halted()
			}
		}
		res.Controls[cid] = string(st)
		if err := e.St.SetControlStatus(e.ProjectID, a.ID, cid, st, reason); err != nil {
			return err
		}
	}
	return nil
}

func identityNames(m *scope.Manifest) []string {
	var out []string
	for _, id := range m.Identities {
		out = append(out, id.Name)
	}
	return out
}

func checkStillListed(m *scope.Manifest, file string) bool {
	for _, c := range m.AuthorizationChecks {
		if u, err := m.CheckURL(c); err == nil && redact.Line(c.Method+" "+u.Redacted()) == file {
			return true
		}
	}
	return false
}

func authzSignal(c scope.AuthCheck, cid, target string, ans authzAnswer, sameBody bool) model.Signal {
	who := ans.Identity
	if ans.Tenant != "" {
		who += " (tenant " + ans.Tenant + ")"
	}
	conf, how := model.StronglySupported, "with a different body than the allowed identities got; check whether it holds the protected data"
	if sameBody {
		conf, how = model.Confirmed, "with the same body the allowed identities got"
	}
	rule, title, cwe, fix := "authz.object-access", "Object readable by another identity (BOLA)", "CWE-639", "Check on the server that the authenticated identity owns or may access this object (tenant and owner), not only that it is logged in."
	switch {
	case cid == "B-004":
		rule, title, cwe, fix = "authz.revoked-credential", "Revoked or logged-out credential still accepted", "CWE-613", "Invalidate sessions and tokens on the server at logout, expiry and revocation, and check that state on every request."
	case c.Kind == "function":
		rule, title, cwe, fix = "authz.function-access", "Privileged function reachable by an identity that is not allowed", "CWE-285", "Enforce the role or permission check on the server for this route, not only in the user interface."
	}
	if ans.Identity == scope.Anonymous {
		title += " without credentials"
	}
	return model.Signal{RuleID: rule, ControlID: cid, Title: title, Severity: model.SevHigh, Confidence: conf, CWE: cwe, File: target,
		Message: redact.Line(fmt.Sprintf("%s got %d for check %q, which only %s may access, %s.", who, ans.Status, c.Name, strings.Join(c.Allowed, ", "), how)),
		Fix:     fix, Collector: "authz", Key: c.Name + "|" + ans.Identity,
		Retest: "Deploy the fix to the approved target, then run `pensec test --profile staging-active` again (needs a valid approval and the identity variables)."}
}
