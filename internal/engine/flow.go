package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// checkInputs reads every request body and header value the checks name,
// before any request is sent: from the provisioning output when it has
// one, otherwise from the environment. A missing one stops the whole run.
func checkInputs(m *scope.Manifest, provided map[string]string) (map[string]string, error) {
	out := map[string]string{}
	envs := m.InputEnvs()
	names := make([]string, 0, len(envs))
	for env := range envs {
		names = append(names, env)
	}
	sort.Strings(names)
	for _, env := range names {
		v, ok := provided[env]
		if !ok {
			v = os.Getenv(env)
		}
		if v == "" {
			return nil, fmt.Errorf("environment variable %s is empty; a check reads its request body or header value from it", env)
		}
		if envs[env] && strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%s holds a header value with a line break", env)
		}
		out[env] = v
	}
	return out, nil
}

// stepAnswer is one request of a flow, as recorded in evidence: no headers
// and no body, only what is needed to judge the step.
type stepAnswer struct {
	Step     int    `json:"step"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Identity string `json:"identity"`
	Expect   string `json:"expect"`
	Status   int    `json:"status,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	BodyHash string `json:"body_sha256,omitempty"`
	Type     string `json:"content_type,omitempty"`
	Error    string `json:"error,omitempty"`
}

// sendStep sends one declared request through the guard, marked as a
// request that may change state.
func sendStep(ctx context.Context, client *http.Client, m *scope.Manifest, s scope.FlowStep, creds map[string]authzCred, inputs map[string]string, ua string) (stepAnswer, string) {
	who := s.As
	if who == "" {
		who = scope.Anonymous
	}
	ans := stepAnswer{Method: s.Method, Identity: who, Expect: s.Expect}
	u, err := m.StepURL(s.Target, s.Path)
	if err != nil {
		ans.Error = err.Error()
		return ans, ""
	}
	ans.Path = redact.Line(u.EscapedPath())
	target := redact.Line(s.Method + " " + u.Redacted())
	var body io.Reader
	if s.BodyEnv != "" {
		body = strings.NewReader(inputs[s.BodyEnv])
	}
	req, err := http.NewRequestWithContext(scope.WithStateChange(ctx), s.Method, u.String(), body)
	if err != nil {
		ans.Error = redact.Line(err.Error())
		return ans, target
	}
	req.Header.Set("User-Agent", ua)
	if s.BodyEnv != "" {
		ct := s.ContentType
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	for h, env := range s.HeaderEnv {
		req.Header.Set(h, inputs[env])
	}
	if cr, ok := creds[who]; ok {
		req.Header.Set(cr.header, cr.value)
	}
	resp, err := client.Do(req)
	if err != nil {
		ans.Error = redact.Line(scrubAll(err.Error(), creds, inputs))
		return ans, target
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, _ := io.Copy(h, resp.Body)
	ans.Status, ans.Bytes, ans.Type = resp.StatusCode, int(n), redact.Line(resp.Header.Get("Content-Type"))
	ans.BodyHash = hex.EncodeToString(h.Sum(nil))[:16]
	return ans, target
}

// scrubAll removes every credential and input value from a message.
func scrubAll(msg string, creds map[string]authzCred, inputs map[string]string) string {
	vals := map[string]string{}
	for k, c := range creds {
		vals["c:"+k] = c.value
	}
	for k, v := range inputs {
		vals["i:"+k] = v
	}
	return scrub(msg, vals)
}

// runFlows sends every flow check in order and decides B-003. A step
// expected to be denied that gets a 2xx is a finding. A step expected to
// succeed that does not means the fixture is wrong, so the rest of that
// flow is not sent and the check cannot be judged.
func (e *Engine) runFlows(ctx context.Context, a *store.Assessment, m *scope.Manifest, ap *store.Approval, rr runtimeRun, g *scope.Guard, creds map[string]authzCred, inputs map[string]string, res *StagingResult, progress func(string)) error {
	client := g.Client()
	type outcome struct{ fail, unclear, passed int }
	out := map[string]*outcome{}
	var sigs []model.Signal
	var evIDs []string
	for _, c := range m.FlowChecks {
		o := out[c.Control]
		if o == nil {
			o = &outcome{}
			out[c.Control] = o
		}
		progress("flow check " + c.Name)
		var answers []stepAnswer
		var found []model.Signal
		unclear := ""
		denied := 0
		for i, s := range c.Steps {
			ans, target := sendStep(ctx, client, m, s, creds, inputs, "pandaward-flow/1 (authorized flow test)")
			ans.Step = i + 1
			answers = append(answers, ans)
			ok2xx := ans.Status >= 200 && ans.Status < 300
			switch {
			case ans.Error != "" || ans.Status == http.StatusTooManyRequests || ans.Status >= 500:
				unclear = fmt.Sprintf("step %d got %s", i+1, answerText(ans))
			case s.Expect == "allowed" && !ok2xx:
				unclear = fmt.Sprintf("step %d was expected to succeed and got %s, so the later steps cannot be judged; fix the step or the fixture", i+1, answerText(ans))
			case s.Expect == "denied" && ok2xx:
				found = append(found, flowSignal(c, i, target, ans))
			case s.Expect == "denied" && ans.Status >= 300 && ans.Status < 400:
				unclear = fmt.Sprintf("step %d got a %d redirect, which does not say whether it was refused; use the API endpoint that answers with a status", i+1, ans.Status)
			case s.Expect == "denied":
				denied++
			}
			if unclear != "" {
				break
			}
		}
		ev, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "flow-steps", Collector: "flow", File: "flow " + redact.Line(c.Name),
			Observation: fmt.Sprintf("flow check %q: %d of %d step(s) sent; credentials, headers and bodies not recorded", c.Name, len(answers), len(c.Steps)),
			Data:        map[string]any{"check": c.Name, "control": c.Control, "steps": answers, "approval_id": ap.ID}})
		if err != nil {
			return err
		}
		for _, s := range found {
			sigs, evIDs = append(sigs, s), append(evIDs, ev)
		}
		switch {
		case len(found) > 0:
			o.fail += len(found)
		case unclear != "":
			o.unclear++
			res.Notes = append(res.Notes, fmt.Sprintf("flow check %q: %s", c.Name, unclear))
		default:
			o.passed += denied
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
		listed := map[string]bool{}
		for _, c := range m.FlowChecks {
			for _, s := range c.Steps {
				if u, err := m.StepURL(s.Target, s.Path); err == nil {
					listed[redact.Line(s.Method+" "+u.Redacted())] = true
				}
			}
		}
		fs, _ := e.St.Findings(e.ProjectID)
		for _, f := range fs {
			if f.Collector == "flow" && f.Status.Active() && !seen[f.Fingerprint] && listed[f.File] && out[f.ControlID] != nil && out[f.ControlID].unclear == 0 {
				old := f.Status
				f.Status = model.FindingRemediated
				f.AssessmentID = a.ID
				_ = e.St.UpsertFinding(e.ProjectID, f)
				_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "negative case refused on re-test")
			}
		}
	}
	for cid, o := range out {
		st, reason := model.StatusPass, fmt.Sprintf("%d negative case(s) refused as expected; PASS applies to the listed flows only", o.passed)
		switch {
		case o.fail > 0:
			st, reason = model.StatusFail, fmt.Sprintf("%d negative case(s) accepted by the server", o.fail)
		case o.unclear > 0 || !complete:
			st, reason = model.StatusInconclusive, fmt.Sprintf("%d flow check(s) could not be judged (a step expected to succeed failed, a redirect, an error, 429 or 5xx)", o.unclear)
			if !complete {
				reason += "; " + g.Halted()
			}
		}
		res.Controls[cid] = string(st)
		if err := e.setRuntime(a, rr, cid, st, reason); err != nil {
			return err
		}
	}
	return nil
}

func answerText(a stepAnswer) string {
	if a.Error != "" {
		return "an error: " + a.Error
	}
	return fmt.Sprintf("status %d", a.Status)
}

func flowSignal(c scope.FlowCheck, i int, target string, ans stepAnswer) model.Signal {
	return model.Signal{RuleID: "flow.negative-case-accepted", ControlID: c.Control, Title: "Authentication flow accepts a case it must refuse", Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-287",
		File:      target,
		Message:   redact.Line(fmt.Sprintf("Flow check %q step %d, sent as %s, was expected to be refused and got %d.", c.Name, i+1, ans.Identity, ans.Status)),
		Fix:       "Reject this request on the server: wrong credentials, a used or expired token, or a skipped step of the flow must not succeed.",
		Collector: "flow", Key: c.Name + "|" + fmt.Sprint(i+1),
		Retest: "Deploy the fix to the approved target, then run `pandaward test --profile staging-active` again (needs a valid approval and the input variables)."}
}
