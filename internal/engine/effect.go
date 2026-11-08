package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// probeValue sends the probe and reads the number at its JSON path. The
// body is parsed in memory and only the number is kept.
func probeValue(ctx context.Context, client *http.Client, m *scope.Manifest, p scope.ProbeStep, creds map[string]authzCred) (float64, string) {
	u, err := m.StepURL(p.Target, p.Path)
	if err != nil {
		return 0, err.Error()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, redact.Line(err.Error())
	}
	req.Header.Set("User-Agent", "pandaward-effect/1 (authorized effect test)")
	req.Header.Set("Accept", "application/json")
	if cr, ok := creds[p.As]; ok {
		req.Header.Set(cr.header, cr.value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, redact.Line(scrubAll(err.Error(), creds, nil))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, fmt.Sprintf("the probe got status %d", resp.StatusCode)
	}
	var doc any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return 0, "the probe answer is not JSON"
	}
	for _, part := range strings.Split(p.JSON, ".") {
		switch v := doc.(type) {
		case map[string]any:
			doc = v[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return 0, "the probe answer has no " + p.JSON
			}
			doc = v[i]
		default:
			return 0, "the probe answer has no " + p.JSON
		}
	}
	switch v := doc.(type) {
	case float64:
		return v, ""
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, ""
		}
	}
	return 0, "the probe value at " + p.JSON + " is not a number"
}

// effectRun is what an effect check records in evidence: statuses and the
// two probe numbers, no headers and no bodies.
type effectRun struct {
	Before   float64      `json:"probe_before"`
	After    float64      `json:"probe_after"`
	Expected float64      `json:"expect_delta"`
	Actions  []stepAnswer `json:"actions"`
	Problem  string       `json:"problem,omitempty"`
}

// runEffects sends each effect check's action repeat times, in sequence
// for F-002 and at once for Q-002, and compares the probe value before and
// after with the change one action makes.
func (e *Engine) runEffects(ctx context.Context, a *store.Assessment, m *scope.Manifest, ap *store.Approval, rr runtimeRun, g *scope.Guard, creds map[string]authzCred, inputs map[string]string, res *StagingResult, progress func(string)) error {
	client := g.Client()
	type outcome struct{ fail, unclear, passed int }
	out := map[string]*outcome{}
	var sigs []model.Signal
	var evIDs []string
	judged := map[string]bool{} // effect check names with a verdict
	for _, c := range m.EffectChecks {
		o := out[c.Control]
		if o == nil {
			o = &outcome{}
			out[c.Control] = o
		}
		how := "in sequence"
		if c.Control == "Q-002" {
			how = "at once"
		}
		progress(fmt.Sprintf("effect check %s: action sent %d times %s", c.Name, c.Repeat, how))
		run := effectRun{Expected: c.ExpectDelta}
		var target string
		var problem string
		run.Before, problem = probeValue(ctx, client, m, c.Probe, creds)
		if problem == "" {
			run.Actions = make([]stepAnswer, c.Repeat)
			if c.Control == "Q-002" {
				var wg sync.WaitGroup
				bctx := scope.WithBurst(ctx, a.ID+"|"+c.Name)
				for i := 0; i < c.Repeat; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						ans, t := sendStep(bctx, client, m, c.Action, creds, inputs, "pandaward-effect/1 (authorized effect test)")
						ans.Step = i + 1
						run.Actions[i] = ans
						if i == 0 {
							target = t
						}
					}(i)
				}
				wg.Wait()
			} else {
				for i := 0; i < c.Repeat; i++ {
					ans, t := sendStep(ctx, client, m, c.Action, creds, inputs, "pandaward-effect/1 (authorized effect test)")
					ans.Step = i + 1
					run.Actions[i] = ans
					target = t
				}
			}
			for _, ans := range run.Actions {
				if ans.Error != "" || ans.Status == http.StatusTooManyRequests || ans.Status >= 500 {
					problem = fmt.Sprintf("action %d got %s", ans.Step, answerText(ans))
					break
				}
			}
			if problem == "" {
				run.After, problem = probeValue(ctx, client, m, c.Probe, creds)
			}
		}
		delta := run.After - run.Before
		var found *model.Signal
		if problem == "" {
			switch {
			case sameSign(delta, c.ExpectDelta) && math.Abs(delta) > math.Abs(c.ExpectDelta)+1e-9:
				s := effectSignal(c, target, run, delta)
				found = &s
			case math.Abs(delta-c.ExpectDelta) <= 1e-9:
			default:
				problem = fmt.Sprintf("the probe changed by %s, not by the %s one action makes; check the action and the fixture", num(delta), num(c.ExpectDelta))
			}
		}
		run.Problem = problem
		ev, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "effect-probe", Collector: "effect", File: "effect " + redact.Line(c.Name),
			Observation: fmt.Sprintf("effect check %q: action sent %d times %s, probe read before and after; credentials, headers and bodies not recorded", c.Name, c.Repeat, how),
			Data:        map[string]any{"check": c.Name, "control": c.Control, "run": run, "approval_id": ap.ID}})
		if err != nil {
			return err
		}
		switch {
		case found != nil:
			o.fail++
			sigs, evIDs = append(sigs, *found), append(evIDs, ev)
			judged[c.Name] = true
		case problem != "":
			o.unclear++
			res.Notes = append(res.Notes, fmt.Sprintf("effect check %q: %s", c.Name, problem))
		default:
			o.passed++
			judged[c.Name] = true
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
			name := strings.TrimPrefix(f.File, "effect ")
			if f.Collector == "effect" && f.Status.Active() && !seen[f.Fingerprint] && judged[name] {
				old := f.Status
				f.Status = model.FindingRemediated
				f.AssessmentID = a.ID
				_ = e.St.UpsertFinding(e.ProjectID, f)
				_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "the action took effect once on re-test")
			}
		}
	}
	for cid, o := range out {
		st, reason := model.StatusPass, fmt.Sprintf("%d effect check(s) took effect exactly once; PASS applies to the listed actions only", o.passed)
		switch {
		case o.fail > 0:
			st, reason = model.StatusFail, fmt.Sprintf("%d action(s) took effect more than once%s", o.fail, plus(o.unclear, " could not be judged"))
		case o.unclear > 0 || !complete:
			st, reason = model.StatusInconclusive, fmt.Sprintf("%d effect check(s) could not be judged (probe or action failed, or the change did not match one action)", o.unclear)
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

func sameSign(a, b float64) bool { return a > 0 && b > 0 || a < 0 && b < 0 }

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func effectSignal(c scope.EffectCheck, target string, run effectRun, delta float64) model.Signal {
	rule, title, cwe, fix := "effect.duplicate-processing", "Repeated request is processed more than once", "CWE-837",
		"Make the handler idempotent: record the event or idempotency key in the same transaction as the effect and ignore a repeat."
	how := "in sequence"
	if c.Control == "Q-002" {
		rule, title, cwe, fix = "effect.race-condition", "Concurrent requests apply an effect more than once", "CWE-362",
			"Serialize the check and the write: a unique constraint, a row lock or an atomic conditional update, not a read followed by a write."
		how = "at once"
	}
	return model.Signal{RuleID: rule, ControlID: c.Control, Title: title, Severity: model.SevHigh, Confidence: model.Confirmed, CWE: cwe,
		File: "effect " + redact.Line(c.Name),
		Message: redact.Line(fmt.Sprintf("Effect check %q sent %s %d times %s; %s changed by %s, but one action changes it by %s.",
			c.Name, target, c.Repeat, how, c.Probe.JSON, num(delta), num(c.ExpectDelta))),
		Fix:       fix,
		Collector: "effect", Key: c.Name,
		Retest: "Deploy the fix to the approved target, then run `pandaward test --profile staging-active` again (needs a valid approval and the input variables)."}
}
