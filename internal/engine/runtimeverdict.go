package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// A runtime verdict (staging-active, production-observe, local-runtime) is
// written into the latest assessment and into the runtime_verdicts ledger.
// Later passive scans cannot observe these controls, so they carry the
// verdict over, but only while everything it ran under is unchanged: the
// catalog, the PandaWard config, the exact scope manifest and its approval
// (not expired, not revoked), and every file in the control's domain. As
// soon as any of these changed, or cannot be checked, the control is STALE
// with a reason naming what changed. A STALE verdict never becomes PASS
// again until a new runtime run decides it.

// runtimeRun is what one runtime test run records with each verdict.
type runtimeRun struct {
	profile      string
	approvalID   string
	manifestHash string
	// inv is the inventory taken at the start of the run; nil when the walk
	// failed, in which case no dependency is recorded and the verdict is
	// never carried over.
	inv *inventory.Inventory
}

func (e *Engine) newRuntimeRun(profile string, m *scope.Manifest, ap *store.Approval) runtimeRun {
	rr := runtimeRun{profile: profile}
	if m != nil {
		rr.manifestHash = m.Hash()
	}
	if ap != nil {
		rr.approvalID = ap.ID
	}
	if inv, err := e.Inventory(); err == nil {
		rr.inv = inv
	}
	return rr
}

// carriedStatus reports whether a runtime status is a verdict worth keeping.
// BLOCKED, ERROR and INCONCLUSIVE describe the run, not the target.
func carriedStatus(st model.Status) bool {
	return st == model.StatusPass || st == model.StatusFail || st == model.StatusSuspected
}

// runtimeDeps returns path -> SHA-256 of the files a runtime verdict for c
// depends on. Which source line a deployed behavior comes from cannot be
// known, so this is deliberately broad: every source file (routes,
// handlers, middleware, app code), every file linked to the control's
// domain and every file behind the inventory feature the control requires
// (route files, AndroidManifest.xml, Info.plist, built packages).
func runtimeDeps(inv *inventory.Inventory, c *catalog.Control) map[string]string {
	feature := map[string]bool{}
	for _, v := range inv.Features[c.Requires] {
		feature[v] = true
		if i := strings.LastIndex(v, "@"); i >= 0 {
			loc := v[i+1:]
			feature[loc] = true
			if j := strings.LastIndex(loc, ":"); j >= 0 {
				feature[loc[:j]] = true
			}
		}
	}
	out := map[string]string{}
	for _, f := range inv.Files {
		dep := inventory.CodeLangs[f.Lang] || feature[f.Path]
		for _, d := range f.Domains {
			dep = dep || d == c.Domain
		}
		if dep {
			out[f.Path] = f.SHA256
		}
	}
	return out
}

// setRuntime writes a runtime result into the assessment and replaces the
// control's runtime verdict. A result that is not a verdict clears the old
// one, so a newer run always wins.
func (e *Engine) setRuntime(a *store.Assessment, rr runtimeRun, cid string, st model.Status, reason string) error {
	if err := e.St.SetControlResult(e.ProjectID, a.ID, cid, st, reason, model.DecidedRuntime); err != nil {
		return err
	}
	if !carriedStatus(st) {
		return e.St.DeleteRuntimeVerdict(e.ProjectID, cid)
	}
	v := store.RuntimeVerdict{ControlID: cid, Profile: rr.profile, Status: st, Reason: reason, AssessmentID: a.ID, DecidedAt: store.Now(),
		ApprovalID: rr.approvalID, ManifestHash: rr.manifestHash, ConfigHash: e.ConfigHash, CatalogVersion: catalog.Version}
	if c := catalog.ControlByID(cid); c != nil && rr.inv != nil {
		v.Deps = runtimeDeps(rr.inv, c)
	}
	return e.St.PutRuntimeVerdict(e.ProjectID, v)
}

// runtimeInvalid returns why a runtime verdict can no longer be trusted, or
// "" when it still holds. inv is the current inventory; nil skips the file
// check (the caller covers file changes another way).
func (e *Engine) runtimeInvalid(v store.RuntimeVerdict, inv *inventory.Inventory, now time.Time) string {
	if v.CatalogVersion != catalog.Version {
		return "the control catalog changed since the runtime run (" + v.CatalogVersion + " -> " + catalog.Version + ")"
	}
	if v.ConfigHash != e.ConfigHash {
		return "the PandaWard config changed since the runtime run"
	}
	if v.Profile != "local-runtime" {
		if why := e.approvalInvalid(v, now); why != "" {
			return why
		}
	}
	if inv == nil {
		return ""
	}
	if v.Deps == nil {
		return "the files it depends on were not recorded, so changes cannot be ruled out"
	}
	c := catalog.ControlByID(v.ControlID)
	if c == nil {
		return "the control is no longer in the catalog"
	}
	cur := runtimeDeps(inv, c)
	var changed []string
	for p, h := range v.Deps {
		switch sum, ok := cur[p]; {
		case !ok:
			changed = append(changed, p+" (deleted)")
		case sum == "" || sum != h:
			changed = append(changed, p)
		}
	}
	for p := range cur {
		if _, ok := v.Deps[p]; !ok {
			changed = append(changed, p+" (new)")
		}
	}
	return changedFiles(changed)
}

// changedFiles names changed dependencies in a reason, or "" for none.
func changedFiles(changed []string) string {
	if len(changed) == 0 {
		return ""
	}
	sort.Strings(changed)
	n := len(changed)
	if len(changed) > 3 {
		changed = append(changed[:3], "...")
	}
	return fmt.Sprintf("%d file(s) it depends on changed since the runtime run (%s)", n, strings.Join(changed, ", "))
}

// approvalInvalid checks the scope manifest and the approval a network
// verdict ran under.
func (e *Engine) approvalInvalid(v store.RuntimeVerdict, now time.Time) string {
	if v.ApprovalID == "" || v.ManifestHash == "" {
		return "the scope approval it ran under was not recorded"
	}
	m, err := scope.Load(e.Root)
	if err != nil {
		return "the scope manifest it ran under can no longer be read"
	}
	if m.Hash() != v.ManifestHash {
		return "the scope manifest changed since the runtime run"
	}
	if probs := m.Validate(now); len(probs) > 0 {
		return "the scope manifest is no longer valid: " + probs[0]
	}
	ap, revoked, err := e.St.ApprovalByID(e.ProjectID, v.ApprovalID)
	switch {
	case err != nil || ap == nil:
		return "the scope approval " + v.ApprovalID + " it ran under is gone"
	case revoked:
		return "the scope approval " + v.ApprovalID + " it ran under was revoked"
	}
	exp, err := time.Parse(time.RFC3339, ap.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return "the scope approval " + v.ApprovalID + " it ran under expired at " + ap.ExpiresAt
	}
	subject, err := e.ApprovalSubject(m, false)
	if errors.Is(err, os.ErrNotExist) || (err == nil && subject != ap.SubjectHash) {
		return "the scope approval " + v.ApprovalID + " does not match this manifest on this machine"
	}
	if err != nil {
		return "the scope approval " + v.ApprovalID + " cannot be checked: " + err.Error()
	}
	return ""
}

func runtimeOrigin(v store.RuntimeVerdict) string {
	return "runtime " + v.Profile + " at " + v.DecidedAt
}

// carryRuntime applies the latest runtime verdicts to the results of a new
// passive assessment: valid ones keep their status, marked as runtime;
// the others become STALE. It returns the controls carried as valid.
func (e *Engine) carryRuntime(results map[string]*model.ControlResult, inv *inventory.Inventory, now time.Time) (map[string]bool, error) {
	vs, err := e.St.RuntimeVerdicts(e.ProjectID)
	if err != nil {
		return nil, err
	}
	valid := map[string]bool{}
	for cid, v := range vs {
		r := results[cid]
		if r == nil || r.Method != catalog.MethodRuntime || r.Status == model.StatusNotApplicable {
			continue
		}
		r.DecidedBy = model.DecidedRuntime
		if why := e.runtimeInvalid(v, inv, now); why != "" {
			r.Status = model.StatusStale
			r.Reason = "was " + string(v.Status) + " (" + runtimeOrigin(v) + "): " + why + "; run `pandaward test --profile " + v.Profile + "` again"
			continue
		}
		r.Status = v.Status
		r.Reason = runtimeOrigin(v) + ", carried over while its scope approval and inputs are unchanged: " + v.Reason
		valid[cid] = true
	}
	return valid, nil
}

// runtimeStaleView marks runtime-decided controls STALE when their approval,
// manifest, config or catalog no longer hold, or when one of the changed
// files (from Changes) is a dependency whose content differs from the
// runtime run. It only reads.
func (e *Engine) runtimeStaleView(cs []model.ControlResult, es []model.Edge, changed []string, now time.Time) ([]model.ControlResult, []model.Edge, error) {
	vs, err := e.St.RuntimeVerdicts(e.ProjectID)
	if err != nil || len(vs) == 0 {
		return cs, es, err
	}
	why := map[string]string{}
	for _, c := range cs {
		v, ok := vs[c.ID]
		if !ok || c.DecidedBy != model.DecidedRuntime || c.Status != v.Status {
			continue
		}
		if w := e.runtimeInvalid(v, nil, now); w != "" {
			why[c.ID] = w
		} else if w := e.depsChanged(v, changed); w != "" {
			why[c.ID] = w
		}
	}
	if len(why) == 0 {
		return cs, es, nil
	}
	outC := make([]model.ControlResult, len(cs))
	for i, c := range cs {
		outC[i] = c
		if w, ok := why[c.ID]; ok {
			outC[i].Status = model.StatusStale
			outC[i].Reason = "was " + string(c.Status) + ": " + w + "; run `pandaward test --profile " + vs[c.ID].Profile + "` again"
		}
	}
	outE := make([]model.Edge, len(es))
	for i, ed := range es {
		outE[i] = ed
		var hit []string
		for _, t := range ed.Tests {
			if _, ok := why[t]; ok {
				hit = append(hit, t)
			}
		}
		if len(hit) > 0 && ed.Status != model.StatusStale {
			sort.Strings(hit)
			outE[i].Reason = "was " + string(ed.Status) + "; stale linked controls: " + strings.Join(hit, ", ")
			outE[i].Status = model.StatusStale
		}
	}
	return outC, outE, nil
}

// depsChanged checks the files changed since the assessment against the
// dependencies of a runtime verdict, hashing only those files.
func (e *Engine) depsChanged(v store.RuntimeVerdict, changed []string) string {
	if len(changed) == 0 {
		return ""
	}
	if v.Deps == nil {
		return "the files it depends on were not recorded, so changes cannot be ruled out"
	}
	c := catalog.ControlByID(v.ControlID)
	var out []string
	for _, f := range changed {
		p := strings.TrimSuffix(f, " (deleted)")
		old, known := v.Deps[p]
		b, err := os.ReadFile(filepath.Join(e.Root, filepath.FromSlash(p)))
		switch {
		case err != nil && known:
			out = append(out, p+" (deleted)")
		case err != nil:
		case known:
			if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != old {
				out = append(out, p)
			}
		case inventory.CodeLangs[inventory.LangOf(path.Base(p))] || (c != nil && containsStr(inventory.DomainsForPath(p), c.Domain)):
			out = append(out, p+" (new)")
		}
	}
	return changedFiles(out)
}

// runtimeCollectors are the finding collectors of the runtime profiles.
var runtimeCollectors = map[string]bool{"authz": true, "zap": true, "observe-headers": true, "local-runtime": true}
