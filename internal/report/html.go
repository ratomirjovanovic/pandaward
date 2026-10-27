package report

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/model"
)

var funcs = template.FuncMap{
	"pct":   pct,
	"lower": func(s any) string { return strings.ToLower(toString(s)) },
	"join":  strings.Join,
	"ctrl":  ctrlTitle,
	"sum": func(m map[string]int) int {
		n := 0
		for _, v := range m {
			n += v
		}
		return n
	},
	"get": func(m map[string]int, k string) int { return m[k] },
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case model.Status:
		return string(x)
	case model.Severity:
		return string(x)
	case model.Confidence:
		return string(x)
	case model.FindingStatus:
		return string(x)
	}
	return ""
}

// HTML renders a self-contained report (no external resources, no scripts).
func HTML(r *Report) ([]byte, error) {
	t, err := template.New("r").Funcs(funcs).Parse(htmlTpl)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	data := map[string]any{"R": r, "Confirmed": r.Confirmed(), "Suspected": r.Suspected(), "Closed": r.Closed(), "Untested": r.Untested(),
		"Statuses": []string{"PASS", "FAIL", "SUSPECTED", "BLOCKED", "UNSUPPORTED", "INCONCLUSIVE", "ERROR", "NOT_APPLICABLE"}}
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const htmlTpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>PenSec report {{.R.Project}}</title>
<style>
:root{--bg:#fbfbfa;--fg:#1d1d1b;--mut:#6b6b66;--line:#e3e2de;--card:#fff;--crit:#9b1c1c;--high:#c2410c;--med:#a16207;--low:#2f6f8f;--ok:#2f7a4b;--sus:#7c4dbb;--blk:#6b6b66}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--mut:#a3a29c;--line:#2e2d2a;--card:#1e1e1c;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#7dd3fc;--ok:#6ee7a0;--sus:#c4a1ff;--blk:#a3a29c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:40px 0 12px;padding-top:8px;border-top:1px solid var(--line)}h3{font-size:16px;margin:0}
.mut{color:var(--mut)}.att{border-left:3px solid var(--med);padding:10px 14px;background:var(--card);margin:16px 0;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:var(--card)}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--mut)}.wrap{overflow-x:auto}
.b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid currentColor;white-space:nowrap}
.critical,.FAIL{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low,.info{color:var(--low)}.PASS{color:var(--ok)}.SUSPECTED,.HYPOTHESIS{color:var(--sus)}
.BLOCKED,.UNSUPPORTED,.INCONCLUSIVE,.NOT_APPLICABLE,.STALE{color:var(--blk)}.ERROR{color:var(--crit)}
.f{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}.f dl{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;margin:10px 0 0;font-size:14px}.f dt{color:var(--mut)}.f dd{margin:0;overflow-wrap:anywhere}
code{font:12.5px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.warn{color:var(--crit);font-weight:600}
</style></head><body><main>
<p class="mut">PenSec assessment report</p>
<h1>{{.R.Project}}</h1>
<p class="mut">{{.R.Assessment.ID}} · {{.R.Assessment.Status}} · profile {{.R.Assessment.Profile}} · revision {{if .R.Assessment.GitCommit}}<code>{{.R.Assessment.GitCommit}}</code>{{if .R.Assessment.GitDirty}} (uncommitted changes){{end}}{{else}}not a git repository{{end}} · {{.R.Assessment.StartedAt}} to {{.R.Assessment.EndedAt}}</p>
<div class="att">{{.R.Attestation}}</div>

<h2>Summary</h2>
<div class="grid">
<div class="tile"><span class="mut">Confirmed, open</span><b>{{len .Confirmed}}</b></div>
<div class="tile"><span class="mut">Suspected, needs review</span><b>{{len .Suspected}}</b></div>
<div class="tile"><span class="mut">Decisive coverage</span><b>{{pct .R.Coverage.Ratio}}</b><span class="mut">{{.R.Coverage.Decisive}} of {{.R.Coverage.Applicable}} applicable controls</span></div>
<div class="tile"><span class="mut">Not decided</span><b>{{len .Untested}}</b><span class="mut">controls, never read as secure</span></div>
<div class="tile"><span class="mut">Cross-domain edges</span><b>{{.R.Coverage.EdgesTotal}}</b><span class="mut">{{.R.Coverage.EdgesVerified}} verified · {{.R.Coverage.EdgesFailed}} failed · {{.R.Coverage.EdgesOpen}} open</span></div>
</div>
{{if .R.StaleFiles}}<p class="warn">{{len .R.StaleFiles}} file(s) changed after this assessment. Results for them are STALE until re-scan.</p>{{end}}
<p class="mut">{{.R.Coverage.Note}}</p>

<h2>Confirmed observations ({{len .Confirmed}})</h2>
{{range .Confirmed}}{{template "finding" .}}{{else}}<p>None.</p>{{end}}

<h2>Suspected signals ({{len .Suspected}})</h2>
<p class="mut">Heuristic or reviewer-proposed hypotheses. They are not confirmed vulnerabilities until verified.</p>
{{range .Suspected}}{{template "finding" .}}{{else}}<p>None.</p>{{end}}

<h2>Coverage by domain</h2>
<div class="wrap"><table><tr><th>Domain</th>{{range $.Statuses}}<th>{{.}}</th>{{end}}</tr>
{{range .R.Domains}}{{$s := index $.R.DomainSummary .ID}}<tr><td><b>{{.ID}}</b> {{.Name}}</td>{{range $.Statuses}}<td>{{get $s .}}</td>{{end}}</tr>{{end}}
</table></div>

<h2>Cross-domain edges</h2>
{{if .R.Edges}}<div class="wrap"><table><tr><th>Edge</th><th>Scenario</th><th>Status</th><th>Reason</th><th>Provenance</th></tr>
{{range .R.Edges}}<tr><td><b>{{.ID}}</b><br><span class="mut">{{.Title}}</span></td><td>{{.Scenario}}</td><td><span class="b {{.Status}}">{{.Status}}</span></td><td>{{.Reason}}</td><td><code>{{join .Provenance ", "}}</code></td></tr>{{end}}
</table></div>{{else}}<p>No seed edge had concrete assets on both sides.</p>{{end}}

<h2>Control ledger</h2>
<div class="wrap"><table><tr><th>Control</th><th>Title</th><th>Method</th><th>Status</th><th>Reason</th></tr>
{{range .R.Controls}}<tr><td><b>{{.ID}}</b></td><td>{{.Title}}</td><td>{{.Method}}</td><td><span class="b {{.Status}}">{{.Status}}</span></td><td>{{.Reason}}</td></tr>{{end}}
</table></div>

<h2>Tool runs</h2>
<div class="wrap"><table><tr><th>Adapter</th><th>Version</th><th>Result</th><th>Signals</th><th>Detail</th></tr>
{{range .R.Runs}}<tr><td>{{.Adapter}}</td><td>{{.ToolVersion}}</td><td><span class="b {{if eq .ExitClass "OK"}}PASS{{else}}{{.ExitClass}}{{end}}">{{.ExitClass}}</span></td><td>{{.SignalsCount}}</td><td>{{.Detail}}</td></tr>{{end}}
</table></div>

{{if .Closed}}<h2>Closed findings</h2>
<div class="wrap"><table><tr><th>ID</th><th>Title</th><th>Status</th><th>Reviewer</th><th>History</th></tr>
{{range .Closed}}<tr><td>{{.ID}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{.Reviewer}}</td><td>{{.Note}}</td></tr>{{end}}
</table></div>{{end}}

<h2>Evidence index</h2>
<p class="mut">{{len .R.EvidenceIndex}} redacted artifacts under <code>.pensec/private/evidence/</code>, named by SHA-256.</p>
<div class="wrap"><table><tr><th>Evidence</th><th>SHA-256</th><th>Collector</th><th>Source</th></tr>
{{range .R.EvidenceIndex}}<tr><td>{{.ID}}</td><td><code>{{.SHA256}}</code></td><td>{{.Collector}}</td><td><code>{{.SourceRef}}</code></td></tr>{{end}}
</table></div>
<p class="mut">Generated {{.R.GeneratedAt}} by {{.R.Generator}}.</p>
</main></body></html>
{{define "finding"}}<div class="f"><h3>{{.ID}} · {{.Title}}</h3>
<span class="b {{lower .Severity}}">{{.Severity}}</span> <span class="b {{.Confidence}}">{{.Confidence}}</span> <span class="b">{{.Status}}</span>{{if .Stale}} <span class="b STALE">STALE</span>{{end}}
<dl><dt>Location</dt><dd><code>{{.File}}{{if .StartLine}}:{{.StartLine}}{{end}}</code></dd>
<dt>Control</dt><dd>{{.ControlID}} {{ctrl .ControlID}}</dd>
{{if .CWE}}<dt>CWE</dt><dd>{{.CWE}}</dd>{{end}}
<dt>Why</dt><dd>{{.Message}}</dd><dt>Fix</dt><dd>{{.Fix}}</dd><dt>Retest</dt><dd>{{.Retest}}</dd>
<dt>Evidence</dt><dd><code>{{join .EvidenceIDs ", "}}</code> via {{.Collector}}</dd>
{{if .Note}}<dt>History</dt><dd>{{.Note}}</dd>{{end}}</dl></div>{{end}}
`
