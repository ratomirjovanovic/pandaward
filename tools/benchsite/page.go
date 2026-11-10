package main

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PandaWard benchmarks</title>
<meta name="description" content="PandaWard's measured detection on the OWASP Benchmarks for Java and Python and on real JavaScript CVEs, per release, with the commands to reproduce every number.">
<link rel="icon" href="../icon.png">
<link rel="stylesheet" href="../style.css">
</head>
<body>
<header class="top"><div class="wrap">
  <a class="home" href="../"><img src="../icon.png" alt=""><b>PandaWard</b></a>
  <nav>
    <a href="../demo/">Demo</a>
    <a href="./">Benchmarks</a>
    <a href="https://github.com/ratomirjovanovic/pandaward/wiki">Docs</a>
    <a href="https://github.com/ratomirjovanovic/pandaward">GitHub</a>
  </nav>
</div></header>

<main class="wrap">
  <section>
    <h1>Benchmarks</h1>
    <p class="sub">What PandaWard finds on public, labelled test suites it did not write, measured the same way for every release. These are baselines, not claims: on most categories the scores are still near zero, and the <a href="https://github.com/ratomirjovanovic/pandaward/blob/main/docs/BENCHMARKS.md">method and interpretation</a> say why. No other product is compared here, because none was run with the same suites, versions and configuration.</p>
    <p class="sub">Latest: <b>{{.Latest.Label}}</b>, {{.Latest.Date}} (<a href="{{.Latest.URL}}">source</a>). Score = true positive rate minus false positive rate per category (Youden's index): 0 is no better than not running the tool, 1 is perfect.</p>
  </section>

  {{range .Latest.Suites}}
  <section>
    <h2>{{.Title}}</h2>
    <p class="sub">Benchmark commit <code>{{short .Commit}}</code>{{if .Asset}}, <a href="{{.Asset}}">raw results</a>{{end}}. Semgrep and Opengrep run PandaWard's bundled rules. "-" means no rule of that engine covers the category.</p>
    <div class="tablewrap"><table>
      <tr><th>Engine</th><th class="num">Average, covered</th><th class="num">Covered</th>{{range .Categories}}<th class="num">{{.}}</th>{{end}}</tr>
      {{$s := .}}{{range .Engines}}
      {{if .NotRun}}<tr><td>{{engine .Name}}</td><td colspan="99">not run: {{.NotRun}}</td></tr>
      {{else}}<tr><td class="name">{{engine .Name}}{{with ver .Name .Version}} <small>{{.}}</small>{{end}}</td><td class="num"><b>{{score .AverageCovered}}</b></td><td class="num">{{.Covered}} of {{len $s.Categories}}</td>{{$e := .}}{{range $s.Categories}}<td class="num">{{cat $e .}}</td>{{end}}</tr>{{end}}
      {{end}}
    </table></div>
  </section>
  {{end}}

  {{with .Latest.CVE}}
  <section>
    <h2>OpenSSF CVE Benchmark (JavaScript and TypeScript)</h2>
    <p class="sub">{{.Scored}} real CVEs, each checked at the commit before and after its fix{{if .Unavailable}}; {{.Unavailable}} unavailable (repository gone){{end}}. Detected: a finding on a labelled vulnerable line. Fix recognized: that rule reports fewer findings in the file after the fix. PandaWard counts a CVE once when the built-in rules or the Semgrep rules find it, as a scan runs both. Benchmark commit <code>{{short .Commit}}</code>{{if .Asset}}, <a href="{{.Asset}}">raw results</a>{{end}}.</p>
    <div class="tablewrap"><table>
      <tr><th>Engine</th><th class="num">Detected</th><th class="num">Rate</th><th class="num">CWE match</th><th class="num">Fix recognized</th><th class="num">Still flagged after fix</th></tr>
      {{range .Engines}}
      {{if .NotRun}}<tr><td>{{engine .Name}}</td><td colspan="5">not run: {{.NotRun}}</td></tr>
      {{else}}<tr><td class="name">{{engine .Name}}{{with ver .Name .Version}} <small>{{.}}</small>{{end}}</td><td class="num"><b>{{.Detected}}</b> of {{.Scored}}</td><td class="num">{{pct .Rate}}</td><td class="num">{{.CWEMatch}}</td><td class="num">{{.Fixed}}</td><td class="num">{{.StillFlagd}}</td></tr>{{end}}
      {{end}}
    </table></div>
  </section>
  {{end}}

  <section>
    <h2>History</h2>
    <p class="sub">Average score over covered categories for the OWASP suites, CVEs detected for the CVE benchmark. Each row links to the release or commit it was measured on. A pull request that lowers any of these numbers fails CI.</p>
    <div class="tablewrap"><table>
      <tr><th rowspan="2">Measured on</th><th colspan="3">Java</th><th colspan="3">Python</th><th colspan="4">JS/TS CVEs</th></tr>
      <tr>{{range engines}}<th class="num">{{.}}</th>{{end}}{{range engines}}<th class="num">{{.}}</th>{{end}}{{range cveengines}}<th class="num">{{.}}</th>{{end}}</tr>
      {{range .History}}{{$h := .}}
      <tr><td><a href="{{.URL}}">{{.Label}}</a><br><small>{{.Date}}</small></td>
        {{$j := suite $h "java"}}{{range engines}}<td class="num">{{with eng $j .}}{{score .AverageCovered}}{{else}}-{{end}}</td>{{end}}
        {{$p := suite $h "python"}}{{range engines}}<td class="num">{{with eng $p .}}{{score .AverageCovered}}{{else}}-{{end}}</td>{{end}}
        {{range cveengines}}<td class="num">{{with cveeng $h.CVE .}}{{.Detected}}/{{.Scored}}{{else}}-{{end}}</td>{{end}}
      </tr>
      {{end}}
    </table></div>
  </section>

  <section>
    <h2>Reproduce</h2>
    <p class="sub">From a clone of the repository at the release tag, with Go installed. Semgrep and Opengrep are optional; an engine that is not installed is reported as not run. Nothing from the benchmarks or the CVE projects is built or executed.</p>
<pre class="code">sh tools/owaspbench/run.sh --suite java   --engine builtin,semgrep,opengrep
sh tools/owaspbench/run.sh --suite python --engine builtin,semgrep,opengrep
sh tools/cvebench/run.sh --engine builtin,semgrep,opengrep   # hours; resumes if interrupted</pre>
  </section>
</main>

<footer><div class="wrap">
  <a href="../">PandaWard</a> ·
  <a href="https://github.com/ratomirjovanovic/pandaward/blob/main/docs/BENCHMARKS.md">Benchmark method</a> ·
  <a href="https://github.com/ratomirjovanovic/pandaward">Source</a>
</div></footer>
</body>
</html>
`
