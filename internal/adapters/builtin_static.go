package adapters

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

// ---- secrets: E-001, E-002 ----

type secretsAdapter struct{}

func (secretsAdapter) Name() string       { return "builtin-secrets" }
func (secretsAdapter) Controls() []string { return []string{"E-001", "E-002"} }
func (secretsAdapter) Maturity() string   { return MaturityUnvalidated }
func (secretsAdapter) Network() bool      { return false }

var exampleRe = regexp.MustCompile(`(?i)(EXAMPLE|dummy|placeholder|your[_-]?(api[_-]?)?key|xxxxxxxx|<[a-z_ -]+>|redacted)`)

func (a secretsAdapter) Run(ctx context.Context, c *Context) (Result, model.Run) {
	run := newRun(a.Name(), version.Version)
	res := Result{Decisions: map[string]Decision{}}
	for _, f := range c.Inv.Files {
		if ctx.Err() != nil {
			return res, finish(run, model.ExitTimeout, "cancelled", len(res.Signals))
		}
		lb := strings.ToLower(path.Base(f.Path))
		if strings.HasSuffix(lb, ".lock") || strings.HasSuffix(lb, "-lock.json") || strings.HasSuffix(lb, "lock.yaml") || lb == "go.sum" {
			continue
		}
		for i, l := range f.Lines {
			if len(l) > 4000 {
				continue
			}
			for _, r := range redact.SecretRules {
				m := r.Re.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				val := m[r.Group]
				if exampleRe.MatchString(val) || (r.ID != "private-key" && exampleRe.MatchString(l) && r.ID != "db-url-password") {
					continue
				}
				if r.ID == "db-url-password" && (strings.HasPrefix(val, "$") || strings.Contains(val, "{") || strings.EqualFold(val, "password")) {
					continue
				}
				sev, conf := model.SevHigh, model.Confirmed
				if r.ID == "private-key" {
					sev = model.SevCritical
				}
				if r.ID == "jwt" || r.ID == "db-url-password" {
					sev, conf = model.SevMedium, model.StronglySupported
				}
				if IsTestPath(f.Path) {
					sev = model.SevLow
				}
				res.Signals = append(res.Signals, model.Signal{
					RuleID: "secret." + r.ID, ControlID: "E-001", Title: "Hardcoded " + r.Title, Severity: sev, Confidence: conf, CWE: "CWE-798",
					File: f.Path, StartLine: i + 1, EndLine: i + 1, Snippet: redact.Line(strings.TrimSpace(l)),
					Message:   "A value matching the " + r.Title + " format is stored in the repository. The value is masked in all PenSec output.",
					Fix:       "Revoke and rotate the credential at the provider first, then remove it from the code and git history; load it from a secret manager or environment at runtime.",
					Retest:    "Re-run `pensec scan`; also verify with the provider that the old credential is revoked.",
					Collector: a.Name(), Key: redact.Mask(val),
				})
			}
		}
	}
	// E-002 tracked sensitive files (names only; content never read).
	if c.Inv.Tracked != nil {
		for _, s := range c.Inv.SensitiveNames {
			if !c.Inv.Tracked[s] {
				continue
			}
			res.Signals = append(res.Signals, model.Signal{
				RuleID: "secret.tracked-sensitive-file", ControlID: "E-002", Title: "Credential or environment file tracked in git", Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-538",
				File: s, Message: "This file type usually holds credentials and is committed to git. PenSec did not read its content.",
				Fix:       "Rotate any credentials it contains, `git rm --cached` it, add it to .gitignore, and purge it from history if the repository is shared.",
				Retest:    "Re-run `pensec scan`; the file must no longer be tracked.",
				Collector: a.Name(),
			})
		}
	}
	return res, finish(run, model.ExitOK, fmt.Sprintf("%d secret formats checked; %d sensitive file names recorded without reading", len(redact.SecretRules), len(c.Inv.SensitiveNames)), len(res.Signals))
}

// ---- CI/CD: N-001..N-004 ----

type cicdAdapter struct{}

func (cicdAdapter) Name() string       { return "builtin-cicd" }
func (cicdAdapter) Controls() []string { return []string{"N-001", "N-002", "N-003", "N-004"} }
func (cicdAdapter) Maturity() string   { return MaturityUnvalidated }
func (cicdAdapter) Network() bool      { return false }

var (
	shaRef        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	untrustedExpr = regexp.MustCompile(`\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|pages|workflow_run)\.[\w.\[\]*]*(title|body|name|message|label|ref|email|head_branch|default_branch)\b[^}]*|github\.head_ref\s*)\}\}`)
	runStart      = regexp.MustCompile(`^(\s*)(-\s*)?run:\s*(.*)$`)
	prtTrigger    = regexp.MustCompile(`(^|\s|\[|,)pull_request_target\b`)
	checkoutHead  = regexp.MustCompile(`ref:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)`)
)

func (a cicdAdapter) Run(_ context.Context, c *Context) (Result, model.Run) {
	run := newRun(a.Name(), version.Version)
	res := Result{Decisions: map[string]Decision{}}
	for _, p := range c.Inv.Features["github_workflows"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		hasPerms := false
		inRun, runIndent := false, 0
		isPRT := false
		for i, l := range f.Lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "#") {
				continue
			}
			if strings.HasPrefix(t, "permissions:") {
				hasPerms = true
			}
			if prtTrigger.MatchString(l) && !strings.Contains(l, "${{") {
				isPRT = true
			}
			if m := inventory.UsesRe().FindStringSubmatch(l); m != nil {
				ref := m[1]
				if !strings.HasPrefix(ref, "./") && !strings.HasPrefix(ref, "docker://") {
					at := strings.LastIndex(ref, "@")
					version := ""
					if at > 0 {
						version = ref[at+1:]
					}
					if !shaRef.MatchString(version) {
						sev := model.SevMedium
						owner := strings.SplitN(ref, "/", 2)[0]
						if owner == "actions" || owner == "github" {
							sev = model.SevLow
						}
						res.Signals = append(res.Signals, sig(lineRule{ID: "cicd.unpinned-action", Control: "N-001", Title: "GitHub Action not pinned to a commit SHA", Severity: sev, Confidence: model.Confirmed, CWE: "CWE-829",
							Message: fmt.Sprintf("%s uses a mutable reference; whoever controls that tag/branch can change the code that runs with this workflow's secrets.", ref),
							Fix:     "Pin to the full 40-character commit SHA of a reviewed release and keep the version in a trailing comment; let Dependabot/Renovate update it."}, f, i+1, a.Name()))
						res.Signals[len(res.Signals)-1].Key = ref
					}
				}
			}
			// run: blocks
			if m := runStart.FindStringSubmatch(l); m != nil {
				val := strings.TrimSpace(m[3])
				if val == "|" || val == ">" || strings.HasPrefix(val, "|") || strings.HasPrefix(val, ">") {
					inRun, runIndent = true, len(m[1])
				} else {
					inRun = false
					if untrustedExpr.MatchString(l) {
						res.Signals = append(res.Signals, injectionSig(f, i+1, a.Name()))
					}
				}
				continue
			}
			if inRun {
				ind := len(l) - len(strings.TrimLeft(l, " "))
				if t != "" && ind <= runIndent {
					inRun = false
				} else if untrustedExpr.MatchString(l) {
					res.Signals = append(res.Signals, injectionSig(f, i+1, a.Name()))
				}
			}
		}
		if isPRT {
			for i, l := range f.Lines {
				if checkoutHead.MatchString(l) {
					res.Signals = append(res.Signals, sig(lineRule{ID: "cicd.prt-untrusted-checkout", Control: "N-003", Title: "pull_request_target checks out untrusted PR code", Severity: model.SevCritical, Confidence: model.Confirmed, CWE: "CWE-829",
						Message: "pull_request_target runs with repository secrets and a write token; checking out the PR head lets any fork author run code with them.",
						Fix:     "Use pull_request for building untrusted code, or split into an unprivileged build and a privileged workflow_run that only consumes artifacts."}, f, i+1, a.Name()))
				}
			}
		}
		if !hasPerms {
			res.Signals = append(res.Signals, model.Signal{RuleID: "cicd.no-permissions", ControlID: "N-004", Title: "Workflow does not declare GITHUB_TOKEN permissions", Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-250",
				File: f.Path, StartLine: 1, EndLine: 1, Message: "Without a permissions block the token gets the repository default, which may be read-write for everything.",
				Fix: "Add `permissions: contents: read` at the top level and grant extra scopes per job only where needed.", Collector: a.Name()})
		}
	}
	return res, finish(run, model.ExitOK, fmt.Sprintf("%d workflows", len(c.Inv.Features["github_workflows"])), len(res.Signals))
}

func injectionSig(f *inventory.File, line int, coll string) model.Signal {
	return sig(lineRule{ID: "cicd.script-injection", Control: "N-002", Title: "Untrusted event data interpolated into a run script", Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-78",
		Message: "Attacker-controlled text (titles, bodies, branch names) is expanded into the shell script before it runs, allowing command injection in CI.",
		Fix:     "Pass the value through an environment variable (env: TITLE: ${{ ... }}) and reference \"$TITLE\" in the script."}, f, line, coll)
}

// ---- infrastructure: J-001..J-004 ----

type infraAdapter struct{}

func (infraAdapter) Name() string       { return "builtin-infra" }
func (infraAdapter) Controls() []string { return []string{"J-001", "J-002", "J-003", "J-004"} }
func (infraAdapter) Maturity() string   { return MaturityUnvalidated }
func (infraAdapter) Network() bool      { return false }

var (
	fromRe      = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
	userRe      = regexp.MustCompile(`(?i)^\s*USER\s+(\S+)`)
	privRe      = regexp.MustCompile(`^\s*(privileged:\s*true|network_mode:\s*['"]?host|pid:\s*['"]?host|hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true|allowPrivilegeEscalation:\s*true|runAsUser:\s*0\b)|/var/run/docker\.sock`)
	publicACLRe = regexp.MustCompile(`acl\s*=\s*"public-read(-write)?"|publicly_accessible\s*=\s*true|block_public_(acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false|ignore_public_acls\s*=\s*false`)
	openCIDRRe  = regexp.MustCompile(`"0\.0\.0\.0/0"|"::/0"`)
	adminPortRe = regexp.MustCompile(`(from_port|to_port|port)\s*=\s*"?(22|3389|3306|5432|6379|27017|9200|5601|11211|2375|2376)\b`)
)

func (a infraAdapter) Run(_ context.Context, c *Context) (Result, model.Run) {
	run := newRun(a.Name(), version.Version)
	res := Result{Decisions: map[string]Decision{}}
	for _, p := range c.Inv.Features["dockerfile"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		stages := map[string]bool{}
		lastUser, lastUserLine, lastFrom := "", 0, 0
		for i, l := range f.Lines {
			if m := fromRe.FindStringSubmatch(l); m != nil {
				img := m[1]
				lastFrom = i + 1
				lastUser, lastUserLine = "", 0
				if m[2] != "" {
					stages[strings.ToLower(m[2])] = true
				}
				lower := strings.ToLower(img)
				if lower == "scratch" || stages[lower] || strings.Contains(img, "$") || strings.Contains(img, "@sha256:") {
					continue
				}
				name := img
				if i := strings.LastIndex(img, "/"); i >= 0 {
					name = img[i+1:]
				}
				if !strings.Contains(name, ":") || strings.HasSuffix(name, ":latest") {
					res.Signals = append(res.Signals, sig(lineRule{ID: "infra.unpinned-base-image", Control: "J-002", Title: "Base image not pinned", Severity: model.SevLow, Confidence: model.Confirmed, CWE: "CWE-829",
						Message: "The base image uses latest or no tag, so builds are not reproducible and can silently pick up a changed image.",
						Fix:     "Pin a specific version tag, ideally with @sha256 digest, and update it deliberately."}, f, i+1, a.Name()))
				}
			}
			if m := userRe.FindStringSubmatch(l); m != nil {
				lastUser, lastUserLine = m[1], i+1
			}
		}
		if lastFrom > 0 && (lastUser == "" || lastUser == "root" || lastUser == "0" || strings.HasPrefix(lastUser, "0:") || strings.HasPrefix(lastUser, "root:")) {
			line := lastFrom
			if lastUserLine > 0 {
				line = lastUserLine
			}
			res.Signals = append(res.Signals, sig(lineRule{ID: "infra.container-root", Control: "J-001", Title: "Container runs as root", Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-250",
				Message: "The final image stage has no non-root USER, so a compromise of the process is root inside the container.",
				Fix:     "Create an unprivileged user and add `USER <uid>` in the final stage."}, f, line, a.Name()))
		}
	}
	for _, p := range c.Inv.Features["orchestration"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		for i, l := range f.Lines {
			if privRe.MatchString(l) {
				res.Signals = append(res.Signals, sig(lineRule{ID: "infra.privileged-container", Control: "J-003", Title: "Privileged container or host namespace", Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-250",
					Message: "The container gets host-level privileges (privileged, host network/PID, docker socket or UID 0); escape to the host becomes trivial.",
					Fix:     "Remove the privilege; grant only the specific capability required and run as non-root."}, f, i+1, a.Name()))
			}
		}
	}
	for _, p := range c.Inv.Features["terraform"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		for i, l := range f.Lines {
			if publicACLRe.MatchString(l) {
				res.Signals = append(res.Signals, sig(lineRule{ID: "infra.public-storage", Control: "J-004", Title: "Public storage or database exposure", Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-284",
					Message: "The resource is configured for public access.", Fix: "Keep storage and databases private; serve public files through a CDN with explicit, read-only policy."}, f, i+1, a.Name()))
			}
			if openCIDRRe.MatchString(l) {
				lo, hi := max(0, i-12), min(len(f.Lines), i+12)
				for j := lo; j < hi; j++ {
					if adminPortRe.MatchString(f.Lines[j]) {
						res.Signals = append(res.Signals, sig(lineRule{ID: "infra.world-open-admin-port", Control: "J-004", Title: "Administrative or database port open to the internet", Severity: model.SevHigh, Confidence: model.StronglySupported, CWE: "CWE-284",
							Message: "A security group/firewall rule allows 0.0.0.0/0 near an SSH, RDP or database port.", Fix: "Restrict the source to a VPN/bastion range or use a managed access proxy."}, f, i+1, a.Name()))
						break
					}
				}
			}
		}
	}
	return res, finish(run, model.ExitOK, "dockerfile/compose/k8s/terraform checks", len(res.Signals))
}

// ---- supply chain: I-001, I-002, I-004, P-002 ----

type supplyAdapter struct{}

func (supplyAdapter) Name() string       { return "builtin-supply" }
func (supplyAdapter) Controls() []string { return []string{"I-001", "I-002", "I-004", "P-002"} }
func (supplyAdapter) Maturity() string   { return MaturityUnvalidated }
func (supplyAdapter) Network() bool      { return false }

var pinnedReq = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\],]+\s*===?\s*[^\s;]+`)
var pkgVersioned = regexp.MustCompile(`^(@[^/]+/)?[^@]+@\d`)

func (a supplyAdapter) Run(_ context.Context, c *Context) (Result, model.Run) {
	run := newRun(a.Name(), version.Version)
	res := Result{Decisions: map[string]Decision{}}
	for _, p := range c.Inv.Features["missing_lockfile"] {
		res.Signals = append(res.Signals, model.Signal{RuleID: "supply.missing-lockfile", ControlID: "I-001", Title: "Package manifest without lockfile", Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-829",
			File: p, StartLine: 1, EndLine: 1, Message: "Without a committed lockfile every install can resolve different transitive versions, including a newly published malicious one.",
			Fix: "Commit the lockfile and install with the frozen/ci mode (npm ci, pip install --require-hashes, go mod verify).", Collector: a.Name()})
	}
	for _, p := range c.Inv.Features["npm_lock"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		var lock struct {
			Packages map[string]struct {
				Version          string `json:"version"`
				HasInstallScript bool   `json:"hasInstallScript"`
			} `json:"packages"`
		}
		if err := json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &lock); err != nil {
			res.Decisions["I-002"] = Decision{model.StatusError, "could not parse " + p}
			continue
		}
		var names []string
		for k, v := range lock.Packages {
			if v.HasInstallScript && k != "" {
				names = append(names, strings.TrimPrefix(k[strings.LastIndex(k, "node_modules/")+len("node_modules/"):], "/")+"@"+v.Version)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			res.Signals = append(res.Signals, model.Signal{RuleID: "supply.install-script", ControlID: "I-002", Title: "Dependency runs an install script", Severity: model.SevInfo, Confidence: model.Confirmed, CWE: "CWE-506",
				File: p, Message: n + " executes code at install time with the installer's environment (including CI secrets).",
				Fix: "Review the need; consider `npm ci --ignore-scripts` in CI and allowlisting required scripts.", Collector: a.Name(), Key: n})
		}
	}
	for _, p := range c.Inv.Features["python_reqs"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		var loose []string
		for _, l := range f.Lines {
			t := strings.TrimSpace(strings.SplitN(l, "#", 2)[0])
			if t == "" || strings.HasPrefix(t, "-") || strings.Contains(t, "://") || strings.HasPrefix(t, "git+") {
				continue
			}
			if !pinnedReq.MatchString(t) {
				loose = append(loose, t)
			}
		}
		if len(loose) > 0 {
			ex := loose
			if len(ex) > 5 {
				ex = ex[:5]
			}
			res.Signals = append(res.Signals, model.Signal{RuleID: "supply.unpinned-requirements", ControlID: "I-004", Title: "Python requirements not pinned", Severity: model.SevLow, Confidence: model.Confirmed, CWE: "CWE-829",
				File: p, StartLine: 1, EndLine: 1, Message: fmt.Sprintf("%d requirement(s) without an exact version, e.g. %s.", len(loose), strings.Join(ex, ", ")),
				Fix: "Pin exact versions (pip-compile / uv lock) and install with --require-hashes.", Collector: a.Name()})
		}
	}
	for _, p := range c.Inv.Features["mcp_config"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		var cfg struct {
			MCPServers map[string]struct {
				Command string            `json:"command"`
				Args    []string          `json:"args"`
				Env     map[string]string `json:"env"`
				Headers map[string]string `json:"headers"`
			} `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &cfg); err != nil {
			res.Decisions["P-002"] = Decision{model.StatusError, "could not parse " + p}
			continue
		}
		names := make([]string, 0, len(cfg.MCPServers))
		for n := range cfg.MCPServers {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			s := cfg.MCPServers[name]
			base := strings.ToLower(path.Base(strings.ReplaceAll(s.Command, `\`, "/")))
			if base == "npx" || base == "npx.cmd" || base == "uvx" || base == "bunx" || base == "pnpx" {
				for _, arg := range s.Args {
					if strings.HasPrefix(arg, "-") {
						continue
					}
					if !pkgVersioned.MatchString(arg) || strings.HasSuffix(arg, "@latest") {
						res.Signals = append(res.Signals, model.Signal{RuleID: "supply.mcp-unpinned", ControlID: "P-002", Title: "MCP server package not pinned", Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-829",
							File: p, Message: fmt.Sprintf("MCP server %q runs %s %s without a fixed version; a new release runs automatically with the agent's privileges.", redact.Line(name), base, redact.Line(arg)),
							Fix: "Pin an exact version (pkg@1.2.3) that you reviewed.", Collector: a.Name(), Key: name})
					}
					break
				}
			}
			for k, v := range mergeMaps(s.Env, s.Headers) {
				if v == "" || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") {
					continue
				}
				if regexp.MustCompile(`(?i)(key|token|secret|password|auth)`).MatchString(k) {
					res.Signals = append(res.Signals, model.Signal{RuleID: "supply.mcp-inline-credential", ControlID: "P-002", Title: "Credential stored inline in MCP config", Severity: model.SevHigh, Confidence: model.StronglySupported, CWE: "CWE-798",
						File: p, Message: fmt.Sprintf("MCP server %q has %s set to a literal value (%s).", redact.Line(name), redact.Line(k), redact.Mask(v)),
						Fix: "Reference an environment variable (${VAR}) and keep the value out of the repository; rotate the exposed value.", Collector: a.Name(), Key: name + "/" + k})
				}
			}
		}
	}
	return res, finish(run, model.ExitOK, "lockfiles, install scripts, requirement pins, MCP configs", len(res.Signals))
}

func mergeMaps(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---- mobile: K-001, K-002, L-001 ----

type mobileAdapter struct{}

func (mobileAdapter) Name() string { return "builtin-mobile" }
func (mobileAdapter) Controls() []string {
	return []string{"K-001", "K-002", "K-004", "L-001", "L-003", "L-004"}
}
func (mobileAdapter) Maturity() string { return MaturityUnvalidated }
func (mobileAdapter) Network() bool    { return false }

func attr(se xml.StartElement, name string) (string, bool) {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

func (a mobileAdapter) Run(_ context.Context, c *Context) (Result, model.Run) {
	run := newRun(a.Name(), version.Version)
	res := Result{Decisions: map[string]Decision{}}
	for _, p := range c.Inv.Features["android"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		sigs, err := manifestSignals(strings.Join(f.Lines, "\n"), p, a.Name(), manifestControls{"K-001", "K-002"})
		res.Signals = append(res.Signals, sigs...)
		if err != nil {
			res.Decisions["K-001"] = Decision{model.StatusError, "could not parse " + p + ": " + err.Error()}
		}
	}
	for _, p := range c.Inv.Features["ios"] {
		f := c.Inv.FileByPath(p)
		if f == nil {
			continue
		}
		for i, l := range f.Lines {
			if strings.Contains(l, "<key>NSAllowsArbitraryLoads</key>") {
				next := l
				if i+1 < len(f.Lines) {
					next += f.Lines[i+1]
				}
				if strings.Contains(next, "<true/>") {
					res.Signals = append(res.Signals, model.Signal{RuleID: "mobile.ios-ats-arbitrary-loads", ControlID: "L-001", Title: "iOS ATS allows arbitrary loads", Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-319",
						File: p, StartLine: i + 1, EndLine: i + 2, Snippet: "NSAllowsArbitraryLoads = true",
						Message: "App Transport Security is disabled globally, allowing cleartext and weak TLS connections.",
						Fix:     "Remove NSAllowsArbitraryLoads; add narrowly scoped NSExceptionDomains only where unavoidable.", Collector: a.Name()})
				}
			}
		}
	}
	res.Signals = append(res.Signals, mobileSourceSignals(c.Inv, a.Name())...)
	return res, finish(run, model.ExitOK, "android manifest, iOS plist and entitlements, mobile storage checks", len(res.Signals))
}
