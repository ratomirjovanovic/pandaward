package adapters

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// Supply-chain checks on GitHub workflows: global tools installed by a
// floating version in a privileged job, and container images used by tag
// instead of digest. Both read the workflow line by line with a small
// indentation model; whatever the model cannot read with certainty (flow
// syntax it does not know, variables, unknown command-line flags) is skipped
// rather than reported.

var (
	wfKeyRe     = regexp.MustCompile(`^([A-Za-z0-9_-]+):\s*(.*)$`)
	exactSemver = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	digestRef   = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	imageRefRe  = regexp.MustCompile(`^(?:[A-Za-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._/]|__|-+)[a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$`)
	flowPairRe  = regexp.MustCompile(`([A-Za-z-]+)\s*:\s*([A-Za-z-]+)`)
	flowImageRe = regexp.MustCompile(`(?:^|[{,\s])image\s*:\s*([^,}\s]+)`)
)

// wfLine is one significant (not blank, not comment) workflow line.
type wfLine struct {
	n      int // 1-based line number
	indent int
	text   string // trimmed
}

// tokenPerms is what a permissions block grants that matters here.
type tokenPerms struct {
	declared bool
	idToken  bool // id-token: write
	write    bool // id-token, contents or packages: write
}

func significantLines(f *inventory.File) []wfLine {
	var out []wfLine
	for i, l := range f.Lines {
		l = strings.TrimRight(l, "\r")
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, wfLine{n: i + 1, indent: len(l) - len(strings.TrimLeft(l, " ")), text: t})
	}
	return out
}

// childEnd returns the index after the last line nested deeper than ls[i].
func childEnd(ls []wfLine, i int) int {
	j := i + 1
	for j < len(ls) && ls[j].indent > ls[i].indent {
		j++
	}
	return j
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// stripYAMLComment drops a trailing " # comment" from a plain scalar.
func stripYAMLComment(s string) string {
	if k := strings.Index(s, " #"); k >= 0 {
		s = s[:k]
	}
	return strings.TrimSpace(s)
}

func grant(p *tokenPerms, scope, level string) {
	if level != "write" {
		return
	}
	switch scope {
	case "id-token":
		p.idToken, p.write = true, true
	case "contents", "packages":
		p.write = true
	}
}

// parsePerms reads the permissions key at ls[i].
func parsePerms(ls []wfLine, i int) tokenPerms {
	p := tokenPerms{declared: true}
	_, v, _ := strings.Cut(ls[i].text, ":")
	v = unquote(stripYAMLComment(v))
	switch {
	case v == "write-all":
		p.idToken, p.write = true, true
	case strings.HasPrefix(v, "{"):
		for _, m := range flowPairRe.FindAllStringSubmatch(v, -1) {
			grant(&p, m[1], m[2])
		}
	case v == "":
		for j := i + 1; j < childEnd(ls, i); j++ {
			if m := wfKeyRe.FindStringSubmatch(ls[j].text); m != nil {
				grant(&p, m[1], unquote(stripYAMLComment(m[2])))
			}
		}
	}
	return p
}

// wfJob is one job of a workflow: its lines are ls[start:end], its keys sit
// at keyIndent.
type wfJob struct {
	start, end, keyIndent int
}

func workflowJobs(ls []wfLine) (wfPerms tokenPerms, jobs []wfJob) {
	for i := 0; i < len(ls); i++ {
		if ls[i].indent != 0 {
			continue
		}
		switch {
		case strings.HasPrefix(ls[i].text, "permissions:"):
			wfPerms = parsePerms(ls, i)
		case ls[i].text == "jobs:":
			end := childEnd(ls, i)
			for j := i + 1; j < end; {
				je := childEnd(ls, j)
				if je > j+1 && strings.HasSuffix(ls[j].text, ":") {
					jobs = append(jobs, wfJob{start: j + 1, end: je, keyIndent: ls[j+1].indent})
				}
				j = je
			}
		}
	}
	return wfPerms, jobs
}

// runLine is one logical shell line of a run script, with backslash
// continuations joined.
type runLine struct {
	n    int
	text string
}

// runScripts returns the shell lines of the run: steps in ls[start:end].
func runScripts(f *inventory.File, ls []wfLine, start, end int) []runLine {
	var out []runLine
	for i := start; i < end; i++ {
		m := runStart.FindStringSubmatch(strings.TrimRight(f.Lines[ls[i].n-1], "\r"))
		if m == nil {
			continue
		}
		val := strings.TrimSpace(m[3])
		if strings.HasPrefix(val, "|") || strings.HasPrefix(val, ">") {
			ind := len(m[1]) + len(m[2])
			var cur *runLine
			for j := ls[i].n; j < len(f.Lines) && (end >= len(ls) || j < ls[end].n-1); j++ {
				l := strings.TrimRight(f.Lines[j], "\r")
				t := strings.TrimSpace(l)
				if t != "" && len(l)-len(strings.TrimLeft(l, " ")) <= ind {
					break
				}
				if t == "" || strings.HasPrefix(t, "#") {
					cur = nil
					continue
				}
				if cur != nil {
					cur.text += " " + strings.TrimSuffix(t, "\\")
				} else {
					out = append(out, runLine{n: j + 1, text: strings.TrimSuffix(t, "\\")})
					cur = &out[len(out)-1]
				}
				if !strings.HasSuffix(t, "\\") {
					cur = nil
				}
			}
			continue
		}
		if val != "" {
			out = append(out, runLine{n: ls[i].n, text: unquote(val)})
		}
	}
	return out
}

var exprRe = regexp.MustCompile(`\$\{\{.*?\}\}`)

// commands splits a shell line into simple commands, each as its words
// without leading sudo, env assignments and the trailing comment. Quoted
// text stays inside its word, quotes included, so a separator or space in
// quotes does not start a new command or word.
func commands(line string) [][]string {
	// An expression becomes one word, so it cannot split a flag value.
	line = exprRe.ReplaceAllString(line, "$${{expr}}")
	var out [][]string
	var words []string
	var cur strings.Builder
	var quote byte
	word := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	command := func() {
		word()
		for len(words) > 0 && (words[0] == "sudo" || words[0] == "-E" || (strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "-"))) {
			words = words[1:]
		}
		if len(words) > 0 {
			out = append(out, words)
		}
		words = nil
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case ' ', '\t':
			word()
		case ';', '&', '|', '(', ')', '`':
			command()
		case '#':
			if cur.Len() == 0 {
				command()
				return out
			}
			cur.WriteByte(c)
		default:
			cur.WriteByte(c)
		}
	}
	command()
	return out
}

// npmBoolFlags are install flags that take no separate value.
var npmBoolFlags = map[string]bool{
	"-g": true, "--global": true, "-y": true, "--yes": true, "-f": true, "--force": true, "-s": true, "--silent": true, "-q": true, "--quiet": true,
	"--no-audit": true, "--no-fund": true, "--no-save": true, "--ignore-scripts": true, "--prefer-offline": true, "--no-progress": true, "--legacy-peer-deps": true,
}

// floatingPkgs returns the package specs of a global install command that
// are not pinned to an exact version. ok is false when the command is not a
// global install or cannot be read with certainty.
func floatingPkgs(w []string) (pkgs []string, ok bool) {
	var args []string
	switch {
	case len(w) >= 3 && w[0] == "npm" && (w[1] == "i" || w[1] == "install" || w[1] == "add" || w[1] == "in"):
		args = w[2:]
	case len(w) >= 4 && w[0] == "npm" && (w[1] == "-g" || w[1] == "--global") && (w[2] == "i" || w[2] == "install"):
		args = append([]string{w[1]}, w[3:]...)
	case len(w) >= 3 && w[0] == "pnpm" && (w[1] == "add" || w[1] == "i" || w[1] == "install"):
		args = w[2:]
	case len(w) >= 4 && w[0] == "yarn" && w[1] == "global" && w[2] == "add":
		args = append([]string{"-g"}, w[3:]...)
	default:
		return nil, false
	}
	global := false
	var names []string
	for _, a := range args {
		switch {
		case a == "-g" || a == "--global" || a == "--location=global":
			global = true
		case strings.HasPrefix(a, "--") && strings.Contains(a, "="):
		case strings.HasPrefix(a, "-"):
			if !npmBoolFlags[a] {
				return nil, false
			}
		default:
			names = append(names, unquote(a))
		}
	}
	if !global {
		return nil, false
	}
	for _, n := range names {
		if _, floating, sure := pkgVersion(n); sure && floating {
			pkgs = append(pkgs, n)
		}
	}
	return pkgs, true
}

// pkgVersion splits name@version; sure is false for specs that are not
// registry packages (paths, URLs, git, variables).
func pkgVersion(spec string) (version string, floating, sure bool) {
	if spec == "" || strings.ContainsAny(spec, "$`{}:\\") || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~") || strings.HasSuffix(spec, ".tgz") {
		return "", false, false
	}
	name := spec
	if at := strings.LastIndex(spec, "@"); at > 0 {
		name, version = spec[:at], spec[at+1:]
	}
	if strings.Count(name, "/") > 1 || (strings.Contains(name, "/") && !strings.HasPrefix(name, "@")) {
		return "", false, false // a GitHub shorthand such as user/repo
	}
	return version, !exactSemver.MatchString(version), true
}

// npxLatest returns the package an npx command runs at @latest.
func npxLatest(w []string) string {
	if len(w) < 2 || w[0] != "npx" {
		return ""
	}
	for i := 1; i < len(w); i++ {
		a := unquote(w[i])
		switch {
		case a == "-y" || a == "--yes" || a == "-q" || a == "--quiet":
		case a == "-p" || a == "--package":
			i++
			if i < len(w) && strings.HasSuffix(unquote(w[i]), "@latest") {
				return unquote(w[i])
			}
		case strings.HasPrefix(a, "--package="):
			if strings.HasSuffix(a, "@latest") {
				return strings.TrimPrefix(a, "--package=")
			}
		case strings.HasPrefix(a, "-"):
			return ""
		default:
			if _, _, sure := pkgVersion(a); sure && strings.HasSuffix(a, "@latest") {
				return a
			}
			return ""
		}
	}
	return ""
}

// docker run flags that take a separate value; short flags as letters.
var (
	dockerValueFlags = map[string]bool{
		"--name": true, "--volume": true, "--env": true, "--env-file": true, "--workdir": true, "--entrypoint": true, "--publish": true, "--network": true, "--net": true,
		"--user": true, "--mount": true, "--platform": true, "--pull": true, "--label": true, "--label-file": true, "--hostname": true, "--add-host": true, "--cap-add": true,
		"--cap-drop": true, "--device": true, "--dns": true, "--memory": true, "--memory-swap": true, "--cpus": true, "--cpu-shares": true, "--cpuset-cpus": true, "--shm-size": true,
		"--ulimit": true, "--security-opt": true, "--tmpfs": true, "--volumes-from": true, "--log-driver": true, "--log-opt": true, "--gpus": true, "--ipc": true, "--pid": true,
		"--restart": true, "--cidfile": true, "--link": true, "--expose": true, "--stop-signal": true, "--runtime": true, "--userns": true, "--group-add": true, "--uts": true,
		"--network-alias": true, "--cgroupns": true, "--health-cmd": true, "--stop-timeout": true, "--attach": true,
	}
	dockerBoolFlags = map[string]bool{
		"--rm": true, "--init": true, "--privileged": true, "--read-only": true, "--interactive": true, "--tty": true, "--detach": true, "--publish-all": true,
		"--quiet": true, "--no-healthcheck": true, "--oom-kill-disable": true,
	}
	dockerShortValue = "evwpuhlmca"
	dockerShortBool  = "itdPq"
)

// dockerRunImage returns the image of a docker run command, or "" when the
// command is not docker run or its arguments cannot be read with certainty.
func dockerRunImage(w []string) string {
	var args []string
	switch {
	case len(w) >= 3 && w[0] == "docker" && w[1] == "run":
		args = w[2:]
	case len(w) >= 4 && w[0] == "docker" && w[1] == "container" && w[2] == "run":
		args = w[3:]
	default:
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return ""
		case strings.HasPrefix(a, "--"):
			name, _, hasValue := strings.Cut(a, "=")
			switch {
			case hasValue && (dockerValueFlags[name] || dockerBoolFlags[name]):
			case dockerBoolFlags[a]:
			case dockerValueFlags[a]:
				i++
			default:
				return ""
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for k := 1; k < len(a); k++ {
				c := a[k]
				if strings.IndexByte(dockerShortBool, c) >= 0 {
					continue
				}
				if strings.IndexByte(dockerShortValue, c) >= 0 {
					if k == len(a)-1 {
						i++
					}
					break
				}
				return ""
			}
		default:
			return unquote(a)
		}
	}
	return ""
}

// imageUnpinned reports whether an image reference names a fixed image that
// is not pinned to a digest. Variables and expressions are never reported.
func imageUnpinned(img string, requireTag bool) bool {
	if img == "" || strings.ContainsAny(img, "$`{}") || digestRef.MatchString(img) || strings.Contains(img, "@") {
		return false
	}
	if strings.HasPrefix(img, "localhost/") || strings.HasPrefix(img, "localhost:") || strings.HasPrefix(img, "127.0.0.1:") {
		return false
	}
	if !imageRefRe.MatchString(img) {
		return false
	}
	last := img[strings.LastIndex(img, "/")+1:]
	return !requireTag || strings.Contains(last, ":")
}

var (
	buildTagRe   = regexp.MustCompile(`(?:^|\s)(?:-t|--tag)[=\s]+["']?([^\s"']+)`)
	dockerTagRe  = regexp.MustCompile(`docker\s+(?:image\s+)?tag\s+\S+\s+["']?([^\s"']+)`)
	dockerLoadRe = regexp.MustCompile(`docker\s+(?:image\s+)?(?:load|import)\b|docker\s+compose\s+build|docker-compose\s+build|docker\s+buildx\b|docker/build-push-action|docker/bake-action`)
)

func imageRepo(img string) string {
	last := strings.LastIndex(img, "/")
	if c := strings.LastIndex(img, ":"); c > last {
		return img[:c]
	}
	return img
}

func supplyChainSignals(f *inventory.File, coll string) []model.Signal {
	var out []model.Signal
	ls := significantLines(f)
	wfPerms, jobs := workflowJobs(ls)

	// Images the workflow builds, tags or loads itself are not pulled from
	// a registry by docker run.
	local := map[string]bool{}
	anyLoad := false
	for _, l := range f.Lines {
		for _, m := range buildTagRe.FindAllStringSubmatch(l, -1) {
			local[imageRepo(m[1])] = true
		}
		for _, m := range dockerTagRe.FindAllStringSubmatch(l, -1) {
			local[imageRepo(m[1])] = true
		}
		if dockerLoadRe.MatchString(l) {
			anyLoad = true
		}
	}
	image := func(line int, img, where string) {
		out = append(out, sig(lineRule{ID: "cicd.image-not-pinned", Control: "N-001", Title: "Container image not pinned to a digest", Severity: model.SevLow, Confidence: model.Confirmed, CWE: "CWE-829",
			Message: fmt.Sprintf("%s (%s) is referenced by a mutable tag; whoever can push that tag changes what runs in this workflow.", img, where),
			Fix:     "Reference the image by digest (image:tag@sha256:<digest>) and let Dependabot or Renovate update it."}, f, line, coll))
		out[len(out)-1].Key = img
	}

	for _, l := range ls {
		if m := inventory.UsesRe().FindStringSubmatch(l.text); m != nil && strings.HasPrefix(m[1], "docker://") {
			if img := strings.TrimPrefix(m[1], "docker://"); imageUnpinned(img, false) {
				image(l.n, img, "uses: docker://")
			}
		}
	}

	for _, j := range jobs {
		perms := wfPerms
		for i := j.start; i < j.end; i++ {
			if ls[i].indent != j.keyIndent {
				continue
			}
			key, val, _ := strings.Cut(ls[i].text, ":")
			val = stripYAMLComment(val)
			switch key {
			case "permissions":
				perms = parsePerms(ls, i)
			case "container":
				switch {
				case val == "":
					ce := childEnd(ls, i)
					for k := i + 1; k < ce; k++ {
						if ls[k].indent == ls[i+1].indent && strings.HasPrefix(ls[k].text, "image:") {
							if img := unquote(stripYAMLComment(strings.TrimPrefix(ls[k].text, "image:"))); imageUnpinned(img, false) {
								image(ls[k].n, img, "job container")
							}
						}
					}
				case strings.HasPrefix(val, "{"):
					if m := flowImageRe.FindStringSubmatch(val); m != nil && imageUnpinned(unquote(m[1]), false) {
						image(ls[i].n, unquote(m[1]), "job container")
					}
				default:
					if img := unquote(val); imageUnpinned(img, false) {
						image(ls[i].n, img, "job container")
					}
				}
			case "services":
				if val != "" {
					continue
				}
				se := childEnd(ls, i)
				for s := i + 1; s < se; s = childEnd(ls, s) {
					if _, sv, _ := strings.Cut(ls[s].text, ":"); strings.HasPrefix(strings.TrimSpace(sv), "{") {
						if m := flowImageRe.FindStringSubmatch(sv); m != nil && imageUnpinned(unquote(m[1]), false) {
							image(ls[s].n, unquote(m[1]), "service container")
						}
						continue
					}
					ce := childEnd(ls, s)
					for k := s + 1; k < ce; k++ {
						if ls[k].indent == ls[s+1].indent && strings.HasPrefix(ls[k].text, "image:") {
							if img := unquote(stripYAMLComment(strings.TrimPrefix(ls[k].text, "image:"))); imageUnpinned(img, false) {
								image(ls[k].n, img, "service container")
							}
						}
					}
				}
			}
		}

		for _, r := range runScripts(f, ls, j.start, j.end) {
			for _, w := range commands(r.text) {
				if img := dockerRunImage(w); img != "" && !anyLoad && !local[imageRepo(img)] && imageUnpinned(img, true) {
					image(r.n, img, "docker run")
				}
				if !perms.write {
					continue
				}
				sev := model.SevLow
				if perms.idToken {
					sev = model.SevMedium
				}
				pkgs, _ := floatingPkgs(w)
				if p := npxLatest(w); p != "" {
					pkgs = append(pkgs, p)
				}
				for _, p := range pkgs {
					out = append(out, sig(lineRule{ID: "cicd.unpinned-tool-install", Control: "N-001", Title: "Tool installed by a floating version in a privileged job", Severity: sev, Confidence: model.Confirmed, CWE: "CWE-829",
						Message: fmt.Sprintf("%s is installed without an exact version in a job that can write to the repository or packages, or mint OIDC tokens; the next release of that package runs with those permissions.", p),
						Fix:     "Install an exact version (name@x.y.z) and let Dependabot or Renovate update it, or move the install to a job without write or id-token permissions."}, f, r.n, coll))
					out[len(out)-1].Key = p
				}
			}
		}
	}
	return out
}
