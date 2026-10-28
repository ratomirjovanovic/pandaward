package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/config"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
)

// SARIFImport is the adapter that imports results of analyzers the user ran
// themselves. PenSec never runs those tools; it only reads their SARIF files.
const SARIFImport = "sarif-import"

// SARIFDir holds SARIF files that are imported without configuration.
const SARIFDir = ".pensec/sarif"

const sarifControl = "R-002"

var (
	// sarifMaxBytes caps one SARIF file; a variable so tests can lower it.
	sarifMaxBytes int64 = 50 << 20
	// sarifMaxResults caps the results of one import. Going over is an
	// error, never a silent cut that would remediate the dropped results.
	sarifMaxResults = 20000
)

// SARIFInputs lists the SARIF files to import as slash-separated paths:
// every *.sarif and *.sarif.json in .pensec/sarif, then scan.sarif_files.
// Configured paths are listed even when they are missing or unsafe, so the
// adapter reports them as an error instead of skipping them silently.
func SARIFInputs(root string, cfg *config.Config) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if ents, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(SARIFDir))); err == nil {
		var names []string
		for _, e := range ents {
			n := strings.ToLower(e.Name())
			if !e.IsDir() && (strings.HasSuffix(n, ".sarif") || strings.HasSuffix(n, ".sarif.json")) {
				names = append(names, SARIFDir+"/"+e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			add(n)
		}
	}
	if cfg != nil {
		for _, p := range cfg.Scan.SARIFFiles {
			if strings.TrimSpace(p) == "" {
				continue
			}
			add(filepath.ToSlash(filepath.Clean(p)))
		}
	}
	return out
}

type sarifAdapter struct{}

func (sarifAdapter) Name() string       { return SARIFImport }
func (sarifAdapter) Controls() []string { return []string{sarifControl} }
func (sarifAdapter) Maturity() string   { return MaturityUnvalidated }
func (sarifAdapter) Network() bool      { return false }

func (sarifAdapter) Run(ctx context.Context, c *Context) (Result, model.Run) {
	res := Result{Decisions: map[string]Decision{}}
	run := newRun(SARIFImport, "")
	fail := func(why string) (Result, model.Run) { return Result{}, finish(run, model.ExitError, why, 0) }
	inputs := SARIFInputs(c.Root, c.Cfg)
	if len(inputs) == 0 {
		return res, finish(run, model.ExitOK, "no SARIF files to import", 0)
	}
	var tools, skipped []string
	for _, in := range inputs {
		if err := ctx.Err(); err != nil {
			return fail(err.Error())
		}
		raw, err := readSARIF(c.Root, in)
		if err != nil {
			return fail(in + ": " + err.Error())
		}
		imp, err := parseSARIF(c, in, raw)
		if err != nil {
			return fail(in + ": not valid SARIF 2.1.0: " + err.Error())
		}
		res.Signals = append(res.Signals, imp.signals...)
		if len(res.Signals) > sarifMaxResults {
			return fail(fmt.Sprintf("more than %d results to import; split or filter the SARIF files", sarifMaxResults))
		}
		tools = append(tools, imp.tools...)
		if imp.skipped > 0 {
			skipped = append(skipped, fmt.Sprintf("%d in %s", imp.skipped, in))
		}
	}
	run.ToolVersion = redact.Line(strings.Join(uniq(tools), ", "))
	detail := fmt.Sprintf("imported %d result(s) from %d file(s) [%s]", len(res.Signals), len(inputs), run.ToolVersion)
	if len(skipped) > 0 {
		detail += "; skipped suppressed, absent or non-failing results: " + strings.Join(skipped, ", ")
	}
	return res, finish(run, model.ExitOK, detail, len(res.Signals))
}

var errTooLarge = errors.New("file is larger than the SARIF size limit (50 MiB)")

// readSARIF reads one input file. It must be a regular file inside the
// project root, reached without following any symlink, and within the cap.
func readSARIF(root, rel string) ([]byte, error) {
	p := filepath.FromSlash(rel)
	if filepath.IsAbs(p) {
		r, err := filepath.Rel(root, p)
		if err != nil {
			return nil, errors.New("path is outside the project root")
		}
		p = r
	}
	p = filepath.Clean(p)
	if p == "." || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) || filepath.IsAbs(p) || filepath.VolumeName(p) != "" {
		return nil, errors.New("path is outside the project root")
	}
	cur := root
	var st os.FileInfo
	parts := strings.Split(p, string(filepath.Separator))
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		var err error
		st, err = os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("file does not exist")
		}
		if err != nil {
			return nil, errors.New("cannot read file")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("path goes through a symlink; symlinks are not followed")
		}
		// Junctions and other reparse points are neither directories nor
		// regular files here, so they are refused like symlinks.
		if i < len(parts)-1 && !st.IsDir() {
			return nil, errors.New("path goes through something that is not a directory")
		}
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > sarifMaxBytes {
		return nil, errTooLarge
	}
	f, err := os.Open(cur)
	if err != nil {
		return nil, errors.New("cannot read file")
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(fi, st) {
		return nil, errors.New("file changed while it was opened")
	}
	b, err := io.ReadAll(io.LimitReader(f, sarifMaxBytes+1))
	if err != nil {
		return nil, errors.New("cannot read file")
	}
	if int64(len(b)) > sarifMaxBytes {
		return nil, errTooLarge
	}
	return b, nil
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity any      `json:"security-severity"`
	CWE              any      `json:"cwe"`
}

type sarifRule struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	ShortDescription     sarifText `json:"shortDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties sarifProps `json:"properties"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
	Index     *int   `json:"index"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Rule      *struct {
		ID    string `json:"id"`
		Index *int   `json:"index"`
	} `json:"rule"`
	Level     string    `json:"level"`
	Kind      string    `json:"kind"`
	Message   sarifText `json:"message"`
	Locations []struct {
		PhysicalLocation *struct {
			ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
			Region           struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Suppressions []struct {
		Status string `json:"status"`
	} `json:"suppressions"`
	BaselineState string     `json:"baselineState"`
	Properties    sarifProps `json:"properties"`
}

type sarifRun struct {
	Tool *struct {
		Driver struct {
			Name            string      `json:"name"`
			Version         string      `json:"version"`
			SemanticVersion string      `json:"semanticVersion"`
			Rules           []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds"`
	Artifacts          []struct {
		Location sarifArtifactLocation `json:"location"`
	} `json:"artifacts"`
	Results []sarifResult `json:"results"`
}

type sarifImportResult struct {
	signals []model.Signal
	tools   []string
	skipped int
}

// parseSARIF turns one SARIF log into signals. Everything in it is
// untrusted: text is redacted, locations must resolve inside the root, and
// snippets come from PenSec's own read of the file, never from the log.
func parseSARIF(c *Context, file string, raw []byte) (sarifImportResult, error) {
	var out sarifImportResult
	var doc struct {
		Version *string    `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return out, err
	}
	if dec.More() {
		return out, errors.New("trailing data after the SARIF log")
	}
	if doc.Version == nil || *doc.Version != "2.1.0" {
		return out, errors.New(`"version" must be "2.1.0"`)
	}
	if doc.Runs == nil {
		return out, errors.New(`missing "runs"`)
	}
	for i, r := range doc.Runs {
		if r.Tool == nil || strings.TrimSpace(r.Tool.Driver.Name) == "" {
			return out, fmt.Errorf("run %d has no tool.driver.name", i)
		}
		d := r.Tool.Driver
		// PenSec's own SARIF report must not be imported back as new findings.
		if strings.EqualFold(d.Name, "PenSec") {
			out.skipped += len(r.Results)
			continue
		}
		ver := d.Version
		if ver == "" {
			ver = d.SemanticVersion
		}
		out.tools = append(out.tools, strings.TrimSpace(redact.Line(d.Name+" "+ver)))
		toolID := sarifID(d.Name, false)
		for _, res := range r.Results {
			switch res.Kind {
			case "pass", "notApplicable", "informational":
				out.skipped++
				continue
			}
			if res.BaselineState == "absent" || suppressed(res) {
				out.skipped++
				continue
			}
			rule := lookupRule(d.Rules, res)
			ruleID := res.RuleID
			if ruleID == "" && res.Rule != nil {
				ruleID = res.Rule.ID
			}
			if ruleID == "" && rule != nil {
				ruleID = rule.ID
			}
			title := ruleID
			if rule != nil {
				switch {
				case rule.ShortDescription.Text != "":
					title = rule.ShortDescription.Text
				case rule.Name != "":
					title = rule.Name
				}
			}
			msg := res.Message.Text
			if msg == "" {
				msg = title
			}
			s := model.Signal{RuleID: "sarif." + toolID + "." + sarifID(ruleID, true), ControlID: sarifControl, Title: redact.Line(d.Name + ": " + title),
				Severity: sarifSeverity(res, rule), Confidence: model.Hypothesis, CWE: sarifCWE(res, rule), Message: redact.Line(msg),
				Fix:       redact.Line("Review this " + d.Name + " result and fix it in the code, or record a false positive. Imported from " + file + "; PenSec did not verify it."),
				Collector: SARIFImport}
			if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
				pl := res.Locations[0].PhysicalLocation
				loc := pl.ArtifactLocation
				if loc.URI == "" && loc.Index != nil && *loc.Index >= 0 && *loc.Index < len(r.Artifacts) {
					loc = r.Artifacts[*loc.Index].Location
				}
				s.File = resolveURI(c.Root, loc, r.OriginalURIBaseIDs)
				if s.File != "" && s.File != "(outside-root)" && pl.Region.StartLine > 0 {
					s.StartLine, s.EndLine = pl.Region.StartLine, pl.Region.EndLine
					if s.EndLine < s.StartLine {
						s.EndLine = s.StartLine
					}
					if c.Inv != nil {
						if f := c.Inv.FileByPath(s.File); f != nil && s.StartLine <= len(f.Lines) {
							s.Snippet = redact.Line(strings.TrimSpace(f.Lines[s.StartLine-1]))
						}
					}
				}
			}
			out.signals = append(out.signals, s)
		}
	}
	return out, nil
}

func lookupRule(rules []sarifRule, res sarifResult) *sarifRule {
	idx := res.RuleIndex
	if idx == nil && res.Rule != nil {
		idx = res.Rule.Index
	}
	if idx != nil && *idx >= 0 && *idx < len(rules) {
		return &rules[*idx]
	}
	id := res.RuleID
	if id == "" && res.Rule != nil {
		id = res.Rule.ID
	}
	for i := range rules {
		if id != "" && rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

// suppressed follows SARIF: a result with suppressions is suppressed unless
// every suppression is under review or rejected.
func suppressed(res sarifResult) bool {
	for _, s := range res.Suppressions {
		if s.Status == "" || s.Status == "accepted" {
			return true
		}
	}
	return false
}

var nonIDChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// sarifID normalises a tool or rule name into a rule ID segment. Dots are
// kept in rule names but not in the tool name, so the tool segment of
// sarif.<tool>.<rule> is unambiguous.
func sarifID(s string, dots bool) string {
	s = strings.ToLower(redact.Sanitize(s))
	if !dots {
		s = strings.ReplaceAll(s, ".", "-")
	}
	s = strings.Trim(nonIDChars.ReplaceAllString(s, "-"), "-.")
	if len(s) > 96 {
		s = strings.TrimRight(s[:96], "-.")
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// sarifSeverity prefers the numeric security-severity property (as used by
// CodeQL and GitHub code scanning) over the SARIF level.
func sarifSeverity(res sarifResult, rule *sarifRule) model.Severity {
	ss := res.Properties.SecuritySeverity
	if ss == nil && rule != nil {
		ss = rule.Properties.SecuritySeverity
	}
	if ss != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(ss)), 64); err == nil {
			switch {
			case v >= 9:
				return model.SevCritical
			case v >= 7:
				return model.SevHigh
			case v >= 4:
				return model.SevMedium
			case v > 0:
				return model.SevLow
			}
			return model.SevInfo
		}
	}
	lvl := res.Level
	if lvl == "" && rule != nil {
		lvl = rule.DefaultConfiguration.Level
	}
	switch lvl {
	case "error":
		return model.SevHigh
	case "note":
		return model.SevLow
	case "none":
		return model.SevInfo
	}
	return model.SevMedium // SARIF's default level is warning
}

var sarifCWERe = regexp.MustCompile(`(?i)\bcwe[-/:_ ]?0*([0-9]+)\b`)

func sarifCWE(res sarifResult, rule *sarifRule) string {
	var cands []string
	for _, p := range []*sarifProps{&res.Properties, ruleProps(rule)} {
		if p == nil {
			continue
		}
		cands = append(cands, p.Tags...)
		if p.CWE != nil {
			cands = append(cands, fmt.Sprint(p.CWE))
		}
	}
	for _, c := range cands {
		if m := sarifCWERe.FindStringSubmatch(c); m != nil {
			return "CWE-" + m[1]
		}
	}
	return ""
}

func ruleProps(r *sarifRule) *sarifProps {
	if r == nil {
		return nil
	}
	return &r.Properties
}

// resolveURI maps a SARIF artifact location to a slash path relative to the
// root. Relative URIs, uriBaseId chains and file:// URIs are supported; a
// base without a known value counts as the project root (as %SRCROOT% does).
// Anything that resolves outside the root becomes "(outside-root)".
func resolveURI(root string, loc sarifArtifactLocation, bases map[string]sarifArtifactLocation) string {
	p, abs, ok := uriPath(loc.URI)
	if !ok || p == "" {
		return ""
	}
	base := loc.URIBaseID
	for depth := 0; !abs && base != "" && depth < 8; depth++ {
		b, known := bases[base]
		if !known {
			break
		}
		bp, babs, ok := uriPath(b.URI)
		if !ok {
			return ""
		}
		p, abs, base = path.Join(bp, p), babs, b.URIBaseID
	}
	p = path.Clean(p)
	if p == "." || p == "/" {
		return ""
	}
	fp := filepath.FromSlash(p)
	if abs != filepath.IsAbs(fp) {
		// An absolute path of another platform cannot be inside this root.
		return "(outside-root)"
	}
	return relPath(root, fp)
}

// uriPath decodes a SARIF URI into a slash path and whether it is absolute.
// Only relative references and file URIs name files.
func uriPath(s string) (string, bool, bool) {
	if s == "" {
		return "", false, true
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false, false
	}
	switch strings.ToLower(u.Scheme) {
	case "":
		return u.Path, path.IsAbs(u.Path), true
	case "file":
		p := u.Path
		// file:///C:/x is "/C:/x"; drop the slash before a drive letter.
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		return p, true, true
	}
	return "", false, false
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
