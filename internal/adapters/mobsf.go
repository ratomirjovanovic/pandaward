package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// MobSFKeyEnv names the environment variable that holds the MobSF REST API
// key. The key is sent only to the configured loopback server and is never
// written to evidence, logs or reports.
const MobSFKeyEnv = "MOBSF_API_KEY"

// mobsfAdapter uploads the APKs and IPAs found in the project to a MobSF
// server the user runs on a loopback address, starts its static scan and
// maps the AppSec scorecard to K-006 (APK) and L-005 (IPA). The REST calls
// follow MobSF 4.5.3: /api/v1/upload, /api/v1/scan and /api/v1/scorecard.
type mobsfAdapter struct{}

func (mobsfAdapter) Name() string       { return "mobsf" }
func (mobsfAdapter) Controls() []string { return []string{"K-006", "L-005"} }
func (mobsfAdapter) Maturity() string   { return MaturityUnvalidated }
func (mobsfAdapter) Network() bool      { return false } // loopback only

// MobSFURL validates a configured MobSF address. Only http or https on
// localhost or a loopback IP is accepted, so packages and the API key never
// leave the machine.
func MobSFURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("scan.mobsf_url %q is not a URL such as http://127.0.0.1:8000", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scan.mobsf_url must use http or https, not %q", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("scan.mobsf_url must not contain credentials; put the API key in " + MobSFKeyEnv)
	}
	h := u.Hostname()
	if ip := net.ParseIP(h); !(strings.EqualFold(h, "localhost") || ip != nil && ip.IsLoopback()) {
		return nil, fmt.Errorf("scan.mobsf_url host %q is not a loopback address; PandaWard only talks to a MobSF server on this machine", h)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}

func (a mobsfAdapter) Run(ctx context.Context, c *Context) (Result, model.Run) {
	res := Result{Decisions: map[string]Decision{}}
	run := newRun(a.Name(), "")
	if c.Cfg.Scan.MobSFURL == "" {
		return res, finish(run, model.ExitBlocked, "scan.mobsf_url is not set; run MobSF on a loopback address (optional) and set it", 0)
	}
	base, err := MobSFURL(c.Cfg.Scan.MobSFURL)
	if err != nil {
		return res, finish(run, model.ExitBlocked, err.Error(), 0)
	}
	key := os.Getenv(MobSFKeyEnv)
	if key == "" {
		return res, finish(run, model.ExitBlocked, MobSFKeyEnv+" is not set; export the MobSF REST API key", 0)
	}
	type pkg struct{ rel, control string }
	var pkgs []pkg
	for _, rel := range c.Inv.Features["apk"] {
		pkgs = append(pkgs, pkg{rel, "K-006"})
	}
	for _, rel := range c.Inv.Features["ipa"] {
		pkgs = append(pkgs, pkg{rel, "L-005"})
	}
	if len(pkgs) == 0 {
		return res, finish(run, model.ExitUnsupported, "no .apk or .ipa files in the project", 0)
	}
	cl := newMobSFClient(base, key)
	// Error text can quote a response; make sure it never carries the key.
	fail := func(class, detail string) (Result, model.Run) {
		return res, finish(run, class, strings.ReplaceAll(detail, key, "[REDACTED]"), len(res.Signals))
	}
	for i, p := range pkgs {
		cctx, cancel := context.WithTimeout(ctx, c.Timeout)
		card, raw, err := cl.analyze(cctx, filepath.Join(c.Root, filepath.FromSlash(p.rel)))
		timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
		cancel()
		if timedOut {
			return fail(model.ExitTimeout, fmt.Sprintf("MobSF exceeded %s on %s", c.Timeout, p.rel))
		}
		if err != nil {
			return fail(model.ExitError, "MobSF could not analyze "+p.rel+": "+err.Error())
		}
		_ = os.WriteFile(filepath.Join(c.RunDir, fmt.Sprintf("mobsf-%d.json", i)), mobsfRaw(raw, key), 0o600)
		if run.ToolVersion == "" {
			run.ToolVersion = card.Version
		}
		res.Signals = append(res.Signals, mobsfSignals(card, p.rel, p.control, a.Name())...)
	}
	return res, finish(run, model.ExitOK, fmt.Sprintf("%d package(s) analyzed by MobSF %s", len(pkgs), run.ToolVersion), len(res.Signals))
}

// mobsfScorecard is the /api/v1/scorecard response (MobSF 4.5.3,
// StaticAnalyzer/views/common/appsec.py).
type mobsfScorecard struct {
	High    []mobsfItem `json:"high"`
	Warning []mobsfItem `json:"warning"`
	Info    []mobsfItem `json:"info"`
	Secure  []mobsfItem `json:"secure"`
	Hotspot []mobsfItem `json:"hotspot"`
	Hash    string      `json:"hash"`
	Version string      `json:"version"`
	// Package is the Android package name from the scan report; the
	// scorecard does not carry it.
	Package string `json:"-"`
}

type mobsfItem struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Section     string `json:"section"`
}

func parseMobSFScorecard(b []byte) (*mobsfScorecard, error) {
	var card mobsfScorecard
	if err := json.Unmarshal(b, &card); err != nil {
		return nil, fmt.Errorf("unexpected scorecard: %w", err)
	}
	if card.Hash == "" {
		return nil, errors.New("unexpected scorecard: no hash")
	}
	return &card, nil
}

// mobsfRaw prepares a scorecard for the private run directory: whole and
// valid JSON (line redaction would cut it at the snippet length), without
// the API key, and without the descriptions of the secrets section, which
// list the candidate secrets themselves.
func mobsfRaw(raw []byte, key string) []byte {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []byte(redact.Text(strings.ReplaceAll(string(raw), key, "[REDACTED]")))
	}
	for _, v := range doc {
		items, _ := v.([]any)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok && m["section"] == "secrets" {
				m["description"] = "[omitted by PandaWard: candidate secrets]"
			}
		}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil
	}
	return []byte(strings.ReplaceAll(string(b), key, "[REDACTED]"))
}

var htmlTagRe = regexp.MustCompile(`<[^>]{1,40}>`)

// mobsfSignals maps a scorecard to signals. MobSF reports a severity but no
// confidence, so every finding is a hypothesis: high and warning make the
// control SUSPECTED, info and hotspot items are listed for review, secure
// items are dropped. A code finding whose files all lie outside the app's
// own package namespace is listed for review too: it is in bundled library
// code the app's developers do not write.
func mobsfSignals(card *mobsfScorecard, file, control, collector string) []model.Signal {
	var out []model.Signal
	for _, g := range []struct {
		items []mobsfItem
		sev   model.Severity
	}{{card.High, model.SevHigh}, {card.Warning, model.SevMedium}, {card.Hotspot, model.SevInfo}, {card.Info, model.SevInfo}} {
		for _, it := range g.items {
			title := redact.Line(strings.TrimSpace(htmlTagRe.ReplaceAllString(it.Title, "")))
			if title == "" {
				continue
			}
			section := strings.ToLower(redact.Line(it.Section))
			if section == "" {
				section = "other"
			}
			msg := "MobSF static analysis (" + section + "). "
			if section == "secrets" {
				// The description lists the candidate secrets themselves.
				msg += "MobSF found strings that may be hardcoded secrets; open the MobSF report to review them."
			} else {
				msg += redact.Line(strings.Join(strings.Fields(htmlTagRe.ReplaceAllString(it.Description, " ")), " "))
			}
			sev := g.sev
			if section == "code" && sev != model.SevInfo && onlyLibraryCode(it.Description, card.Package) {
				sev = model.SevInfo
				msg = "Only in bundled library code, outside " + redact.Line(card.Package) + ". " + msg
			}
			out = append(out, model.Signal{RuleID: "mobsf." + section, ControlID: control, Title: title, Severity: sev, Confidence: model.Hypothesis,
				File: file, Message: msg, Fix: "Review the finding in the MobSF report for this package and fix it in the source or build configuration.", Collector: collector, Key: title})
		}
	}
	return out
}

// onlyLibraryCode reports whether every file a MobSF code finding lists is
// outside the app's namespace, taken as the first two segments of its
// package (com.example.app -> com/example/), so code in sibling packages of
// the same vendor still counts as the app's. Without a package or a file
// list it reports false and the finding keeps its severity.
func onlyLibraryCode(desc, pkg string) bool {
	segs := strings.Split(pkg, ".")
	if pkg == "" || len(segs) == 0 {
		return false
	}
	if len(segs) > 2 {
		segs = segs[:2]
	}
	ns := strings.Join(segs, "/") + "/"
	_, files, ok := strings.Cut(desc, "\nFiles:\n")
	if !ok {
		return false
	}
	n := 0
	for _, l := range strings.Split(files, "\n") {
		path, _, _ := strings.Cut(strings.TrimSpace(l), ", line(s)")
		if path == "" {
			continue
		}
		n++
		if strings.HasPrefix(path, ns) {
			return false
		}
	}
	return n > 0
}

// mobsfClient talks to one MobSF server. It ignores proxy settings and does
// not follow redirects, so requests cannot leave the loopback address.
type mobsfClient struct {
	base *url.URL
	key  string
	http *http.Client
}

func newMobSFClient(base *url.URL, key string) *mobsfClient {
	return &mobsfClient{base: base, key: key, http: &http.Client{
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// analyze uploads one package, runs the static scan and returns the
// scorecard and its raw JSON.
func (m *mobsfClient) analyze(ctx context.Context, path string) (*mobsfScorecard, []byte, error) {
	var up struct {
		Hash string `json:"hash"`
	}
	if err := m.upload(ctx, path, &up); err != nil {
		return nil, nil, err
	}
	if up.Hash == "" {
		return nil, nil, errors.New("upload returned no hash")
	}
	form := url.Values{"hash": {up.Hash}}
	scan, err := m.post(ctx, "scan", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), 0)
	if err != nil {
		return nil, nil, err
	}
	var rep struct {
		Package string `json:"package_name"`
	}
	_ = json.Unmarshal(scan, &rep) // an IPA report has no package_name
	raw, err := m.post(ctx, "scorecard", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), 0)
	if err != nil {
		return nil, nil, err
	}
	card, err := parseMobSFScorecard(raw)
	if card != nil {
		card.Package = rep.Package
	}
	return card, raw, err
}

// upload sends one package as multipart form data. MobSF runs Django under
// gunicorn, which reads no body without a Content-Length, so the length is
// computed up front and the file is streamed rather than chunked.
func (m *mobsfClient) upload(ctx context.Context, path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	var head, tail bytes.Buffer
	mw := multipart.NewWriter(&head)
	if _, err := mw.CreateFormFile("file", filepath.Base(path)); err != nil {
		return err
	}
	tw := multipart.NewWriter(&tail)
	if err := tw.SetBoundary(mw.Boundary()); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	// The closing delimiter starts with CRLF, which ends the file part.
	size := int64(head.Len()) + fi.Size() + int64(tail.Len())
	body := io.MultiReader(&head, io.LimitReader(f, fi.Size()), &tail)
	b, err := m.post(ctx, "upload", mw.FormDataContentType(), body, size)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unexpected upload response: %w", err)
	}
	return nil
}

// post sends one API request. size sets the Content-Length when the body
// cannot report it; 0 leaves it to net/http.
func (m *mobsfClient) post(ctx context.Context, endpoint, contentType string, body io.Reader, size int64) ([]byte, error) {
	u := *m.base
	u.Path += "/api/v1/" + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return nil, err
	}
	if size > 0 {
		req.ContentLength = size
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Mobsf-Api-Key", m.key)
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&limitedBuffer{b: &buf, max: 64 << 20}, resp.Body); err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("%s: MobSF rejected the API key in %s (401)", endpoint, MobSFKeyEnv)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(buf.Bytes(), &e)
		why := e.Error
		if why == "" {
			why = firstLine(buf.String())
		}
		return nil, fmt.Errorf("%s returned %d: %s", endpoint, resp.StatusCode, why)
	}
	return buf.Bytes(), nil
}
