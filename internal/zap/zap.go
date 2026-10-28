// Package zap runs a user-installed OWASP ZAP through its automation
// framework, chained to the Pandaward scope guard, and reads its JSON report.
// Pandaward never installs or downloads ZAP.
package zap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

// DefaultMinutes bounds each ZAP job when the manifest does not.
const DefaultMinutes = 10

// launchers are the names ZAP installs under.
var launchers = []string{"zap.sh", "zap.bat", "zaproxy", "zap"}

// installDirs are the default install locations per platform.
func installDirs() []string {
	switch runtime.GOOS {
	case "windows":
		var out []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
			if d := os.Getenv(env); d != "" {
				out = append(out, filepath.Join(d, "ZAP", "Zed Attack Proxy", "zap.bat"), filepath.Join(d, "Programs", "ZAP", "Zed Attack Proxy", "zap.bat"))
			}
		}
		return out
	case "darwin":
		return []string{"/Applications/ZAP.app/Contents/Java/zap.sh"}
	}
	return []string{"/usr/share/zaproxy/zap.sh", "/opt/zaproxy/zap.sh", "/snap/bin/zaproxy"}
}

// Locate finds the ZAP launcher: the configured path, then PATH, then the
// default install locations.
func Locate(configured string) (string, error) {
	if configured != "" {
		if st, err := os.Stat(configured); err == nil && !st.IsDir() {
			return filepath.Abs(configured)
		}
		return "", fmt.Errorf("runtime.zap_path %s does not exist", configured)
	}
	for _, n := range launchers {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	for _, p := range installDirs() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("ZAP is not installed (optional; install it from zaproxy.org and make sure Java 17+ is available, or set runtime.zap_path in .pandaward/config.yaml)")
}

var jarRe = regexp.MustCompile(`^zap-(\d+\.\d+\.\d+)\.jar$`)

// Version reads the version from the ZAP jar next to the launcher, so no
// JVM has to start. It returns "" when unknown.
func Version(launcher string) string {
	dir := filepath.Dir(launcher)
	if real, err := filepath.EvalSymlinks(launcher); err == nil {
		dir = filepath.Dir(real)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if m := jarRe.FindStringSubmatch(e.Name()); m != nil {
			return m[1]
		}
	}
	return ""
}

// Options for one ZAP run.
type Options struct {
	Launcher string
	Manifest *scope.Manifest
	Guard    *scope.Guard
	WorkDir  string // private directory for the plan, ZAP home and report
	Active   bool   // add the active scan job
	Minutes  int    // per-job limit
	Progress func(string)
}

// Result of one ZAP run.
type Result struct {
	Version  string
	ExitCode int
	Alerts   []Alert
	Report   string // path of the raw report in WorkDir
}

// Alert is one ZAP alert type on one site, with its instances.
type Alert struct {
	Site       string
	PluginID   string
	Name       string
	Risk       int // 0 info, 1 low, 2 medium, 3 high
	Confidence int // 0 false positive, 1 low, 2 medium, 3 high, 4 confirmed
	CWE        int
	Desc       string
	Solution   string
	Instances  []Instance
}

// Instance is one place an alert was raised.
type Instance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// Run writes the automation plan, starts ZAP chained to a guard proxy and
// parses the report. Any failure is returned as an error: a ZAP run that
// did not complete must never be read as a clean result.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Minutes <= 0 {
		o.Minutes = DefaultMinutes
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	home := filepath.Join(o.WorkDir, "zap-home")
	reportDir := filepath.Join(o.WorkDir, "zap-report")
	for _, d := range []string{home, reportDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	plan, err := Plan(o.Manifest, reportDir, o.Active, o.Minutes)
	if err != nil {
		return nil, err
	}
	planPath := filepath.Join(o.WorkDir, "zap-plan.yaml")
	if err := os.WriteFile(planPath, plan, 0o600); err != nil {
		return nil, err
	}
	px, err := StartProxy(o.Manifest, o.Guard)
	if err != nil {
		return nil, err
	}
	defer px.Close()

	jobs := 3
	if o.Active {
		jobs++
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(jobs*o.Minutes+5)*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, o.Launcher, Args(home, planPath, px.Port())...)
	cmd.Dir = filepath.Dir(o.Launcher)
	cmd.Env = env(home)
	var stderr bytes.Buffer
	cmd.Stderr = &capped{b: &stderr, max: 1 << 20}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	res := &Result{Version: Version(o.Launcher)}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start ZAP: %w", err)
	}
	var log bytes.Buffer
	sc := bufio.NewScanner(io.TeeReader(out, &capped{b: &log, max: 4 << 20}))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			o.Progress(redact.Line(l))
		}
	}
	err = cmd.Wait()
	_ = os.WriteFile(filepath.Join(o.WorkDir, "zap-output.txt"), []byte(redact.Text(log.String()+"\n"+stderr.String())), 0o600)
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("ZAP did not finish within %d minutes", jobs*o.Minutes+5)
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, err
		}
		res.ExitCode = ee.ExitCode()
	}
	// The automation framework exits 0 on success and 2 when a job only
	// raised warnings; 1 means a job failed.
	if res.ExitCode != 0 && res.ExitCode != 2 {
		return nil, fmt.Errorf("ZAP exited %d: %s", res.ExitCode, lastLine(log.String()+"\n"+stderr.String()))
	}
	res.Report = filepath.Join(reportDir, "zap.json")
	raw, err := os.ReadFile(res.Report)
	if err != nil {
		return nil, fmt.Errorf("ZAP wrote no report (%v): %s", err, lastLine(log.String()))
	}
	if res.Alerts, err = ParseReport(raw); err != nil {
		return nil, fmt.Errorf("could not read the ZAP report: %w", err)
	}
	return res, nil
}

// Args is the ZAP command line: headless, no update checks or other
// unsolicited requests, a disposable home, and every connection chained
// to the guard proxy on loopback.
func Args(home, plan string, port int) []string {
	p := strconv.Itoa(port)
	return []string{"-cmd", "-silent", "-dir", home, "-autorun", plan,
		"-config", "network.connection.httpProxy.enabled=true",
		"-config", "network.connection.httpProxy.host=127.0.0.1",
		"-config", "network.connection.httpProxy.port=" + p,
	}
}

// env keeps the scrubbed tool environment plus what the JVM needs.
func env(home string) []string {
	var out []string
	for _, kv := range inventory.MinimalEnv() {
		switch strings.ToUpper(strings.SplitN(kv, "=", 2)[0]) {
		case "HOME", "USERPROFILE":
			continue
		}
		out = append(out, kv)
	}
	if j := os.Getenv("JAVA_HOME"); j != "" {
		out = append(out, "JAVA_HOME="+j)
	}
	return append(out, "HOME="+home, "USERPROFILE="+home)
}

type planDoc struct {
	Env  planEnv   `yaml:"env"`
	Jobs []planJob `yaml:"jobs"`
}

type planEnv struct {
	Contexts   []planContext  `yaml:"contexts"`
	Parameters map[string]any `yaml:"parameters"`
}

type planContext struct {
	Name         string   `yaml:"name"`
	URLs         []string `yaml:"urls"`
	IncludePaths []string `yaml:"includePaths"`
	ExcludePaths []string `yaml:"excludePaths,omitempty"`
}

type planJob struct {
	Type       string         `yaml:"type"`
	Parameters map[string]any `yaml:"parameters,omitempty"`
}

// Plan builds the automation framework plan: a context limited to the
// manifest targets minus excluded paths, the traditional spider, a wait for
// the passive scanner, the active scan only when asked, and a JSON report.
func Plan(m *scope.Manifest, reportDir string, active bool, minutes int) ([]byte, error) {
	c := planContext{Name: "pandaward"}
	for _, t := range m.Targets {
		u, err := scope.ParseTarget(t.URL)
		if err != nil {
			return nil, err
		}
		base := strings.TrimSuffix(u.Scheme+"://"+u.Host+u.EscapedPath(), "/")
		c.URLs = append(c.URLs, base+"/")
		c.IncludePaths = append(c.IncludePaths, "^"+regexp.QuoteMeta(base)+"([/?#].*)?$")
		for _, ex := range m.ExcludedPaths {
			if ex == "" {
				continue
			}
			c.ExcludePaths = append(c.ExcludePaths, "^"+regexp.QuoteMeta(u.Scheme+"://"+u.Host+strings.TrimSuffix(ex, "/"))+"([/?#].*)?$")
		}
	}
	jobs := []planJob{
		{Type: "passiveScan-config", Parameters: map[string]any{"scanOnlyInScope": true, "maxAlertsPerRule": 10, "enableTags": false}},
		{Type: "spider", Parameters: map[string]any{"context": "pandaward", "maxDuration": minutes, "maxDepth": 5, "maxChildren": 50, "acceptCookies": false, "handleODataParametersVisited": false}},
		{Type: "passiveScan-wait", Parameters: map[string]any{"maxDuration": minutes}},
	}
	if active {
		jobs = append(jobs, planJob{Type: "activeScan", Parameters: map[string]any{"context": "pandaward", "maxScanDurationInMins": minutes, "maxRuleDurationInMins": 2, "threadPerHost": 1}})
	}
	jobs = append(jobs, planJob{Type: "report", Parameters: map[string]any{"template": "traditional-json", "reportDir": reportDir, "reportFile": "zap", "reportTitle": "Pandaward ZAP run"}})
	doc := planDoc{Env: planEnv{Contexts: []planContext{c}, Parameters: map[string]any{"failOnError": true, "failOnWarning": false, "progressToStdout": true}}, Jobs: jobs}
	return yaml.Marshal(doc)
}

// report is the traditional-json layout.
type report struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID   string     `json:"pluginid"`
			Name       string     `json:"alert"`
			Risk       string     `json:"riskcode"`
			Confidence string     `json:"confidence"`
			CWE        string     `json:"cweid"`
			Desc       string     `json:"desc"`
			Solution   string     `json:"solution"`
			Instances  []Instance `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// ParseReport reads a traditional-json report.
func ParseReport(raw []byte) ([]Alert, error) {
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	var out []Alert
	for _, s := range r.Site {
		for _, a := range s.Alerts {
			al := Alert{Site: s.Name, PluginID: a.PluginID, Name: a.Name, Desc: text(a.Desc), Solution: text(a.Solution), Instances: a.Instances}
			al.Risk, _ = strconv.Atoi(a.Risk)
			al.Confidence, _ = strconv.Atoi(a.Confidence)
			al.CWE, _ = strconv.Atoi(a.CWE)
			out = append(out, al)
		}
	}
	return out, nil
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

// text turns ZAP's HTML fragments into one plain line.
func text(s string) string {
	return strings.Join(strings.Fields(tagRe.ReplaceAllString(s, " ")), " ")
}

// Origin returns scheme://host[:port] of a URL, or the input when it does
// not parse.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

func lastLine(s string) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	return redact.Line(strings.TrimSpace(ls[len(ls)-1]))
}

type capped struct {
	b   *bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if c.b.Len() < c.max {
		n := c.max - c.b.Len()
		if n > len(p) {
			n = len(p)
		}
		c.b.Write(p[:n])
	}
	return len(p), nil
}
