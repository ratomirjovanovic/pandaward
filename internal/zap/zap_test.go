package zap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

func manifest(t *testing.T, extra string, targets ...string) *scope.Manifest {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".pandaward"), 0o755); err != nil {
		t.Fatal(err)
	}
	var ts []string
	for _, u := range targets {
		ts = append(ts, "  - url: "+u)
	}
	y := strings.NewReplacer(
		`owner: ""`, `owner: "Fixture Owner"`,
		`reference: ""`, `reference: "TEST-1"`,
		`purpose: ""`, `purpose: "unit test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n"+strings.Join(ts, "\n"),
		"allow_private_addresses: false", "allow_private_addresses: true",
		"max_requests_total: 20", "max_requests_total: 200",
		"requests_per_second: 1", "requests_per_second: 10",
		"excluded_paths: []", "excluded_paths: [/private]",
	).Replace(scope.Template) + extra
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := scope.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// fixtureSite serves a page that links to an in-scope page, an excluded
// path and a page on another origin.
func fixtureSite(t *testing.T, outside string) (*httptest.Server, *int64) {
	var hits int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/about">about</a> <a href="/private/x">private</a> <a href="%s/steal">elsewhere</a></body></html>`, outside)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func counter(t *testing.T, tlsSrv bool) (*httptest.Server, *int64) {
	var hits int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt64(&hits, 1) })
	var srv *httptest.Server
	if tlsSrv {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, &hits
}

func proxyClient(p *Proxy) *http.Client {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.Port()))
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // like ZAP, the client does not check the guard's certificate
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestProxyEnforcesScope(t *testing.T) {
	outside, outHits := counter(t, false)
	site, siteHits := fixtureSite(t, outside.URL)
	m := manifest(t, "", site.URL)
	g := scope.NewGuard(m, nil)
	p, err := StartProxy(m, g)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c := proxyClient(p)
	status := func(u string) int {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := status(site.URL + "/"); s != 200 {
		t.Fatalf("in-scope page: %d", s)
	}
	for _, u := range []string{outside.URL + "/steal", site.URL + "/private/x"} {
		if s := status(u); s != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403 from the guard", u, s)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, site.URL+"/", strings.NewReader("x=1"))
	if resp, err := c.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST must be refused when allowed_methods is GET, HEAD: %v %v", resp, err)
	}
	if n := atomic.LoadInt64(outHits); n != 0 {
		t.Fatalf("out-of-scope server received %d requests", n)
	}
	if atomic.LoadInt64(siteHits) != 1 || g.Sent() != 1 {
		t.Fatalf("site hits %d, guard sent %d; want 1 and 1", *siteHits, g.Sent())
	}
	if len(g.Refused()) != 3 {
		t.Errorf("refusals: %v", g.Refused())
	}
}

func TestProxyTunnelsHTTPSThroughGuard(t *testing.T) {
	in, inHits := counter(t, true)
	out, outHits := counter(t, true)
	m := manifest(t, "", in.URL)
	// The guard must check the real target's certificate; trust the fixture.
	pool := in.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	g := scope.NewGuard(m, pool)
	p, err := StartProxy(m, g)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c := proxyClient(p)
	for i := 0; i < 2; i++ { // two requests in one tunnel
		resp, err := c.Get(in.URL + "/page")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("in-scope https: %d", resp.StatusCode)
		}
	}
	if resp, err := c.Get(out.URL + "/"); err == nil {
		resp.Body.Close()
		t.Fatalf("CONNECT to an out-of-scope origin must fail, got %d", resp.StatusCode)
	}
	if atomic.LoadInt64(outHits) != 0 || atomic.LoadInt64(inHits) != 2 {
		t.Fatalf("hits in=%d out=%d", *inHits, *outHits)
	}
}

func TestProxyBudgetAndHalt(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := manifest(t, "", srv.URL)
	g := scope.NewGuard(m, nil)
	p, _ := StartProxy(m, g)
	defer p.Close()
	c := proxyClient(p)
	for i := 0; i < 6; i++ {
		if resp, err := c.Get(srv.URL + "/"); err == nil {
			resp.Body.Close()
		}
	}
	if hits != scope.HaltAfter || g.Halted() == "" {
		t.Fatalf("guard must halt after %d 5xx answers: hits %d, halted %q", scope.HaltAfter, hits, g.Halted())
	}
}

func TestPlan(t *testing.T) {
	m := manifest(t, "", "https://staging.example.com/app")
	b, err := Plan(m, "/out", false, 7)
	if err != nil {
		t.Fatal(err)
	}
	var doc planDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.Env.Contexts[0]
	inc := regexp.MustCompile(c.IncludePaths[0])
	exc := regexp.MustCompile(c.ExcludePaths[0])
	for u, want := range map[string]bool{"https://staging.example.com/app": true, "https://staging.example.com/app/x?y=1": true, "https://staging.example.com/apple": false, "https://evil.example.com/app": false} {
		if inc.MatchString(u) != want {
			t.Errorf("include %s = %v", u, !want)
		}
	}
	if !exc.MatchString("https://staging.example.com/private/a") || exc.MatchString("https://staging.example.com/privateer") {
		t.Error("exclude regex wrong")
	}
	var types []string
	for _, j := range doc.Jobs {
		types = append(types, j.Type)
	}
	if strings.Join(types, ",") != "passiveScan-config,spider,passiveScan-wait,report" {
		t.Fatalf("jobs without active scan: %v", types)
	}
	b, _ = Plan(m, "/out", true, 7)
	if !strings.Contains(string(b), "activeScan") {
		t.Fatal("active scan job missing")
	}
}

func TestParseReport(t *testing.T) {
	raw := []byte(`{"@version":"2.17.0","site":[{"@name":"http://127.0.0.1:8080","alerts":[{"pluginid":"10038","alert":"Content Security Policy (CSP) Header Not Set","riskcode":"2","confidence":"3","cweid":"693","desc":"<p>CSP is missing.</p>","solution":"<p>Set it.</p>","instances":[{"uri":"http://127.0.0.1:8080/","method":"GET"}]}]}]}`)
	as, err := ParseReport(raw)
	if err != nil || len(as) != 1 {
		t.Fatal(as, err)
	}
	a := as[0]
	if a.PluginID != "10038" || a.Risk != 2 || a.Confidence != 3 || a.CWE != 693 || a.Desc != "CSP is missing." || a.Solution != "Set it." || len(a.Instances) != 1 {
		t.Fatalf("%+v", a)
	}
	if _, err := ParseReport([]byte("not json")); err == nil {
		t.Fatal("bad report must be an error")
	}
}

// TestRealZAP runs the installed ZAP against the fixture site. It needs ZAP
// and Java 17+, so it runs only with PANDAWARD_REAL_ZAP=1 (PANDAWARD_ZAP_PATH may
// point to the launcher).
func TestRealZAP(t *testing.T) {
	if os.Getenv("PANDAWARD_REAL_ZAP") != "1" {
		t.Skip("set PANDAWARD_REAL_ZAP=1 to run against an installed ZAP")
	}
	launcher, err := Locate(os.Getenv("PANDAWARD_ZAP_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	outside, outHits := counter(t, false)
	site, siteHits := fixtureSite(t, outside.URL)
	m := manifest(t, "", site.URL)
	g := scope.NewGuard(m, nil)
	res, err := Run(context.Background(), Options{Launcher: launcher, Manifest: m, Guard: g, WorkDir: t.TempDir(), Minutes: 2, Progress: func(l string) { t.Log(l) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ZAP %s exit %d, %d alerts, guard sent %d, refused %v", res.Version, res.ExitCode, len(res.Alerts), g.Sent(), g.Refused())
	if atomic.LoadInt64(outHits) != 0 {
		t.Fatalf("out-of-scope server received %d requests", *outHits)
	}
	if atomic.LoadInt64(siteHits) == 0 || g.Sent() == 0 {
		t.Fatal("ZAP traffic did not go through the guard")
	}
	csp := false
	for _, a := range res.Alerts {
		if a.PluginID == "10038" {
			csp = true
		}
	}
	if !csp {
		t.Fatalf("expected the missing CSP alert (10038), got %+v", res.Alerts)
	}
}
