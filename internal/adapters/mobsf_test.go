package adapters

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

const testMobSFKey = "f3b1c2d4e5a6978812345678deadbeef0123456789abcdef0123456789abcd"

func TestMobSFURLAcceptsOnlyLoopback(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://127.0.0.1:8000":        true,
		"http://127.10.0.1:8000/":      true,
		"https://localhost:8443/mobsf": true,
		"http://[::1]:8000":            true,
		"http://192.168.1.10:8000":     false,
		"http://mobsf.example.com":     false,
		"http://0.0.0.0:8000":          false,
		"http://127.0.0.1.nip.io:8000": false,
		"http://key@127.0.0.1:8000":    false,
		"ftp://127.0.0.1":              false,
		"127.0.0.1:8000":               false,
	} {
		if _, err := MobSFURL(raw); (err == nil) != ok {
			t.Errorf("MobSFURL(%q): err=%v, want ok=%v", raw, err, ok)
		}
	}
}

func TestMobSFScorecardMapping(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "mobsf-scorecard-apk.json"))
	if err != nil {
		t.Fatal(err)
	}
	card, err := parseMobSFScorecard(b)
	if err != nil {
		t.Fatal(err)
	}
	if card.Version != "v4.5.3" {
		t.Errorf("version %q", card.Version)
	}
	got := map[string]model.Signal{}
	for _, s := range mobsfSignals(card, "dist/app.apk", "K-006", "mobsf") {
		if s.ControlID != "K-006" || s.File != "dist/app.apk" || s.Confidence != model.Hypothesis {
			t.Errorf("signal %+v", s)
		}
		got[s.Title] = s
	}
	want := map[string]model.Severity{
		"Debug Enabled For App":                                                   model.SevHigh,
		"Application Data can be Backed up":                                       model.SevMedium,
		"This app may contain hardcoded secrets":                                  model.SevMedium,
		"Found 1 critical permission(s)":                                          model.SevInfo,
		"The App logs information. Sensitive information should never be logged.": model.SevInfo,
	}
	if len(got) != len(want) {
		t.Errorf("got %d signals, want %d: %v", len(got), len(want), got)
	}
	for title, sev := range want {
		if got[title].Severity != sev {
			t.Errorf("%s: severity %q, want %q", title, got[title].Severity, sev)
		}
	}
	if s := got["This app may contain hardcoded secrets"]; strings.Contains(s.Message, "wJalr") || s.RuleID != "mobsf.secrets" {
		t.Errorf("secrets signal leaks its values or has the wrong rule: %+v", s)
	}
}

// fakeMobSF serves the three MobSF endpoints the adapter uses and checks the
// API key header.
func fakeMobSF(t *testing.T, card string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Mobsf-Api-Key") != testMobSFKey {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error": "You are unauthorized to make this request."}`)
			return
		}
		switch r.URL.Path {
		case "/api/v1/upload":
			f, h, err := r.FormFile("file")
			if err != nil {
				http.Error(w, `{"error": "no file"}`, http.StatusUnprocessableEntity)
				return
			}
			f.Close()
			json.NewEncoder(w).Encode(map[string]string{"file_name": h.Filename, "hash": "3a2f8f0f1b5c4d6e7f8091a2b3c4d5e6", "scan_type": strings.TrimPrefix(filepath.Ext(h.Filename), ".")})
		case "/api/v1/scan":
			if r.FormValue("hash") != "3a2f8f0f1b5c4d6e7f8091a2b3c4d5e6" {
				http.Error(w, `{"error": "The file is not uploaded/available"}`, http.StatusInternalServerError)
				return
			}
			io.WriteString(w, `{"app_name": "ClipDump"}`)
		case "/api/v1/scorecard":
			io.WriteString(w, card)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func mobsfProject(t *testing.T, url string, files ...string) *Context {
	t.Helper()
	root := t.TempDir()
	for _, p := range files {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte("PK\x03\x04\x00binary"), 0o644)
	}
	cfg := config.Default("t")
	cfg.Scan.MobSFURL = url
	inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes})
	if err != nil {
		t.Fatal(err)
	}
	return &Context{Root: root, Inv: inv, Cfg: cfg, RunDir: t.TempDir(), ToolHome: t.TempDir(), Timeout: time.Minute}
}

// assertNoKey fails if the API key appears in the run, the signals or any
// file the adapter wrote.
func assertNoKey(t *testing.T, c *Context, res Result, run model.Run) {
	t.Helper()
	b, _ := json.Marshal(struct {
		R Result
		M model.Run
	}{res, run})
	if strings.Contains(string(b), testMobSFKey) {
		t.Error("API key appears in the result or run")
	}
	filepath.Walk(c.RunDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), testMobSFKey) {
				t.Errorf("API key written to %s", p)
			}
		}
		return nil
	})
}

func TestMobSFAnalyzesAPKAndIPA(t *testing.T) {
	card, err := os.ReadFile(filepath.Join("testdata", "mobsf-scorecard-apk.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, calls := fakeMobSF(t, string(card))
	c := mobsfProject(t, srv.URL, "release/app-release.apk", "release/App.ipa")
	if got := c.Inv.Features["ipa"]; len(got) != 1 || got[0] != "release/App.ipa" || !c.Inv.Has("ios") {
		t.Fatalf("ipa feature: %v", c.Inv.Features)
	}
	t.Setenv(MobSFKeyEnv, testMobSFKey)
	res, run := mobsfAdapter{}.Run(context.Background(), c)
	if run.ExitClass != model.ExitOK {
		t.Fatalf("run %s: %s", run.ExitClass, run.Detail)
	}
	if run.ToolVersion != "v4.5.3" {
		t.Errorf("tool version %q", run.ToolVersion)
	}
	perControl := map[string]string{}
	for _, s := range res.Signals {
		perControl[s.ControlID] = s.File
	}
	if perControl["K-006"] != "release/app-release.apk" || perControl["L-005"] != "release/App.ipa" {
		t.Errorf("signals per control: %v", perControl)
	}
	if want := 6; len(*calls) != want {
		t.Errorf("calls %v, want %d", *calls, want)
	}
	assertNoKey(t, c, res, run)
}

func TestMobSFWrongKeyIsError(t *testing.T) {
	srv, _ := fakeMobSF(t, "{}")
	c := mobsfProject(t, srv.URL, "app.apk")
	t.Setenv(MobSFKeyEnv, "wrong-"+testMobSFKey)
	res, run := mobsfAdapter{}.Run(context.Background(), c)
	if run.ExitClass != model.ExitError || !strings.Contains(run.Detail, "401") {
		t.Fatalf("wrong key must be ERROR, got %s: %s", run.ExitClass, run.Detail)
	}
	if strings.Contains(run.Detail, "wrong-") {
		t.Error("detail quotes the key")
	}
	assertNoKey(t, c, res, run)
}

func TestMobSFBlockedWithoutServerOrKey(t *testing.T) {
	srv, calls := fakeMobSF(t, "{}")
	for name, tc := range map[string]struct{ url, key string }{
		"no url":       {"", testMobSFKey},
		"no key":       {srv.URL, ""},
		"not loopback": {"http://10.0.0.5:8000", testMobSFKey},
	} {
		t.Run(name, func(t *testing.T) {
			c := mobsfProject(t, tc.url, "app.apk")
			t.Setenv(MobSFKeyEnv, tc.key)
			_, run := mobsfAdapter{}.Run(context.Background(), c)
			if run.ExitClass != model.ExitBlocked {
				t.Fatalf("%s: got %s (%s), want BLOCKED", name, run.ExitClass, run.Detail)
			}
		})
	}
	if len(*calls) != 0 {
		t.Errorf("a blocked run contacted MobSF: %v", *calls)
	}
}

func TestMobSFDoesNotFollowRedirects(t *testing.T) {
	away := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request followed a redirect")
	}))
	defer away.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, away.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := mobsfProject(t, srv.URL, "app.apk")
	t.Setenv(MobSFKeyEnv, testMobSFKey)
	_, run := mobsfAdapter{}.Run(context.Background(), c)
	if run.ExitClass != model.ExitError {
		t.Fatalf("redirect must be ERROR, got %s: %s", run.ExitClass, run.Detail)
	}
}

// TestRealMobSF runs the adapter against a MobSF server, the pinned image in
// the mobsf CI job. PANDAWARD_MOBSF_APK names the APK to upload; the server
// address and key come from PANDAWARD_MOBSF_URL and MOBSF_API_KEY.
func TestRealMobSF(t *testing.T) {
	apk := os.Getenv("PANDAWARD_MOBSF_APK")
	if apk == "" {
		t.Skip("set PANDAWARD_MOBSF_APK, PANDAWARD_MOBSF_URL and MOBSF_API_KEY to run against MobSF")
	}
	b, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	c := mobsfProject(t, os.Getenv("PANDAWARD_MOBSF_URL"), "app.apk")
	if err := os.WriteFile(filepath.Join(c.Root, "app.apk"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	c.Timeout = 15 * time.Minute
	res, run := mobsfAdapter{}.Run(context.Background(), c)
	if run.ExitClass != model.ExitOK {
		t.Fatalf("run %s: %s", run.ExitClass, run.Detail)
	}
	if want := os.Getenv("PANDAWARD_MOBSF_VERSION"); want != "" && run.ToolVersion != want {
		t.Errorf("MobSF version %q, want %q", run.ToolVersion, want)
	}
	if len(res.Signals) == 0 {
		t.Error("MobSF reported nothing for the fixture APK")
	}
	for _, s := range res.Signals {
		if s.ControlID != "K-006" || s.Title == "" || s.Confidence != model.Hypothesis {
			t.Errorf("signal %+v", s)
		}
	}
	key := os.Getenv(MobSFKeyEnv)
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), key) || strings.Contains(run.Detail, key) {
		t.Error("API key appears in the result")
	}
	if dir := os.Getenv("PANDAWARD_MOBSF_OUT"); dir != "" {
		raw, _ := os.ReadFile(filepath.Join(c.RunDir, "mobsf-0.json"))
		os.WriteFile(filepath.Join(dir, "mobsf-scorecard.json"), raw, 0o644)
		os.WriteFile(filepath.Join(dir, "mobsf-signals.json"), out, 0o644)
	}
}
