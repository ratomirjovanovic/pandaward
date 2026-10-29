package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setup points the state file at a temporary directory and fixes the clock.
func setup(t *testing.T) {
	t.Helper()
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	t.Setenv("PANDAWARD_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "")
	day := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return day }
	old := Endpoint
	t.Cleanup(func() { now = func() time.Time { return time.Now().UTC() }; Endpoint = old })
}

func nextDay() { d := now().Add(24 * time.Hour); now = func() time.Time { return d } }

func TestOffByDefaultRecordsNothing(t *testing.T) {
	setup(t)
	Record("cli", "scan", t.TempDir())
	p, _ := Path()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("a state file exists without opt-in: %v", err)
	}
}

func TestPayloadHoldsNoPathsOrNames(t *testing.T) {
	setup(t)
	if _, err := Enable(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "acme-secret-project")
	Record("cli", "scan", root)
	Record("cli", "scan", root)
	Record("mcp", "pandaward_get_status", root)
	Record("hook", "stop", "")
	nextDay()
	s := Load()
	p, ok := Pending(s)
	if !ok || len(p.Days) != 1 {
		t.Fatalf("pending %+v ok=%v", p, ok)
	}
	d := p.Days[0]
	if d.Counts["cli:scan"] != 2 || d.Counts["mcp:pandaward_get_status"] != 1 || d.Counts["hook:stop"] != 1 || len(d.Projects) != 1 {
		t.Errorf("day %+v", d)
	}
	b, _ := json.Marshal(p)
	for _, leak := range []string{"acme-secret-project", filepath.ToSlash(root), s.Salt, os.Getenv("USERNAME"), os.Getenv("USER")} {
		if leak != "" && strings.Contains(string(b), leak) {
			t.Errorf("payload contains %q: %s", leak, b)
		}
	}
	if ProjectID(s.Salt, root) == ProjectID("another-salt", root) {
		t.Error("project IDs must differ across installs")
	}
}

func TestEnvironmentForcesOff(t *testing.T) {
	for _, kv := range [][2]string{{"PANDAWARD_TELEMETRY", "off"}, {"DO_NOT_TRACK", "1"}} {
		setup(t)
		Enable()
		t.Setenv(kv[0], kv[1])
		Record("cli", "scan", "")
		if Today(Load()) != nil {
			t.Errorf("%s=%s: a use was recorded", kv[0], kv[1])
		}
	}
}

func TestFlushSendsFinishedDaysOncePerDay(t *testing.T) {
	setup(t)
	var calls atomic.Int32
	var got Payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	Endpoint = srv.URL
	Enable()
	Record("cli", "scan", "")
	Flush(context.Background())
	if calls.Load() != 0 {
		t.Fatal("today is still being counted and must not be sent")
	}
	nextDay()
	Record("cli", "report", "")
	Flush(context.Background())
	Flush(context.Background())
	if calls.Load() != 1 {
		t.Fatalf("%d requests, want 1", calls.Load())
	}
	if len(got.Days) != 1 || got.Days[0].Counts["cli:scan"] != 1 || got.InstallID == "" {
		t.Errorf("payload %+v", got)
	}
	s := Load()
	if _, ok := s.Days["2026-10-28"]; ok {
		t.Error("an accepted day must be forgotten")
	}
	if Today(s) == nil || Today(s).Counts["cli:report"] != 1 {
		t.Error("today's counters must stay")
	}
}

func TestUnreachableCollectorIsTriedOncePerDay(t *testing.T) {
	setup(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	Endpoint = srv.URL
	srv.Close() // nothing listens any more
	Enable()
	Record("cli", "scan", "")
	nextDay()
	start := time.Now()
	Flush(context.Background())
	Flush(context.Background())
	if time.Since(start) > 8*time.Second {
		t.Errorf("flushing took %s", time.Since(start))
	}
	s := Load()
	if s.LastSent != "2026-10-29" || s.Days["2026-10-28"] == nil {
		t.Errorf("the attempt must be recorded and the day kept: %+v", s)
	}
}

func TestDisableDeletesCounters(t *testing.T) {
	setup(t)
	Enable()
	Record("cli", "scan", "")
	if err := Disable(); err != nil {
		t.Fatal(err)
	}
	s := Load()
	if s.Enabled || s.InstallID != "" || len(s.Days) != 0 {
		t.Errorf("state after off: %+v", s)
	}
}

func TestNoEndpointSendsNothing(t *testing.T) {
	setup(t)
	Endpoint = ""
	Enable()
	Record("cli", "scan", "")
	nextDay()
	Flush(context.Background())
	if Load().LastSent != "" {
		t.Error("Flush did something without a collector address")
	}
}
