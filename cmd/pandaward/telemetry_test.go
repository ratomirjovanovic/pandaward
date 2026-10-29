package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/telemetry"
)

// A command never waits for the collector: when a send is due it starts
// the sender and returns, and what it prints and returns is the same as
// with telemetry off. The sender itself, `telemetry send`, tolerates an
// unreachable collector.
func TestCommandsIgnoreUnreachableCollector(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANDAWARD_CONFIG_DIR", dir)
	t.Setenv("PANDAWARD_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "")
	spawned := 0
	oldSpawn := telemetry.Spawn
	telemetry.Spawn = func() { spawned++ }
	defer func() { telemetry.Spawn = oldSpawn }()

	var outOff bytes.Buffer
	if code := run(context.Background(), []string{"version"}, nil, &outOff, &bytes.Buffer{}); code != 0 {
		t.Fatalf("version: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "telemetry.json")); !os.IsNotExist(err) {
		t.Fatal("a command created telemetry state without opt-in")
	}
	if spawned != 0 {
		t.Fatal("a sender was started with telemetry off")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	old := telemetry.Endpoint
	telemetry.Endpoint = srv.URL
	srv.Close()
	defer func() { telemetry.Endpoint = old }()
	if _, err := telemetry.Enable(); err != nil {
		t.Fatal(err)
	}
	// A finished day waiting to be sent makes a send due.
	b, _ := os.ReadFile(filepath.Join(dir, "telemetry.json"))
	b = bytes.Replace(b, []byte(`"enabled": true,`), []byte(`"enabled": true, "days": {"2000-01-01": {"counts": {"cli:scan": 1}}},`), 1)
	os.WriteFile(filepath.Join(dir, "telemetry.json"), b, 0o600)

	var outOn, errOn bytes.Buffer
	if code := run(context.Background(), []string{"version"}, nil, &outOn, &errOn); code != 0 || outOn.String() != outOff.String() || errOn.Len() != 0 {
		t.Errorf("with a send due: exit %d, stdout %q (want %q), stderr %q", code, outOn.String(), outOff.String(), errOn.String())
	}
	if spawned != 1 {
		t.Errorf("sender started %d times, want 1", spawned)
	}

	// The sender: one attempt, recorded, the day kept, exit 0 and no output.
	var outSend, errSend bytes.Buffer
	if code := run(context.Background(), []string{"telemetry", "send"}, nil, &outSend, &errSend); code != 0 || outSend.Len() != 0 || errSend.Len() != 0 {
		t.Errorf("telemetry send: exit %d, stdout %q, stderr %q", code, outSend.String(), errSend.String())
	}
	s := telemetry.Load()
	if s.LastSent == "" || s.Days["2000-01-01"] == nil {
		t.Errorf("after a failed send: last_sent %q, days %v", s.LastSent, s.Days)
	}
}

// An agent, or anything else without a terminal, cannot give consent.
func TestTelemetryOnNeedsATerminal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANDAWARD_CONFIG_DIR", dir)
	old := isInteractive
	isInteractive = func() bool { return false }
	defer func() { isInteractive = old }()
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"telemetry", "on"}, nil, &bytes.Buffer{}, &errOut); code != 3 {
		t.Fatalf("exit %d, want 3: %s", code, errOut.String())
	}
	if telemetry.Load().Enabled {
		t.Error("telemetry was turned on without a terminal")
	}
}
