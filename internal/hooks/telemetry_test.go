package hooks

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/telemetry"
)

// Hooks run on every edit and turn; they count a use but never wait on the
// network, even with telemetry on and finished days waiting to be sent.
func TestHooksNeverSendTelemetry(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	t.Setenv("PANDAWARD_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "")
	t.Setenv("CLAUDE_PROJECT_DIR", t.TempDir())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	old := telemetry.Endpoint
	telemetry.Endpoint = srv.URL
	defer func() { telemetry.Endpoint = old }()
	if _, err := telemetry.Enable(); err != nil {
		t.Fatal(err)
	}
	// A finished day is waiting, so any send attempt would reach the server.
	path, _ := telemetry.Path()
	st, _ := os.ReadFile(path)
	st = bytes.Replace(st, []byte(`"enabled": true,`), []byte(`"enabled": true, "days": {"2000-01-01": {"counts": {"cli:scan": 1}}},`), 1)
	if err := os.WriteFile(path, st, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"pre-compact", "post-edit"} {
		Run(h, strings.NewReader(`{}`), io.Discard)
	}
	if calls.Load() != 0 {
		t.Fatalf("hooks made %d request(s)", calls.Load())
	}
	d := telemetry.Today(telemetry.Load())
	if d == nil || d.Counts["hook:pre-compact"] != 1 || d.Counts["hook:post-edit"] != 1 {
		t.Errorf("hook uses not counted: %+v", d)
	}
}
