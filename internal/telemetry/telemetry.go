// Package telemetry keeps opt-in usage counters and sends them, at most once
// a day, to the PandaWard collector. It is off unless the user turns it on
// with `pandaward telemetry on`; the setting lives only in the user config
// directory, so no repository can enable it. Counters hold an entry point
// and command name per day, the version, OS and architecture, and salted
// project IDs. Arguments, paths, file names, findings and code are never
// recorded. Every error is ignored: telemetry never changes a command's
// result.
package telemetry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// Endpoint is the collector URL. While it is empty nothing is ever sent;
// counters are still kept for users who turned telemetry on, and `show`
// prints them.
var Endpoint = ""

// SchemaVersion of the payload. Bump on any change to its fields.
const SchemaVersion = 1

// keepDays bounds how many unsent days are kept when the collector cannot
// be reached.
const keepDays = 30

// State is the telemetry file in the user config directory.
type State struct {
	Enabled   bool            `json:"enabled"`
	InstallID string          `json:"install_id,omitempty"`
	Salt      string          `json:"salt,omitempty"` // never sent
	LastSent  string          `json:"last_sent,omitempty"`
	Days      map[string]*Day `json:"days,omitempty"`
}

// Day holds one UTC day of counters.
type Day struct {
	Counts   map[string]int `json:"counts"`
	Projects []string       `json:"projects,omitempty"`
}

// Payload is exactly what is sent.
type Payload struct {
	Schema    int         `json:"schema"`
	InstallID string      `json:"install_id"`
	Version   string      `json:"version"`
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	Days      []DayReport `json:"days"`
}

// DayReport is one finished day in a payload.
type DayReport struct {
	Day      string         `json:"day"`
	Counts   map[string]int `json:"counts"`
	Projects []string       `json:"projects,omitempty"`
}

var now = func() time.Time { return time.Now().UTC() }

// Path returns the state file location.
func Path() (string, error) {
	if d := config.Env("CONFIG_DIR"); d != "" {
		return filepath.Join(d, "telemetry.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pandaward", "telemetry.json"), nil
}

// ForcedOff reports whether the environment turns telemetry off whatever
// the state file says.
func ForcedOff() bool {
	if v := strings.ToLower(os.Getenv("PANDAWARD_TELEMETRY")); v == "off" || v == "0" || v == "false" {
		return true
	}
	if v := os.Getenv("DO_NOT_TRACK"); v != "" && v != "0" {
		return true
	}
	return false
}

// Load reads the state; a missing or unreadable file is the zero state
// (off).
func Load() State {
	var s State
	p, err := Path()
	if err != nil {
		return s
	}
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return State{}
	}
	return s
}

func save(s State) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Write and rename so concurrent hooks never leave a torn file.
	tmp := p + "." + randHex(4) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Enable turns telemetry on, creating the install ID and salt on first use.
func Enable() (State, error) {
	s := Load()
	s.Enabled = true
	if s.InstallID == "" {
		s.InstallID = randHex(16)
	}
	if s.Salt == "" {
		s.Salt = randHex(32)
	}
	return s, save(s)
}

// Disable turns telemetry off and deletes the unsent counters. The install
// ID is dropped too, so turning it on again starts a new install.
func Disable() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil
	}
	return save(State{})
}

// Record counts one use. entry is cli, mcp or hook; name is a command, MCP
// tool or hook name from a fixed list the caller checks; root is the
// project root, or "" when there is none. It does nothing unless telemetry
// is on.
func Record(entry, name, root string) {
	if ForcedOff() {
		return
	}
	s := Load()
	if !s.Enabled || s.Salt == "" {
		return
	}
	day := now().Format("2006-01-02")
	if s.Days == nil {
		s.Days = map[string]*Day{}
	}
	d := s.Days[day]
	if d == nil {
		d = &Day{Counts: map[string]int{}}
		s.Days[day] = d
	}
	d.Counts[entry+":"+name]++
	if root != "" {
		if id := ProjectID(s.Salt, root); !contains(d.Projects, id) {
			d.Projects = append(d.Projects, id)
		}
	}
	prune(&s)
	_ = save(s)
}

// ProjectID is an HMAC of the absolute project root under the install's
// salt: stable for one install, not reversible and not comparable across
// installs.
func ProjectID(salt, root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(filepath.Clean(abs)))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// Today returns the counters of the day still being counted, or nil.
func Today(s State) *DayReport {
	day := now().Format("2006-01-02")
	d := s.Days[day]
	if d == nil {
		return nil
	}
	return &DayReport{Day: day, Counts: d.Counts, Projects: d.Projects}
}

// Pending builds the payload for the finished days (today is still being
// counted). ok is false when there is nothing to send.
func Pending(s State) (Payload, bool) {
	p := Payload{Schema: SchemaVersion, InstallID: s.InstallID, Version: version.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Days: []DayReport{}}
	today := now().Format("2006-01-02")
	var days []string
	for d := range s.Days {
		if d < today {
			days = append(days, d)
		}
	}
	sort.Strings(days)
	for _, d := range days {
		p.Days = append(p.Days, DayReport{Day: d, Counts: s.Days[d].Counts, Projects: s.Days[d].Projects})
	}
	return p, s.Enabled && s.InstallID != "" && len(p.Days) > 0
}

// Flush sends the finished days, at most once a day, and forgets them once
// the collector accepted them. It returns quickly: the request has a short
// timeout and every failure is ignored.
func Flush(ctx context.Context) {
	if ForcedOff() || Endpoint == "" {
		return
	}
	s := Load()
	today := now().Format("2006-01-02")
	if !s.Enabled || s.LastSent == today {
		return
	}
	p, ok := Pending(s)
	if !ok {
		return
	}
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	// One attempt a day, recorded first: an offline machine must not pay
	// the timeout on every command.
	s.LastSent = today
	if save(s) != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, Endpoint, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return
	}
	// Re-read: another process may have counted meanwhile.
	s = Load()
	if !s.Enabled {
		return
	}
	for _, d := range p.Days {
		delete(s.Days, d.Day)
	}
	_ = save(s)
}

func prune(s *State) {
	if len(s.Days) <= keepDays {
		return
	}
	var days []string
	for d := range s.Days {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, d := range days[:len(days)-keepDays] {
		delete(s.Days, d)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
