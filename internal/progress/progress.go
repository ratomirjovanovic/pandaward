// Package progress records what PandaWard's reviewer subagents are doing and
// renders it while they run: as rows in Claude Code's subagent panel and as
// a stream of short lines for the guided assessment to pass on to the user.
// Events are written by the plugin hooks to a gitignored JSONL file. They
// name files and search patterns the reviewers used and never hold file
// contents.
package progress

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
)

// Prefix is the agent type prefix of PandaWard's reviewers.
const Prefix = "pandaward:"

// Event kinds.
const (
	KindStart      = "start"
	KindTool       = "tool"
	KindHypothesis = "hypothesis"
	KindStop       = "stop"
)

// Tool kinds of a KindTool event.
const (
	ToolRead   = "read"
	ToolSearch = "search"
)

// maxFile is the size at which the log is rotated when a reviewer starts.
const maxFile = 1 << 20

// Event is one line of the progress log.
type Event struct {
	TS      time.Time `json:"ts"`
	Kind    string    `json:"kind"`
	Agent   string    `json:"agent"`
	Type    string    `json:"type"`
	Tool    string    `json:"tool,omitempty"`
	Target  string    `json:"target,omitempty"`
	Finding string    `json:"finding,omitempty"`
	Title   string    `json:"title,omitempty"`
}

// Path is the progress log of the project at root.
func Path(root string) string { return filepath.Join(config.PrivateDir(root), "progress.jsonl") }

// Append writes ev to the log. Concurrent reviewers append from separate
// hook processes; each event is a single short write in append mode.
func Append(root string, ev Event) error {
	p := Path(root)
	if ev.Kind == KindStart {
		if st, err := os.Stat(p); err == nil && st.Size() > maxFile {
			_ = os.Rename(p, p+".old")
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Load reads the log. A missing log is empty; malformed lines are skipped.
func Load(root string) ([]Event, error) {
	f, err := os.Open(Path(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var evs []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Agent != "" {
			evs = append(evs, ev)
		}
	}
	return evs, sc.Err()
}

// Reviewer is the folded state of one reviewer subagent.
type Reviewer struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Started    time.Time `json:"started"`
	Last       time.Time `json:"last_activity"`
	Stopped    time.Time `json:"stopped,omitempty"`
	Done       bool      `json:"done"`
	Reads      int       `json:"files_read"`
	Searches   int       `json:"searches"`
	Hypotheses []string  `json:"hypotheses"`
	Titles     []string  `json:"hypothesis_titles"`
	Target     string    `json:"current,omitempty"`
}

// Name is the reviewer's short name, such as "api".
func (r Reviewer) Name() string { return strings.TrimPrefix(r.Type, Prefix) }

// Elapsed is how long the reviewer ran, or has been running at now.
func (r Reviewer) Elapsed(now time.Time) time.Duration {
	end := now
	if r.Done {
		end = r.Stopped
	}
	return end.Sub(r.Started)
}

// Fold turns events into reviewers ordered by start time. A reviewer whose
// start was not recorded starts at its first event.
func Fold(evs []Event) []Reviewer {
	by := map[string]*Reviewer{}
	var order []string
	for _, ev := range evs {
		r := by[ev.Agent]
		if r == nil {
			r = &Reviewer{ID: ev.Agent, Type: ev.Type, Started: ev.TS, Hypotheses: []string{}, Titles: []string{}}
			by[ev.Agent] = r
			order = append(order, ev.Agent)
		}
		if ev.TS.After(r.Last) {
			r.Last = ev.TS
		}
		switch ev.Kind {
		case KindStart:
			r.Started = ev.TS
		case KindTool:
			if ev.Tool == ToolRead {
				r.Reads++
				r.Target = "reading " + ev.Target
			} else {
				r.Searches++
				r.Target = "searching " + ev.Target
			}
		case KindHypothesis:
			id := ev.Finding
			if id == "" {
				id = "hypothesis"
			}
			r.Hypotheses = append(r.Hypotheses, id)
			r.Titles = append(r.Titles, ev.Title)
			r.Target = "recorded " + id
		case KindStop:
			r.Done, r.Stopped, r.Target = true, ev.TS, ""
		}
	}
	out := make([]Reviewer, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// batchWindow is how far apart reviewers of one review may start.
const batchWindow = 15 * time.Minute

// Current returns the reviewers of the latest review: those that started
// within batchWindow of the latest start, plus any still running from
// earlier that were active in the last hour.
func Current(rs []Reviewer, now time.Time) []Reviewer {
	var latest time.Time
	for _, r := range rs {
		if r.Started.After(latest) {
			latest = r.Started
		}
	}
	var out []Reviewer
	for _, r := range rs {
		if !r.Started.Before(latest.Add(-batchWindow)) || (!r.Done && now.Sub(r.Last) < time.Hour) {
			out = append(out, r)
		}
	}
	return out
}

// Dur formats a duration as 45s, 3m12s or 1h04m.
func Dur(d time.Duration) string {
	d = d.Round(time.Second)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Counts is the work summary of a reviewer, such as
// "24 files read, 6 searches, 2 hypotheses".
func (r Reviewer) Counts() string {
	return plural(r.Reads, "file read", "files read") + ", " + plural(r.Searches, "search", "searches") + ", " +
		plural(len(r.Hypotheses), "hypothesis", "hypotheses")
}
