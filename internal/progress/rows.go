package progress

import (
	"encoding/json"
	"io"
	"math"
	"strings"
	"time"
)

// Task is the part of a subagent panel row that Rows reads.
type Task struct {
	ID        string `json:"id"`
	AgentType string `json:"agentType"`
	Status    string `json:"status"`
	StartTime int64  `json:"startTime"`
}

// PanelInput is what Claude Code passes to a subagentStatusLine command.
type PanelInput struct {
	Cwd     string `json:"cwd"`
	Columns int    `json:"columns"`
	Tasks   []Task `json:"tasks"`
}

// ReadPanelInput decodes the panel input; a bad input reads as no tasks.
func ReadPanelInput(r io.Reader) PanelInput {
	var in PanelInput
	b, _ := io.ReadAll(io.LimitReader(r, 4<<20))
	_ = json.Unmarshal(b, &in)
	return in
}

// HasReviewers reports whether any row belongs to a PandaWard reviewer, so
// the command can return before touching the project for other subagents.
func (in PanelInput) HasReviewers() bool {
	for _, t := range in.Tasks {
		if strings.HasPrefix(t.AgentType, Prefix) {
			return true
		}
	}
	return false
}

// matchSlack is how far a task's start may be from the recorded start.
const matchSlack = time.Minute

// Rows writes one {"id","content"} line per PandaWard reviewer row it can
// match to recorded progress. Other rows are not written, so Claude Code
// keeps its default rendering for them.
func Rows(w io.Writer, in PanelInput, rs []Reviewer, now time.Time) {
	used := map[string]bool{}
	for _, t := range in.Tasks {
		if !strings.HasPrefix(t.AgentType, Prefix) {
			continue
		}
		r, ok := match(t, rs, used)
		if !ok {
			continue
		}
		used[r.ID] = true
		b, _ := json.Marshal(struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		}{t.ID, fit(Row(r, now), in.Columns)})
		w.Write(append(b, '\n'))
	}
}

func match(t Task, rs []Reviewer, used map[string]bool) (Reviewer, bool) {
	for _, r := range rs {
		if r.ID == t.ID {
			return r, true
		}
	}
	start := time.UnixMilli(t.StartTime)
	best, bestD := -1, math.MaxFloat64
	for i, r := range rs {
		if used[r.ID] || r.Type != t.AgentType {
			continue
		}
		d := math.Abs(float64(r.Started.Sub(start)))
		if d <= float64(matchSlack) && d < bestD {
			best, bestD = i, d
		}
	}
	if best < 0 {
		return Reviewer{}, false
	}
	return rs[best], true
}

// Row is the panel text of one reviewer, such as
// "api · 3m12s · 24 files read, 6 searches, 2 hypotheses · reading src/app.ts".
func Row(r Reviewer, now time.Time) string {
	parts := []string{r.Name()}
	if r.Done {
		parts = append(parts, "finished in "+Dur(r.Elapsed(now)))
	} else {
		parts = append(parts, Dur(r.Elapsed(now)))
	}
	parts = append(parts, r.Counts())
	if r.Target != "" {
		parts = append(parts, r.Target)
	}
	return strings.Join(parts, " · ")
}

// fit cuts s to the row width, if Claude Code gave one.
func fit(s string, cols int) string {
	rs := []rune(s)
	if cols <= 0 || len(rs) <= cols {
		return s
	}
	if cols <= 3 {
		return string(rs[:cols])
	}
	return string(rs[:cols-3]) + "..."
}
