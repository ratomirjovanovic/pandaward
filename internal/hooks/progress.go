package hooks

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/progress"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// hypothesisTool is the MCP tool reviewers record hypotheses with.
const hypothesisTool = "pandaward_record_hypothesis"

var findingID = regexp.MustCompile(`\bPW-\d{4,}\b`)

// recordProgress appends a progress event for a PandaWard reviewer. Every
// other agent, and the main session, returns at once without writing.
func recordProgress(in Input, kind string) int {
	if !strings.HasPrefix(in.AgentType, progress.Prefix) || in.AgentID == "" {
		return 0
	}
	root, err := engine.FindRoot(projectDir(in))
	if err != nil {
		return 0
	}
	ev := progress.Event{TS: time.Now().UTC(), Kind: kind, Agent: in.AgentID, Type: in.AgentType}
	if kind == progress.KindTool && !toolEvent(&ev, in, root) {
		return 0
	}
	_ = progress.Append(root, ev)
	return 0
}

// toolEvent fills ev from a reviewer's tool call and reports whether the
// call is one progress tracks.
func toolEvent(ev *progress.Event, in Input, root string) bool {
	var ti struct {
		FilePath string `json:"file_path"`
		Pattern  string `json:"pattern"`
		Path     string `json:"path"`
		Title    string `json:"title"`
	}
	_ = json.Unmarshal(in.ToolInput, &ti)
	switch {
	case in.ToolName == "Read":
		ev.Tool, ev.Target = progress.ToolRead, relPath(root, ti.FilePath)
	case in.ToolName == "Grep" || in.ToolName == "Glob":
		ev.Tool, ev.Target = progress.ToolSearch, shorten(redact.Line(ti.Pattern), 40)
		if p := relPath(root, ti.Path); p != "." {
			ev.Target += " in " + p
		}
	case strings.HasSuffix(in.ToolName, "__"+hypothesisTool):
		ev.Kind = progress.KindHypothesis
		ev.Finding = findingID.FindString(string(in.ToolResponse))
		ev.Title = shorten(redact.Line(ti.Title), 120)
	default:
		return false
	}
	return true
}

// relPath shows p relative to the project root, or by its base name when it
// lies outside it.
func relPath(root, p string) string {
	if p == "" {
		return "."
	}
	if !filepath.IsAbs(p) {
		// Already relative to the session directory.
	} else if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
		p = r
	} else {
		p = filepath.Base(p)
	}
	return shorten(redact.Line(filepath.ToSlash(p)), 80)
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}
