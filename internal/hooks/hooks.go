// Package hooks implements the Claude Code lifecycle hooks. Every hook is
// silent and exits 0 when PenSec is not initialized, and none of them sends
// network traffic. Only the Stop hook scans: a changed-only passive retest
// after a turn that edited files, bounded by RetestBudget and turned off with
// hooks.auto_retest: false.
package hooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/redact"
)

// Input is the subset of the hook payload PenSec reads.
type Input struct {
	SessionID string          `json:"session_id"`
	Cwd       string          `json:"cwd"`
	HookEvent string          `json:"hook_event_name"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	// StopHookActive is set when Claude continues because of a Stop hook.
	StopHookActive bool `json:"stop_hook_active"`
}

func readInput(r io.Reader) Input {
	var in Input
	b, _ := io.ReadAll(io.LimitReader(r, 4<<20))
	_ = json.Unmarshal(b, &in)
	return in
}

func projectDir(in Input) string {
	if d := os.Getenv("CLAUDE_PROJECT_DIR"); d != "" {
		return d
	}
	if in.Cwd != "" {
		return in.Cwd
	}
	d, _ := os.Getwd()
	return d
}

func openEngine(in Input) *engine.Engine {
	root, err := engine.FindRoot(projectDir(in))
	if err != nil {
		return nil
	}
	e, err := engine.Open(root)
	if err != nil {
		return nil
	}
	return e
}

// Run dispatches a hook by name.
func Run(name string, stdin io.Reader, stdout io.Writer) int {
	in := readInput(stdin)
	switch name {
	case "session-start":
		return sessionStart(in, stdout)
	case "post-edit":
		return postEdit(in)
	case "pre-tool":
		return preTool(in, stdout)
	case "pre-compact":
		return preCompact(in)
	case "stop":
		return stop(in, stdout)
	}
	return 0
}

func sessionStart(in Input, w io.Writer) int {
	e := openEngine(in)
	if e == nil {
		return 0
	}
	defer e.Close()
	// Leave headroom under the hook timeout on large repositories.
	e.HashBudget = 5 * time.Second
	s, err := e.Status()
	if err != nil {
		return 0
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PenSec ledger for %q (source of truth is .pensec/private/state.db, not this summary).\n", redact.Line(s.Project))
	if s.Assessment == nil {
		b.WriteString("No assessment yet. When the user asks about security, run the guided assessment yourself (skill pensec:start).\n")
	} else {
		fmt.Fprintf(&b, "Latest: %s (%s). Decisive coverage %d/%d controls. Open findings: %d confirmed, %d suspected.\n",
			s.Assessment.ID, s.Assessment.Status, s.Coverage.Decisive, s.Coverage.Applicable, s.Confirmed, s.Suspected)
		if len(s.StaleFiles) > 0 {
			fmt.Fprintf(&b, "%d file(s) changed since then (%d outside Claude Code); %d control(s) STALE.\n", len(s.StaleFiles), len(s.ChangedOutside), len(s.StaleControls))
		}
		if s.ChangeCheck != "" {
			b.WriteString(redact.Line(s.ChangeCheck) + "\n")
		}
		if len(s.Blockers) > 0 {
			fmt.Fprintf(&b, "%d blocker(s); details in pensec_get_status.\n", len(s.Blockers))
		}
		fmt.Fprintf(&b, "Suggested next step: %s.\n", s.NextAction)
		b.WriteString("Do not ask the user to type PenSec commands: offer the next step in one sentence and run it yourself after a yes. After you edit code in this project, run pensec_retest yourself and report the delta.\n")
	}
	fmt.Fprint(w, b.String())
	return 0
}

func postEdit(in Input) int {
	var ti struct {
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
	}
	_ = json.Unmarshal(in.ToolInput, &ti)
	p := ti.FilePath
	if p == "" {
		p = ti.NotebookPath
	}
	if p == "" {
		return 0
	}
	e := openEngine(in)
	if e == nil {
		return 0
	}
	defer e.Close()
	_, _ = e.MarkChanged(p)
	return 0
}

func preCompact(in Input) int {
	e := openEngine(in)
	if e == nil {
		return 0
	}
	defer e.Close()
	_ = e.St.Event(e.ProjectID, "session:"+redact.Line(in.SessionID), "", "CHECKPOINT", "context compaction; ledger state is authoritative")
	return 0
}

var (
	humanOnlyCmd = regexp.MustCompile(`(?i)\bpensec(\.exe)?["']?\s+(scope\s+(approve|revoke)|test\b|findings\s+(false-positive|accept-risk|reopen|confirm|apply)\b|purge\b|init\s+--force)`)
	applyFile    = regexp.MustCompile(`(?i)\bfindings\s+apply\b.*?--file[=\s]+(?:"([^"]+)"|'([^']+)'|(\S+))`)
	privateRef   = regexp.MustCompile(`(?i)\.pensec[\\/]+(private|reports)\b|state\.db`)
	scopeRef     = regexp.MustCompile(`(?i)\.pensec[\\/]+(scope|config)\.ya?ml`)
	readOnlyCmd  = regexp.MustCompile(`(?i)^\s*(cat|type|less|more|head|tail|Get-Content|gc|bat)\s`)
)

type decision struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func emit(w io.Writer, d, reason string) int {
	var out decision
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = d
	out.HookSpecificOutput.PermissionDecisionReason = reason
	b, _ := json.Marshal(out)
	fmt.Fprintln(w, string(b))
	return 0
}

// GuardDecision returns "", "ask" or "deny" with a reason for a tool call.
func GuardDecision(toolName string, toolInput json.RawMessage) (string, string) {
	switch toolName {
	case "Bash", "PowerShell":
		var ti struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(toolInput, &ti)
		c := ti.Command
		if humanOnlyCmd.MatchString(c) {
			return "ask", "PenSec: this command approves scope, sends network traffic, or changes a finding disposition. It must be confirmed by the human operator."
		}
		if privateRef.MatchString(c) && !strings.HasPrefix(strings.TrimSpace(c), "pensec") {
			return "ask", "PenSec: direct access to the private ledger or evidence store bypasses the engine. Confirm only if you intend it."
		}
		if scopeRef.MatchString(c) && !readOnlyCmd.MatchString(c) {
			return "ask", "PenSec: the scope/config manifest defines what may be tested. Changes must come from the human operator."
		}
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		var ti struct {
			FilePath     string `json:"file_path"`
			NotebookPath string `json:"notebook_path"`
		}
		_ = json.Unmarshal(toolInput, &ti)
		p := filepath.ToSlash(ti.FilePath + ti.NotebookPath)
		if privateRef.MatchString(p) {
			return "deny", "PenSec: the private ledger, evidence and reports are written only by the PenSec engine."
		}
		if scopeRef.MatchString(p) {
			return "ask", "PenSec: the scope/config manifest defines what may be tested. Changes must be confirmed by the human operator."
		}
	}
	return "", ""
}

func preTool(in Input, w io.Writer) int {
	d, reason := GuardDecision(in.ToolName, in.ToolInput)
	if d == "" {
		return 0
	}
	var ti struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(in.ToolInput, &ti)
	if s := applySummary(ti.Command, projectDir(in)); s != "" {
		reason += "\n" + s
	}
	return emit(w, d, reason)
}

// maxSummaryLines caps the decisions listed in a confirmation prompt.
const maxSummaryLines = 30

// applySummary lists the decisions a `pensec findings apply` command would
// record, so the human confirms the batch knowing what is in it.
func applySummary(cmd, dir string) string {
	m := applyFile.FindStringSubmatch(cmd)
	if m == nil {
		return ""
	}
	p := m[1] + m[2] + m[3]
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	ds, err := engine.ReadTriageDecisions(p)
	if err != nil {
		return "The decisions file could not be read (" + redact.Line(err.Error()) + "); the command will fail."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Decisions to record (%d):", len(ds))
	for i, d := range ds {
		if i == maxSummaryLines {
			fmt.Fprintf(&b, "\n  and %d more in %s", len(ds)-i, redact.Line(p))
			break
		}
		note := redact.Line(d.Note)
		if r := []rune(note); len(r) > 120 {
			note = string(r[:117]) + "..."
		}
		fmt.Fprintf(&b, "\n  %s %s: %s", redact.Line(d.FindingID), redact.Line(d.Action), note)
		if d.Expires != "" {
			fmt.Fprintf(&b, " (until %s)", redact.Line(d.Expires))
		}
	}
	return b.String()
}
