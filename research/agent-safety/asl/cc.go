package asl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrUsageLimit means the subscription stopped the run at a usage limit. It is
// not an attack outcome and not an episode result: the run stops cleanly and
// resumes later at the next unfinished episode.
var ErrUsageLimit = errors.New("claude code usage limit reached")

var usageLimitRe = regexp.MustCompile(`(?i)(usage limit|rate limit|limit reached|limit will reset|resets (at|in)|too many requests|overloaded)`)

// CCConfig drives headless Claude Code on the maintainer's subscription. It is
// the end-to-end track: a different system prompt and tool plumbing than the
// API track, so its results are never merged with it.
type CCConfig struct {
	Claude    string // the claude executable
	PandaWard string // this binary, started as the stdio MCP server
	CorpusDir string
	Model     string
	Timeout   time.Duration
	// Launch runs a command and returns its stdout. Tests replace it.
	Launch func(ctx context.Context, name string, args, env []string, dir string) ([]byte, error)
}

// CCArgs are the headless Claude Code arguments of an episode. The point of
// each flag is isolation: no built-in tools (nothing can touch the host), only
// the lab MCP server, none of the maintainer's settings, hooks, plugins or
// memory, no saved session, and only the lab tools allowed, so any other tool
// request is denied rather than prompted. Checked on a real claude 2.1.326:
// the agent saw no memory path, instructions or plugins.
func CCArgs(prompt, model, mcpConfig string) []string {
	args := []string{
		"-p", prompt,
		// No user, project or local settings: no hooks, plugins, memory or
		// permissions of the maintainer reach the agent. (--safe-mode would
		// also switch MCP servers off, which the lab needs.)
		"--setting-sources", "",
		"--settings", `{"autoMemoryEnabled":false,"hooks":{},"enabledPlugins":{}}`,
		"--tools", "",
		"--strict-mcp-config", "--mcp-config", mcpConfig,
		"--allowed-tools", "mcp__" + MCPServerName,
		"--no-session-persistence",
		"--output-format", "json",
		"--append-system-prompt", SystemPrompt,
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	return args
}

// CCEnv keeps what Claude Code needs to find the subscription login and drops
// everything that could change the billing or the provider: with an API key
// in the environment Claude Code would bill the API instead of the plan.
func CCEnv(environ []string) []string {
	keep := map[string]bool{
		"PATH": true, "HOME": true, "USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true,
		"SYSTEMROOT": true, "SYSTEMDRIVE": true, "TEMP": true, "TMP": true, "TMPDIR": true, "COMSPEC": true,
		"PATHEXT": true, "USERNAME": true, "LANG": true, "LC_ALL": true, "TERM": true, "XDG_CONFIG_HOME": true,
		"HOMEDRIVE": true, "HOMEPATH": true, "PROGRAMFILES": true, "PROGRAMDATA": true, "WINDIR": true,
	}
	out := []string{"CLAUDE_CODE_DISABLE_AUTO_MEMORY=1"}
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if keep[strings.ToUpper(k)] {
			out = append(out, kv)
		}
	}
	return out
}

func defaultLaunch(ctx context.Context, name string, args, env []string, dir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env, cmd.Dir = env, dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && out.Len() == 0 {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), err
}

func (c *CCConfig) launch() func(context.Context, string, []string, []string, string) ([]byte, error) {
	if c.Launch != nil {
		return c.Launch
	}
	return defaultLaunch
}

// Version returns `claude --version`, recorded in the manifest.
func (c *CCConfig) Version(ctx context.Context) string {
	out, err := c.launch()(ctx, c.Claude, []string{"--version"}, CCEnv(os.Environ()), os.TempDir())
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

type ccResult struct {
	Result   string `json:"result"`
	IsError  bool   `json:"is_error"`
	Subtype  string `json:"subtype"`
	NumTurns int    `json:"num_turns"`
}

// ccEpisode runs one episode through headless Claude Code. The bool is true
// when the subscription limit stopped it, in which case the episode is not
// recorded and the run stops to resume later.
func (c *RunConfig) ccEpisode(ctx context.Context, it planItem) (EpisodeResult, bool) {
	s := it.sc
	cc := c.CC
	tmp, err := os.MkdirTemp("", "asl-cc-")
	if err != nil {
		return invalid(s, it.arm, ProviderCC, err.Error()), false
	}
	defer os.RemoveAll(tmp)
	workdir := filepath.Join(tmp, "work")
	_ = os.MkdirAll(workdir, 0o700)
	journal := filepath.Join(tmp, "journal.json")
	cfgPath := filepath.Join(tmp, "mcp.json")
	cfg, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{MCPServerName: map[string]any{
		"command": cc.PandaWard,
		"args":    []string{"lab", "mcp", "--corpus", cc.CorpusDir, "--scenario", s.ID, "--arm", string(it.arm), "--journal", journal},
	}}})
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return invalid(s, it.arm, ProviderCC, err.Error()), false
	}
	timeout := cc.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Minute
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, lerr := cc.launch()(ectx, cc.Claude, CCArgs(s.UserTask, cc.Model, cfgPath), CCEnv(os.Environ()), workdir)

	res := EpisodeResult{Schema: Schema, Scenario: s.ID, Arm: it.arm, Provider: ProviderCC, Status: StatusValid}
	var r ccResult
	_ = json.Unmarshal(bytes.TrimSpace(out), &r)
	if usageLimitRe.MatchString(r.Result) && (r.IsError || lerr != nil) || (lerr != nil && usageLimitRe.MatchString(lerr.Error())) {
		return res, true
	}
	res.Final = r.Result
	jb, jerr := os.ReadFile(journal)
	var jf JournalFile
	if jerr == nil {
		_ = json.Unmarshal(jb, &jf)
	}
	res.Journal, res.Steps = jf.Journal, jf.Steps
	switch {
	case errors.Is(ectx.Err(), context.DeadlineExceeded):
		res.Status, res.InvalidReason = StatusInvalid, "claude code: timeout"
	case jerr != nil:
		res.Status, res.InvalidReason = StatusInvalid, "claude code: no journal was written (the MCP server did not start)"
	case jf.Limit != "":
		res.Status, res.InvalidReason = StatusInvalid, jf.Limit
	case lerr != nil:
		res.Status, res.InvalidReason = StatusInvalid, "claude code: "+truncate(lerr.Error(), 120)
	case r.IsError:
		res.Status, res.InvalidReason = StatusInvalid, "claude code: "+truncate(r.Subtype+" "+r.Result, 120)
	}
	res.Outcome = Judge(s, res.Journal)
	judgeReport(s, &res)
	return res, false
}
