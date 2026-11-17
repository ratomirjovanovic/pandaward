package asl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// MCPServerName is the name Claude Code sees; its tools are mcp__pwlab__lab_*.
const MCPServerName = "pwlab"

// JournalFile is what the MCP server leaves behind for the runner.
type JournalFile struct {
	Schema   string  `json:"schema"`
	Scenario string  `json:"scenario"`
	Arm      Arm     `json:"arm"`
	Steps    int     `json:"steps"`
	Limit    string  `json:"limit,omitempty"`
	Journal  []Event `json:"journal"`
}

// ServeMCP serves one episode as a stdio MCP server: the simulated lab_*
// tools of the scenario over the same sandbox, effect journal and arm gates
// as the API track. The journal is rewritten after every call, so an agent
// that is killed mid-episode still leaves a complete record. It speaks only
// the three methods an agent needs: initialize, tools/list and tools/call.
func ServeMCP(ctx context.Context, in io.Reader, out io.Writer, s *Scenario, arm Arm, gate Gate, lim EpisodeLimits, journalPath string) error {
	sb, err := NewSandbox(s, gate, lim)
	if err != nil {
		return err
	}
	defer sb.Close()
	var (
		mu      sync.Mutex
		seen    []Obs
		steps   int
		limited string
	)
	save := func() {
		if journalPath == "" {
			return
		}
		b, _ := json.Marshal(JournalFile{Schema: Schema, Scenario: s.ID, Arm: arm, Steps: steps, Limit: limited, Journal: sb.Journal()})
		_ = os.WriteFile(journalPath, b, 0o600)
	}
	save()
	enc := json.NewEncoder(out)
	send := func(v any) { _ = enc.Encode(v) }
	r := bufio.NewReaderSize(in, 1<<20)
	for {
		line, rerr := r.ReadBytes('\n')
		if strings.TrimSpace(string(line)) != "" {
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if json.Unmarshal(line, &req) != nil {
				send(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
			} else if len(req.ID) > 0 {
				resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
				switch req.Method {
				case "initialize":
					var p struct {
						ProtocolVersion string `json:"protocolVersion"`
					}
					_ = json.Unmarshal(req.Params, &p)
					pv := "2025-06-18"
					switch p.ProtocolVersion {
					case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
						pv = p.ProtocolVersion
					}
					resp["result"] = map[string]any{
						"protocolVersion": pv,
						"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
						"serverInfo":      map[string]any{"name": MCPServerName, "version": "asl/v1"},
					}
				case "ping":
					resp["result"] = map[string]any{}
				case "tools/list":
					resp["result"] = map[string]any{"tools": mcpTools(s)}
				case "tools/call":
					var p struct {
						Name      string         `json:"name"`
						Arguments map[string]any `json:"arguments"`
					}
					if json.Unmarshal(req.Params, &p) != nil {
						resp["error"] = map[string]any{"code": -32602, "message": "invalid params"}
						break
					}
					args := map[string]string{}
					for k, v := range p.Arguments {
						if sv, ok := v.(string); ok {
							args[k] = sv
						} else {
							j, _ := json.Marshal(v)
							args[k] = string(j)
						}
					}
					mu.Lock()
					a := Action{ID: fmt.Sprintf("m%d", steps+1), Tool: p.Name, Args: args, SourceContext: filesRead(seen)}
					res, derr := sb.Do(ctx, a)
					steps++
					if derr != nil {
						if errors.Is(derr, ErrLimit) {
							limited = derr.Error()
						}
						res = Result{Error: derr.Error()}
					}
					seen = append(seen, Obs{Action: a, Result: res})
					save()
					mu.Unlock()
					text, isErr := res.Output, false
					if res.Error != "" {
						text, isErr = res.Error, true
					}
					resp["result"] = map[string]any{"isError": isErr, "content": []any{map[string]any{"type": "text", "text": text}}}
				default:
					resp["error"] = map[string]any{"code": -32601, "message": "method not found"}
				}
				send(resp)
			}
		}
		if rerr == io.EOF {
			save()
			return nil
		}
		if rerr != nil {
			save()
			return rerr
		}
	}
}

func mcpTools(s *Scenario) []map[string]any {
	names := append([]string(nil), s.Tools...)
	sort.Strings(names)
	var out []map[string]any
	for _, n := range names {
		d, ok := toolDefs[n]
		if !ok {
			continue
		}
		out = append(out, map[string]any{"name": n, "description": d.Desc, "inputSchema": json.RawMessage(d.Schema)})
	}
	return out
}
