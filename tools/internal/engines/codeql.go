package engines

import (
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

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

// CodeQL is the engine name of GitHub's CodeQL with its default Python
// queries, run as a user would run it: no PandaWard rule or option.
const CodeQL = "codeql-default"

// Environment variables of the codeql-default engine.
const (
	// CodeQLHome is the directory of an unpacked CodeQL bundle (the CLI with
	// its standard queries). Without it the engine is not run.
	CodeQLHome = "PANDAWARD_CODEQL_HOME"
	// codeQLSuite is the query suite GitHub's default setup for code
	// scanning runs on Python, from the standard query pack in the bundle.
	codeQLSuite = "codeql/python-queries:codeql-suites/python-code-scanning.qls"
)

// codeql builds a CodeQL database of the Python sources, which needs no
// build, runs the default code scanning suite and reads the SARIF.
//
// CodeQL's license allows analysing an open source codebase hosted on GitHub
// and academic research, and forbids sharing the software; the bundle is
// downloaded by the workflow from GitHub's release and never redistributed.
func codeql(ctx context.Context, inv *inventory.Inventory) (Run, error) {
	r := Run{Engine: CodeQL}
	if inv.Languages["python"] == 0 {
		r.NotRun = "CodeQL is measured on Python only (no Python files in this tree)"
		return r, nil
	}
	home := os.Getenv(CodeQLHome)
	if home == "" {
		r.NotRun = CodeQLHome + " is not set (an unpacked CodeQL bundle)"
		return r, nil
	}
	bin := filepath.Join(home, "codeql")
	if _, err := exec.LookPath(bin); err != nil {
		r.NotRun = "no codeql executable in " + home
		return r, nil
	}
	work, err := os.MkdirTemp("", "pwcodeql-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(work)
	env := append(os.Environ(), "HOME="+filepath.Join(work, "home"), "USERPROFILE="+filepath.Join(work, "home"))
	run := func(timeout time.Duration, args ...string) (string, error) {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(cctx, bin, args...)
		cmd.Env = env
		var out, errb strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return out.String(), fmt.Errorf("codeql %s: %v %s", args[0], err, lastLine(errb.String()))
		}
		return out.String(), nil
	}
	if out, err := run(time.Minute, "version", "--format=terse"); err == nil {
		r.Version = "CodeQL " + strings.TrimSpace(out)
	}
	db := filepath.Join(work, "db")
	if _, err := run(2*time.Hour, "database", "create", db, "--language=python", "--source-root", inv.Root, "--overwrite"); err != nil {
		return r, err
	}
	sarif := filepath.Join(work, "out.sarif")
	if _, err := run(3*time.Hour, "database", "analyze", db, codeQLSuite, "--format=sarif-latest", "--output", sarif); err != nil {
		return r, err
	}
	b, err := os.ReadFile(sarif)
	if err != nil {
		return r, err
	}
	fs, err := parseSARIF(b)
	if err != nil {
		return r, fmt.Errorf("%s: %v", CodeQL, err)
	}
	r.Findings = fs
	return r, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

var cweTagRe = regexp.MustCompile(`(?i)^external/cwe/cwe-0*(\d+)$`)

type sarifRule struct {
	ID         string `json:"id"`
	Properties struct {
		Tags []string `json:"tags"`
	} `json:"properties"`
}

// parseSARIF reads CodeQL's SARIF into findings. The CWE is the first
// external/cwe tag of the rule that produced the result.
func parseSARIF(b []byte) ([]Finding, error) {
	var d struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []sarifRule `json:"rules"`
				} `json:"driver"`
				Extensions []struct {
					Rules []sarifRule `json:"rules"`
				} `json:"extensions"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							Start int `json:"startLine"`
							End   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("the output is not SARIF JSON: " + err.Error())
	}
	var out []Finding
	for _, run := range d.Runs {
		cwe := map[string]string{}
		note := func(r sarifRule) {
			for _, t := range r.Properties.Tags {
				if m := cweTagRe.FindStringSubmatch(t); m != nil {
					if _, ok := cwe[r.ID]; !ok {
						cwe[r.ID] = "CWE-" + m[1]
					}
				}
			}
		}
		for _, r := range run.Tool.Driver.Rules {
			note(r)
		}
		for _, e := range run.Tool.Extensions {
			for _, r := range e.Rules {
				note(r)
			}
		}
		for _, r := range run.Results {
			if len(r.Locations) == 0 {
				continue
			}
			p := r.Locations[0].Physical
			end := p.Region.End
			if end < p.Region.Start {
				end = p.Region.Start
			}
			file := strings.TrimPrefix(filepath.ToSlash(p.Artifact.URI), "./")
			out = append(out, Finding{Rule: "codeql." + r.RuleID, CWE: cwe[r.RuleID], File: file, Line: p.Region.Start, EndLine: end})
		}
	}
	return out, nil
}
