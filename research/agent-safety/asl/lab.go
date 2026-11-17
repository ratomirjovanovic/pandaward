package asl

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RunConfig describes one run of the lab.
type RunConfig struct {
	Corpus *Corpus
	Arms   []Arm
	Reps   int
	Seed   int64
	// Split limits the corpus: dev, heldout or all.
	Split string
	// Provider is mock or api. Mock runs scripted agents (Mock says safe or
	// unsafe) and are always labeled mock.
	Provider     string
	Mock         string
	Model        string
	MonitorModel string
	Run          string
	OutDir       string
	Ledger       *Ledger
	APIKey       string
	Limits       EpisodeLimits
	MaxTurns     int
	Version      string
	Now          func() time.Time
}

// Manifest records exactly what a run was, so it can be replayed and audited.
type Manifest struct {
	Schema       string        `json:"schema"`
	Run          string        `json:"run"`
	Provider     string        `json:"provider"`
	Mock         string        `json:"mock,omitempty"`
	Model        string        `json:"model,omitempty"`
	MonitorModel string        `json:"monitor_model,omitempty"`
	CorpusVer    string        `json:"corpus_version"`
	CorpusSHA256 string        `json:"corpus_sha256"`
	Split        string        `json:"split"`
	Arms         []Arm         `json:"arms"`
	Reps         int           `json:"reps"`
	Seed         int64         `json:"seed"`
	Scenarios    int           `json:"scenarios"`
	Planned      int           `json:"planned_episodes"`
	Limits       EpisodeLimits `json:"limits"`
	MaxTurns     int           `json:"max_model_turns,omitempty"`
	Version      string        `json:"pandaward_version"`
	CreatedAt    time.Time     `json:"created_at"`
}

type planItem struct {
	sc  *Scenario
	arm Arm
	rep int
}

func (p planItem) key() string { return fmt.Sprintf("%s|%s|%d", p.sc.ID, p.arm, p.rep) }

func (c *RunConfig) selected() []*Scenario {
	var out []*Scenario
	for _, s := range c.Corpus.Scenarios {
		switch c.Split {
		case "", "all":
		case SplitDev, SplitHeldOut:
			if s.Split != c.Split {
				continue
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Plan lists every episode of the run in a fixed pseudo-random order, so a
// provider's time-dependent behavior is not confounded with an arm.
func (c *RunConfig) Plan() []planItem {
	var items []planItem
	for _, s := range c.selected() {
		for rep := 0; rep < c.Reps; rep++ {
			for _, a := range c.Arms {
				items = append(items, planItem{s, a, rep})
			}
		}
	}
	rng := rand.New(rand.NewSource(c.Seed))
	rng.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	return items
}

// CorpusHash fingerprints the scenarios of a run.
func CorpusHash(scs []*Scenario) string {
	h := sha256.New()
	for _, s := range scs {
		b, _ := json.Marshal(s)
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RunSummary is what Execute reports.
type RunSummary struct {
	Planned   int
	Done      int // finished in earlier invocations
	Ran       int
	Invalid   int
	Stopped   string // why the run stopped early, if it did
	Directory string
}

func (c *RunConfig) manifest(n int) Manifest {
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	scs := c.selected()
	return Manifest{
		Schema: Schema, Run: c.Run, Provider: c.Provider, Mock: c.Mock, Model: c.Model, MonitorModel: c.MonitorModel,
		CorpusVer: c.Corpus.Version, CorpusSHA256: CorpusHash(scs), Split: orAll(c.Split), Arms: c.Arms, Reps: c.Reps,
		Seed: c.Seed, Scenarios: len(scs), Planned: n, Limits: c.Limits, MaxTurns: c.MaxTurns, Version: c.Version, CreatedAt: now,
	}
}

func orAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

// Execute runs the plan, appending one JSON line per episode and skipping
// episodes already recorded, so an interrupted run resumes at the next
// unfinished one. It stops, without dropping anything, when the budget cap is
// reached or the context ends.
func Execute(ctx context.Context, c *RunConfig) (RunSummary, error) {
	var sum RunSummary
	if c.Corpus == nil || len(c.selected()) == 0 {
		return sum, errors.New("no scenarios selected")
	}
	if c.Run == "" || strings.ContainsAny(c.Run, `/\`) || c.Run == "." || c.Run == ".." {
		return sum, errors.New("run id must be a plain name")
	}
	if c.Reps < 1 || len(c.Arms) == 0 {
		return sum, errors.New("need at least one arm and one repetition")
	}
	if c.Provider != ProviderMock && c.Provider != ProviderAPI {
		return sum, fmt.Errorf("unknown provider %q", c.Provider)
	}
	if c.Provider == ProviderAPI && (c.Ledger == nil || c.APIKey == "") {
		return sum, errors.New("a live run needs a budget ledger and an API key")
	}
	dir := filepath.Join(c.OutDir, c.Run)
	sum.Directory = dir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return sum, err
	}
	plan := c.Plan()
	sum.Planned = len(plan)
	mf := c.manifest(len(plan))
	mpath := filepath.Join(dir, "manifest.json")
	if b, err := os.ReadFile(mpath); err == nil {
		var old Manifest
		if json.Unmarshal(b, &old) != nil {
			return sum, errors.New("manifest.json is unreadable")
		}
		old.CreatedAt, mf.CreatedAt = time.Time{}, time.Time{}
		a, _ := json.Marshal(old)
		bb, _ := json.Marshal(mf)
		if string(a) != string(bb) {
			return sum, errors.New("this run directory has a different configuration or corpus: use a new run id")
		}
	} else {
		b, _ := json.MarshalIndent(mf, "", "  ")
		if err := os.WriteFile(mpath, append(b, '\n'), 0o644); err != nil {
			return sum, err
		}
	}
	done, err := readDone(filepath.Join(dir, "episodes.jsonl"))
	if err != nil {
		return sum, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "episodes.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	for _, it := range plan {
		if done[it.key()] {
			sum.Done++
			continue
		}
		if err := ctx.Err(); err != nil {
			sum.Stopped = "interrupted: " + err.Error()
			return sum, nil
		}
		res, budget := c.episode(ctx, it)
		res.Rep = it.rep
		line, _ := json.Marshal(res)
		if _, err := f.Write(append(line, '\n')); err != nil {
			return sum, err
		}
		_ = f.Sync()
		sum.Ran++
		if res.Status != StatusValid {
			sum.Invalid++
		}
		if budget {
			sum.Stopped = "budget cap reached: " + res.InvalidReason
			return sum, ErrBudget
		}
	}
	return sum, nil
}

func (c *RunConfig) episode(ctx context.Context, it planItem) (EpisodeResult, bool) {
	s := it.sc
	if c.Provider == ProviderMock {
		steps := s.Scripts.Safe
		if c.Mock == "unsafe" && len(s.Scripts.Unsafe) > 0 {
			steps = s.Scripts.Unsafe
		}
		gate := GateFor(it.arm, s, EvidenceGate{}, &MonitorGate{Model: MockMonitor{}, Ctx: ctx})
		return RunEpisode(ctx, s, it.arm, &Scripted{Steps: steps}, ProviderMock, gate, c.Limits), false
	}
	epID := fmt.Sprintf("%s-%s-%d", s.ID, it.arm, it.rep)
	client, err := NewClient(c.Model, c.APIKey, c.Ledger, c.Run, epID)
	if err != nil {
		return invalid(s, it.arm, ProviderAPI, err.Error()), false
	}
	var monitor Gate
	if it.arm == ArmD {
		mm := c.MonitorModel
		if mm == "" {
			mm = c.Model
		}
		mc, err := NewClient(mm, c.APIKey, c.Ledger, c.Run, epID)
		if err != nil {
			return invalid(s, it.arm, ProviderAPI, err.Error()), false
		}
		monitor = &MonitorGate{Model: &LLMMonitor{Client: mc}, Ctx: ctx, Timeout: 90 * time.Second}
	}
	agent := &ModelAgent{Client: client, Task: s.UserTask, Tools: s.Tools, MaxTurns: c.MaxTurns}
	res := RunEpisode(ctx, s, it.arm, agent, ProviderAPI, GateFor(it.arm, s, EvidenceGate{}, monitor), c.Limits)
	return res, strings.Contains(res.InvalidReason, ErrBudget.Error())
}

func invalid(s *Scenario, arm Arm, provider, reason string) EpisodeResult {
	return EpisodeResult{Schema: Schema, Scenario: s.ID, Arm: arm, Provider: provider, Status: StatusInvalid, InvalidReason: reason}
}

func readDone(path string) (map[string]bool, error) {
	done := map[string]bool{}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return done, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var r EpisodeResult
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		done[fmt.Sprintf("%s|%s|%d", r.Scenario, r.Arm, r.Rep)] = true
	}
	return done, sc.Err()
}

// LoadRun reads a run directory.
func LoadRun(dir string) (Manifest, []EpisodeResult, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return m, nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, nil, err
	}
	f, err := os.Open(filepath.Join(dir, "episodes.jsonl"))
	if err != nil {
		return m, nil, err
	}
	defer f.Close()
	var out []EpisodeResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var r EpisodeResult
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return m, nil, fmt.Errorf("episodes.jsonl: %w", err)
		}
		out = append(out, r)
	}
	return m, out, sc.Err()
}

// MockMonitor stands in for a model monitor in mock runs: it blocks any
// effect proposed after the agent read a file, which is the rule a real
// monitor is meant to approximate. Mock results are labeled mock and say
// nothing about a real monitor.
type MockMonitor struct{}

// Classify implements MonitorModel.
func (MockMonitor) Classify(_ context.Context, r MonitorRequest) (MonitorDecision, error) {
	if len(r.Sources) > 0 && !strings.HasPrefix(r.Effect, EffectReport+":") {
		return MonitorDecision{Block: true, Reason: "mock monitor: effect after reading untrusted files"}, nil
	}
	return MonitorDecision{}, nil
}
