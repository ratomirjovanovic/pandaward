package asl

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Triage measures whether an agent that reads a finding and its source can
// tell a true finding from a false positive, using findings that a benchmark
// has labelled. The agent has no tools: the source file is in the prompt, so
// nothing can touch the host and a verdict can only rest on what was shown.
// A verdict is a hypothesis: the report says what it removed and what it
// wrongly removed, and nothing here closes a finding.

// TriageSample is one labelled finding (a line of `owaspbench --emit-findings`).
type TriageSample struct {
	Suite    string `json:"suite"`
	Engine   string `json:"engine"`
	TestCase string `json:"test_case"`
	Category string `json:"category"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Rule     string `json:"rule"`
	CWE      string `json:"cwe,omitempty"`
	Label    string `json:"label"`
}

// Held reports whether a test case belongs to the held-out split. The split
// is a fixed function of the case name, so it is frozen without a file and
// cannot be tuned: one case in five.
func Held(testCase string) bool {
	h := sha256.Sum256([]byte("asl-triage-split/" + testCase))
	return binary.BigEndian.Uint32(h[:4])%5 == 0
}

// LoadTriageSamples reads labelled findings, keeps the true and false
// positive ones of one engine in one split and returns a balanced, seeded
// sample of at most n per label, one finding per test case.
func LoadTriageSamples(path, engine string, held bool, n int, seed int64) ([]TriageSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	byLabel := map[string]map[string]TriageSample{"true": {}, "false_positive": {}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var s TriageSample
		if json.Unmarshal(sc.Bytes(), &s) != nil || s.Engine != engine || s.TestCase == "" || Held(s.TestCase) != held {
			continue
		}
		m, ok := byLabel[s.Label]
		if !ok {
			continue
		}
		if _, dup := m[s.TestCase]; !dup {
			m[s.TestCase] = s
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var out []TriageSample
	for _, label := range []string{"true", "false_positive"} {
		var all []TriageSample
		for _, s := range byLabel[label] {
			all = append(all, s)
		}
		key := func(s TriageSample) string {
			h := sha256.Sum256([]byte(fmt.Sprintf("%d/%s/%s", seed, label, s.TestCase)))
			return string(h[:])
		}
		sort.Slice(all, func(i, j int) bool { return key(all[i]) < key(all[j]) })
		if len(all) > n {
			all = all[:n]
		}
		out = append(out, all...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TestCase < out[j].TestCase })
	return out, nil
}

// TriagePrompt is the whole task. It never names the label or the benchmark.
func TriagePrompt(s TriageSample, source string) string {
	var b strings.Builder
	b.WriteString("You are triaging one finding of a static analysis scanner. Decide from the code below whether it is a real vulnerability (true_positive) or a false positive. Judge only what the code shows: follow the data from where it enters to the flagged line and check whether a sanitizer, a constant, a safe API or dead code stops it.\n\n")
	fmt.Fprintf(&b, "Finding: rule %s", s.Rule)
	if s.CWE != "" {
		fmt.Fprintf(&b, " (%s)", s.CWE)
	}
	fmt.Fprintf(&b, " at %s line %d.\n\nSource of %s (line numbers added):\n", s.File, s.Line, filepath.Base(s.File))
	for i, l := range strings.Split(source, "\n") {
		fmt.Fprintf(&b, "%4d  %s\n", i+1, l)
	}
	b.WriteString("\nAnswer with exactly one line of JSON and nothing else: {\"verdict\":\"true_positive\" or \"false_positive\",\"line\":<the line number that decides it>,\"quote\":\"<the exact text of that line, trimmed>\",\"reason\":\"<one sentence>\"}\n")
	return b.String()
}

// TriageVerdict is a parsed answer.
type TriageVerdict struct {
	Verdict string `json:"verdict"`
	Line    int    `json:"line"`
	Quote   string `json:"quote"`
	Reason  string `json:"reason"`
}

var jsonLineRe = regexp.MustCompile(`\{[^{}]*"verdict"[^{}]*\}`)

// ParseVerdict finds the verdict in an agent reply.
func ParseVerdict(reply string) (TriageVerdict, bool) {
	for _, m := range jsonLineRe.FindAllString(reply, -1) {
		var v TriageVerdict
		if json.Unmarshal([]byte(m), &v) == nil && (v.Verdict == "true_positive" || v.Verdict == "false_positive") {
			return v, true
		}
	}
	return TriageVerdict{}, false
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// EvidenceOK is the evidence gate: the cited line must exist and the quote
// must be the text of that line (whitespace aside). A verdict that cites
// nothing real is not accepted.
func EvidenceOK(v TriageVerdict, source string) bool {
	lines := strings.Split(source, "\n")
	if v.Line < 1 || v.Line > len(lines) || squash(v.Quote) == "" {
		return false
	}
	have := squash(lines[v.Line-1])
	want := squash(v.Quote)
	return have != "" && (strings.Contains(have, want) || strings.Contains(want, have))
}

// TriageRecord is the result of one finding.
type TriageRecord struct {
	TriageSample
	Verdict       TriageVerdict `json:"verdict"`
	Parsed        bool          `json:"parsed"`
	GateOK        bool          `json:"gate_ok"`
	Status        string        `json:"status"`
	InvalidReason string        `json:"invalid_reason,omitempty"`
	Model         string        `json:"model"`
}

// TriageConfig runs triage through headless Claude Code on the subscription.
type TriageConfig struct {
	CC       CCConfig
	Checkout string // root of the benchmark checkout
	Out      string // JSON lines of records; finished findings are skipped on resume
	Parallel int
}

func triageArgs(prompt, model string) []string {
	args := []string{
		"-p", prompt,
		"--setting-sources", "",
		"--settings", `{"autoMemoryEnabled":false,"hooks":{},"enabledPlugins":{}}`,
		"--tools", "",
		"--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`,
		"--no-session-persistence",
		"--output-format", "json",
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	return args
}

func triageKey(s TriageSample) string {
	return s.Engine + "|" + s.TestCase + "|" + s.File + "|" + fmt.Sprint(s.Line)
}

// RunTriage judges every sample once and appends one record each to Out. It
// returns ErrUsageLimit when the subscription stops it; a rerun resumes.
func RunTriage(ctx context.Context, c TriageConfig, samples []TriageSample) error {
	done := map[string]bool{}
	if f, err := os.Open(c.Out); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var r TriageRecord
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				done[triageKey(r.TriageSample)] = true
			}
		}
		f.Close()
	}
	out, err := os.OpenFile(c.Out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	par := c.Parallel
	if par < 1 {
		par = 1
	}
	var mu sync.Mutex
	var limitHit bool
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for _, s := range samples {
		if done[triageKey(s)] {
			continue
		}
		mu.Lock()
		stop := limitHit
		mu.Unlock()
		if stop || ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(s TriageSample) {
			defer wg.Done()
			defer func() { <-sem }()
			rec, limit := c.one(ctx, s)
			mu.Lock()
			defer mu.Unlock()
			if limit {
				limitHit = true
				return
			}
			b, _ := json.Marshal(rec)
			_, _ = out.Write(append(b, '\n'))
		}(s)
	}
	wg.Wait()
	if limitHit {
		return ErrUsageLimit
	}
	return ctx.Err()
}

func (c TriageConfig) one(ctx context.Context, s TriageSample) (TriageRecord, bool) {
	rec := TriageRecord{TriageSample: s, Status: StatusValid, Model: c.CC.Model}
	rel := filepath.FromSlash(s.File)
	src, err := os.ReadFile(filepath.Join(c.Checkout, rel))
	if err != nil {
		rec.Status, rec.InvalidReason = StatusInvalid, "source not readable"
		return rec, false
	}
	timeout := c.CC.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tmp, _ := os.MkdirTemp("", "asl-triage-")
	defer os.RemoveAll(tmp)
	raw, lerr := c.CC.launch()(ectx, c.CC.Claude, triageArgs(TriagePrompt(s, string(src)), c.CC.Model), CCEnv(os.Environ()), tmp)
	var r ccResult
	_ = json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &r)
	if usageLimitRe.MatchString(r.Result) && (r.IsError || lerr != nil) || (lerr != nil && usageLimitRe.MatchString(lerr.Error())) {
		return rec, true
	}
	switch {
	case ectx.Err() != nil:
		rec.Status, rec.InvalidReason = StatusInvalid, "timeout"
	case lerr != nil && r.Result == "":
		rec.Status, rec.InvalidReason = StatusInvalid, "claude code: "+truncate(lerr.Error(), 120)
	case r.IsError:
		rec.Status, rec.InvalidReason = StatusInvalid, "claude code: "+truncate(r.Subtype, 120)
	default:
		v, ok := ParseVerdict(r.Result)
		rec.Verdict, rec.Parsed = v, ok
		if !ok {
			rec.Status, rec.InvalidReason = StatusInvalid, "no verdict in the reply"
		} else {
			rec.GateOK = EvidenceOK(v, string(src))
		}
	}
	return rec, false
}

// TriageArm is the outcome of one way of using the verdicts. "Kept" findings
// are those the user still sees.
type TriageArm struct {
	Name string
	// Counts over the valid records.
	TrueKept, TrueDismissed, FPKept, FPDismissed int
}

// Precision of the findings the user still sees.
func (a TriageArm) Precision() Rate { return Wilson(a.TrueKept, a.TrueKept+a.FPKept) }

// Recall is the share of true findings still shown.
func (a TriageArm) Recall() Rate { return Wilson(a.TrueKept, a.TrueKept+a.TrueDismissed) }

// FPRemoved is the share of false positives removed.
func (a TriageArm) FPRemoved() Rate { return Wilson(a.FPDismissed, a.FPDismissed+a.FPKept) }

// ScoreTriage compares the raw scan (nothing dismissed), triage (a false
// positive verdict dismisses) and triage with the evidence gate (a dismissal
// counts only when its cited line is real). Invalid records are counted and
// returned, never dropped silently.
func ScoreTriage(recs []TriageRecord) (arms []TriageArm, invalid int) {
	raw, tri, gate := TriageArm{Name: "raw scan"}, TriageArm{Name: "triage"}, TriageArm{Name: "triage + evidence gate"}
	add := func(a *TriageArm, isTrue, dismissed bool) {
		switch {
		case isTrue && dismissed:
			a.TrueDismissed++
		case isTrue:
			a.TrueKept++
		case dismissed:
			a.FPDismissed++
		default:
			a.FPKept++
		}
	}
	for _, r := range recs {
		if r.Status != StatusValid {
			invalid++
			continue
		}
		isTrue := r.Label == "true"
		fpVerdict := r.Verdict.Verdict == "false_positive"
		add(&raw, isTrue, false)
		add(&tri, isTrue, fpVerdict)
		add(&gate, isTrue, fpVerdict && r.GateOK)
	}
	return []TriageArm{raw, tri, gate}, invalid
}

// LoadTriageRecords reads a records file.
func LoadTriageRecords(path string) ([]TriageRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []TriageRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r TriageRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}
