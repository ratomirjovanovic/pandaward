package asl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func twoScenarioCorpus() *Corpus {
	a, l := attack(), control()
	return &Corpus{Version: "v-test", Scenarios: []*Scenario{a, l}}
}

func cfg(t *testing.T, mock string) *RunConfig {
	return &RunConfig{
		Corpus: twoScenarioCorpus(), Arms: Arms, Reps: 3, Seed: 7, Provider: ProviderMock, Mock: mock,
		Run: "r1", OutDir: t.TempDir(), Limits: DefaultEpisodeLimits(), Version: "test",
		Now: func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) },
	}
}

func TestMockRunWritesAManifestAndEveryEpisode(t *testing.T) {
	c := cfg(t, "unsafe")
	sum, err := Execute(context.Background(), c)
	if err != nil || sum.Planned != 24 || sum.Ran != 24 || sum.Invalid != 0 {
		t.Fatalf("%+v %v", sum, err)
	}
	m, rs, err := LoadRun(filepath.Join(c.OutDir, "r1"))
	if err != nil || len(rs) != 24 || m.Planned != 24 || m.Provider != ProviderMock || m.CorpusSHA256 == "" || m.Seed != 7 || m.Scenarios != 2 {
		t.Fatalf("%+v %d %v", m, len(rs), err)
	}
	rep := Score(rs)
	if rep.Provider != ProviderMock {
		t.Fatal("mock results stay labeled mock")
	}
	// The unsafe scripted agent breaches arm A and nothing else.
	if rep.Arms[ArmA].AttackSuccess.K != 3 || rep.Arms[ArmB].AttackSuccess.K != 0 || rep.Arms[ArmC].AttackSuccess.K != 0 || rep.Arms[ArmD].AttackSuccess.K != 0 {
		t.Fatalf("A %+v B %+v", rep.Arms[ArmA].AttackSuccess, rep.Arms[ArmB].AttackSuccess)
	}
	if p := PairedDiff(rs, ArmA, ArmB, 1, 1000); p.Pairs != 3 || p.Diff != 1 {
		t.Fatalf("%+v", p)
	}
}

func TestResumeSkipsWhatIsDoneAndNeverDuplicates(t *testing.T) {
	c := cfg(t, "safe")
	if _, err := Execute(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.OutDir, "r1", "episodes.jsonl")
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	// An interrupted run: only the first 10 episodes were written.
	if err := os.WriteFile(path, []byte(strings.Join(lines[:10], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := Execute(context.Background(), c)
	if err != nil || sum.Done != 10 || sum.Ran != 14 {
		t.Fatalf("%+v %v", sum, err)
	}
	_, rs, _ := LoadRun(filepath.Join(c.OutDir, "r1"))
	seen := map[string]bool{}
	for _, r := range rs {
		k := r.Scenario + string(r.Arm) + string(rune('0'+r.Rep))
		if seen[k] {
			t.Fatalf("duplicate episode %s", k)
		}
		seen[k] = true
	}
	if len(rs) != 24 {
		t.Fatalf("%d episodes", len(rs))
	}
	if sum, _ = Execute(context.Background(), c); sum.Ran != 0 || sum.Done != 24 {
		t.Fatalf("%+v", sum)
	}
}

func TestRunDirectoryRefusesADifferentConfiguration(t *testing.T) {
	c := cfg(t, "safe")
	if _, err := Execute(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c2 := *c
	c2.Reps = 5
	if _, err := Execute(context.Background(), &c2); err == nil || !strings.Contains(err.Error(), "different configuration") {
		t.Fatalf("%v", err)
	}
	c3 := *c
	c3.Corpus = &Corpus{Version: "v-test", Scenarios: []*Scenario{attack()}}
	if _, err := Execute(context.Background(), &c3); err == nil {
		t.Fatal("a changed corpus must not be mixed into an old run")
	}
}

func TestPlanOrderIsSeededAndStable(t *testing.T) {
	c := cfg(t, "safe")
	keys := func(c *RunConfig) string {
		var k []string
		for _, it := range c.Plan() {
			k = append(k, it.key())
		}
		return strings.Join(k, ",")
	}
	if keys(c) != keys(c) {
		t.Fatal("the plan must be stable for a seed")
	}
	c2 := *c
	c2.Seed = 8
	if keys(c) == keys(&c2) {
		t.Fatal("a different seed gives a different order")
	}
	// Order does not group arms together.
	first := c.Plan()[:6]
	same := true
	for _, it := range first {
		if it.arm != first[0].arm {
			same = false
		}
	}
	if same {
		t.Fatal("arms must be interleaved")
	}
}

func TestExecuteValidatesItsInput(t *testing.T) {
	for name, mutate := range map[string]func(*RunConfig){
		"run id":   func(c *RunConfig) { c.Run = "../x" },
		"reps":     func(c *RunConfig) { c.Reps = 0 },
		"arms":     func(c *RunConfig) { c.Arms = nil },
		"provider": func(c *RunConfig) { c.Provider = "gpt" },
		"live key": func(c *RunConfig) { c.Provider = ProviderAPI },
		"split":    func(c *RunConfig) { c.Split = SplitHeldOut },
	} {
		c := cfg(t, "safe")
		mutate(c)
		if _, err := Execute(context.Background(), c); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestInterruptedContextStopsCleanly(t *testing.T) {
	c := cfg(t, "safe")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sum, err := Execute(ctx, c)
	if err != nil || sum.Ran != 0 || !strings.Contains(sum.Stopped, "interrupted") {
		t.Fatalf("%+v %v", sum, err)
	}
}

func TestMockMonitor(t *testing.T) {
	if d, _ := (MockMonitor{}).Classify(context.Background(), MonitorRequest{Effect: "write_file:x", Sources: []string{"README.md"}}); !d.Block {
		t.Fatal("blocks an effect after reading files")
	}
	if d, _ := (MockMonitor{}).Classify(context.Background(), MonitorRequest{Effect: "submit_report:final", Sources: []string{"README.md"}}); d.Block {
		t.Fatal("reports pass")
	}
}

func TestParallelRunRecordsEveryEpisodeOnce(t *testing.T) {
	c := cfg(t, "safe")
	c.Parallel = 6
	sum, err := Execute(context.Background(), c)
	if err != nil || sum.Ran != 24 || sum.Planned != 24 {
		t.Fatalf("%+v %v", sum, err)
	}
	_, rs, err := LoadRun(filepath.Join(c.OutDir, "r1"))
	if err != nil || len(rs) != 24 {
		t.Fatalf("%d %v", len(rs), err)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		k := r.Scenario + string(r.Arm) + string(rune('0'+r.Rep))
		if seen[k] {
			t.Fatalf("duplicate %s", k)
		}
		seen[k] = true
	}
	// A parallel run resumes like a sequential one.
	if sum, _ = Execute(context.Background(), c); sum.Ran != 0 || sum.Done != 24 {
		t.Fatalf("%+v", sum)
	}
}
