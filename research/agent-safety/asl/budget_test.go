package asl

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestCost(t *testing.T) {
	// $0.10 and $0.50 per million tokens: 10,000 in and 1,000 out.
	c, err := Cost("claude-haiku-5-5", 10000, 1000)
	if err != nil || c != 1500 {
		t.Fatalf("haiku cost %d %v, want 1500 micro-dollars", c, err)
	}
	// Prompts over 100K tokens are billed at the long rates.
	c, _ = Cost("claude-haiku-5-5", 200000, 1000)
	if want := Micro(200000*0.5 + 1000*2.5); c != want {
		t.Fatalf("long prompt cost %d, want %d", c, want)
	}
	c, _ = Cost("claude-sonnet-5-5", 1000000, 1000000)
	if c != Dollars(12) {
		t.Fatalf("sonnet cost %s", c.USD())
	}
	if _, err := Cost("claude-unknown", 1, 1); err == nil {
		t.Fatal("an unpriced model must be refused")
	}
	if Dollars(5) != 5_000_000 || Dollars(0.05).USD() != "$0.0500" {
		t.Fatal("dollar conversion")
	}
}

func newLedger(t *testing.T, lim Limits) (*Ledger, string) {
	p := filepath.Join(t.TempDir(), "budget.json")
	l, err := OpenLedger(p, lim)
	if err != nil {
		t.Fatal(err)
	}
	return l, p
}

func TestReserveCommitAndCaps(t *testing.T) {
	l, _ := newLedger(t, Limits{Total: Dollars(1), PerRun: Dollars(0.5), PerEpis: Dollars(0.1)})
	// A worst case of $0.06 (400k... use haiku: 500k in at long rate is $0.25, keep small)
	r, err := l.Reserve("r1", "e1", "claude-haiku-5-5", 80000, 4000)
	if err != nil {
		t.Fatal(err)
	}
	if rep := l.Report(); rep.Spent != 80000*0.1+4000*0.5 {
		t.Fatalf("the worst case is held while the call runs: %s", rep.Spent.USD())
	}
	// The call used less than reserved.
	if err := r.Commit(60000, 1000); err != nil {
		t.Fatal(err)
	}
	if got := l.Report().Spent; got != Micro(60000*0.1+1000*0.5) {
		t.Fatalf("committed spend %s", got.USD())
	}
	if err := r.Commit(1, 1); err == nil {
		t.Fatal("a reservation settles once")
	}
	// An episode cap: this episode has $0.0065 spent; a $0.12 call exceeds $0.1.
	if _, err := l.Reserve("r1", "e1", "claude-sonnet-5-5", 40000, 4000); !errors.Is(err, ErrBudget) {
		t.Fatalf("episode cap not enforced: %v", err)
	}
	// Another episode of the same run is fine until the run cap.
	if _, err := l.Reserve("r1", "e2", "claude-haiku-5-5", 80000, 4000); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownOutcomeStaysCharged(t *testing.T) {
	l, _ := newLedger(t, DefaultLimits())
	r, err := l.Reserve("r", "e", "claude-haiku-5-5", 10000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Abandon(); err != nil {
		t.Fatal(err)
	}
	if got := l.Report().Spent; got != Micro(10000*0.1+2000*0.5) {
		t.Fatalf("an abandoned call keeps its whole reservation: %s", got.USD())
	}
	r2, _ := l.Reserve("r", "e", "claude-haiku-5-5", 10000, 2000)
	if err := r2.Cancel(); err != nil {
		t.Fatal(err)
	}
	if got := l.Report().Spent; got != Micro(10000*0.1+2000*0.5) {
		t.Fatalf("a call that was never sent costs nothing: %s", got.USD())
	}
}

func TestTotalCapAndPersistence(t *testing.T) {
	l, path := newLedger(t, Limits{Total: Dollars(0.01), PerRun: Dollars(0.01), PerEpis: Dollars(0.01)})
	if _, err := l.Reserve("r", "e", "claude-haiku-5-5", 10000, 1000); err != nil { // $0.0015
		t.Fatal(err)
	}
	// Reopening with a larger cap keeps the original: raising it is a file edit.
	l2, err := OpenLedger(path, Limits{Total: Dollars(500), PerRun: Dollars(500), PerEpis: Dollars(500)})
	if err != nil {
		t.Fatal(err)
	}
	if rep := l2.Report(); rep.Cap != Dollars(0.01) || rep.Spent != 1500 {
		t.Fatalf("the ledger must keep its cap and spend: %+v", rep)
	}
	for i := 0; i < 10; i++ {
		if _, err := l2.Reserve("r", "e"+string(rune('a'+i)), "claude-haiku-5-5", 10000, 1000); err != nil {
			if !errors.Is(err, ErrBudget) {
				t.Fatal(err)
			}
			if l2.Report().Spent > Dollars(0.01) {
				t.Fatalf("spent %s over the cap", l2.Report().Spent.USD())
			}
			return
		}
	}
	t.Fatal("the total cap was never reached")
}

// Concurrent calls must never take the total over the cap.
func TestConcurrentReservationsRespectCap(t *testing.T) {
	cap := Dollars(0.05)
	l, _ := newLedger(t, Limits{Total: cap, PerRun: cap, PerEpis: cap})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = l.Reserve("r", "e"+string(rune('A'+i%26))+string(rune('a'+i/26)), "claude-haiku-5-5", 20000, 2000)
		}(i)
	}
	wg.Wait()
	if rep := l.Report(); rep.Spent > cap || rep.Spent == 0 {
		t.Fatalf("spent %s with a cap of %s", rep.Spent.USD(), cap.USD())
	}
}

func TestUnpricedModelAndBadLedger(t *testing.T) {
	l, _ := newLedger(t, DefaultLimits())
	if _, err := l.Reserve("r", "e", "claude-fable-5-2", 1, 1); err == nil {
		t.Fatal("a model without a pinned price must not be used")
	}
	if _, err := OpenLedger(filepath.Join(t.TempDir(), "x.json"), Limits{}); err == nil {
		t.Fatal("zero limits must be refused")
	}
}

// The default budget must be able to pay for the planned T1 matrix on the
// cheap model, or the plan is wrong.
func TestPlannedT1FitsTheBudget(t *testing.T) {
	// 20 scenarios x 3 repeats x 4 arms = 240 episodes, 12 turns each, the
	// prompt growing from 2k to 10k tokens (about 72k input tokens in all),
	// 600 output tokens per turn, plus a monitor call per action in arm D.
	perEpisode, _ := Cost("claude-haiku-5-5", 72000, 7200)
	monitor, _ := Cost("claude-haiku-5-5", 12*1500, 12*60)
	total := 240*perEpisode + 60*monitor
	if total >= DefaultLimits().PerRun {
		t.Fatalf("T1 estimate %s does not fit the run cap %s", total.USD(), DefaultLimits().PerRun.USD())
	}
	t.Logf("T1 estimate on claude-haiku-5-5: %s of %s", total.USD(), DefaultLimits().Total.USD())
}
