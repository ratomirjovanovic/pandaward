package asl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Money is counted in micro-dollars (1e-6 USD) so sums never drift. A price
// of $1 per million tokens is exactly 1 micro-dollar per token.
type Micro int64

// USD formats m as dollars.
func (m Micro) USD() string { return fmt.Sprintf("$%.4f", float64(m)/1e6) }

// Dollars converts dollars to micro-dollars.
func Dollars(d float64) Micro { return Micro(d*1e6 + 0.5) }

// Price is a model's price in dollars per million tokens. Prompts longer than
// LongOver input tokens are billed at the Long* rates when those are set.
type Price struct {
	In, Out         float64
	LongIn, LongOut float64
	LongOver        int
}

// Prices are the first-party API rates the budget is computed with. They are
// pinned here with their source date so a price change is a reviewed edit,
// not a silent one. An unknown model is refused: spend on it could not be
// bounded.
//
// Source: Anthropic model pricing as listed on 2026-11-03.
var Prices = map[string]Price{
	"claude-haiku-5-5":  {In: 0.10, Out: 0.50, LongIn: 0.50, LongOut: 2.50, LongOver: 100000},
	"claude-sonnet-5-5": {In: 2.00, Out: 10.00},
	"claude-opus-5-5":   {In: 4.00, Out: 20.00},
}

// Cost is the price of one request. cacheRead and cacheWrite tokens are
// charged as ordinary input, which is never less than their real price, so
// the figure is an upper bound.
func Cost(model string, inputTokens, outputTokens int) (Micro, error) {
	p, ok := Prices[model]
	if !ok {
		return 0, fmt.Errorf("no price for model %q: refusing to spend on it", model)
	}
	in, out := p.In, p.Out
	if p.LongOver > 0 && inputTokens > p.LongOver {
		in, out = p.LongIn, p.LongOut
	}
	return Micro(float64(inputTokens)*in + float64(outputTokens)*out + 0.999999), nil
}

// ErrBudget is returned when a call would take the lab over a cap. The
// caller must stop and record the episode INVALID, not retry.
var ErrBudget = errors.New("budget cap reached")

// Entry is one settled spend.
type Entry struct {
	Time    time.Time `json:"time"`
	Run     string    `json:"run"`
	Episode string    `json:"episode"`
	Model   string    `json:"model"`
	In      int       `json:"input_tokens"`
	Out     int       `json:"output_tokens"`
	Cost    Micro     `json:"cost_micro_usd"`
	// Charged is true when the call outcome was unknown (timeout, dropped
	// connection) and the whole reservation was counted as spent.
	Charged bool `json:"charged_unknown,omitempty"`
}

// Ledger enforces the budget across every run of the lab. It is a file, so
// the total survives restarts: the cap is for the whole lab, not per run.
type Ledger struct {
	mu   sync.Mutex
	path string
	st   ledgerState
}

type ledgerState struct {
	Schema  string  `json:"schema"`
	Cap     Micro   `json:"cap_micro_usd"`
	RunCap  Micro   `json:"run_cap_micro_usd"`
	EpCap   Micro   `json:"episode_cap_micro_usd"`
	Spent   Micro   `json:"spent_micro_usd"`
	Entries []Entry `json:"entries"`
}

// Limits are the caps a ledger is created with.
type Limits struct {
	Total   Micro // the whole lab, all runs
	PerRun  Micro // one run
	PerEpis Micro // one episode
}

// DefaultLimits are the lab's budget: $5 in total, with $3.50 usable by one
// run and $0.05 by one episode. The rest of the total is kept back for
// reruns after a bug is fixed.
func DefaultLimits() Limits {
	return Limits{Total: Dollars(5), PerRun: Dollars(3.5), PerEpis: Dollars(0.05)}
}

// OpenLedger loads the ledger at path or creates it with lim. An existing
// ledger keeps the caps it was created with: raising a cap is an explicit
// edit of that file, never a side effect of a flag.
func OpenLedger(path string, lim Limits) (*Ledger, error) {
	l := &Ledger{path: path}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &l.st); err != nil {
			return nil, fmt.Errorf("budget ledger %s: %w", path, err)
		}
		if l.st.Schema != Schema || l.st.Cap <= 0 {
			return nil, fmt.Errorf("budget ledger %s is not a valid asl/v1 ledger", path)
		}
	case errors.Is(err, os.ErrNotExist):
		if lim.Total <= 0 || lim.PerRun <= 0 || lim.PerEpis <= 0 {
			return nil, errors.New("limits must be positive")
		}
		l.st = ledgerState{Schema: Schema, Cap: lim.Total, RunCap: lim.PerRun, EpCap: lim.PerEpis}
		if err := l.save(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return l, nil
}

func (l *Ledger) save() error {
	b, err := json.MarshalIndent(&l.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Reservation is money set aside before a call: the worst case it can cost.
type Reservation struct {
	l       *Ledger
	run     string
	episode string
	model   string
	in, out int
	cost    Micro
	done    bool
}

// Reserve sets aside the worst case of a call before it is sent: the prompt's
// input tokens (count them with the token counting endpoint, which is free,
// or use a deliberate over-estimate) and the full maxOutput. It fails with
// ErrBudget when the call could take the lab, the run or the episode over a
// cap, so no request is sent that could exceed the budget.
func (l *Ledger) Reserve(run, episode, model string, inputTokens, maxOutput int) (*Reservation, error) {
	cost, err := Cost(model, inputTokens, maxOutput)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var total, perRun, perEp Micro
	for _, e := range l.st.Entries {
		total += e.Cost
		if e.Run == run {
			perRun += e.Cost
			if e.Episode == episode {
				perEp += e.Cost
			}
		}
	}
	switch {
	case total+cost > l.st.Cap:
		return nil, fmt.Errorf("%w: %s spent of %s, this call could cost %s", ErrBudget, total.USD(), l.st.Cap.USD(), cost.USD())
	case perRun+cost > l.st.RunCap:
		return nil, fmt.Errorf("%w: run %s has spent %s of %s", ErrBudget, run, perRun.USD(), l.st.RunCap.USD())
	case perEp+cost > l.st.EpCap:
		return nil, fmt.Errorf("%w: episode %s has spent %s of %s", ErrBudget, episode, perEp.USD(), l.st.EpCap.USD())
	}
	// Hold the worst case in the file at once, so a crash during the call
	// cannot lose the spend.
	l.st.Entries = append(l.st.Entries, Entry{Time: time.Now().UTC(), Run: run, Episode: episode, Model: model, In: inputTokens, Out: maxOutput, Cost: cost, Charged: true})
	l.st.Spent = total + cost
	if err := l.save(); err != nil {
		return nil, err
	}
	return &Reservation{l: l, run: run, episode: episode, model: model, in: inputTokens, out: maxOutput, cost: cost}, nil
}

// Commit settles a reservation with the usage the API reported. The actual
// cost never exceeds the reservation when inputTokens was counted exactly;
// if it would, the larger figure is recorded, never the smaller.
func (r *Reservation) Commit(inputTokens, outputTokens int) error {
	return r.settle(inputTokens, outputTokens, false)
}

// Abandon is for a call whose outcome is unknown (timeout, dropped
// connection): the request may have been served, so the whole reservation
// stays counted as spent.
func (r *Reservation) Abandon() error {
	return r.settle(r.in, r.out, true)
}

// Cancel is for a call that was provably never sent (a local error before
// the request): the reservation is released.
func (r *Reservation) Cancel() error {
	return r.settle(0, 0, false)
}

func (r *Reservation) settle(in, out int, unknown bool) error {
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.done {
		return errors.New("reservation already settled")
	}
	r.done = true
	cost := Micro(0)
	if in > 0 || out > 0 {
		c, err := Cost(r.model, in, out)
		if err != nil {
			return err
		}
		cost = c
	}
	if unknown {
		cost = r.cost
	}
	for i := len(l.st.Entries) - 1; i >= 0; i-- {
		e := &l.st.Entries[i]
		if e.Run == r.run && e.Episode == r.episode && e.Cost == r.cost && e.Charged && e.In == r.in && e.Out == r.out {
			e.In, e.Out, e.Cost, e.Charged = in, out, cost, unknown
			if cost == 0 {
				l.st.Entries = append(l.st.Entries[:i], l.st.Entries[i+1:]...)
			}
			break
		}
	}
	var total Micro
	for _, e := range l.st.Entries {
		total += e.Cost
	}
	l.st.Spent = total
	return l.save()
}

// Report summarizes spend per run and model for the research report.
type Report struct {
	Cap, Spent Micro
	ByModel    map[string]Micro
	ByRun      map[string]Micro
	Calls      int
}

// Report returns the totals.
func (l *Ledger) Report() Report {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Report{Cap: l.st.Cap, ByModel: map[string]Micro{}, ByRun: map[string]Micro{}, Calls: len(l.st.Entries)}
	for _, e := range l.st.Entries {
		r.Spent += e.Cost
		r.ByModel[e.Model] += e.Cost
		r.ByRun[e.Run] += e.Cost
	}
	return r
}

// Runs lists the run ids in the ledger.
func (r Report) Runs() []string {
	var out []string
	for k := range r.ByRun {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
