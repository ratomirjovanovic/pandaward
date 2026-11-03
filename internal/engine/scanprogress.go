package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// Progress is one update of a running scan.
type Progress struct {
	Step    int `json:"step"`  // the adapter being run, from 1; 0 before the first
	Steps   int `json:"steps"` // adapters in this scan
	Percent int `json:"percent"`
	// Left is the estimated time still needed, 0 when unknown.
	Left time.Duration `json:"left_ns"`
	// Estimated is true when the durations come from the inventory because
	// the project has no recorded runs yet.
	Estimated bool   `json:"estimated"`
	Message   string `json:"message"`
}

// Heartbeat is how often a running adapter reports that it is still busy.
var Heartbeat = 20 * time.Second

// adapterShare is the part of the bar the adapters fill; the rest is for
// writing findings and evidence.
const adapterShare = 95

// meter turns the planned adapters and their expected durations into
// progress updates. The percentage counts expected work, so it only grows:
// an adapter that ends early moves it forward at once, and one that runs
// long stops at 95% of its share until it ends.
type meter struct {
	mu        sync.Mutex
	say       func(Progress)
	names     []string
	want      []time.Duration
	total     time.Duration
	done      time.Duration // expected time of the finished adapters
	estimated bool
	last      int
	now       func() time.Time
}

func newMeter(say func(Progress), names []string, want []time.Duration, estimated bool) *meter {
	m := &meter{say: say, names: names, want: want, estimated: estimated, now: time.Now}
	for _, d := range want {
		m.total += d
	}
	return m
}

func (m *meter) emit(step int, pct int, left time.Duration, msg string) {
	if pct < m.last {
		pct = m.last
	}
	m.last = pct
	prefix := fmt.Sprintf("[%d/%d %3d%%] ", step, len(m.names), pct)
	m.say(Progress{Step: step, Steps: len(m.names), Percent: pct, Left: left, Estimated: m.estimated, Message: prefix + msg})
}

// at is the percentage and time left with elapsed spent in adapter i.
func (m *meter) at(i int, elapsed time.Duration) (int, time.Duration) {
	if m.total <= 0 {
		return adapterShare * i / max(len(m.names), 1), 0
	}
	cur := time.Duration(0)
	if i < len(m.want) {
		cur = min(elapsed, m.want[i]*95/100)
	}
	pct := int(int64(adapterShare) * int64(m.done+cur) / int64(m.total))
	left := m.total - m.done - cur
	if i < len(m.want) && elapsed > m.want[i] {
		left = m.total - m.done - m.want[i]
	}
	return pct, left
}

func (m *meter) plan(files int, mb float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	how := "from earlier scans of this project"
	if m.estimated {
		how = "a first estimate from the inventory"
	}
	m.emit(0, 0, m.total, fmt.Sprintf("plan: %d file(s), %.1f MB; %d adapter(s) to run, %s (%s)", files, mb, len(m.names), approx(m.total, m.estimated), how))
}

func (m *meter) carried(i int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.done += m.want[i]
	pct, left := m.at(i+1, 0)
	m.emit(i+1, pct, left, m.names[i]+": inputs unchanged, carried over")
}

// start reports adapter i and returns a function that stops its heartbeat.
func (m *meter) start(i int) func() {
	m.mu.Lock()
	pct, left := m.at(i, 0)
	m.emit(i+1, pct, left, m.names[i]+": running"+leftNote(left, m.estimated))
	m.mu.Unlock()
	return m.heartbeat(func(el time.Duration) {
		pct, left := m.at(i, el)
		note := leftNote(left, m.estimated)
		if el > m.want[i] {
			note = "; taking longer than estimated"
		}
		m.emit(i+1, pct, left, fmt.Sprintf("%s: still running (%s)%s", m.names[i], clock(el), note))
	})
}

// heartbeat calls tick with the elapsed time every Heartbeat, holding the
// lock, until the returned function is called (more than once is fine).
func (m *meter) heartbeat(tick func(time.Duration)) func() {
	began := m.now()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(Heartbeat)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				m.mu.Lock()
				tick(m.now().Sub(began))
				m.mu.Unlock()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-stopped }) }
}

func (m *meter) finish(i int, run model.Run, took time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.done += m.want[i]
	pct, left := m.at(i+1, 0)
	res := fmt.Sprintf("%s in %s", run.ExitClass, clock(took))
	if run.ExitClass == model.ExitOK {
		res = fmt.Sprintf("OK in %s, %d signal(s)", clock(took), run.SignalsCount)
	} else if run.Detail != "" {
		d := redact.Line(run.Detail)
		if r := []rune(d); len(r) > 100 {
			d = string(r[:97]) + "..."
		}
		res += ": " + d
	}
	m.emit(i+1, pct, left, m.names[i]+": "+res)
}

// findings reports writing findings and evidence, which can take a while
// on a large project, and returns a function that stops its heartbeat.
func (m *meter) findings() func() {
	m.mu.Lock()
	m.emit(len(m.names), adapterShare, 0, "findings: normalizing, fingerprinting and writing redacted evidence")
	m.mu.Unlock()
	return m.heartbeat(func(el time.Duration) {
		m.emit(len(m.names), min(m.last+1, 99), 0, fmt.Sprintf("findings: still writing (%s)", clock(el)))
	})
}

func (m *meter) end(took time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emit(len(m.names), 100, 0, "done in "+clock(took))
}

func leftNote(left time.Duration, estimated bool) string {
	if left <= 0 {
		return ""
	}
	return "; " + approx(left, estimated) + " left"
}

// approx rounds a duration for people: "under a minute", "about 4 min", or
// "roughly 4 min" when it is only estimated from the inventory.
func approx(d time.Duration, estimated bool) string {
	if d < time.Minute {
		return "under a minute"
	}
	word := "about"
	if estimated {
		word = "roughly"
	}
	return fmt.Sprintf("%s %d min", word, int((d+30*time.Second)/time.Minute))
}

// clock prints elapsed time as 45s or 2m10s.
func clock(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return fmt.Sprintf("%dm%02ds", int(d/time.Minute), int(d%time.Minute/time.Second))
}

// expected returns how long each adapter is likely to take: the average of
// its last three completed runs in this project, scaled by the change in
// file count, or an estimate from the inventory when it has none. The
// second result is true when any adapter had to be estimated.
func (e *Engine) expected(ads []adapters.Adapter, actx *adapters.Context) ([]time.Duration, bool) {
	hist := map[string][]time.Duration{}
	scale := 1.0
	a, _ := e.St.LatestAssessment(e.ProjectID)
	for n := 0; a != nil && n < 5; n++ {
		if n == 0 && actx.Inv != nil {
			if hs, err := e.St.FileHashes(a.ID); err == nil && len(hs) > 0 {
				scale = min(max(float64(len(actx.Inv.Files))/float64(len(hs)), 0.5), 2)
			}
		}
		rs, _ := e.St.Runs(a.ID)
		for _, r := range rs {
			if r.ExitClass != model.ExitOK || len(hist[r.Adapter]) >= 3 {
				continue
			}
			s, err1 := time.Parse(time.RFC3339, r.StartedAt)
			t, err2 := time.Parse(time.RFC3339, r.EndedAt)
			if err1 == nil && err2 == nil && !t.Before(s) {
				hist[r.Adapter] = append(hist[r.Adapter], t.Sub(s))
			}
		}
		a, _ = e.St.PreviousObserved(e.ProjectID, a.Seq)
	}
	out := make([]time.Duration, len(ads))
	estimated := false
	for i, ad := range ads {
		est := adapters.Estimate(ad, actx)
		if h := hist[ad.Name()]; len(h) > 0 && est > 0 {
			var sum time.Duration
			for _, d := range h {
				sum += d
			}
			// Runs are recorded to the second; a fast adapter still counts.
			out[i] = max(time.Duration(float64(sum/time.Duration(len(h)))*scale), 500*time.Millisecond)
			continue
		}
		out[i] = est
		if est > 2*time.Second {
			estimated = true
		}
	}
	return out, estimated
}

// names of the adapters, for the meter.
func names(ads []adapters.Adapter) []string {
	out := make([]string, len(ads))
	for i, a := range ads {
		out[i] = a.Name()
	}
	return out
}
