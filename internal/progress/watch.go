package progress

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// WatchOptions tune Watch. Zero values take the defaults.
type WatchOptions struct {
	Poll      time.Duration // how often the log is read (1s)
	Heartbeat time.Duration // a summary when nothing else was said (60s)
	Idle      time.Duration // warn about a reviewer silent this long (10m)
	WaitStart time.Duration // give up when no reviewer starts this soon (2m)
	Timeout   time.Duration // stop watching after this long (25m)
}

func (o *WatchOptions) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&o.Poll, time.Second)
	set(&o.Heartbeat, time.Minute)
	set(&o.Idle, 10*time.Minute)
	set(&o.WaitStart, 2*time.Minute)
	set(&o.Timeout, 25*time.Minute)
}

// settle is how long Watch waits after the last reviewer finished.
const settle = 5 * time.Second

// watcher turns successive snapshots of the log into lines worth telling
// the user. It is pure so tests can drive it with a fake clock.
type watcher struct {
	opt      WatchOptions
	began    time.Time
	lastSaid time.Time
	known    map[string]*seen
	order    []string
}

type seen struct {
	hyps   int
	done   bool
	warned bool
}

func newWatcher(opt WatchOptions, now time.Time) *watcher {
	opt.defaults()
	return &watcher{opt: opt, began: now, lastSaid: now, known: map[string]*seen{}}
}

// step returns the lines for this snapshot and whether the watch is over.
func (w *watcher) step(evs []Event, now time.Time) ([]string, bool) {
	rs := Current(Fold(evs), now)
	var lines []string
	first := len(w.known) == 0
	var fresh []string
	for _, r := range rs {
		s := w.known[r.ID]
		if s == nil {
			// A reviewer that finished before the watch began belongs to an
			// earlier review.
			if r.Done && r.Stopped.Before(w.began) {
				continue
			}
			s = &seen{hyps: len(r.Hypotheses)}
			w.known[r.ID] = s
			w.order = append(w.order, r.ID)
			fresh = append(fresh, r.Name())
			if !first {
				s.hyps = 0
			}
		}
		for i := min(s.hyps, len(r.Hypotheses)); i < len(r.Hypotheses); i++ {
			l := fmt.Sprintf("%s recorded %s", r.Name(), r.Hypotheses[i])
			if r.Titles[i] != "" {
				l += ": " + r.Titles[i]
			}
			lines = append(lines, l)
		}
		s.hyps = len(r.Hypotheses)
		if r.Done && !s.done {
			s.done = true
			lines = append(lines, fmt.Sprintf("%s finished in %s: %s%s", r.Name(), Dur(r.Elapsed(now)), r.Counts(), ids(r.Hypotheses)))
		}
		if !r.Done && !s.warned && now.Sub(r.Last) >= w.opt.Idle {
			s.warned = true
			lines = append(lines, fmt.Sprintf("%s has shown no activity for %s and may be stuck; /tasks shows its transcript", r.Name(), Dur(now.Sub(r.Last))))
		}
		if !r.Done && now.Sub(r.Last) < w.opt.Idle {
			s.warned = false
		}
	}
	if len(fresh) > 0 {
		verb := "started"
		if first {
			verb = "running"
		}
		lines = append([]string{fmt.Sprintf("Reviewers %s: %s", verb, strings.Join(fresh, ", "))}, lines...)
	}

	tracked := w.tracked(rs)
	if len(tracked) == 0 {
		if now.Sub(w.began) >= w.opt.WaitStart {
			return append(lines, fmt.Sprintf("No PandaWard reviewer started within %s; nothing to watch.", Dur(w.opt.WaitStart))), true
		}
		return w.said(lines, now), false
	}
	running, hyps := 0, 0
	var lastStop time.Time
	for _, r := range tracked {
		hyps += len(r.Hypotheses)
		if !r.Done {
			running++
		} else if r.Stopped.After(lastStop) {
			lastStop = r.Stopped
		}
	}
	// Reviewers launched together start within moments of each other; wait
	// briefly after the last finish so a late start is not missed.
	if running == 0 && now.Sub(lastStop) >= settle {
		who := fmt.Sprintf("All %d reviewers", len(tracked))
		if len(tracked) == 1 {
			who = "The reviewer"
		}
		return append(lines, fmt.Sprintf("%s finished in %s: %s.", who, Dur(lastStop.Sub(earliest(tracked))), plural(hyps, "hypothesis", "hypotheses"))), true
	}
	if len(lines) == 0 && now.Sub(w.lastSaid) >= w.opt.Heartbeat {
		lines = append(lines, summary(tracked, now))
	}
	if now.Sub(w.began) >= w.opt.Timeout {
		return append(lines, fmt.Sprintf("Stopped watching after %s; %d reviewer(s) still running: %s", Dur(w.opt.Timeout), running, summary(tracked, now))), true
	}
	return w.said(lines, now), false
}

func (w *watcher) said(lines []string, now time.Time) []string {
	if len(lines) > 0 {
		w.lastSaid = now
	}
	return lines
}

func (w *watcher) tracked(rs []Reviewer) []Reviewer {
	by := map[string]Reviewer{}
	for _, r := range rs {
		by[r.ID] = r
	}
	var out []Reviewer
	for _, id := range w.order {
		if r, ok := by[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

func earliest(rs []Reviewer) time.Time {
	t := rs[0].Started
	for _, r := range rs[1:] {
		if r.Started.Before(t) {
			t = r.Started
		}
	}
	return t
}

func ids(h []string) string {
	if len(h) == 0 {
		return ""
	}
	return " (" + strings.Join(h, ", ") + ")"
}

// summary is one line on every tracked reviewer, running ones first.
func summary(rs []Reviewer, now time.Time) string {
	var run, done []string
	for _, r := range rs {
		if r.Done {
			done = append(done, r.Name())
			continue
		}
		s := fmt.Sprintf("%s %s, %s", r.Name(), Dur(r.Elapsed(now)), r.Counts())
		if r.Target != "" {
			s += ", " + r.Target
		}
		run = append(run, s)
	}
	out := "Still running: " + strings.Join(run, "; ")
	if len(done) > 0 {
		out += ". Finished: " + strings.Join(done, ", ")
	}
	return out + "."
}

// Watch prints progress lines until every reviewer of the current review has
// finished, none started within WaitStart, the timeout passes or ctx ends.
// Each line is written on its own so a line-based monitor sees it at once.
func Watch(ctx context.Context, root string, out io.Writer, opt WatchOptions) error {
	opt.defaults()
	w := newWatcher(opt, time.Now())
	t := time.NewTicker(opt.Poll)
	defer t.Stop()
	for {
		evs, err := Load(root)
		if err != nil {
			return err
		}
		lines, done := w.step(evs, time.Now())
		for _, l := range lines {
			fmt.Fprintln(out, l)
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
