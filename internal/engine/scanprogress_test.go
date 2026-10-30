package engine

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestMeter(t *testing.T) {
	var mu sync.Mutex
	var got []Progress
	say := func(p Progress) { mu.Lock(); got = append(got, p); mu.Unlock() }
	old := Heartbeat
	Heartbeat = 5 * time.Millisecond
	defer func() { Heartbeat = old }()
	clockAt := time.Unix(0, 0)
	m := newMeter(say, []string{"builtin-code", "semgrep", "gitleaks"}, []time.Duration{time.Second, 8 * time.Second, time.Second}, true)
	m.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clockAt }
	m.plan(10, 1.5)
	m.carried(0)
	stop := m.start(1)
	// semgrep runs longer than its 8 seconds.
	for _, at := range []time.Duration{2 * time.Second, 6 * time.Second, 12 * time.Second} {
		mu.Lock()
		clockAt = time.Unix(0, 0).Add(at)
		n := len(got)
		mu.Unlock()
		for deadline := time.Now().Add(2 * time.Second); ; {
			mu.Lock()
			ok := len(got) > n && strings.Contains(got[len(got)-1].Message, "still running ("+clock(at)+")")
			mu.Unlock()
			if ok || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	stop()
	m.finish(1, model.Run{ExitClass: model.ExitOK, SignalsCount: 3}, 12*time.Second)
	m.finish(2, model.Run{ExitClass: model.ExitBlocked, Detail: "gitleaks is not installed"}, 0)
	m.findings()()
	m.end(14 * time.Second)

	prev := -1
	var text []string
	for _, p := range got {
		if p.Percent < prev {
			t.Fatalf("percent went back: %v", got)
		}
		prev = p.Percent
		text = append(text, p.Message)
	}
	all := strings.Join(text, "\n")
	for _, want := range []string{
		"[0/3   0%] plan: 10 file(s), 1.5 MB; 3 adapter(s) to run, under a minute (a first estimate from the inventory)",
		"[1/3   9%] builtin-code: inputs unchanged, carried over",
		"[2/3   9%] semgrep: running; under a minute left",
		"semgrep: still running (2s); under a minute left",
		"semgrep: still running (12s); taking longer than estimated\n",
		"[2/3  85%] semgrep: OK in 12s, 3 signal(s)",
		"[3/3  95%] gitleaks: BLOCKED in 0s: gitleaks is not installed",
		"[3/3 100%] done in 14s",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("progress lacks %q:\n%s", want, all)
		}
	}
	// While semgrep overran, the bar stayed below the end of its share.
	for _, p := range got {
		if strings.Contains(p.Message, "taking longer") && p.Percent >= 85 {
			t.Errorf("overrunning adapter reached its full share: %s", p.Message)
		}
	}
}

var progressLine = regexp.MustCompile(`^\[(\d+)/(\d+) +(\d+)%\] `)

func TestScanProgress(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	var lines []string
	var updates []Progress
	e.OnProgress = func(p Progress) { updates = append(updates, p) }
	if _, err := e.Scan(context.Background(), func(m string) { lines = append(lines, m) }); err != nil {
		t.Fatal(err)
	}
	prev, n := -1, 0
	for _, l := range lines {
		m := progressLine.FindStringSubmatch(l)
		if m == nil {
			if !strings.HasPrefix(l, "inventory:") && !strings.HasPrefix(l, "recovered ") {
				t.Errorf("line without step and percent: %q", l)
			}
			continue
		}
		n++
		pct, _ := strconv.Atoi(m[3])
		if pct < prev {
			t.Errorf("percent went back at %q", l)
		}
		prev = pct
	}
	if n == 0 || prev != 100 || !strings.Contains(lines[len(lines)-1], "done in ") {
		t.Fatalf("scan progress did not end at 100%%:\n%s", strings.Join(lines, "\n"))
	}
	if len(updates) != n {
		t.Errorf("OnProgress got %d updates for %d lines", len(updates), n)
	}
	// The fixture was scanned before, so the plan uses recorded runs.
	if !strings.Contains(strings.Join(lines, "\n"), "from earlier scans of this project") {
		t.Errorf("second scan should use recorded durations:\n%s", strings.Join(lines, "\n"))
	}
}
