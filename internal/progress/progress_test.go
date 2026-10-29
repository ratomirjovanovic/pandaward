package progress

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
)

var t0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func ev(s int, kind, agent, typ string) Event {
	return Event{TS: at(s), Kind: kind, Agent: agent, Type: Prefix + typ}
}

func read(s int, agent, typ, file string) Event {
	e := ev(s, KindTool, agent, typ)
	e.Tool, e.Target = ToolRead, file
	return e
}

func hyp(s int, agent, typ, id, title string) Event {
	e := ev(s, KindHypothesis, agent, typ)
	e.Finding, e.Title = id, title
	return e
}

func TestAppendLoadFold(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(config.PrivateDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		ev(0, KindStart, "a1", "api"),
		read(5, "a1", "api", "src/server.js"),
		{TS: at(6), Kind: KindTool, Agent: "a1", Type: Prefix + "api", Tool: ToolSearch, Target: "verifySignature"},
		hyp(9, "a1", "api", "PW-0042", "Webhook without signature check"),
		ev(2, KindStart, "b2", "identity"),
		ev(70, KindStop, "a1", "api"),
	} {
		if err := Append(root, e); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.OpenFile(Path(root), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json\n")
	f.Close()

	evs, err := Load(root)
	if err != nil || len(evs) != 6 {
		t.Fatalf("Load = %d events, %v; want 6, malformed line skipped", len(evs), err)
	}
	rs := Fold(evs)
	if len(rs) != 2 || rs[0].Name() != "api" || rs[1].Name() != "identity" {
		t.Fatalf("Fold order = %+v", rs)
	}
	api := rs[0]
	if !api.Done || api.Reads != 1 || api.Searches != 1 || len(api.Hypotheses) != 1 || api.Hypotheses[0] != "PW-0042" {
		t.Errorf("api = %+v", api)
	}
	if got := api.Elapsed(at(500)); got != 70*time.Second {
		t.Errorf("elapsed of a finished reviewer = %s, want 70s", got)
	}
	if got := rs[1].Elapsed(at(62)); got != time.Minute {
		t.Errorf("elapsed of a running reviewer = %s, want 1m", got)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	evs, err := Load(t.TempDir())
	if err != nil || evs != nil {
		t.Fatalf("Load of a missing log = %v, %v", evs, err)
	}
}

func TestCurrentKeepsTheLatestReview(t *testing.T) {
	old := ev(0, KindStart, "o", "api")
	oldStop := ev(60, KindStop, "o", "api")
	n1 := ev(3600, KindStart, "n1", "api")
	n2 := ev(3610, KindStart, "n2", "cloud")
	rs := Current(Fold([]Event{old, oldStop, n1, n2}), at(3700))
	if len(rs) != 2 || rs[0].ID != "n1" || rs[1].ID != "n2" {
		t.Fatalf("Current = %+v, want the two reviewers of the latest review", rs)
	}
}

func TestDur(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second: "45s", 192 * time.Second: "3m12s", 64 * time.Minute: "1h04m", -time.Second: "0s",
	} {
		if got := Dur(d); got != want {
			t.Errorf("Dur(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestRowsRenderOnlyReviewers(t *testing.T) {
	rs := Fold([]Event{
		ev(0, KindStart, "a1", "api"),
		read(30, "a1", "api", "src/webhooks/stripe.ts"),
		ev(1, KindStart, "c3", "cloud"),
	})
	in := PanelInput{Columns: 200, Tasks: []Task{
		{ID: "a1", AgentType: Prefix + "api", StartTime: t0.UnixMilli()},
		// Matched by type and start time when the task ID differs.
		{ID: "task-9", AgentType: Prefix + "cloud", StartTime: at(1).UnixMilli() + 400},
		{ID: "x", AgentType: "Explore", StartTime: t0.UnixMilli()},
		// No recorded progress: keep the default row.
		{ID: "m", AgentType: Prefix + "mobile", StartTime: t0.UnixMilli()},
	}}
	if !in.HasReviewers() {
		t.Fatal("HasReviewers = false")
	}
	var out bytes.Buffer
	Rows(&out, in, rs, at(192))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows = %q, want two", out.String())
	}
	var row struct{ ID, Content string }
	json.Unmarshal([]byte(lines[0]), &row)
	if row.ID != "a1" || row.Content != "api · 3m12s · 1 file read, 0 searches, 0 hypotheses · reading src/webhooks/stripe.ts" {
		t.Errorf("api row = %+v", row)
	}
	json.Unmarshal([]byte(lines[1]), &row)
	if row.ID != "task-9" || !strings.HasPrefix(row.Content, "cloud · 3m11s") {
		t.Errorf("cloud row = %+v", row)
	}

	out.Reset()
	in.Columns = 20
	Rows(&out, PanelInput{Columns: 20, Tasks: in.Tasks[:1]}, rs, at(192))
	json.Unmarshal(out.Bytes(), &row)
	if len([]rune(row.Content)) != 20 || !strings.HasSuffix(row.Content, "...") {
		t.Errorf("row is not cut to the width: %q", row.Content)
	}
	if (PanelInput{Tasks: []Task{{ID: "x", AgentType: "Explore"}}}).HasReviewers() {
		t.Error("HasReviewers is true without a PandaWard task")
	}
}

func TestWatcher(t *testing.T) {
	opt := WatchOptions{Heartbeat: time.Minute, Idle: 10 * time.Minute, WaitStart: 2 * time.Minute, Timeout: 25 * time.Minute}
	w := newWatcher(opt, t0)
	var evs []Event
	step := func(s int, add ...Event) ([]string, bool) {
		evs = append(evs, add...)
		return w.step(evs, at(s))
	}
	expect := func(lines []string, done bool, wantDone bool, want ...string) {
		t.Helper()
		if done != wantDone || len(lines) != len(want) {
			t.Fatalf("lines = %q, done = %v; want %q, done = %v", lines, done, want, wantDone)
		}
		for i := range want {
			if !strings.Contains(lines[i], want[i]) {
				t.Errorf("line %d = %q, want it to contain %q", i, lines[i], want[i])
			}
		}
	}

	l, d := step(1)
	expect(l, d, false)
	l, d = step(2, ev(1, KindStart, "a1", "api"), ev(1, KindStart, "b2", "identity"))
	expect(l, d, false, "Reviewers running: api, identity")
	l, d = step(30, read(20, "a1", "api", "src/server.js"))
	expect(l, d, false)
	l, d = step(40, hyp(39, "a1", "api", "PW-0042", "Webhook without signature check"))
	expect(l, d, false, "api recorded PW-0042: Webhook without signature check")
	l, d = step(99)
	expect(l, d, false)
	l, d = step(100)
	expect(l, d, false, "Still running: api 1m39s, 1 file read, 0 searches, 1 hypothesis, recorded PW-0042; identity")
	l, d = step(130, ev(125, KindStart, "c3", "cloud"), ev(128, KindStop, "a1", "api"))
	expect(l, d, false, "Reviewers started: cloud", "api finished in 2m07s: 1 file read, 0 searches, 1 hypothesis (PW-0042)")
	l, d = step(700)
	expect(l, d, false, "identity has shown no activity for 11m39s")
	l, d = step(710, ev(705, KindStop, "b2", "identity"), ev(708, KindStop, "c3", "cloud"))
	expect(l, d, false, "identity finished", "cloud finished")
	l, d = step(714)
	expect(l, d, true, "All 3 reviewers finished in 11m47s: 1 hypothesis.")
}

func TestWatcherEnds(t *testing.T) {
	w := newWatcher(WatchOptions{}, t0)
	l, d := w.step(nil, at(121))
	if !d || len(l) != 1 || !strings.Contains(l[0], "No PandaWard reviewer started within 2m00s") {
		t.Fatalf("no reviewers: %q, %v", l, d)
	}

	// A review that finished before the watch began is not watched again,
	// even one that ended moments ago; the new reviewers are.
	old := []Event{ev(-70, KindStart, "o", "api"), ev(-50, KindStop, "o", "api")}
	w = newWatcher(WatchOptions{}, t0)
	if l, d := w.step(old, at(1)); d || len(l) != 0 {
		t.Fatalf("old review: %q, %v", l, d)
	}
	l, d = w.step(append(old, ev(3, KindStart, "n", "cloud")), at(4))
	if d || len(l) != 1 || l[0] != "Reviewers running: cloud" {
		t.Fatalf("new review after an old one: %q, %v", l, d)
	}
	l, d = w.step(append(old, ev(3, KindStart, "n", "cloud"), ev(20, KindStop, "n", "cloud")), at(30))
	if !d || l[len(l)-1] != "The reviewer finished in 17s: 0 hypotheses." {
		t.Fatalf("single reviewer end: %q, %v", l, d)
	}

	w = newWatcher(WatchOptions{Timeout: 5 * time.Minute}, t0)
	run := []Event{ev(0, KindStart, "a1", "api")}
	w.step(run, at(1))
	l, d = w.step(run, at(300))
	if !d || !strings.Contains(l[len(l)-1], "Stopped watching after 5m00s; 1 reviewer(s) still running") {
		t.Fatalf("timeout: %q, %v", l, d)
	}
}
