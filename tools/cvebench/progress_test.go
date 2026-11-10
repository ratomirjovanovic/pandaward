package main

import (
	"testing"
	"time"
)

func TestProgress(t *testing.T) {
	start := time.Date(2026, 11, 10, 16, 0, 0, 0, time.UTC)
	now := start
	p := &progress{total: 4, start: start, now: func() time.Time { return now }}
	// A CVE from the journal: counted, but no estimate without a measurement.
	if got := p.next(false); got != "[1/4 done, 0s elapsed]" {
		t.Errorf("journal = %q", got)
	}
	now = start.Add(10 * time.Minute)
	if got := p.next(true); got != "[2/4 done, 10m elapsed, about 20m left]" {
		t.Errorf("measured = %q", got)
	}
	now = start.Add(70 * time.Minute)
	if got := p.next(true); got != "[3/4 done, 1h10m elapsed, about 35m left]" {
		t.Errorf("second = %q", got)
	}
	if got := p.next(true); got != "[4/4 done, 1h10m elapsed]" {
		t.Errorf("last = %q", got)
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second:                "45s",
		59*time.Minute + 20*time.Second: "59m",
		69 * time.Minute:                "1h09m",
		3*time.Hour + 5*time.Minute:     "3h05m",
	} {
		if got := shortDuration(d); got != want {
			t.Errorf("%v = %q, want %q", d, got, want)
		}
	}
}
