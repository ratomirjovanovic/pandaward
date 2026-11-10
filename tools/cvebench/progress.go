package main

import (
	"fmt"
	"time"
)

// progress counts finished CVEs and estimates the time left from the CVEs
// measured in this run; CVEs read from the journal cost no time and do not
// count toward the average.
type progress struct {
	total, done, measured int
	start                 time.Time
	now                   func() time.Time
}

func newProgress(total int) *progress {
	return &progress{total: total, start: time.Now(), now: time.Now}
}

// next records one finished CVE and returns the line prefix, such as
// "[37/219 done, 14m elapsed, about 1h09m left]".
func (p *progress) next(measured bool) string {
	p.done++
	if measured {
		p.measured++
	}
	elapsed := p.now().Sub(p.start)
	s := fmt.Sprintf("[%d/%d done, %s elapsed", p.done, p.total, shortDuration(elapsed))
	if left := p.total - p.done; left > 0 && p.measured > 0 {
		s += ", about " + shortDuration(elapsed/time.Duration(p.measured)*time.Duration(left)) + " left"
	}
	return s + "]"
}

// shortDuration prints whole seconds under a minute, whole minutes under an
// hour and hours with minutes above.
func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Round(time.Second)/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Round(time.Minute)/time.Minute))
	}
	d = d.Round(time.Minute)
	return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
}
