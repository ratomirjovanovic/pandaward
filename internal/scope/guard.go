package scope

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ErrRefused marks a request the guard did not send.
var ErrRefused = errors.New("scope guard refused the request")

// HaltAfter is the number of consecutive 429 or 5xx answers after which the
// guard stops sending, so a struggling target is not pushed further.
const HaltAfter = 3

// MaxResponseBytes caps every response body read through the guard.
const MaxResponseBytes = 16 << 20

// Guard is the single egress point for network-active tests. Every request
// is checked against the manifest (origin, path, method), counted against
// the request budget, paced to the rate limit and sent over a dialer that
// re-checks resolved addresses. Redirects are never followed.
type Guard struct {
	m        *Manifest
	rt       http.RoundTripper
	interval time.Duration

	mu      sync.Mutex
	sent    int
	next    time.Time
	streak  int
	halted  string
	refused map[string]int
}

// NewGuard builds a guard for a validated manifest. roots replaces the
// system certificate pool and is only used by tests.
func NewGuard(m *Manifest, roots *x509.CertPool) *Guard {
	timeout := time.Duration(m.Limits.TimeoutSeconds) * time.Second
	tr := &http.Transport{
		Proxy:                 nil, // never route through an inherited proxy
		DialContext:           m.DialContext(timeout),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          4,
		DisableCompression:    true,
	}
	return &Guard{m: m, rt: tr, interval: time.Duration(float64(time.Second) / m.Limits.RequestsPerSecond), refused: map[string]int{}}
}

// Client returns an HTTP client that sends through the guard and never
// follows redirects.
func (g *Guard) Client() *http.Client {
	return &http.Client{Transport: g, Timeout: time.Duration(g.m.Limits.TimeoutSeconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// RoundTrip implements http.RoundTripper.
func (g *Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.admit(req); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	resp, err := g.rt.RoundTrip(req)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		g.streak++
		if g.streak >= HaltAfter && g.halted == "" {
			g.halted = fmt.Sprintf("stopped after %d consecutive 429/5xx responses (last %d from %s)", g.streak, resp.StatusCode, req.URL.Redacted())
		}
	} else {
		g.streak = 0
	}
	resp.Body = &limitedBody{r: io.LimitReader(resp.Body, MaxResponseBytes), c: resp.Body}
	return resp, nil
}

// Refuse records a request that was refused before it reached the guard,
// such as a CONNECT to an origin outside the manifest.
func (g *Guard) Refuse(why string) {
	g.mu.Lock()
	g.refused[why]++
	g.mu.Unlock()
}

// admit checks one request and waits for its slot in the rate limit.
func (g *Guard) admit(req *http.Request) error {
	refuse := func(why string) error {
		g.Refuse(why)
		return fmt.Errorf("%w: %s", ErrRefused, why)
	}
	if err := g.m.InScope(req.URL); err != nil {
		return refuse(err.Error())
	}
	if !g.m.MethodAllowed(req.Method) {
		return refuse("method " + req.Method + " is not in allowed_methods")
	}
	g.mu.Lock()
	if g.halted != "" {
		g.mu.Unlock()
		return refuse(g.halted)
	}
	if g.sent >= g.m.Limits.MaxRequestsTotal {
		g.mu.Unlock()
		return refuse(fmt.Sprintf("request budget of %d exhausted", g.m.Limits.MaxRequestsTotal))
	}
	g.sent++
	now := time.Now()
	slot := g.next
	if slot.Before(now) {
		slot = now
	}
	g.next = slot.Add(g.interval)
	g.mu.Unlock()
	if wait := time.Until(slot); wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-req.Context().Done():
			return req.Context().Err()
		}
	}
	return nil
}

// Sent is the number of requests sent so far.
func (g *Guard) Sent() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sent
}

// Halted returns why the guard stopped sending, or "".
func (g *Guard) Halted() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.halted
}

// Refused returns the reasons for refused requests with their counts.
func (g *Guard) Refused() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.refused))
	for k, v := range g.refused {
		out[k] = v
	}
	return out
}

type limitedBody struct {
	r io.Reader
	c io.Closer
}

func (b *limitedBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *limitedBody) Close() error               { return b.c.Close() }
