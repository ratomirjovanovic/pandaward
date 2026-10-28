package zap

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

// Proxy is the local forward proxy ZAP is chained to. It is the only way
// ZAP traffic leaves the machine: plain HTTP requests and requests inside
// CONNECT tunnels (terminated with a throwaway certificate) are re-sent
// through the scope guard one by one, so origin, path, method, budget,
// rate limit and address checks apply to every ZAP request. It listens on
// loopback only, on a random port, for the duration of one run.
type Proxy struct {
	g  *scope.Guard
	m  *scope.Manifest
	ln net.Listener
	ca *tls.Certificate

	mu    sync.Mutex
	certs map[string]*tls.Certificate
	srv   *http.Server
}

// StartProxy listens on 127.0.0.1 and serves until Close.
func StartProxy(m *scope.Manifest, g *scope.Guard) (*Proxy, error) {
	ca, err := newCA()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{g: g, m: m, ln: ln, ca: ca, certs: map[string]*tls.Certificate{}}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second}
	go p.srv.Serve(ln)
	return p, nil
}

// Port is the listening port.
func (p *Proxy) Port() int { return p.ln.Addr().(*net.TCPAddr).Port }

// Close stops the proxy and drops open tunnels.
func (p *Proxy) Close() error { return p.srv.Close() }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "Pandaward scope guard: proxy requests only", http.StatusBadRequest)
		return
	}
	p.forward(w, r, r.URL)
}

// tunnel accepts a CONNECT only for an https origin in the manifest, then
// reads the requests inside the tunnel and sends each through the guard.
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !p.originInScope(host) {
		why := "https://" + host + " is not in scope"
		p.g.Refuse(why)
		http.Error(w, "Pandaward scope guard: "+why, http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		name = host
	}
	cert, err := p.leaf(name)
	if err != nil {
		return
	}
	tc := tls.Server(&bufConn{Conn: conn, r: buf.Reader}, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(tc)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		u := *req.URL
		u.Scheme, u.Host = "https", host
		rw := &connWriter{c: tc, h: http.Header{}}
		p.forward(rw, req, &u)
		rw.flush()
		if rw.err != nil || req.Close {
			return
		}
	}
}

// originInScope reports whether any https target has this host:port.
func (p *Proxy) originInScope(hostport string) bool {
	u := &url.URL{Scheme: "https", Host: hostport}
	for _, t := range p.m.Targets {
		tu, err := scope.ParseTarget(t.URL)
		if err != nil || tu.Scheme != "https" {
			continue
		}
		if strings.EqualFold(tu.Hostname(), u.Hostname()) && port(tu) == port(u) {
			return true
		}
	}
	return false
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// hopHeaders are not forwarded in either direction.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, u *url.URL) {
	out, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		http.Error(w, "Pandaward scope guard: bad request", http.StatusBadRequest)
		return
	}
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	out.ContentLength = r.ContentLength
	resp, err := p.g.RoundTrip(out)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, scope.ErrRefused) {
			code = http.StatusForbidden
		}
		http.Error(w, "Pandaward scope guard: "+err.Error(), code)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for _, h := range hopHeaders {
		w.Header().Del(h)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// leaf returns a certificate for name signed by the run's throwaway CA.
// ZAP does not validate upstream certificates; the guard validates the
// real target's certificate against the system roots.
func (p *Proxy) leaf(name string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.certs[name]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(name); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{name}
	}
	caCert, err := x509.ParseCertificate(p.ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, p.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, p.ca.Certificate[0]}, PrivateKey: key}
	p.certs[name] = c
	return c, nil
}

func newCA() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Pandaward scope guard (one run)"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// bufConn replays bytes already buffered by the HTTP server.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// connWriter writes one HTTP/1.1 response to a tunnel connection.
type connWriter struct {
	c      net.Conn
	h      http.Header
	status int
	body   []byte
	err    error
	wrote  bool
}

func (w *connWriter) Header() http.Header { return w.h }
func (w *connWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *connWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.body = append(w.body, b...)
	if len(w.body) > scope.MaxResponseBytes {
		return 0, errors.New("response too large")
	}
	return len(b), nil
}

// flush sends the buffered response with a Content-Length.
func (w *connWriter) flush() {
	if w.wrote {
		return
	}
	w.wrote = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	resp := &http.Response{StatusCode: w.status, ProtoMajor: 1, ProtoMinor: 1, Header: w.h, ContentLength: int64(len(w.body)), Body: io.NopCloser(strings.NewReader(string(w.body)))}
	w.h.Del("Content-Length")
	w.err = resp.Write(w.c)
}
