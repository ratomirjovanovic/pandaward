package scope

import (
	"net/netip"
	"net/url"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseTarget(t *testing.T) {
	for _, bad := range []string{"ftp://x.example", "https://*.example.com", "https://user:pw@x.example", "https://x.example.", "https://x.example/?q=1", "x.example", "https://"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
	if _, err := ParseTarget("https://staging.example.com/app"); err != nil {
		t.Fatal(err)
	}
}

func TestInScope(t *testing.T) {
	m := &Manifest{ExcludedPaths: []string{"/app/admin"}}
	m.Targets = append(m.Targets, struct {
		URL string `yaml:"url"`
	}{"https://staging.example.com/app"})
	cases := map[string]bool{
		"https://staging.example.com/app":          true,
		"https://staging.example.com/app/x":        true,
		"https://staging.example.com/application":  false,
		"https://staging.example.com/app/admin/x":  false,
		"http://staging.example.com/app":           false,
		"https://staging.example.com:8443/app":     false,
		"https://evil.example/app":                 false,
		"https://staging.example.com.evil.com/app": false,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := m.InScope(u) == nil; got != want {
			t.Errorf("%s: got %v want %v", raw, got, want)
		}
	}
}

func TestAddrAllowed(t *testing.T) {
	m := &Manifest{}
	for _, a := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fd00:ec2::254", "100.64.0.1", "0.0.0.0", "::ffff:127.0.0.1"} {
		if m.AddrAllowed(netip.MustParseAddr(a)) == nil {
			t.Errorf("%s must be blocked by default", a)
		}
	}
	if m.AddrAllowed(netip.MustParseAddr("93.184.215.14")) != nil {
		t.Error("public address must be allowed")
	}
	m.AllowPrivateAddresses = true
	if m.AddrAllowed(netip.MustParseAddr("127.0.0.1")) != nil {
		t.Error("loopback allowed when explicitly enabled")
	}
	if m.AddrAllowed(netip.MustParseAddr("169.254.169.254")) == nil {
		t.Error("metadata address must always be blocked")
	}
}

func TestTemplateIsNotValid(t *testing.T) {
	m := &Manifest{}
	if err := yaml.Unmarshal([]byte(Template), m); err != nil {
		t.Fatal(err)
	}
	if len(m.Validate(time.Now())) == 0 {
		t.Fatal("the shipped template must not be usable without human edits")
	}
}
