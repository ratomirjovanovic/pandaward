package adapters

import (
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// #470: certificate verification switched off only inside a condition that
// reads a setting is listed as information; an unconditional call stays high.
func TestTLSVerifyOffOptIn(t *testing.T) {
	cases := []struct {
		name, file, src string
		optIn           bool
	}{
		{"go setting", "a.go", "package a\n\nfunc dial(conf Config) {\n\tif conf.InsecureSkipVerify {\n\t\td.TLSConfig = &tls.Config{InsecureSkipVerify: true}\n\t}\n}\n", true},
		{"go skip tls", "a.go", "package a\n\nfunc f(cf Config) {\n\tif cf.SkipTlsVerify {\n\t\ttransport := &http.Transport{\n\t\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n\t\t}\n\t}\n}\n", true},
		{"js negated setting", "a.js", "function mail(s) {\n  if (!this.rejectUnauthorized) {\n    payload.tls = {\n      rejectUnauthorized: false\n    }\n  }\n}\n", true},
		{"js env", "a.js", "function db() {\n  if (process.env.KNEX_REJECT_UNAUTHORIZED_SSL_CERTIFICATE === 'false') {\n    return { rejectUnauthorized: false };\n  }\n}\n", true},
		{"python setting", "a.py", "def get(cfg):\n    if cfg.skip_tls_verify:\n        r = requests.get(url, verify=False)\n", true},
		{"go unconditional", "a.go", "package a\n\nfunc dial() {\n\tconn, err = ldap.DialTLS(\"tcp\", addr, &tls.Config{InsecureSkipVerify: true})\n}\n", false},
		{"go unrelated condition", "a.go", "package a\n\nfunc dial() {\n\tif err != nil {\n\t\treturn\n\t}\n\td.TLSConfig = &tls.Config{InsecureSkipVerify: true}\n}\n", false},
		{"go earlier sibling block closed", "a.go", "package a\n\nfunc dial(conf Config) {\n\tif conf.InsecureSkipVerify {\n\t\tlog.Print(\"x\")\n\t}\n\td.TLSConfig = &tls.Config{InsecureSkipVerify: true}\n}\n", false},
		{"js unconditional", "a.js", "const agent = new https.Agent({\n  rejectUnauthorized: false\n})\n", false},
		{"python unconditional", "a.py", "r = requests.get(url, verify=False)\n", false},
		{"python sibling after block", "a.py", "def f(cfg):\n    if cfg.skip_tls_verify:\n        pass\n    r = requests.get(url, verify=False)\n", false},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, map[string]string{"src/" + c.file: c.src})
		var got model.Severity
		seen := false
		for _, s := range sigs {
			if s.RuleID == "code.tls-verify-off" {
				got, seen = s.Severity, true
			}
		}
		if !seen {
			t.Errorf("%s: no signal", c.name)
			continue
		}
		if c.optIn && got != model.SevInfo {
			t.Errorf("%s: want information, got %q", c.name, got)
		}
		if !c.optIn && got != model.SevHigh {
			t.Errorf("%s: want high, got %q", c.name, got)
		}
	}
}
