package adapters

import (
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func weakCSP(sigs []model.Signal) []model.Signal {
	var out []model.Signal
	for _, s := range sigs {
		if s.RuleID == "code.weak-csp" {
			out = append(out, s)
		}
	}
	return out
}

func TestWeakCSPConfigFormats(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		lines []int // expected StartLine of each signal; nil means none
	}{
		{"vercel inline", map[string]string{"vercel.json": "{\n  \"headers\": [\n    {\n      \"source\": \"/(.*)\",\n      \"headers\": [\n        { \"key\": \"Content-Security-Policy\", \"value\": \"script-src 'self' 'unsafe-inline'\" }\n      ]\n    }\n  ]\n}\n"}, []int{6}},
		{"vercel legacy routes", map[string]string{"vercel.json": `{"routes":[{"src":"/(.*)","headers":{"content-security-policy":"default-src 'self' 'unsafe-eval'"}}]}`}, []int{1}},
		{"vercel strict", map[string]string{"vercel.json": `{"headers":[{"source":"/(.*)","headers":[{"key":"Content-Security-Policy","value":"script-src 'self' 'nonce-abc' 'unsafe-inline' 'strict-dynamic'"}]}]}`}, nil},
		{"vercel report-only", map[string]string{"vercel.json": `{"headers":[{"source":"/(.*)","headers":[{"key":"Content-Security-Policy-Report-Only","value":"script-src 'unsafe-inline'"}]}]}`}, nil},
		{"netlify basic", map[string]string{"netlify.toml": "[[headers]]\n  for = \"/*\"\n  [headers.values]\n    Content-Security-Policy = \"default-src 'self' 'unsafe-eval'\"\n"}, []int{4}},
		{"netlify multi-line", map[string]string{"netlify.toml": "[[headers]]\n  for = \"/*\"\n  [headers.values]\n    Content-Security-Policy = '''\n      default-src 'self';\n      script-src 'self' 'unsafe-inline'\n    '''\n"}, []int{4}},
		{"netlify styles only", map[string]string{"netlify.toml": "[[headers]]\n  for = \"/*\"\n  [headers.values]\n    Content-Security-Policy = \"script-src 'self'; style-src 'unsafe-inline'\"\n"}, nil},
		{"netlify commented", map[string]string{"netlify.toml": "#    Content-Security-Policy = \"script-src 'unsafe-inline'\"\n"}, nil},
		{"_headers", map[string]string{"public/_headers": "/*\n  Content-Security-Policy: script-src 'self' 'unsafe-inline'\n"}, []int{2}},
		{"_headers hash", map[string]string{"public/_headers": "/*\n  Content-Security-Policy: script-src 'self' 'sha256-xyz' 'unsafe-inline'\n"}, nil},
		{"next literal", map[string]string{"next.config.js": "module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: [\n      { key: 'Content-Security-Policy', value: \"script-src 'self' 'unsafe-inline'\" },\n    ] }]\n  },\n}\n"}, []int{4}},
		{"next join", map[string]string{"next.config.mjs": "export default {\n  async headers() {\n    return [{ source: '/(.*)', headers: [{\n      key: 'Content-Security-Policy',\n      value: [\n        \"default-src 'self'\",\n        \"script-src 'self' 'unsafe-eval'\",\n      ].join('; '),\n    }] }]\n  },\n}\n"}, []int{5}},
		{"next template literal", map[string]string{"next.config.ts": "export default {\n  async headers() {\n    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: `\n      default-src 'self';\n      script-src 'self' 'unsafe-inline';\n    ` }] }]\n  },\n}\n"}, []int{3}},
		{"next variable skipped", map[string]string{"next.config.js": "const csp = \"script-src 'self' 'unsafe-inline'\";\nmodule.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: csp }] }] } }\n"}, nil},
		{"next replace call skipped", map[string]string{"next.config.js": "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: \"script-src 'unsafe-inline'\".replace(/x/, '') }] }] } }\n"}, nil},
		{"next substitution skipped", map[string]string{"next.config.js": "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: `script-src 'unsafe-inline' ${extra}` }] }] } }\n"}, nil},
		{"next nonce", map[string]string{"next.config.js": "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: \"script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'\" }] }] } }\n"}, nil},
		{"test path skipped", map[string]string{"test/fixtures/vercel.json": `{"headers":[{"source":"/(.*)","headers":[{"key":"Content-Security-Policy","value":"script-src 'unsafe-inline'"}]}]}`}, nil},
	}
	for _, c := range cases {
		got := weakCSP(runOn(t, codeAdapter{}, c.files))
		if len(got) != len(c.lines) {
			t.Errorf("%s: %d signal(s), want %d: %+v", c.name, len(got), len(c.lines), got)
			continue
		}
		for i, s := range got {
			if s.StartLine != c.lines[i] || s.ControlID != "H-004" || s.Confidence != model.Hypothesis || s.Severity != model.SevMedium {
				t.Errorf("%s: unexpected signal %+v", c.name, s)
			}
		}
	}
}
