package adapters

import "testing"

func TestDocumentedPublicAndProse(t *testing.T) {
	cases := []struct {
		name       string
		line, prev string
		public     bool
		prose      bool
	}{
		{"public key comment above", `export const PING_KEY = "00aa11bb22cc33dd44ee55ff66778899";`, `/** Public key of a search-engine ping protocol; served at /<key>.txt. */`, true, false},
		{"public key trailing comment", `const k = "00aa11bb22cc33dd44ee55ff66778899"; // public key`, ``, true, false},
		{"plain secret", `export const API_KEY = "00aa11bb22cc33dd44ee55ff66778899";`, `// the key of the billing account`, false, false},
		{"public word without key", `const k = "00aa11bb22cc33dd44ee55ff66778899";`, `// public page`, false, false},
		{"locale sentence", `  "landing.u1.when": "Ispitivac deli programerski zadatak, gresku koju treba ispraviti ili upit.",`, ``, false, true},
		{"short value", `const k = "abc123XYZ789token";`, ``, false, false},
	}
	for _, tc := range cases {
		if got := documentedPublic(tc.line, tc.prev); got != tc.public {
			t.Errorf("%s: documentedPublic = %v, want %v", tc.name, got, tc.public)
		}
		if got := proseLine(tc.line); got != tc.prose {
			t.Errorf("%s: proseLine = %v, want %v", tc.name, got, tc.prose)
		}
	}
}
