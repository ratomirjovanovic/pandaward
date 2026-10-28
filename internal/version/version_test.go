package version

import "testing"

func TestFromModule(t *testing.T) {
	for in, want := range map[string]string{
		"v0.1.2":                               "0.1.2",
		"v0.2.0-rc.1":                          "0.2.0-rc.1",
		"v0.1.3-0.20261028061500-1a0d67f3e2c1": "0.1.3-0.20261028061500-1a0d67f3e2c1",
		"(devel)":                              "dev",
		"":                                     "dev",
	} {
		if got := fromModule(in); got != want {
			t.Errorf("fromModule(%q) = %q, want %q", in, got, want)
		}
	}
}
