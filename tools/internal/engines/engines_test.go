package engines

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	got, err := Parse(" builtin, opengrep,builtin ")
	if err != nil || strings.Join(got, ",") != "builtin,opengrep" {
		t.Fatalf("Parse = %v, %v", got, err)
	}
	for _, bad := range []string{"", " , ", "codeql", "builtin,codeql"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}
