package adapters

import (
	"strings"
	"testing"
)

func TestToolEnvUsesSeparateTempDir(t *testing.T) {
	t.Setenv("TMPDIR", "/should/not/leak")
	env := toolEnv(&Context{ToolHome: "/deep/project/.pensec/private/tool-home"}, "/tmp/pensec-1")
	got := map[string][]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = append(got[k], v)
	}
	for _, k := range []string{"TEMP", "TMP", "TMPDIR"} {
		if len(got[k]) != 1 || got[k][0] != "/tmp/pensec-1" {
			t.Errorf("%s = %v, want only the per-run temp dir", k, got[k])
		}
	}
	if len(got["HOME"]) != 1 || got["HOME"][0] != "/deep/project/.pensec/private/tool-home" {
		t.Errorf("HOME = %v, want the tool home", got["HOME"])
	}
}
