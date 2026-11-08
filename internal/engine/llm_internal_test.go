package engine

import (
	"strings"
	"testing"
)

// No payload may contain its own canary, even after normalization, or an
// answer that only repeats the input would count as followed.
func TestLLMPayloadsDoNotContainCanary(t *testing.T) {
	for i, tmpl := range llmPayloads {
		part := "a1b2c3d4"
		if strings.Contains(normText(strings.ReplaceAll(tmpl, "%s", part)), canaryNorm(part)) {
			t.Errorf("payload %d contains its canary", i+1)
		}
	}
}

func TestFillTemplateEscapes(t *testing.T) {
	got := fillTemplate(`{"document":"x {{payload}}"}`, "application/json", "a\"b\nc")
	if got != `{"document":"x a\"b\nc"}` {
		t.Errorf("json: %s", got)
	}
	if got := fillTemplate("q={{payload}}", "application/x-www-form-urlencoded", "a b&c"); got != "q=a+b%26c" {
		t.Errorf("form: %s", got)
	}
}
