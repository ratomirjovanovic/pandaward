package adapters

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// Every rule ID written in the built-in adapters' source must be listed by
// RuleIDs, so the benchmark corpus cannot silently miss a rule.
func TestRuleIDsMatchSource(t *testing.T) {
	ids := RuleIDs()
	lit := regexp.MustCompile(`"((?:code|cicd|infra|supply|mobile|secret|inventory)\.[a-z0-9-]+)"`)
	for _, f := range []string{"builtin_code.go", "builtin_static.go", "mobile.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
			if !slices.Contains(ids, m[1]) {
				t.Errorf("%s emits %s, which RuleIDs does not list", f, m[1])
			}
		}
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			t.Errorf("duplicate rule ID %s", ids[i])
		}
	}
}
