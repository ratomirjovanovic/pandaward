package version

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// The GitHub Action downloads the release named in its default version
// input; a release bump must move it together with the plugin version.
func TestActionVersionMatchesPlugin(t *testing.T) {
	b, err := os.ReadFile("../../.claude-plugin/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	var plugin struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &plugin); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^  version:\n(?:    .*\n)*?    default: "([^"]+)"`).FindSubmatch(a)
	if m == nil {
		t.Fatal("action.yml has no default for the version input")
	}
	if string(m[1]) != plugin.Version {
		t.Fatalf("action.yml downloads %s but the plugin is %s; bump both", m[1], plugin.Version)
	}
}
