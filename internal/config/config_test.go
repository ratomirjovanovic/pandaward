package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadRoundTripAndStrictKeys(t *testing.T) {
	root := t.TempDir()
	if err := Write(root, Default("demo"), false); err != nil {
		t.Fatal(err)
	}
	c, hash, err := Load(root)
	if err != nil || c.Project.Name != "demo" || hash == "" {
		t.Fatalf("written default config must load: %+v %q %v", c, hash, err)
	}
	b, _ := os.ReadFile(Path(root))
	typo := strings.Replace(string(b), "allow_tool_network:", "allow_tool_netwrok:", 1)
	if typo == string(b) {
		t.Fatal("default config has no allow_tool_network key to misspell")
	}
	os.WriteFile(Path(root), []byte(typo), 0o644)
	if _, _, err := Load(root); err == nil || !strings.Contains(err.Error(), "allow_tool_netwrok") {
		t.Fatalf("a misspelled key must be rejected, got %v", err)
	}
	os.WriteFile(Path(root), []byte(strings.Replace(string(b), "schema_version: 1", "schema_version: 2", 1)), 0o644)
	if _, _, err := Load(root); err == nil {
		t.Fatal("an unknown schema_version must be rejected")
	}
}
