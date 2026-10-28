package engine

import (
	"os"
	"testing"
)

// TestMain keeps the approval key of these tests out of the real user
// config directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pandaward-config-")
	if err != nil {
		panic(err)
	}
	os.Setenv("PANDAWARD_CONFIG_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
