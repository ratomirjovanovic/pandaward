package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateLegacyMovesOldDirectory(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, LegacyDir)
	os.MkdirAll(filepath.Join(old, "private"), 0o700)
	os.WriteFile(filepath.Join(old, "config.yaml"), []byte("schema_version: 1\n"), 0o644)
	os.WriteFile(filepath.Join(old, "private", "state.db"), []byte("ledger"), 0o600)
	moved, err := MigrateLegacy(root)
	if err != nil || !moved {
		t.Fatalf("moved %v, err %v", moved, err)
	}
	if b, err := os.ReadFile(filepath.Join(root, Dir, "private", "state.db")); err != nil || string(b) != "ledger" {
		t.Fatalf("ledger not carried over: %q %v", b, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old directory still there")
	}
	if moved, _ := MigrateLegacy(root); moved {
		t.Fatal("second call must do nothing")
	}
}

func TestMigrateLegacyKeepsBothWhenNewExists(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{LegacyDir, Dir} {
		os.MkdirAll(filepath.Join(root, d), 0o700)
		os.WriteFile(filepath.Join(root, d, "config.yaml"), []byte(d), 0o644)
	}
	if moved, err := MigrateLegacy(root); moved || err != nil {
		t.Fatalf("moved %v, err %v", moved, err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, Dir, "config.yaml")); string(b) != Dir {
		t.Fatal("existing .pandaward was overwritten")
	}
}

func TestEnvFallsBackToLegacyName(t *testing.T) {
	t.Setenv("PENSEC_ASCII", "1")
	if Env("ASCII") != "1" {
		t.Fatal("PENSEC_ASCII must still be read")
	}
	t.Setenv("PANDAWARD_ASCII", "")
	if Env("ASCII") != "" {
		t.Fatal("a set PANDAWARD_ variable wins, even when empty")
	}
}
