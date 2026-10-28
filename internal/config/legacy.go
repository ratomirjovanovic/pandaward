package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The project was called PenSec before 0.2.0. These names keep projects,
// scripts and approvals from that time working.
const (
	// LegacyDir is the project directory used before the rename.
	LegacyDir = ".pensec"
	// LegacyEnvPrefix is the environment variable prefix used before.
	LegacyEnvPrefix = "PENSEC_"
	// LegacyUserDir is the user config directory name used before.
	LegacyUserDir = "pensec"
)

// Env returns PANDAWARD_<name>, or PENSEC_<name> when only the old variable
// is set.
func Env(name string) string {
	if v, ok := os.LookupEnv("PANDAWARD_" + name); ok {
		return v
	}
	return os.Getenv(LegacyEnvPrefix + name)
}

// MigrateLegacy moves an old .pensec directory at root to .pandaward when
// the new one does not exist yet. It reports whether it moved anything.
func MigrateLegacy(root string) (bool, error) {
	old := filepath.Join(root, LegacyDir)
	if _, err := os.Stat(filepath.Join(old, "config.yaml")); err != nil {
		return false, nil
	}
	if _, err := os.Lstat(filepath.Join(root, Dir)); err == nil {
		return false, nil // both exist: leave the old one alone
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if fi, err := os.Lstat(old); err != nil || !fi.IsDir() {
		return false, nil // never follow a symlink planted as .pensec
	}
	if err := os.Rename(old, filepath.Join(root, Dir)); err != nil {
		return false, fmt.Errorf("could not move %s to %s: %w", old, Dir, err)
	}
	return true, nil
}
