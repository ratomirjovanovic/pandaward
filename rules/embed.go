// Package rules embeds the reviewed rule packs PenSec ships with.
package rules

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed semgrep/*.yaml
var semgrepFS embed.FS

// SemgrepFiles lists the bundled Semgrep rule files.
func SemgrepFiles() ([]string, error) {
	return fs.Glob(semgrepFS, "semgrep/*.yaml")
}

// WriteSemgrep writes the bundled Semgrep rules into dir, replacing older
// copies, and returns dir for use as a --config path.
func WriteSemgrep(dir string) (string, error) {
	files, err := SemgrepFiles()
	if err != nil {
		return "", err
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, f := range files {
		b, err := semgrepFS.ReadFile(f)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o600); err != nil {
			return "", err
		}
	}
	return dir, nil
}
