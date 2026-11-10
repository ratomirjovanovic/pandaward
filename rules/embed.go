// Package rules embeds the reviewed rule packs PandaWard ships with.
package rules

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
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

// SemgrepRule is the part of a bundled rule that tools outside the scanner
// need: its id, languages and CWE.
type SemgrepRule struct {
	ID        string   `yaml:"id"`
	Languages []string `yaml:"languages"`
	Metadata  struct {
		CWE     string `yaml:"cwe"`
		Control string `yaml:"pandaward-control"`
		// Supersedes names built-in rules this rule replaces in files of
		// its languages when the semgrep adapter completes.
		Supersedes []string `yaml:"pandaward-supersedes"`
	} `yaml:"metadata"`
}

// SemgrepRules lists the bundled Semgrep rules.
func SemgrepRules() ([]SemgrepRule, error) {
	files, err := SemgrepFiles()
	if err != nil {
		return nil, err
	}
	var out []SemgrepRule
	for _, f := range files {
		b, err := semgrepFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Rules []SemgrepRule `yaml:"rules"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, doc.Rules...)
	}
	return out, nil
}

// SemgrepHash is the SHA-256 of the bundled Semgrep rule files, in name
// order, so a measurement can say which rule set it used.
func SemgrepHash() (string, error) {
	files, err := SemgrepFiles()
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		b, err := semgrepFS.ReadFile(f)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\n%d\n", path.Base(f), len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
