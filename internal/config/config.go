// Package config loads and writes .pensec/config.yaml.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Dir is the per-project PenSec directory.
const Dir = ".pensec"

// Config is the project configuration (schema v1).
type Config struct {
	SchemaVersion int `yaml:"schema_version"`
	Project       struct {
		Name string `yaml:"name"`
	} `yaml:"project"`
	Profile   string `yaml:"profile"`
	Inventory struct {
		Exclude      []string `yaml:"exclude"`
		MaxFileBytes int64    `yaml:"max_file_bytes"`
		MaxFiles     int      `yaml:"max_files"`
	} `yaml:"inventory"`
	Scan struct {
		MaxDurationMinutes int  `yaml:"max_duration_minutes"`
		AdapterTimeoutSec  int  `yaml:"adapter_timeout_seconds"`
		FailOnAdapterError bool `yaml:"fail_on_adapter_error"`
		// AllowToolNetwork lets optional scanners download advisory
		// databases or rule packs. It never allows requests to targets.
		AllowToolNetwork bool     `yaml:"allow_tool_network"`
		SemgrepConfig    string   `yaml:"semgrep_config"`
		Adapters         []string `yaml:"adapters"`
		// SARIFFiles lists SARIF results to import, relative to the project
		// root, in addition to .pensec/sarif/*.sarif.
		SARIFFiles []string `yaml:"sarif_files"`
	} `yaml:"scan"`
	Report struct {
		Formats         []string `yaml:"formats"`
		IncludeUntested bool     `yaml:"include_untested"`
	} `yaml:"report"`
	Policy struct {
		AIAnalysis string `yaml:"ai_analysis"`
	} `yaml:"policy"`
}

// Default returns the default configuration.
func Default(name string) *Config {
	c := &Config{SchemaVersion: 1, Profile: "local-passive"}
	c.Project.Name = name
	c.Inventory.Exclude = []string{"node_modules", "vendor", "dist", "build", ".git", ".next", ".nuxt", "target", "bin", "obj", ".venv", "venv", "__pycache__", ".pensec", "coverage", ".terraform", "Pods", ".gradle"}
	c.Inventory.MaxFileBytes = 2 << 20
	c.Inventory.MaxFiles = 200000
	c.Scan.MaxDurationMinutes = 45
	c.Scan.AdapterTimeoutSec = 600
	c.Scan.FailOnAdapterError = true
	c.Scan.AllowToolNetwork = false
	c.Scan.SemgrepConfig = ""
	c.Scan.Adapters = []string{"builtin-inventory", "builtin-secrets", "builtin-code", "builtin-cicd", "builtin-infra", "builtin-supply", "builtin-mobile", "gitleaks", "semgrep", "osv-scanner", "trivy"}
	c.Report.Formats = []string{"html", "markdown", "json", "sarif"}
	c.Report.IncludeUntested = true
	c.Policy.AIAnalysis = "opt_in"
	return c
}

// Path returns the config path for a project root.
func Path(root string) string { return filepath.Join(root, Dir, "config.yaml") }

// PrivateDir returns the gitignored private state directory.
func PrivateDir(root string) string { return filepath.Join(root, Dir, "private") }

// ReportsDir returns the gitignored report directory.
func ReportsDir(root string) string { return filepath.Join(root, Dir, "reports") }

// ErrNotInitialized is returned when .pensec/config.yaml is missing.
var ErrNotInitialized = errors.New("project not initialized: run `pensec init` first")

// Load reads the config of a project.
func Load(root string) (*Config, string, error) {
	b, err := os.ReadFile(Path(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNotInitialized
	}
	if err != nil {
		return nil, "", err
	}
	c := Default("")
	// Unknown keys are errors: a misspelled setting must not be ignored.
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, "", fmt.Errorf("invalid %s: %w", Path(root), err)
	}
	if c.SchemaVersion != 1 {
		return nil, "", fmt.Errorf("unsupported config schema_version %d", c.SchemaVersion)
	}
	if err := c.Validate(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return c, hex.EncodeToString(sum[:]), nil
}

// Validate checks value ranges.
func (c *Config) Validate() error {
	switch c.Profile {
	case "local-passive", "":
	default:
		return fmt.Errorf("config profile %q: only local-passive may be the default profile; runtime profiles are chosen per invocation", c.Profile)
	}
	if c.Inventory.MaxFileBytes <= 0 || c.Inventory.MaxFileBytes > 64<<20 {
		return fmt.Errorf("inventory.max_file_bytes must be between 1 and 64MiB")
	}
	if c.Scan.AdapterTimeoutSec <= 0 || c.Scan.AdapterTimeoutSec > 7200 {
		return fmt.Errorf("scan.adapter_timeout_seconds must be between 1 and 7200")
	}
	if c.Policy.AIAnalysis != "opt_in" && c.Policy.AIAnalysis != "off" && c.Policy.AIAnalysis != "on" {
		return fmt.Errorf("policy.ai_analysis must be opt_in, on or off")
	}
	return nil
}

// Write saves the config, refusing to overwrite unless force is set.
func Write(root string, c *Config, force bool) error {
	p := Path(root)
	if _, err := os.Stat(p); err == nil && !force {
		return fmt.Errorf("%s already exists", p)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	header := "# PenSec project configuration (schema v1). Safe to commit.\n# Private state lives in .pensec/private/ and is gitignored.\n"
	return os.WriteFile(p, append([]byte(header), b...), 0o644)
}

// EnsureLayout creates private directories and the .pensec/.gitignore.
func EnsureLayout(root string) error {
	for _, d := range []string{PrivateDir(root), filepath.Join(PrivateDir(root), "evidence"), filepath.Join(PrivateDir(root), "runs"), ReportsDir(root)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	gi := filepath.Join(root, Dir, ".gitignore")
	if _, err := os.Stat(gi); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(gi, []byte("# PenSec private state, evidence and reports never go to git\nprivate/\nreports/\n"), 0o644)
	}
	return nil
}
