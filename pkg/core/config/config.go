// Package config provides configuration management for pcilint.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the complete configuration for pcilint.
type Config struct {
	// Paths to scan (relative to config file or absolute)
	Paths []string `yaml:"paths"`

	// Patterns to exclude (gitignore-style)
	Exclude []string `yaml:"exclude"`

	// Target language (auto-detect if empty)
	Language string `yaml:"language"`

	// Minimum severity to report: "high", "medium", "low"
	Severity string `yaml:"severity"`

	// Output format: "text", "json", "sarif"
	Format string `yaml:"format"`

	// Rules configuration
	Rules RulesConfig `yaml:"rules"`

	// Number of concurrent workers
	Concurrency int `yaml:"concurrency"`

	// Custom rules directory
	RulesDir string `yaml:"rules_dir"`

	// Exit with code 1 if any violations found
	FailOnAny bool `yaml:"fail_on_any"`

	// Suppress non-error output
	Quiet bool `yaml:"quiet"`
}

// RulesConfig holds rule-specific configuration.
type RulesConfig struct {
	// Explicitly enabled rule IDs (if set, only these run)
	Enabled []string `yaml:"enabled"`

	// Explicitly disabled rule IDs
	Disabled []string `yaml:"disabled"`

	// Severity overrides per rule
	Overrides map[string]RuleOverride `yaml:"overrides"`
}

// RuleOverride allows overriding rule properties.
type RuleOverride struct {
	Severity string `yaml:"severity"`
	Enabled  *bool  `yaml:"enabled"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Paths:       []string{"."},
		Exclude:     []string{"vendor/**", "node_modules/**", "**/*_test.go"},
		Language:    "",
		Severity:    "low",
		Format:      "text",
		Concurrency: 0, // Will use runtime.NumCPU()
		FailOnAny:   false,
		Quiet:       false,
	}
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Make paths relative to config file directory
	configDir := filepath.Dir(path)
	for i, p := range cfg.Paths {
		if !filepath.IsAbs(p) {
			cfg.Paths[i] = filepath.Join(configDir, p)
		}
	}

	return cfg, nil
}

// FindConfigFile searches for a config file in the current and parent directories.
func FindConfigFile() (string, bool) {
	names := []string{".pcilint.yaml", ".pcilint.yml", "pcilint.yaml", "pcilint.yml"}

	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}

	for {
		for _, name := range names {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path, true
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", false
}

// Merge merges command-line flags into the configuration.
// Command-line flags take precedence over config file values.
func (c *Config) Merge(flags *Config) {
	if len(flags.Paths) > 0 && !(len(flags.Paths) == 1 && flags.Paths[0] == ".") {
		c.Paths = flags.Paths
	}
	if len(flags.Exclude) > 0 {
		c.Exclude = append(c.Exclude, flags.Exclude...)
	}
	if flags.Language != "" {
		c.Language = flags.Language
	}
	if flags.Severity != "" {
		c.Severity = flags.Severity
	}
	if flags.Format != "" {
		c.Format = flags.Format
	}
	if flags.Concurrency > 0 {
		c.Concurrency = flags.Concurrency
	}
	if flags.RulesDir != "" {
		c.RulesDir = flags.RulesDir
	}
	if flags.FailOnAny {
		c.FailOnAny = true
	}
	if flags.Quiet {
		c.Quiet = true
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if len(c.Paths) == 0 {
		return fmt.Errorf("no paths specified")
	}

	validSeverities := map[string]bool{"high": true, "medium": true, "low": true, "": true}
	if !validSeverities[c.Severity] {
		return fmt.Errorf("invalid severity: %s (must be high, medium, or low)", c.Severity)
	}

	validFormats := map[string]bool{"text": true, "json": true, "sarif": true}
	if !validFormats[c.Format] {
		return fmt.Errorf("invalid format: %s (must be text, json, or sarif)", c.Format)
	}

	return nil
}
