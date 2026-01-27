// Package rules provides functionality for loading and managing PCI rules.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/khanhduong95/pcilint/pkg/parser"
	"gopkg.in/yaml.v3"
)

// Loader loads rules from YAML files.
type Loader struct {
	rulesDir    string
	embeddedFS  embed.FS
	useEmbedded bool
}

// NewLoader creates a new rule loader.
// If rulesDir is empty, it will use embedded rules.
func NewLoader(rulesDir string) *Loader {
	return &Loader{
		rulesDir:    rulesDir,
		useEmbedded: rulesDir == "",
	}
}

// NewLoaderWithEmbedded creates a loader that uses embedded rules.
func NewLoaderWithEmbedded(efs embed.FS) *Loader {
	return &Loader{
		embeddedFS:  efs,
		useEmbedded: true,
	}
}

// LoadAll loads all rules from the rules directory.
func (l *Loader) LoadAll() ([]parser.Rule, error) {
	if l.useEmbedded && l.rulesDir == "" {
		return l.loadEmbedded()
	}
	return l.loadFromDir(l.rulesDir)
}

// loadFromDir loads rules from a filesystem directory.
func (l *Loader) loadFromDir(dir string) ([]parser.Rule, error) {
	var rules []parser.Rule

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		rule, err := l.loadRuleFile(path)
		if err != nil {
			return fmt.Errorf("failed to load rule %s: %w", path, err)
		}

		rule.Enabled = true
		rules = append(rules, rule)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %w", err)
	}

	return rules, nil
}

// loadEmbedded loads rules from embedded filesystem.
func (l *Loader) loadEmbedded() ([]parser.Rule, error) {
	var rules []parser.Rule

	err := fs.WalkDir(l.embeddedFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := l.embeddedFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read embedded rule %s: %w", path, err)
		}

		var rule parser.Rule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("failed to parse rule %s: %w", path, err)
		}

		rule.Enabled = true
		rules = append(rules, rule)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk embedded rules: %w", err)
	}

	return rules, nil
}

// loadRuleFile loads a single rule from a YAML file.
func (l *Loader) loadRuleFile(path string) (parser.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return parser.Rule{}, fmt.Errorf("failed to read file: %w", err)
	}

	var rule parser.Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return parser.Rule{}, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return rule, nil
}

// LoadByID loads a specific rule by its ID.
func (l *Loader) LoadByID(id string) (parser.Rule, error) {
	rules, err := l.LoadAll()
	if err != nil {
		return parser.Rule{}, err
	}

	for _, rule := range rules {
		if rule.ID == id {
			return rule, nil
		}
	}

	return parser.Rule{}, fmt.Errorf("rule not found: %s", id)
}

// LoadForLanguage loads rules for a specific language.
func (l *Loader) LoadForLanguage(language string) ([]parser.Rule, error) {
	allRules, err := l.LoadAll()
	if err != nil {
		return nil, err
	}

	return FilterByLanguage(allRules, language), nil
}

// FilterByLanguage returns rules that apply to the given language.
// Rules with empty language field are considered universal and always included.
func FilterByLanguage(rules []parser.Rule, language string) []parser.Rule {
	if language == "" {
		return rules
	}

	language = strings.ToLower(language)
	var filtered []parser.Rule
	for _, rule := range rules {
		ruleLang := strings.ToLower(rule.Language)
		// Include if: rule has no language (universal) OR matches the target language
		if ruleLang == "" || ruleLang == language {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// FilterRules filters rules by enabled/disabled lists, severity, and optionally language.
func FilterRules(rules []parser.Rule, enabled, disabled []string, minSeverity string) []parser.Rule {
	enabledSet := make(map[string]bool)
	disabledSet := make(map[string]bool)

	for _, id := range enabled {
		enabledSet[id] = true
	}
	for _, id := range disabled {
		disabledSet[id] = true
	}

	var filtered []parser.Rule
	for _, rule := range rules {
		// Check if explicitly disabled
		if disabledSet[rule.ID] {
			continue
		}

		// If enabled list is provided, only include those rules
		if len(enabledSet) > 0 && !enabledSet[rule.ID] {
			continue
		}

		// Check severity
		if minSeverity != "" && !meetsMinSeverity(rule.Severity, minSeverity) {
			continue
		}

		filtered = append(filtered, rule)
	}

	return filtered
}

// meetsMinSeverity checks if a rule severity meets the minimum threshold.
func meetsMinSeverity(ruleSeverity, minSeverity string) bool {
	levels := map[string]int{
		"low":    1,
		"medium": 2,
		"high":   3,
	}

	ruleLevel := levels[strings.ToLower(ruleSeverity)]
	minLevel := levels[strings.ToLower(minSeverity)]

	return ruleLevel >= minLevel
}
