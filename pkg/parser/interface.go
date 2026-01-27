// Package parser provides the interface for language-specific parsers.
package parser

import (
	"context"

	"github.com/khanhduong95/pcilint/pkg/violation"
)

// Parser defines the interface that all language parsers must implement.
type Parser interface {
	// Name returns the language name (e.g., "go", "python", "php").
	Name() string

	// Extensions returns file extensions this parser handles (e.g., [".go"]).
	Extensions() []string

	// Parse analyzes a single file and returns violations.
	Parse(ctx context.Context, filepath string, content []byte, rules []Rule) ([]violation.Violation, error)

	// SupportsRule checks if this parser can check a specific rule.
	SupportsRule(rule Rule) bool
}

// Rule represents a PCI rule to check.
type Rule struct {
	ID          string            `yaml:"id"`          // e.g., "pci-001"
	Name        string            `yaml:"name"`        // e.g., "no-card-in-logs"
	Severity    string            `yaml:"severity"`    // "high", "medium", "low"
	Description string            `yaml:"description"` // Full description
	Message     string            `yaml:"message"`     // Short message for violations
	Patterns    []Pattern         `yaml:"patterns"`    // Pattern matching config
	Suggestion  string            `yaml:"suggestion"`  // How to fix
	References  []string          `yaml:"references"`  // PCI-DSS references
	Enabled     bool              `yaml:"-"`           // Whether rule is enabled (runtime)
}

// Pattern defines a pattern to match in code.
type Pattern struct {
	Type             string   `yaml:"type"`              // "function_call", "variable", "string_literal"
	Functions        []string `yaml:"functions"`         // Function names to check
	ArgumentPatterns []ArgPattern `yaml:"argument_patterns"` // Patterns for arguments
	VariableNames    []string `yaml:"variable_names"`    // Variable name patterns
	StringPatterns   []string `yaml:"string_patterns"`   // String literal patterns
}

// ArgPattern defines a pattern to match in function arguments.
type ArgPattern struct {
	Regex         string   `yaml:"regex"`          // Regex pattern to match
	ContainsWords []string `yaml:"contains_words"` // Words that indicate card data
}

// Factory creates parser instances.
type Factory interface {
	// CreateParser creates a parser for the given language.
	CreateParser(language string) (Parser, error)

	// SupportedLanguages returns a list of supported language names.
	SupportedLanguages() []string

	// ParserForExtension returns a parser that handles the given file extension.
	ParserForExtension(ext string) (Parser, bool)
}
