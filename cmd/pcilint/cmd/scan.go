package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/khanhduong95/pcilint/pkg/core/config"
	"github.com/khanhduong95/pcilint/pkg/core/reporter"
	"github.com/khanhduong95/pcilint/pkg/core/rules"
	"github.com/khanhduong95/pcilint/pkg/core/scanner"
	"github.com/khanhduong95/pcilint/pkg/parser"
	"github.com/khanhduong95/pcilint/pkg/parser/golang"
)

var (
	// Scan flags
	exclude     []string
	language    string
	format      string
	configFile  string
	concurrency int
	rulesDir    string
	severity    string
	failOnAny   bool
	quiet       bool
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan files for PCI-DSS compliance violations",
	Long: `Scan analyzes source code files for potential PCI-DSS compliance violations.

Examples:
  # Scan current directory
  pcilint scan .

  # Scan specific paths
  pcilint scan ./src ./pkg

  # Exclude test files
  pcilint scan . --exclude "**/*_test.go"

  # Output as JSON
  pcilint scan . --format json

  # Only report high severity issues
  pcilint scan . --severity high

  # Exit with code 1 if any violations found (for CI/CD)
  pcilint scan . --fail-on-any`,
	Args: cobra.ArbitraryArgs,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringArrayVarP(&exclude, "exclude", "e", nil, "Patterns to exclude (gitignore-style)")
	scanCmd.Flags().StringVarP(&language, "lang", "l", "", "Target language (auto-detect if not specified)")
	scanCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format (text, json, sarif)")
	scanCmd.Flags().StringVarP(&configFile, "config", "c", "", "Config file path")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of concurrent workers (default: NumCPU)")
	scanCmd.Flags().StringVar(&rulesDir, "rules", "", "Custom rules directory")
	scanCmd.Flags().StringVarP(&severity, "severity", "s", "", "Minimum severity to report (high, medium, low)")
	scanCmd.Flags().BoolVar(&failOnAny, "fail-on-any", false, "Exit with code 1 if any violations found")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-error output")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Build configuration
	cfg := config.DefaultConfig()

	// Try to load config file
	if configFile != "" {
		loadedCfg, err := config.LoadFromFile(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
		cfg = loadedCfg
	} else if path, found := config.FindConfigFile(); found {
		loadedCfg, err := config.LoadFromFile(path)
		if err == nil {
			cfg = loadedCfg
		}
	}

	// Override with command-line flags
	flagCfg := &config.Config{
		Paths:       args,
		Exclude:     exclude,
		Language:    language,
		Format:      format,
		Concurrency: concurrency,
		RulesDir:    rulesDir,
		Severity:    severity,
		FailOnAny:   failOnAny,
		Quiet:       quiet,
	}
	cfg.Merge(flagCfg)

	// Set default paths if none provided
	if len(cfg.Paths) == 0 {
		cfg.Paths = []string{"."}
	}

	// Set default concurrency
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = runtime.NumCPU()
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Load rules
	var allRules []parser.Rule
	if cfg.RulesDir != "" {
		loader := rules.NewLoader(cfg.RulesDir)
		loadedRules, err := loader.LoadAll()
		if err != nil {
			return fmt.Errorf("failed to load rules from %s: %w", cfg.RulesDir, err)
		}
		allRules = loadedRules
	} else {
		// Use built-in rules
		allRules = getBuiltInRules()
	}

	// Filter rules
	filteredRules := rules.FilterRules(allRules, cfg.Rules.Enabled, cfg.Rules.Disabled, cfg.Severity)

	// Create parser factory
	factory := parser.NewFactory()
	factory.Register(golang.NewParser())

	// Create scanner
	s := scanner.NewScanner(cfg, factory, filteredRules)

	// Run scan
	if !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "Scanning %d path(s)...\n\n", len(cfg.Paths))
	}

	report, err := s.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Create reporter
	rep := reporter.NewReporter(reporter.Format(cfg.Format), os.Stdout, cfg.Quiet)

	// Output report
	if err := rep.Report(report); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Exit with code 1 if violations found and --fail-on-any is set
	if cfg.FailOnAny && report.HasViolations() {
		os.Exit(1)
	}

	return nil
}

// getBuiltInRules returns the built-in PCI rules for Go.
func getBuiltInRules() []parser.Rule {
	return []parser.Rule{
		{
			ID:          "pci-001",
			Name:        "no-card-in-logs",
			Language:    "go",
			Severity:    "high",
			Description: "Detects potential credit card numbers in logging statements",
			Message:     "Potential credit card number detected in log statement. Card data must not be logged per PCI-DSS requirement 3.4.",
			Suggestion:  "Use a masking function to redact card numbers before logging. Example: log.Printf(\"Card: %s\", maskCard(cardNumber))",
			Enabled:     true,
		},
		{
			ID:          "pci-002",
			Name:        "no-cvv-storage",
			Language:    "go",
			Severity:    "high",
			Description: "Detects CVV/CVC codes stored in variables or databases",
			Message:     "CVV/CVC code appears to be stored. CVV must never be stored per PCI-DSS requirement 3.2.",
			Suggestion:  "CVV should only be used for transaction authorization and immediately discarded. Never store CVV data.",
			Enabled:     true,
		},
		{
			ID:          "pci-003",
			Name:        "no-card-in-urls",
			Language:    "go",
			Severity:    "high",
			Description: "Detects card data in URL parameters or query strings",
			Message:     "Card data detected in URL parameters. Card data in URLs can be logged by servers and proxies.",
			Suggestion:  "Never pass card data in URLs. Use POST requests with encrypted body for sensitive data transmission.",
			Enabled:     true,
		},
		{
			ID:          "pci-004",
			Name:        "no-plaintext-card-storage",
			Language:    "go",
			Severity:    "high",
			Description: "Detects unencrypted card data in files or databases",
			Message:     "Plaintext card data detected in storage operation. Card data must be encrypted at rest.",
			Suggestion:  "Encrypt card data using strong cryptography (AES-256) before storage. Consider using a tokenization service.",
			Enabled:     true,
		},
		{
			ID:          "pci-005",
			Name:        "no-card-in-errors",
			Language:    "go",
			Severity:    "high",
			Description: "Detects card numbers in error messages",
			Message:     "Potential card data in error message. Error messages may be logged or displayed to users.",
			Suggestion:  "Mask or remove card data from error messages. Use generic error messages for payment failures.",
			Enabled:     true,
		},
	}
}
