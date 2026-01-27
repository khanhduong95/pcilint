package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/khanhduong95/pcilint/pkg/parser"
)

// rulesCmd represents the rules command.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage PCI compliance rules",
	Long: `View and manage available PCI compliance rules.

Commands:
  list    List all available rules
  show    Show details for a specific rule`,
}

// rulesListCmd represents the rules list command.
var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available rules",
	Long: `List all available PCI compliance rules with their IDs,
names, and severity levels.`,
	RunE: runRulesList,
}

// rulesShowCmd represents the rules show command.
var rulesShowCmd = &cobra.Command{
	Use:   "show <rule-id>",
	Short: "Show details for a specific rule",
	Long: `Show detailed information about a specific rule,
including its description, severity, and suggestions.`,
	Args: cobra.ExactArgs(1),
	RunE: runRulesShow,
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesShowCmd)
}

func runRulesList(cmd *cobra.Command, args []string) error {
	rules := getBuiltInRules()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// Header
	bold := color.New(color.Bold)
	bold.Fprintf(w, "ID\tNAME\tSEVERITY\tDESCRIPTION\n")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", "──────", "────────────────────", "────────", "────────────────────────────────────────")

	// Rules
	for _, rule := range rules {
		severityColor := getSeverityColor(rule.Severity)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			rule.ID,
			rule.Name,
			severityColor.Sprint(strings.ToUpper(rule.Severity)),
			truncate(rule.Description, 50))
	}

	return nil
}

func runRulesShow(cmd *cobra.Command, args []string) error {
	ruleID := args[0]
	rules := getBuiltInRules()

	var rule *parser.Rule
	for _, r := range rules {
		if r.ID == ruleID || r.Name == ruleID {
			rule = &r
			break
		}
	}

	if rule == nil {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	// Display rule details
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	severityColor := getSeverityColor(rule.Severity)

	bold.Printf("Rule: %s\n", rule.ID)
	fmt.Printf("Name: %s\n", rule.Name)
	fmt.Printf("Severity: %s\n", severityColor.Sprint(strings.ToUpper(rule.Severity)))
	fmt.Println()

	cyan.Println("Description:")
	fmt.Printf("  %s\n", rule.Description)
	fmt.Println()

	cyan.Println("Message:")
	fmt.Printf("  %s\n", rule.Message)
	fmt.Println()

	cyan.Println("Suggestion:")
	fmt.Printf("  %s\n", rule.Suggestion)

	if len(rule.References) > 0 {
		fmt.Println()
		cyan.Println("References:")
		for _, ref := range rule.References {
			fmt.Printf("  - %s\n", ref)
		}
	}

	return nil
}

func getSeverityColor(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "high":
		return color.New(color.FgRed, color.Bold)
	case "medium":
		return color.New(color.FgYellow, color.Bold)
	case "low":
		return color.New(color.FgCyan)
	default:
		return color.New(color.FgWhite)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
