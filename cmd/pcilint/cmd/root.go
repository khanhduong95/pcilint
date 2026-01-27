// Package cmd provides the CLI commands for pcilint.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version is set at build time.
	Version = "0.1.0"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "pcilint",
	Short: "A static analysis tool for PCI-DSS compliance",
	Long: `pcilint is a static analysis tool that scans your code for
PCI-DSS compliance violations.

It detects issues such as:
  - Credit card numbers in log statements
  - CVV/CVC storage
  - Card data in URLs
  - Plaintext card storage
  - Card numbers in error messages

Usage:
  pcilint scan [paths...]    Scan files for PCI violations
  pcilint rules list         List available rules
  pcilint rules show <id>    Show rule details
  pcilint version            Show version information`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add version flag to root
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("pcilint version {{.Version}}\n")

	// Set help template
	rootCmd.SetHelpTemplate(`{{.Long}}

{{if .HasAvailableSubCommands}}Commands:{{range .Commands}}{{if .IsAvailableCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}

{{if .HasAvailableLocalFlags}}Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}

Use "{{.CommandPath}} [command] --help" for more information about a command.
`)
}

// exitWithError prints an error and exits with code 1.
func exitWithError(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+msg+"\n", args...)
	os.Exit(1)
}
