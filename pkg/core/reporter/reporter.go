// Package reporter provides output formatting for scan results.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"

	"github.com/khanhduong95/pcilint/pkg/violation"
)

// Reporter formats and outputs scan results.
type Reporter interface {
	Report(report *violation.Report) error
}

// Format represents the output format.
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// NewReporter creates a reporter for the given format.
func NewReporter(format Format, w io.Writer, quiet bool) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{w: w}
	case FormatSARIF:
		return &SARIFReporter{w: w}
	default:
		return &TextReporter{w: w, quiet: quiet, useColor: isTerminal(w)}
	}
}

// isTerminal checks if the writer is a terminal.
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}
	return false
}

// TextReporter outputs results in human-readable text format.
type TextReporter struct {
	w        io.Writer
	quiet    bool
	useColor bool
}

// Report outputs the scan results.
func (r *TextReporter) Report(report *violation.Report) error {
	// Configure colors
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	white := color.New(color.FgWhite)
	gray := color.New(color.FgHiBlack)

	if !r.useColor {
		red.DisableColor()
		yellow.DisableColor()
		cyan.DisableColor()
		green.DisableColor()
		white.DisableColor()
		gray.DisableColor()
	}

	// Output violations
	for _, v := range report.Violations {
		// File location
		relPath, _ := filepath.Rel(".", v.File)
		if relPath == "" {
			relPath = v.File
		}

		// Severity color
		var severityStr string
		switch v.Severity {
		case "high":
			severityStr = red.Sprintf("[HIGH]")
		case "medium":
			severityStr = yellow.Sprintf("[MEDIUM]")
		case "low":
			severityStr = cyan.Sprintf("[LOW]")
		default:
			severityStr = fmt.Sprintf("[%s]", strings.ToUpper(v.Severity))
		}

		fmt.Fprintf(r.w, "\n%s:%d:%d: %s %s\n",
			white.Sprint(relPath), v.Line, v.Column, severityStr, v.RuleName)

		// Message
		fmt.Fprintf(r.w, "  %s\n", v.Message)

		// Code snippet
		if v.Code != "" {
			fmt.Fprintf(r.w, "\n")
			gray.Fprintf(r.w, "  %4d | ", v.Line)
			fmt.Fprintf(r.w, "%s\n", v.Code)
		}

		// Suggestion
		if v.Suggestion != "" {
			fmt.Fprintf(r.w, "\n")
			green.Fprintf(r.w, "  Suggestion: ")
			fmt.Fprintf(r.w, "%s\n", v.Suggestion)
		}
	}

	// Summary
	if !r.quiet {
		fmt.Fprintf(r.w, "\n%s\n", strings.Repeat("─", 50))
		fmt.Fprintf(r.w, "Summary:\n")
		fmt.Fprintf(r.w, "  Files scanned:     %d\n", report.Summary.FilesScanned)
		fmt.Fprintf(r.w, "  Files with issues: %d\n", report.Summary.FilesWithIssues)
		fmt.Fprintf(r.w, "  Total violations:  %d\n", report.Summary.TotalViolations)
		fmt.Fprintf(r.w, "\n")

		if report.Summary.HighSeverity > 0 {
			red.Fprintf(r.w, "  High:   %d\n", report.Summary.HighSeverity)
		} else {
			fmt.Fprintf(r.w, "  High:   %d\n", report.Summary.HighSeverity)
		}
		if report.Summary.MediumSeverity > 0 {
			yellow.Fprintf(r.w, "  Medium: %d\n", report.Summary.MediumSeverity)
		} else {
			fmt.Fprintf(r.w, "  Medium: %d\n", report.Summary.MediumSeverity)
		}
		fmt.Fprintf(r.w, "  Low:    %d\n", report.Summary.LowSeverity)

		fmt.Fprintf(r.w, "\nScan completed in %s\n", report.Duration)
	}

	return nil
}

// JSONReporter outputs results in JSON format.
type JSONReporter struct {
	w io.Writer
}

// Report outputs the scan results as JSON.
func (r *JSONReporter) Report(report *violation.Report) error {
	encoder := json.NewEncoder(r.w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// SARIFReporter outputs results in SARIF format for GitHub integration.
type SARIFReporter struct {
	w io.Writer
}

// SARIFReport represents a SARIF 2.1.0 report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run in a SARIF report.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents a rule definition.
type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFMessage      `json:"shortDescription"`
	FullDescription  SARIFMessage      `json:"fullDescription,omitempty"`
	DefaultConfig    SARIFRuleConfig   `json:"defaultConfiguration,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
}

// SARIFRuleConfig represents rule configuration.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult represents a single result.
type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations"`
}

// SARIFMessage represents a message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a physical location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation represents an artifact location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a region in a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// Report outputs the scan results in SARIF format.
func (r *SARIFReporter) Report(report *violation.Report) error {
	sarif := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "pcilint",
						Version:        "0.1.0",
						InformationURI: "https://github.com/khanhduong95/pcilint",
					},
				},
				Results: make([]SARIFResult, 0, len(report.Violations)),
			},
		},
	}

	// Convert violations to SARIF results
	for _, v := range report.Violations {
		level := "error"
		switch v.Severity {
		case "medium":
			level = "warning"
		case "low":
			level = "note"
		}

		relPath, _ := filepath.Rel(".", v.File)
		if relPath == "" {
			relPath = v.File
		}

		result := SARIFResult{
			RuleID: v.RuleID,
			Level:  level,
			Message: SARIFMessage{
				Text: v.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: relPath,
						},
						Region: SARIFRegion{
							StartLine:   v.Line,
							StartColumn: v.Column,
						},
					},
				},
			},
		}

		sarif.Runs[0].Results = append(sarif.Runs[0].Results, result)
	}

	encoder := json.NewEncoder(r.w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}
