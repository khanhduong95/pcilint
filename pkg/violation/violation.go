// Package violation provides data structures for representing PCI compliance violations.
package violation

import "time"

// Violation represents a single PCI compliance violation found in code.
type Violation struct {
	RuleID     string    `json:"rule_id"`     // e.g., "pci-001"
	RuleName   string    `json:"rule_name"`   // e.g., "no-card-in-logs"
	Severity   string    `json:"severity"`    // "high", "medium", "low"
	Message    string    `json:"message"`     // Human-readable message
	File       string    `json:"file"`        // Absolute file path
	Line       int       `json:"line"`        // Line number (1-indexed)
	Column     int       `json:"column"`      // Column number (1-indexed)
	Code       string    `json:"code"`        // The offending code snippet
	Suggestion string    `json:"suggestion"`  // How to fix
	Timestamp  time.Time `json:"timestamp"`   // When the violation was detected
}

// Report contains all violations from a scan.
type Report struct {
	Summary    Summary     `json:"summary"`
	Violations []Violation `json:"violations"`
	Duration   string      `json:"duration"`
}

// Summary provides aggregate statistics about the scan.
type Summary struct {
	TotalFiles      int `json:"total_files"`
	FilesScanned    int `json:"files_scanned"`
	FilesWithIssues int `json:"files_with_issues"`
	TotalViolations int `json:"total_violations"`
	HighSeverity    int `json:"high_severity"`
	MediumSeverity  int `json:"medium_severity"`
	LowSeverity     int `json:"low_severity"`
}

// SeverityHigh is the severity level for critical PCI violations.
const SeverityHigh = "high"

// SeverityMedium is the severity level for moderate PCI violations.
const SeverityMedium = "medium"

// SeverityLow is the severity level for minor PCI violations.
const SeverityLow = "low"

// NewReport creates a new empty Report.
func NewReport() *Report {
	return &Report{
		Violations: []Violation{},
	}
}

// AddViolation adds a violation to the report and updates the summary.
func (r *Report) AddViolation(v Violation) {
	r.Violations = append(r.Violations, v)
	r.Summary.TotalViolations++

	switch v.Severity {
	case SeverityHigh:
		r.Summary.HighSeverity++
	case SeverityMedium:
		r.Summary.MediumSeverity++
	case SeverityLow:
		r.Summary.LowSeverity++
	}
}

// HasViolations returns true if the report contains any violations.
func (r *Report) HasViolations() bool {
	return len(r.Violations) > 0
}

// HasHighSeverity returns true if the report contains high severity violations.
func (r *Report) HasHighSeverity() bool {
	return r.Summary.HighSeverity > 0
}

// FilterBySeverity returns violations at or above the given severity level.
func (r *Report) FilterBySeverity(minSeverity string) []Violation {
	var filtered []Violation
	minLevel := severityLevel(minSeverity)

	for _, v := range r.Violations {
		if severityLevel(v.Severity) >= minLevel {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// severityLevel returns a numeric level for severity comparison.
func severityLevel(severity string) int {
	switch severity {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
