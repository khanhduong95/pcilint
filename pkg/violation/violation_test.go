package violation

import (
	"testing"
	"time"
)

func TestNewReport(t *testing.T) {
	report := NewReport()

	if report == nil {
		t.Fatal("NewReport() returned nil")
	}

	if report.Violations == nil {
		t.Error("NewReport() should initialize Violations slice")
	}

	if len(report.Violations) != 0 {
		t.Error("NewReport() should have empty Violations slice")
	}
}

func TestReport_AddViolation(t *testing.T) {
	report := NewReport()

	v := Violation{
		RuleID:    "pci-001",
		RuleName:  "no-card-in-logs",
		Severity:  SeverityHigh,
		Message:   "Test message",
		File:      "test.go",
		Line:      10,
		Column:    5,
		Timestamp: time.Now(),
	}

	report.AddViolation(v)

	if len(report.Violations) != 1 {
		t.Errorf("AddViolation() should add violation, got %d violations", len(report.Violations))
	}

	if report.Summary.TotalViolations != 1 {
		t.Errorf("AddViolation() should update TotalViolations, got %d", report.Summary.TotalViolations)
	}

	if report.Summary.HighSeverity != 1 {
		t.Errorf("AddViolation() should update HighSeverity count, got %d", report.Summary.HighSeverity)
	}
}

func TestReport_AddViolation_SeverityCounts(t *testing.T) {
	report := NewReport()

	// Add high severity
	report.AddViolation(Violation{Severity: SeverityHigh})
	report.AddViolation(Violation{Severity: SeverityHigh})

	// Add medium severity
	report.AddViolation(Violation{Severity: SeverityMedium})

	// Add low severity
	report.AddViolation(Violation{Severity: SeverityLow})
	report.AddViolation(Violation{Severity: SeverityLow})
	report.AddViolation(Violation{Severity: SeverityLow})

	if report.Summary.HighSeverity != 2 {
		t.Errorf("Expected 2 high severity, got %d", report.Summary.HighSeverity)
	}
	if report.Summary.MediumSeverity != 1 {
		t.Errorf("Expected 1 medium severity, got %d", report.Summary.MediumSeverity)
	}
	if report.Summary.LowSeverity != 3 {
		t.Errorf("Expected 3 low severity, got %d", report.Summary.LowSeverity)
	}
	if report.Summary.TotalViolations != 6 {
		t.Errorf("Expected 6 total violations, got %d", report.Summary.TotalViolations)
	}
}

func TestReport_HasViolations(t *testing.T) {
	report := NewReport()

	if report.HasViolations() {
		t.Error("Empty report should not have violations")
	}

	report.AddViolation(Violation{Severity: SeverityLow})

	if !report.HasViolations() {
		t.Error("Report with violations should return true for HasViolations")
	}
}

func TestReport_HasHighSeverity(t *testing.T) {
	report := NewReport()

	if report.HasHighSeverity() {
		t.Error("Empty report should not have high severity")
	}

	report.AddViolation(Violation{Severity: SeverityLow})
	report.AddViolation(Violation{Severity: SeverityMedium})

	if report.HasHighSeverity() {
		t.Error("Report without high severity should return false")
	}

	report.AddViolation(Violation{Severity: SeverityHigh})

	if !report.HasHighSeverity() {
		t.Error("Report with high severity should return true")
	}
}

func TestReport_FilterBySeverity(t *testing.T) {
	report := NewReport()

	report.AddViolation(Violation{RuleID: "1", Severity: SeverityHigh})
	report.AddViolation(Violation{RuleID: "2", Severity: SeverityMedium})
	report.AddViolation(Violation{RuleID: "3", Severity: SeverityLow})
	report.AddViolation(Violation{RuleID: "4", Severity: SeverityHigh})

	// Filter for high only
	high := report.FilterBySeverity(SeverityHigh)
	if len(high) != 2 {
		t.Errorf("FilterBySeverity(high) should return 2 violations, got %d", len(high))
	}

	// Filter for medium and above
	medium := report.FilterBySeverity(SeverityMedium)
	if len(medium) != 3 {
		t.Errorf("FilterBySeverity(medium) should return 3 violations, got %d", len(medium))
	}

	// Filter for low and above (all)
	low := report.FilterBySeverity(SeverityLow)
	if len(low) != 4 {
		t.Errorf("FilterBySeverity(low) should return 4 violations, got %d", len(low))
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityHigh != "high" {
		t.Errorf("SeverityHigh should be 'high', got %s", SeverityHigh)
	}
	if SeverityMedium != "medium" {
		t.Errorf("SeverityMedium should be 'medium', got %s", SeverityMedium)
	}
	if SeverityLow != "low" {
		t.Errorf("SeverityLow should be 'low', got %s", SeverityLow)
	}
}
