package golang

import (
	"context"
	"testing"

	"github.com/khanhduong95/pcilint/pkg/parser"
)

func TestParser_Name(t *testing.T) {
	p := NewParser()
	if got := p.Name(); got != "go" {
		t.Errorf("Parser.Name() = %v, want %v", got, "go")
	}
}

func TestParser_Extensions(t *testing.T) {
	p := NewParser()
	exts := p.Extensions()
	if len(exts) != 1 || exts[0] != ".go" {
		t.Errorf("Parser.Extensions() = %v, want [.go]", exts)
	}
}

func TestParser_DetectCardInLogs(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "card variable in log.Printf",
			code: `package main

import "log"

func main() {
	card := "4532015112830366"
	log.Printf("Processing card: %s", card)
}`,
			wantViolations: 1,
		},
		{
			name: "card variable in fmt.Println",
			code: `package main

import "fmt"

func process(cardNumber string) {
	fmt.Println("Card number:", cardNumber)
}`,
			wantViolations: 1,
		},
		{
			name: "card number literal in log",
			code: `package main

import "log"

func main() {
	log.Printf("Test card: 4532015112830366")
}`,
			wantViolations: 1,
		},
		{
			name: "masked card in log (should pass)",
			code: `package main

import "log"

func main() {
	maskedCard := "4532********0366"
	log.Printf("Card: %s", maskedCard)
}`,
			wantViolations: 0,
		},
		{
			name: "no card reference in log (should pass)",
			code: `package main

import "log"

func main() {
	userID := "12345"
	log.Printf("User ID: %s", userID)
}`,
			wantViolations: 0,
		},
		{
			name: "logger.Info with card",
			code: `package main

type Logger struct{}
func (l *Logger) Info(args ...interface{}) {}

func main() {
	logger := &Logger{}
	pan := "4111111111111111"
	logger.Info("PAN:", pan)
}`,
			wantViolations: 1,
		},
	}

	p := NewParser()
	rule := parser.Rule{
		ID:         "pci-001",
		Name:       "no-card-in-logs",
		Severity:   "high",
		Message:    "Card data in logs",
		Suggestion: "Mask card data before logging",
		Enabled:    true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := p.Parse(context.Background(), "test.go", []byte(tt.code), []parser.Rule{rule})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(violations) != tt.wantViolations {
				t.Errorf("Parse() got %d violations, want %d", len(violations), tt.wantViolations)
				for _, v := range violations {
					t.Logf("  Violation: %s at line %d", v.RuleName, v.Line)
				}
			}
		})
	}
}

func TestParser_DetectCVVStorage(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "cvv variable assignment",
			code: `package main

func processPayment() {
	cvv := "123"
	_ = cvv
}`,
			wantViolations: 1,
		},
		{
			name: "CVV struct field",
			code: `package main

type Card struct {
	Number string
	CVV    string
	Expiry string
}`,
			wantViolations: 1,
		},
		{
			name: "securityCode variable",
			code: `package main

func verify(securityCode string) {
	code := securityCode
	_ = code
}`,
			wantViolations: 1,
		},
		{
			name: "cvv in database insert",
			code: `package main

type DB struct{}
func (d *DB) Exec(query string, args ...interface{}) {}

func saveCard(db *DB, number, cvv string) {
	db.Exec("INSERT INTO cards (number, cvv) VALUES (?, ?)", number, cvv)
}`,
			wantViolations: 2, // One for INSERT with cvv, one for cvv parameter
		},
		{
			name: "no cvv storage (should pass)",
			code: `package main

func processPayment(amount float64) {
	tax := amount * 0.1
	_ = tax
}`,
			wantViolations: 0,
		},
	}

	p := NewParser()
	rule := parser.Rule{
		ID:         "pci-002",
		Name:       "no-cvv-storage",
		Severity:   "high",
		Message:    "CVV storage detected",
		Suggestion: "Never store CVV data",
		Enabled:    true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := p.Parse(context.Background(), "test.go", []byte(tt.code), []parser.Rule{rule})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(violations) != tt.wantViolations {
				t.Errorf("Parse() got %d violations, want %d", len(violations), tt.wantViolations)
				for _, v := range violations {
					t.Logf("  Violation: %s at line %d: %s", v.RuleName, v.Line, v.Code)
				}
			}
		})
	}
}

func TestParser_DetectCardInURLs(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "card in URL query parameter",
			code: `package main

import "fmt"

func buildURL(cardNumber string) string {
	return fmt.Sprintf("https://api.example.com/pay?card=%s", cardNumber)
}`,
			wantViolations: 1,
		},
		{
			name: "card in http.NewRequest URL",
			code: `package main

import (
	"net/http"
	"fmt"
)

func makeRequest(pan string) {
	url := fmt.Sprintf("https://api.example.com?pan=%s", pan)
	http.NewRequest("GET", url, nil)
}`,
			wantViolations: 1,
		},
		{
			name: "no card in URL (should pass)",
			code: `package main

import "fmt"

func buildURL(userID string) string {
	return fmt.Sprintf("https://api.example.com/user?id=%s", userID)
}`,
			wantViolations: 0,
		},
	}

	p := NewParser()
	rule := parser.Rule{
		ID:         "pci-003",
		Name:       "no-card-in-urls",
		Severity:   "high",
		Message:    "Card data in URL",
		Suggestion: "Use POST with encrypted body",
		Enabled:    true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := p.Parse(context.Background(), "test.go", []byte(tt.code), []parser.Rule{rule})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(violations) != tt.wantViolations {
				t.Errorf("Parse() got %d violations, want %d", len(violations), tt.wantViolations)
				for _, v := range violations {
					t.Logf("  Violation: %s at line %d", v.RuleName, v.Line)
				}
			}
		})
	}
}

func TestParser_DetectCardInErrors(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "card in errors.New",
			code: `package main

import "errors"

func processCard(cardNumber string) error {
	return errors.New("Failed to process card: " + cardNumber)
}`,
			wantViolations: 1,
		},
		{
			name: "card in fmt.Errorf",
			code: `package main

import "fmt"

func validateCard(pan string) error {
	return fmt.Errorf("invalid card: %s", pan)
}`,
			wantViolations: 1,
		},
		{
			name: "no card in error (should pass)",
			code: `package main

import "errors"

func processPayment() error {
	return errors.New("payment failed")
}`,
			wantViolations: 0,
		},
	}

	p := NewParser()
	rule := parser.Rule{
		ID:         "pci-005",
		Name:       "no-card-in-errors",
		Severity:   "high",
		Message:    "Card data in error",
		Suggestion: "Use generic error messages",
		Enabled:    true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := p.Parse(context.Background(), "test.go", []byte(tt.code), []parser.Rule{rule})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(violations) != tt.wantViolations {
				t.Errorf("Parse() got %d violations, want %d", len(violations), tt.wantViolations)
				for _, v := range violations {
					t.Logf("  Violation: %s at line %d", v.RuleName, v.Line)
				}
			}
		})
	}
}

func TestParser_SupportsRule(t *testing.T) {
	p := NewParser()

	supportedRules := []string{"pci-001", "pci-002", "pci-003", "pci-004", "pci-005"}
	for _, ruleID := range supportedRules {
		rule := parser.Rule{ID: ruleID}
		if !p.SupportsRule(rule) {
			t.Errorf("Parser should support rule %s", ruleID)
		}
	}

	unsupportedRules := []string{"pci-999", "other-rule"}
	for _, ruleID := range unsupportedRules {
		rule := parser.Rule{ID: ruleID}
		if p.SupportsRule(rule) {
			t.Errorf("Parser should not support rule %s", ruleID)
		}
	}
}

func TestParser_MultipleRules(t *testing.T) {
	code := `package main

import (
	"log"
	"fmt"
)

type Payment struct {
	CardNumber string
	CVV        string
}

func processPayment(card, cvv string) error {
	log.Printf("Processing card: %s", card)
	return fmt.Errorf("failed for card: %s", card)
}
`
	p := NewParser()
	rules := []parser.Rule{
		{ID: "pci-001", Name: "no-card-in-logs", Severity: "high", Message: "Card in logs", Suggestion: "Mask it", Enabled: true},
		{ID: "pci-002", Name: "no-cvv-storage", Severity: "high", Message: "CVV storage", Suggestion: "Don't store", Enabled: true},
		{ID: "pci-005", Name: "no-card-in-errors", Severity: "high", Message: "Card in errors", Suggestion: "Generic errors", Enabled: true},
	}

	violations, err := p.Parse(context.Background(), "test.go", []byte(code), rules)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should find violations from multiple rules
	if len(violations) < 3 {
		t.Errorf("Expected at least 3 violations, got %d", len(violations))
		for _, v := range violations {
			t.Logf("  Found: %s at line %d", v.RuleName, v.Line)
		}
	}
}
