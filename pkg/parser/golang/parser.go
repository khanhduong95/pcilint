// Package golang provides a Go language parser for PCI compliance checking.
package golang

import (
	"context"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"regexp"
	"strings"
	"time"

	"github.com/khanhduong95/pcilint/pkg/parser"
	"github.com/khanhduong95/pcilint/pkg/violation"
)

// cardNumberPattern matches potential credit card numbers (13-19 digits).
var cardNumberPattern = regexp.MustCompile(`\b[0-9]{13,19}\b`)

// cardVariableNames contains common variable names that might hold card data.
var cardVariableNames = []string{
	"card", "cardnumber", "cardnum", "card_number", "card_num",
	"pan", "primaryaccountnumber", "primary_account_number",
	"creditcard", "credit_card", "ccnumber", "cc_number", "ccnum", "cc_num",
	"accountnumber", "account_number", "acctnum", "acct_num",
}

// cvvVariableNames contains common variable names for CVV/CVC.
var cvvVariableNames = []string{
	"cvv", "cvc", "cvv2", "cvc2", "securitycode", "security_code",
	"cardverification", "card_verification", "verificationcode",
}

// logFunctions contains common logging function signatures.
var logFunctions = map[string]bool{
	"Printf":    true,
	"Println":   true,
	"Print":     true,
	"Sprintf":   true,
	"Errorf":    true,
	"Fatalf":    true,
	"Panicf":    true,
	"Info":      true,
	"Infof":     true,
	"Debug":     true,
	"Debugf":    true,
	"Warn":      true,
	"Warnf":     true,
	"Warning":   true,
	"Warningf":  true,
	"Error":     true,
	"Errorln":   true,
	"Fatal":     true,
	"Fatalln":   true,
	"Panic":     true,
	"Panicln":   true,
	"Log":       true,
	"Logf":      true,
	"WithField": true,
	"WithFields": true,
}

// logPackages contains common logging package names.
var logPackages = map[string]bool{
	"log":     true,
	"fmt":     true,
	"logger":  true,
	"logging": true,
	"logrus":  true,
	"zap":     true,
	"zerolog": true,
	"glog":    true,
	"klog":    true,
}

// Parser implements the Go language parser.
type Parser struct{}

// NewParser creates a new Go parser.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the language name.
func (p *Parser) Name() string {
	return "go"
}

// Extensions returns file extensions this parser handles.
func (p *Parser) Extensions() []string {
	return []string{".go"}
}

// SupportsRule checks if this parser can check a specific rule.
func (p *Parser) SupportsRule(rule parser.Rule) bool {
	supportedRules := map[string]bool{
		"pci-001": true, // no-card-in-logs
		"pci-002": true, // no-cvv-storage
		"pci-003": true, // no-card-in-urls
		"pci-004": true, // no-plaintext-card-storage
		"pci-005": true, // no-card-in-errors
	}
	return supportedRules[rule.ID]
}

// Parse analyzes a single file and returns violations.
func (p *Parser) Parse(ctx context.Context, filepath string, content []byte, rules []parser.Rule) ([]violation.Violation, error) {
	// Parse Go source into AST
	fset := token.NewFileSet()
	file, err := goparser.ParseFile(fset, filepath, content, goparser.ParseComments)
	if err != nil {
		// Skip files that can't be parsed (might be generated or have syntax errors)
		return nil, nil
	}

	var violations []violation.Violation

	// Check each rule
	for _, rule := range rules {
		if !p.SupportsRule(rule) {
			continue
		}

		select {
		case <-ctx.Done():
			return violations, ctx.Err()
		default:
		}

		ruleViolations := p.checkRule(fset, file, content, rule, filepath)
		violations = append(violations, ruleViolations...)
	}

	return violations, nil
}

// checkRule applies a specific rule to the AST.
func (p *Parser) checkRule(fset *token.FileSet, file *ast.File, content []byte, rule parser.Rule, filepath string) []violation.Violation {
	switch rule.ID {
	case "pci-001":
		return p.checkNoCardInLogs(fset, file, content, rule, filepath)
	case "pci-002":
		return p.checkNoCVVStorage(fset, file, content, rule, filepath)
	case "pci-003":
		return p.checkNoCardInURLs(fset, file, content, rule, filepath)
	case "pci-004":
		return p.checkNoPlaintextCardStorage(fset, file, content, rule, filepath)
	case "pci-005":
		return p.checkNoCardInErrors(fset, file, content, rule, filepath)
	default:
		return nil
	}
}

// checkNoCardInLogs detects card numbers in logging statements (pci-001).
func (p *Parser) checkNoCardInLogs(fset *token.FileSet, file *ast.File, content []byte, rule parser.Rule, filepath string) []violation.Violation {
	var violations []violation.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if !p.isLogFunction(call) {
			return true
		}

		// Check arguments for card patterns
		for _, arg := range call.Args {
			if p.containsCardReference(arg) {
				pos := fset.Position(call.Pos())
				violations = append(violations, violation.Violation{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   rule.Severity,
					Message:    rule.Message,
					File:       filepath,
					Line:       pos.Line,
					Column:     pos.Column,
					Code:       p.getCodeSnippet(content, pos.Line),
					Suggestion: rule.Suggestion,
					Timestamp:  time.Now(),
				})
				break // One violation per log statement
			}
		}

		return true
	})

	return violations
}

// checkNoCVVStorage detects CVV storage in variables or databases (pci-002).
func (p *Parser) checkNoCVVStorage(fset *token.FileSet, file *ast.File, content []byte, rule parser.Rule, filepath string) []violation.Violation {
	var violations []violation.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Check for CVV variable assignments
			for _, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					if p.isCVVVariableName(ident.Name) {
						pos := fset.Position(node.Pos())
						violations = append(violations, violation.Violation{
							RuleID:     rule.ID,
							RuleName:   rule.Name,
							Severity:   rule.Severity,
							Message:    rule.Message,
							File:       filepath,
							Line:       pos.Line,
							Column:     pos.Column,
							Code:       p.getCodeSnippet(content, pos.Line),
							Suggestion: rule.Suggestion,
							Timestamp:  time.Now(),
						})
					}
				}
			}

		case *ast.Field:
			// Check for CVV fields in structs
			for _, name := range node.Names {
				if p.isCVVVariableName(name.Name) {
					pos := fset.Position(node.Pos())
					violations = append(violations, violation.Violation{
						RuleID:     rule.ID,
						RuleName:   rule.Name,
						Severity:   rule.Severity,
						Message:    rule.Message,
						File:       filepath,
						Line:       pos.Line,
						Column:     pos.Column,
						Code:       p.getCodeSnippet(content, pos.Line),
						Suggestion: rule.Suggestion,
						Timestamp:  time.Now(),
					})
				}
			}

		case *ast.CallExpr:
			// Check for CVV in database operations
			if p.isDatabaseCall(node) && p.containsCVVReference(node) {
				pos := fset.Position(node.Pos())
				violations = append(violations, violation.Violation{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   rule.Severity,
					Message:    rule.Message,
					File:       filepath,
					Line:       pos.Line,
					Column:     pos.Column,
					Code:       p.getCodeSnippet(content, pos.Line),
					Suggestion: rule.Suggestion,
					Timestamp:  time.Now(),
				})
			}
		}

		return true
	})

	return violations
}

// checkNoCardInURLs detects card data in URL parameters (pci-003).
func (p *Parser) checkNoCardInURLs(fset *token.FileSet, file *ast.File, content []byte, rule parser.Rule, filepath string) []violation.Violation {
	var violations []violation.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for URL building functions
		if p.isURLBuildingFunction(call) && p.containsCardReference(call) {
			pos := fset.Position(call.Pos())
			violations = append(violations, violation.Violation{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				Message:    rule.Message,
				File:       filepath,
				Line:       pos.Line,
				Column:     pos.Column,
				Code:       p.getCodeSnippet(content, pos.Line),
				Suggestion: rule.Suggestion,
				Timestamp:  time.Now(),
			})
		}

		// Check for string concatenation with URLs
		if p.isStringConcatWithURL(call) && p.containsCardReference(call) {
			pos := fset.Position(call.Pos())
			violations = append(violations, violation.Violation{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				Message:    rule.Message,
				File:       filepath,
				Line:       pos.Line,
				Column:     pos.Column,
				Code:       p.getCodeSnippet(content, pos.Line),
				Suggestion: rule.Suggestion,
				Timestamp:  time.Now(),
			})
		}

		return true
	})

	return violations
}

// checkNoPlaintextCardStorage detects unencrypted card storage (pci-004).
func (p *Parser) checkNoPlaintextCardStorage(fset *token.FileSet, file *ast.File, content []byte, rule parser.Rule, filepath string) []violation.Violation {
	var violations []violation.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for file write operations with card data
		if p.isFileWriteFunction(call) && p.containsCardReference(call) {
			pos := fset.Position(call.Pos())
			violations = append(violations, violation.Violation{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				Message:    rule.Message,
				File:       filepath,
				Line:       pos.Line,
				Column:     pos.Column,
				Code:       p.getCodeSnippet(content, pos.Line),
				Suggestion: rule.Suggestion,
				Timestamp:  time.Now(),
			})
		}

		// Check for database inserts with card data (without encryption)
		if p.isDatabaseInsert(call) && p.containsCardReference(call) && !p.hasEncryptionCall(call) {
			pos := fset.Position(call.Pos())
			violations = append(violations, violation.Violation{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				Message:    rule.Message,
				File:       filepath,
				Line:       pos.Line,
				Column:     pos.Column,
				Code:       p.getCodeSnippet(content, pos.Line),
				Suggestion: rule.Suggestion,
				Timestamp:  time.Now(),
			})
		}

		return true
	})

	return violations
}

// checkNoCardInErrors detects card numbers in error messages (pci-005).
func (p *Parser) checkNoCardInErrors(fset *token.FileSet, file *ast.File, content []byte, rule parser.Rule, filepath string) []violation.Violation {
	var violations []violation.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for error creation functions
		if p.isErrorFunction(call) && p.containsCardReference(call) {
			pos := fset.Position(call.Pos())
			violations = append(violations, violation.Violation{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				Message:    rule.Message,
				File:       filepath,
				Line:       pos.Line,
				Column:     pos.Column,
				Code:       p.getCodeSnippet(content, pos.Line),
				Suggestion: rule.Suggestion,
				Timestamp:  time.Now(),
			})
		}

		return true
	})

	return violations
}

// isLogFunction checks if a call expression is a logging function.
func (p *Parser) isLogFunction(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		// Check for package.Function (e.g., log.Printf)
		if ident, ok := fun.X.(*ast.Ident); ok {
			pkgName := strings.ToLower(ident.Name)
			if logPackages[pkgName] && logFunctions[fun.Sel.Name] {
				return true
			}
		}
		// Check for method calls (e.g., logger.Info)
		if logFunctions[fun.Sel.Name] {
			return true
		}
	case *ast.Ident:
		// Direct function call
		if logFunctions[fun.Name] {
			return true
		}
	}
	return false
}

// isErrorFunction checks if a call expression creates an error.
func (p *Parser) isErrorFunction(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		funcName := fun.Sel.Name
		// Check for errors.New, fmt.Errorf, etc.
		if funcName == "New" || funcName == "Errorf" || funcName == "Wrapf" || funcName == "Wrap" {
			if ident, ok := fun.X.(*ast.Ident); ok {
				pkgName := ident.Name
				if pkgName == "errors" || pkgName == "fmt" || pkgName == "xerrors" || pkgName == "pkg" {
					return true
				}
			}
		}
	}
	return false
}

// isURLBuildingFunction checks if a call builds URLs.
func (p *Parser) isURLBuildingFunction(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		funcName := fun.Sel.Name
		// Check for url.Values, http.NewRequest, etc.
		if funcName == "Add" || funcName == "Set" || funcName == "Encode" || funcName == "NewRequest" {
			return true
		}
	}
	return false
}

// isStringConcatWithURL checks for URL string concatenation.
func (p *Parser) isStringConcatWithURL(call *ast.CallExpr) bool {
	// Check for fmt.Sprintf with URL patterns
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Printf" {
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					val := strings.ToLower(lit.Value)
					if strings.Contains(val, "http") || strings.Contains(val, "url") ||
						strings.Contains(val, "?") || strings.Contains(val, "&") {
						return true
					}
				}
			}
		}
	}
	return false
}

// isFileWriteFunction checks if a call writes to files.
func (p *Parser) isFileWriteFunction(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		funcName := fun.Sel.Name
		if funcName == "Write" || funcName == "WriteString" || funcName == "WriteFile" ||
			funcName == "Fprintf" || funcName == "Fprintln" {
			return true
		}
	}
	return false
}

// isDatabaseCall checks if a call is a database operation.
func (p *Parser) isDatabaseCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		funcName := fun.Sel.Name
		dbFuncs := map[string]bool{
			"Exec": true, "Query": true, "QueryRow": true,
			"Insert": true, "Create": true, "Save": true, "Update": true,
			"Prepare": true, "ExecContext": true, "QueryContext": true,
		}
		return dbFuncs[funcName]
	}
	return false
}

// isDatabaseInsert checks for database insert operations.
func (p *Parser) isDatabaseInsert(call *ast.CallExpr) bool {
	if !p.isDatabaseCall(call) {
		return false
	}

	// Check if the SQL contains INSERT
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			val := strings.ToUpper(lit.Value)
			if strings.Contains(val, "INSERT") {
				return true
			}
		}
	}
	return false
}

// containsCardReference checks if an expression references card data.
func (p *Parser) containsCardReference(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}

		switch x := n.(type) {
		case *ast.Ident:
			if p.isCardVariableName(x.Name) {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if p.isCardVariableName(x.Sel.Name) {
				found = true
				return false
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				// Check for card number patterns in string literals
				if cardNumberPattern.MatchString(x.Value) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// containsCVVReference checks if an expression references CVV data.
func (p *Parser) containsCVVReference(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}

		switch x := n.(type) {
		case *ast.Ident:
			if p.isCVVVariableName(x.Name) {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if p.isCVVVariableName(x.Sel.Name) {
				found = true
				return false
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				val := strings.ToLower(x.Value)
				if strings.Contains(val, "cvv") || strings.Contains(val, "cvc") {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// hasEncryptionCall checks if an expression involves encryption.
func (p *Parser) hasEncryptionCall(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}

		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				funcName := strings.ToLower(sel.Sel.Name)
				if strings.Contains(funcName, "encrypt") || strings.Contains(funcName, "hash") ||
					strings.Contains(funcName, "cipher") || strings.Contains(funcName, "mask") {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// safeCardPrefixes are prefixes that indicate the card data is already masked/sanitized.
var safeCardPrefixes = []string{
	"masked", "redacted", "sanitized", "safe", "truncated", "hidden", "obfuscated",
}

// isCardVariableName checks if a name indicates card data.
// Returns false if the name suggests the data is already masked/sanitized.
func (p *Parser) isCardVariableName(name string) bool {
	lower := strings.ToLower(name)

	// Check if name indicates masked/sanitized data
	for _, prefix := range safeCardPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
		// Also check for underscore-separated prefixes (e.g., masked_card)
		if strings.Contains(lower, prefix+"_") || strings.Contains(lower, "_"+prefix) {
			return false
		}
	}

	for _, cardName := range cardVariableNames {
		if strings.Contains(lower, cardName) {
			return true
		}
	}
	return false
}

// isCVVVariableName checks if a name indicates CVV data.
func (p *Parser) isCVVVariableName(name string) bool {
	lower := strings.ToLower(name)
	for _, cvvName := range cvvVariableNames {
		if strings.Contains(lower, cvvName) {
			return true
		}
	}
	return false
}

// getCodeSnippet extracts a code snippet from the content.
func (p *Parser) getCodeSnippet(content []byte, line int) string {
	lines := strings.Split(string(content), "\n")
	if line <= 0 || line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[line-1])
}
