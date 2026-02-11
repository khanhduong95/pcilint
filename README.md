# pcilint

A static analysis tool for detecting PCI-DSS compliance violations in code.

[![Go Report Card](https://goreportcard.com/badge/github.com/khanhduong95/pcilint)](https://goreportcard.com/report/github.com/khanhduong95/pcilint)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

`pcilint` scans your source code for potential PCI-DSS (Payment Card Industry Data Security Standard) compliance violations. It detects common security issues related to handling payment card data, helping you maintain compliance and protect sensitive cardholder information.

## Features

- Detects credit card numbers in log statements
- Identifies CVV/CVC storage violations
- Finds card data in URL parameters
- Catches plaintext card storage
- Locates card numbers in error messages
- Multiple output formats (text, JSON, SARIF)
- CI/CD friendly with configurable exit codes
- Fast concurrent scanning

## Installation

```bash
# From source
go install github.com/khanhduong95/pcilint/cmd/pcilint@latest

# Or clone and build
git clone https://github.com/khanhduong95/pcilint.git
cd pcilint
go build -o pcilint ./cmd/pcilint
```

## Quick Start

```bash
# Scan current directory
pcilint scan .

# Scan specific paths
pcilint scan ./src ./pkg

# Output as JSON
pcilint scan . --format json

# Exit with code 1 if violations found (for CI/CD)
pcilint scan . --fail-on-any
```

## Rules

pcilint includes the following PCI-DSS compliance rules:

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| pci-001 | no-card-in-logs | HIGH | Detects credit card numbers in logging statements |
| pci-002 | no-cvv-storage | HIGH | Detects CVV/CVC codes stored in variables or databases |
| pci-003 | no-card-in-urls | HIGH | Detects card data in URL parameters |
| pci-004 | no-plaintext-card-storage | HIGH | Detects unencrypted card data storage |
| pci-005 | no-card-in-errors | HIGH | Detects card numbers in error messages |

### List available rules

```bash
pcilint rules list
```

### Show rule details

```bash
pcilint rules show pci-001
```

## Usage

### Basic Scan

```bash
pcilint scan [paths...]
```

### Options

```
Flags:
  -e, --exclude strings    Patterns to exclude (gitignore-style)
  -f, --format string      Output format (text, json, sarif) (default "text")
  -l, --lang string        Target language (auto-detect if not specified)
  -s, --severity string    Minimum severity to report (high, medium, low)
  -j, --concurrency int    Number of concurrent workers
  -c, --config string      Config file path
      --rules string       Custom rules directory
      --fail-on-any        Exit with code 1 if any violations found
  -q, --quiet              Suppress non-error output
  -h, --help               help for scan
```

### Examples

```bash
# Exclude test files and vendor
pcilint scan . --exclude "**/*_test.go" --exclude "vendor/**"

# Only report high severity issues
pcilint scan . --severity high

# Output SARIF format for GitHub integration
pcilint scan . --format sarif > results.sarif

# Use a config file
pcilint scan --config .pcilint.yaml
```

## Configuration File

Create a `.pcilint.yaml` file in your project root:

```yaml
# Paths to scan
paths:
  - ./src
  - ./pkg

# Patterns to exclude
exclude:
  - "vendor/**"
  - "**/*_test.go"
  - "**/*.generated.go"

# Minimum severity to report
severity: medium

# Output format
format: text

# Rules configuration
rules:
  # Disable specific rules
  disabled:
    - pci-010

  # Severity overrides
  overrides:
    pci-003:
      severity: medium
```

## Output Formats

### Text (default)

```
src/payment/processor.go:45:12: [HIGH] no-card-in-logs
  Potential credit card number detected in log statement.

    45 | log.Printf("Processing card: %s", card)

  Suggestion: Use a masking function to redact card numbers before logging.

──────────────────────────────────────────────────
Summary:
  Files scanned:     47
  Files with issues: 1
  Total violations:  1

  High:   1
  Medium: 0
  Low:    0

Scan completed in 0.34s
```

### JSON

```bash
pcilint scan . --format json
```

### SARIF (for GitHub Code Scanning)

```bash
pcilint scan . --format sarif > results.sarif
```

## CI/CD Integration

### GitHub Actions

```yaml
name: PCI Lint
on: [push, pull_request]

jobs:
  pcilint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install pcilint
        run: go install github.com/khanhduong95/pcilint/cmd/pcilint@latest

      - name: Run pcilint
        run: pcilint scan . --fail-on-any
```

### GitHub Code Scanning (SARIF)

```yaml
name: PCI Security Scan
on: [push, pull_request]

jobs:
  pcilint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install pcilint
        run: go install github.com/khanhduong95/pcilint/cmd/pcilint@latest

      - name: Run pcilint
        run: pcilint scan . --format sarif > results.sarif
        continue-on-error: true

      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Supported Languages

- Go (`.go` files)

More languages coming soon!

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success (no violations, or violations found but `--fail-on-any` not set) |
| 1 | Violations found (when `--fail-on-any` is set) |
| 2 | Error during execution |

## Best Practices

### Masking Card Numbers

```go
// BAD: Logging raw card number
log.Printf("Processing card: %s", cardNumber)

// GOOD: Mask before logging
func maskPAN(pan string) string {
    if len(pan) < 10 {
        return "****"
    }
    return pan[:4] + strings.Repeat("*", len(pan)-8) + pan[len(pan)-4:]
}

log.Printf("Processing card: %s", maskPAN(cardNumber))
```

### Never Store CVV

```go
// BAD: Storing CVV
type Card struct {
    Number string
    CVV    string  // NEVER do this
    Expiry string
}

// GOOD: CVV only used transiently for authorization
func ProcessPayment(cardNumber, cvv string) error {
    // Pass CVV directly to payment processor
    // Never store it
    result := paymentGateway.Authorize(cardNumber, cvv, amount)
    return result
}
```

### Use Tokenization

```go
// GOOD: Store tokens instead of card numbers
type Payment struct {
    Token       string  // Tokenized card reference
    MaskedPAN   string  // "4111********1111" for display
    ExpiryMonth int
    ExpiryYear  int
}
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## References

- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [PCI DSS Quick Reference Guide](https://www.pcisecuritystandards.org/document_library)
