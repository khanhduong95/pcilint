// Package examples contains example code with PCI-DSS violations for testing.
// This file is intentionally full of bad practices for demonstration purposes.
// DO NOT use this code in production!
package examples

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
)

// Card represents a payment card - BAD: storing CVV in struct
type Card struct {
	Number      string `json:"number"`
	CVV         string `json:"cvv"`          // PCI-002: CVV storage
	ExpiryMonth int    `json:"expiry_month"`
	ExpiryYear  int    `json:"expiry_year"`
}

// ProcessPayment processes a payment - MULTIPLE VIOLATIONS
func ProcessPayment(cardNumber, cvv string) error {
	// PCI-001: Card number in logs
	log.Printf("Processing payment for card: %s", cardNumber)

	// PCI-002: CVV stored in variable
	securityCode := cvv
	_ = securityCode

	// PCI-005: Card number in error message
	if len(cardNumber) < 13 {
		return errors.New("invalid card number: " + cardNumber)
	}

	return nil
}

// BuildPaymentURL builds a payment URL - BAD: card in URL
func BuildPaymentURL(pan string) string {
	// PCI-003: Card data in URL parameters
	return fmt.Sprintf("https://payment.example.com/process?card=%s&amount=100", pan)
}

// SaveCardToFile saves card data to a file - BAD: plaintext storage
func SaveCardToFile(card Card) error {
	// PCI-004: Plaintext card storage
	data, _ := json.Marshal(card)
	return os.WriteFile("cards.json", data, 0644)
}

// LogCardDetails logs card details - BAD: multiple violations
func LogCardDetails(card Card) {
	// PCI-001: Card number in logs
	fmt.Printf("Card number: %s\n", card.Number)

	// PCI-001: CVV in logs
	log.Println("CVV:", card.CVV)
}

// ValidateCard validates a card - BAD: card in error
func ValidateCard(cardNumber string) error {
	// PCI-005: Card number in error
	return fmt.Errorf("card validation failed for: %s", cardNumber)
}

// GetPaymentURL returns a URL with card data - BAD
func GetPaymentURL(accountNumber string) string {
	// PCI-003: Account number in URL
	url := "https://api.example.com/charge?accountnumber=" + accountNumber
	return url
}
