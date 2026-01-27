// Package examples contains example code demonstrating PCI-DSS compliant practices.
// This file shows how to properly handle payment card data.
package examples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
)

// MaskedCard represents a card with masked PAN - GOOD: no CVV stored
type MaskedCard struct {
	MaskedPAN   string `json:"masked_pan"` // e.g., "4111********1111"
	Token       string `json:"token"`      // Tokenized card reference
	ExpiryMonth int    `json:"expiry_month"`
	ExpiryYear  int    `json:"expiry_year"`
}

// maskPAN masks a card number for safe display/logging
func maskPAN(pan string) string {
	if len(pan) < 10 {
		return "****"
	}
	// Show first 4 and last 4 digits
	return pan[:4] + strings.Repeat("*", len(pan)-8) + pan[len(pan)-4:]
}

// ProcessPaymentSecurely processes a payment securely
func ProcessPaymentSecurely(token string) error {
	// GOOD: Log only the token, not the actual card number
	log.Printf("Processing payment with token: %s", token)

	// CVV is never stored, only passed directly to payment processor
	// and not logged or saved anywhere

	return nil
}

// BuildSecurePaymentRequest builds a payment request without card data in URL
func BuildSecurePaymentRequest(token string, amount int) string {
	// GOOD: Use token in URL, not actual card data
	// Actual card data is sent in encrypted request body
	return fmt.Sprintf("https://payment.example.com/process?token=%s&amount=%d", token, amount)
}

// EncryptCardData encrypts card data before storage
func EncryptCardData(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// LogPaymentResult logs payment result without sensitive data
func LogPaymentResult(token string, success bool, maskedPAN string) {
	// GOOD: Log only masked PAN and token
	if success {
		log.Printf("Payment successful for card %s (token: %s)", maskedPAN, token)
	} else {
		log.Printf("Payment failed for card %s (token: %s)", maskedPAN, token)
	}
}

// ValidateCardSecurely validates a card without exposing data in errors
func ValidateCardSecurely(token string) error {
	// GOOD: Generic error message without card data
	if token == "" {
		return errors.New("card validation failed: invalid token")
	}
	return nil
}

// CreateMaskedCard creates a masked card representation
func CreateMaskedCard(pan string, expiryMonth, expiryYear int, token string) *MaskedCard {
	return &MaskedCard{
		MaskedPAN:   maskPAN(pan),
		Token:       token,
		ExpiryMonth: expiryMonth,
		ExpiryYear:  expiryYear,
	}
}
