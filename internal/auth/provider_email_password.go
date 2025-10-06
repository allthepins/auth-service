package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// EmailPasswordProvider implements authentication using email and password.
// It stores passwords using bcrypt hashing.
type EmailPasswordProvider struct {
	minPasswordLength int
	bcryptCost        int
}

// emailPasswordCredentials represents the stored credential format.
type emailPasswordCredentials struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

// NewEmailPasswordProvider creates a new email/password authentication provider.
func NewEmailPasswordProvider() *EmailPasswordProvider {
	return &EmailPasswordProvider{
		minPasswordLength: 8,
		bcryptCost:        12, // TODO Look into what a resonable cost in terms of security/perf is
	}
}

// Name returns the provider name.
func (p *EmailPasswordProvider) Name() string {
	return "email_password"
}

// ValidateCredentials validates email and password requirements.
func (p *EmailPasswordProvider) ValidateCredentials(credentials map[string]any) error {
	email, password, err := extractEmailPassword(credentials)
	if err != nil {
		return err
	}

	// Validate email format
	if err := p.validateEmail(email); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	// Validate password strength
	if err := p.validatePassword(password); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	return nil
}

// PrepareCredentials hashes the password and prepares tcredentials for storage.
func (p *EmailPasswordProvider) PrepareCredentials(credentials map[string]any) ([]byte, error) {
	email, password, err := extractEmailPassword(credentials)
	if err != nil {
		return nil, err
	}

	// Normalize email
	email = strings.ToLower(strings.TrimSpace(email))

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), p.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create storage format
	stored := emailPasswordCredentials{
		Email:        email,
		PasswordHash: string(hashedPassword),
	}

	return json.Marshal(stored)
}

// VerifyCredentials verifies provided credentials against stored ones.
func (p *EmailPasswordProvider) VerifyCredentials(provided map[string]any, stored []byte) error {
	email, password, err := extractEmailPassword(provided)
	if err != nil {
		return err
	}

	// Normalize email
	email = strings.ToLower(strings.TrimSpace(email))

	// Unmarshal stored credentials
	var storedCreds emailPasswordCredentials
	if err := json.Unmarshal(stored, &storedCreds); err != nil {
		return fmt.Errorf("failed to unmarshal stored credentials: %w", err)
	}

	// Verify email matches
	if email != storedCreds.Email {
		return errors.New("email mismatch")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(storedCreds.PasswordHash), []byte(password)); err != nil {
		return errors.New("invalid password")
	}

	return nil
}

func (p *EmailPasswordProvider) GetIdentifier(credentials map[string]any) (string, error) {
	email, ok := credentials["email"].(string)
	if !ok || email == "" {
		return "", errors.New("email is required")
	}

	return strings.ToLower(strings.TrimSpace(email)), nil
}

// validateEmail validates email format and basic requirements.
// TODO Implement more comprehensive email validation.
func (p *EmailPasswordProvider) validateEmail(email string) error {
	// Basic format validation
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email format")
	}

	// TODO Implement more comprehensive email validation

	return nil
}

// validatePassword validates password strength requirements.
// TODO Needs more stringent strength requirements.
func (p *EmailPasswordProvider) validatePassword(password string) error {
	if len(password) < p.minPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", p.minPasswordLength)
	}

	// TODO Implement more stringent strength requirements

	return nil
}

// extractEmailPassword is a helper to get and validate the presence of email and password
// in provided credentials.
func extractEmailPassword(credentials map[string]any) (string, string, error) {
	email, ok := credentials["email"].(string)
	if !ok || email == "" {
		return "", "", errors.New("email is required")
	}

	passsword, ok := credentials["password"].(string)
	if !ok || passsword == "" {
		return "", "", errors.New("password is required")
	}

	return email, passsword, nil
}
