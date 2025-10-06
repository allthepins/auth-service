package auth

// Provider defines the required behavior for an authentication provider.
type Provider interface {
	// Name returns the unique identifier for this provider.
	Name() string

	// ValidateCredentials validates the provided credentials for registration.
	ValidateCredentials(credentials map[string]any) error

	// PrepareCredentials preps the credentials for storage (e.g. hashing passwords).
	PrepareCredentials(credentials map[string]any) ([]byte, error)

	// VerifyCredentials verifies provided credentials against stored credentials.
	VerifyCredentials(provided map[string]any, stored []byte) error

	// GetIdentifier extracts the unique identifier from credentials (e.g. email)
	GetIdentifier(credentials map[string]any) (string, error)
}
