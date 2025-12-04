// Package config handles application config.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// ServerConfig holds server-related config.
type ServerConfig struct {
	Port string
}

// DatabaseConfig holds database-related config.
type DatabaseConfig struct {
	URL string
}

// JWTConfig holds JWT-related config.
type JWTConfig struct {
	Secret        string
	Issuer        string
	Audience      string
	ExpiryMinutes int
}

// AuthConfig holds authentication-related config.
type AuthConfig struct {
	RefreshTokenExpiry time.Duration
	IPCryptKey         string
}

// Config holds all application config.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Auth     AuthConfig
}

// getEnv retrieves an environment variable or returns a default value.
// TODO Should we return an error if the value is not set?
func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

// getEnvInt retrieves an environment variable as an integer or returns a default value.
// If the value cannot be parsed as an int, the default is returned.
// TODO Should we return an error if value can't be parsed as an int?
func getEnvInt(key string, defaultVal int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultVal
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultVal
	}
	return value
}

// getEnvDuration retrieves an environment variable as a duration or returns a default value.
// The value should be a string parseable by time.ParseDuration (e.g. "30m", "24h" etc.).
// If the value cannot be parsed as a duration, the default is returned.
// TODO Look into whether it's better to return an error if value can't be parsed.
func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultVal
	}

	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultVal
	}
	return value
}

// validate checks that all required configuration values are present.
func (c *Config) validate() error {
	if c.Database.URL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.JWT.Secret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}
	if c.Auth.IPCryptKey == "" {
		return fmt.Errorf("IPCRYPT_KEY is required")
	}
	return nil
}

// Load reads configuration from env variables.
// TODO Adapt so that it can (optionally) read from remote sources as well,
// e.g. Secret Managers.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnv("API_PORT", "8080"),
		},
		Database: DatabaseConfig{
			URL: os.Getenv("DATABASE_URL"),
		},
		JWT: JWTConfig{
			Secret:        os.Getenv("JWT_SECRET"),
			Issuer:        getEnv("JWT_ISSUER", "auth-service"),
			Audience:      getEnv("JWT_AUDIENCE", "auth-service"),
			ExpiryMinutes: getEnvInt("JWT_EXPIRY_MINUTES", 15),
		},
		Auth: AuthConfig{
			RefreshTokenExpiry: getEnvDuration("REFRESH_TOKEN_EXPIRY", 30*24*time.Hour),
			IPCryptKey:         os.Getenv("IPCRYPT_KEY"),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
