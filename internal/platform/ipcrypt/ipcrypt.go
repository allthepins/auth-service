// Package ipcrypt provides IP address encryption for privacy protection.
package ipcrypt

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/jedisct1/go-ipcrypt"
)

// Encryptor handles IP address encryption and decryption.
type Encryptor interface {
	Encrypt(ip string) (string, error)
	Decrypt(encrypted string) (string, error)
}

// encryptor implements the Encryptor interface using ipcrypt-deterministic mode.
// https://www.ietf.org/archive/id/draft-denis-ipcrypt-12.html#name-ipcrypt-deterministic
type encryptor struct {
	key []byte
}

// New creates a new IP encryptor with the given base64-encoded key.
// (The key must be exactly 16 bytes when decoded).
func New(keyBase64 string) (Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid IPCrypt key format: %w", err)
	}

	if len(key) != ipcrypt.KeySizeDeterministic {
		return nil, fmt.Errorf("IPCrypt key must be %d bytes, got %d", ipcrypt.KeySizeDeterministic, len(key))
	}

	return &encryptor{key: key}, nil
}

// Encrypt encrypts an IP address string.
// It returns a string representation of the encrypted IP.
func (e *encryptor) Encrypt(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	encrypted, err := ipcrypt.EncryptIP(e.key, ip)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt IP: %w", err)
	}

	return encrypted.String(), nil
}

// Decrypt decrypts an encrypted IP address string.
// Returns a string of the original IP address.
func (e *encryptor) Decrypt(encryptedStr string) (string, error) {
	encrypted := net.ParseIP(encryptedStr)
	if encrypted == nil {
		return "", fmt.Errorf("invalid encrypted IP: %s", encryptedStr)
	}

	decrypted, err := ipcrypt.DecryptIP(e.key, encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt IP: %w", err)
	}

	return decrypted.String(), nil
}
