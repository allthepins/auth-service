package ipcrypt_test

import (
	"encoding/base64"
	"net"
	"testing"

	"github.com/allthepins/auth-service/internal/platform/ipcrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKey creates a valid 16-byte base64-encoded key for testing
func generateTestKey() string {
	key := make([]byte, 16) // 16 bytes for ipcrypt-deterministic
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestNew(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		validKey := generateTestKey()
		enc, err := ipcrypt.New(validKey)
		require.NoError(t, err)
		assert.NotNil(t, enc)
	})

	t.Run("invalid base64", func(t *testing.T) {
		invalidKey := "not-valid-base64!!!"
		enc, err := ipcrypt.New(invalidKey)
		require.Error(t, err)
		assert.Nil(t, enc)
		assert.Contains(t, err.Error(), "invalid IPCrypt key format")
	})

	t.Run("wrong key length", func(t *testing.T) {
		shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
		enc, err := ipcrypt.New(shortKey)
		require.Error(t, err)
		assert.Nil(t, enc)
		assert.Contains(t, err.Error(), "must be 16 bytes")
	})
}

func TestEncrypt(t *testing.T) {
	validKey := generateTestKey()
	enc, err := ipcrypt.New(validKey)
	require.NoError(t, err)

	t.Run("valid IPv4", func(t *testing.T) {
		ip := "192.168.1.1"
		encrypted, err := enc.Encrypt(ip)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, ip, encrypted)
	})

	t.Run("valid IPv6", func(t *testing.T) {
		ip := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
		encrypted, err := enc.Encrypt(ip)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, ip, encrypted)
	})

	t.Run("invalid IP", func(t *testing.T) {
		ip := "not-an-ip"
		encrypted, err := enc.Encrypt(ip)
		require.Error(t, err)
		assert.Empty(t, encrypted)
		assert.Contains(t, err.Error(), "invalid IP address")
	})
}

func TestEncryptDecrypt(t *testing.T) {
	validKey := generateTestKey()
	enc, err := ipcrypt.New(validKey)
	require.NoError(t, err)

	testCases := []struct {
		name string
		ip   string
	}{
		{"IPv4 loopback", "127.0.0.1"},
		{"IPv4 private", "192.168.1.100"},
		{"IPv4 public", "8.8.8.8"},
		{"IPv6 loopback", "::1"},
		{"IPv6 address", "2001:db8::1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := enc.Encrypt(tc.ip)
			require.NoError(t, err)
			assert.NotEqual(t, tc.ip, encrypted, "encrypted IP should differ from original")

			// Decrypt
			decrypted, err := enc.Decrypt(encrypted)
			require.NoError(t, err)

			// Parse both IPs to compare them properly (handles IPv6 normalization)
			originalIP := normalizeIP(tc.ip)
			decryptedIP := normalizeIP(decrypted)
			assert.Equal(t, originalIP, decryptedIP, "decrypted IP should match original")
		})
	}
}

func TestDecrypt(t *testing.T) {
	validKey := generateTestKey()
	enc, err := ipcrypt.New(validKey)
	require.NoError(t, err)

	t.Run("invalid encrypted IP format", func(t *testing.T) {
		invalid := "not-an-ip"
		decrypted, err := enc.Decrypt(invalid)
		require.Error(t, err)
		assert.Empty(t, decrypted)
		assert.Contains(t, err.Error(), "invalid encrypted IP")
	})
}

func TestDifferentKeysProduceDifferentResults(t *testing.T) {
	key1 := generateTestKey()
	key2 := base64.StdEncoding.EncodeToString([]byte("different16bytes"))

	enc1, err := ipcrypt.New(key1)
	require.NoError(t, err)

	enc2, err := ipcrypt.New(key2)
	require.NoError(t, err)

	ip := "192.168.1.1"

	encrypted1, err := enc1.Encrypt(ip)
	require.NoError(t, err)

	encrypted2, err := enc2.Encrypt(ip)
	require.NoError(t, err)

	assert.NotEqual(t, encrypted1, encrypted2, "different keys should produce different encrypted results")
}

func TestSameKeyProducesSameResults(t *testing.T) {
	validKey := generateTestKey()
	enc, err := ipcrypt.New(validKey)
	require.NoError(t, err)

	ip := "192.168.1.1"

	encrypted1, err := enc.Encrypt(ip)
	require.NoError(t, err)

	encrypted2, err := enc.Encrypt(ip)
	require.NoError(t, err)

	assert.Equal(t, encrypted1, encrypted2, "same key should produce same encrypted result for same IP")
}

// normalizeIP parses and returns the normalized string representation of an IP
func normalizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	return ip.String()
}
