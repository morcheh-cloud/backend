// Package secrets seals credentials (SSH passwords, private keys) at rest with
// AES-256-GCM. Sealed values are nonce || ciphertext.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

type Box struct {
	aead cipher.AEAD
}

// New takes the base64 SECRETS_KEY, which must decode to 32 bytes.
func New(encodedKey string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("secrets key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets key: want 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal returns nil for an empty value, so "no secret" stays NULL in the DB.
func (b *Box) Seal(plain string) []byte {
	if plain == "" {
		return nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b.aead.Seal(nonce, nonce, []byte(plain), nil)
}

// Open reverses Seal; nil opens to "".
func (b *Box) Open(sealed []byte) (string, error) {
	if len(sealed) == 0 {
		return "", nil
	}
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return "", errors.New("secrets: sealed value too short")
	}
	plain, err := b.aead.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		return "", fmt.Errorf("secrets: open: %w", err)
	}
	return string(plain), nil
}
