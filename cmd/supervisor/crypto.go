package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	saltSize   = 16
	keySize    = 32 // AES-256
	hkdfInfo   = "vaultwarden-serverless-rsa-key"
	rsaKeyBits = 2048
)

// GenerateRSAKeyPEM generates a new 2048-bit RSA private key and encodes it in PKCS#1 PEM format.
func GenerateRSAKeyPEM() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %d-bit RSA key: %w", rsaKeyBits, err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}

	encoded := pem.EncodeToMemory(pemBlock)
	if encoded == nil {
		return nil, errors.New("failed to encode RSA private key to PEM")
	}

	return encoded, nil
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM.
// The key is derived from the passphrase and a random 16-byte salt using HKDF-SHA256.
// Output format: [16-byte salt][12-byte nonce][ciphertext + 16-byte auth tag]
func EncryptAESGCM(passphrase string, plaintext []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase must not be empty")
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	key, err := hkdf.Key(sha256.New, []byte(passphrase), salt, hkdfInfo, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine: salt + nonce + ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptAESGCM decrypts ciphertext produced by EncryptAESGCM.
// Verifies authenticity tag; returns error if passphrase is incorrect or data is tampered with.
func DecryptAESGCM(passphrase string, data []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase must not be empty")
	}

	minLen := saltSize + 12 // salt + 12-byte GCM nonce
	if len(data) < minLen {
		return nil, errors.New("encrypted payload too short")
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+12]
	ciphertext := data[saltSize+12:]

	key, err := hkdf.Key(sha256.New, []byte(passphrase), salt, hkdfInfo, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid passphrase or corrupted data): %w", err)
	}

	return plaintext, nil
}
