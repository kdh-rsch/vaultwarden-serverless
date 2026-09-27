package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateRSAKeyPEM(t *testing.T) {
	pemData, err := GenerateRSAKeyPEM()
	if err != nil {
		t.Fatalf("unexpected error generating RSA key: %v", err)
	}

	if !strings.HasPrefix(string(pemData), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("expected PEM prefix '-----BEGIN RSA PRIVATE KEY-----', got: %s", string(pemData[:35]))
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode generated PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS#1 private key: %v", err)
	}

	if privKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d bits", privKey.N.BitLen())
	}
}

func TestEncryptDecryptAESGCM_RoundTrip(t *testing.T) {
	passphrase := "super-secure-cloud-run-passphrase-123"
	original := []byte("secret-vaultwarden-rsa-private-key-contents")

	encrypted, err := EncryptAESGCM(passphrase, original)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(encrypted, original) {
		t.Fatal("encrypted data matches plaintext!")
	}

	decrypted, err := DecryptAESGCM(passphrase, encrypted)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("decrypted content mismatch: got %q, expected %q", string(decrypted), string(original))
	}
}

func TestEncryptDecryptAESGCM_WrongPassphrase(t *testing.T) {
	passphrase := "correct-passphrase"
	wrongPassphrase := "wrong-passphrase"
	original := []byte("confidential-payload")

	encrypted, err := EncryptAESGCM(passphrase, original)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	_, err = DecryptAESGCM(wrongPassphrase, encrypted)
	if err == nil {
		t.Fatal("expected decryption error with wrong passphrase, but got nil")
	}
}

func TestEncryptDecryptAESGCM_TamperedData(t *testing.T) {
	passphrase := "my-passphrase"
	original := []byte("tamper-test-payload")

	encrypted, err := EncryptAESGCM(passphrase, original)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Tamper with the last byte (auth tag)
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err = DecryptAESGCM(passphrase, encrypted)
	if err == nil {
		t.Fatal("expected authentication error on tampered ciphertext, but got nil")
	}
}
