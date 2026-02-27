/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGetPrivateKeyFromPem(t *testing.T) {
	// Test RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	key, err := GetPrivateKeyFromPem(pemBytes)
	if err != nil || key == nil {
		t.Errorf("Failed to parse RSA private key: %v", err)
	}

	// Test ECDSA
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8Bytes, _ = x509.MarshalPKCS8PrivateKey(ecKey)
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	key, err = GetPrivateKeyFromPem(pemBytes)
	if err != nil || key == nil {
		t.Errorf("Failed to parse ECDSA private key: %v", err)
	}

	// Error case: invalid PEM
	_, err = GetPrivateKeyFromPem([]byte("invalid"))
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}

	// Error case: valid PEM but invalid key data
	invalidPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid key data")})
	_, err = GetPrivateKeyFromPem(invalidPem)
	if err == nil {
		t.Error("Expected error for invalid key data in PEM")
	}
}

func TestGetPublicKeyFromPem(t *testing.T) {
	// Test RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	key, err := GetPublicKeyFromPem(pemBytes)
	if err != nil || key == nil {
		t.Errorf("Failed to parse RSA public key: %v", err)
	}

	// Test ECDSA
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes, _ = x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	key, err = GetPublicKeyFromPem(pemBytes)
	if err != nil || key == nil {
		t.Errorf("Failed to parse ECDSA public key: %v", err)
	}

	// Error case: invalid PEM
	_, err = GetPublicKeyFromPem([]byte("invalid"))
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}

	// Error case: wrong PEM block type
	wrongTypePem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pubKeyBytes})
	_, err = GetPublicKeyFromPem(wrongTypePem)
	if err == nil {
		t.Error("Expected error for wrong PEM block type")
	}

	// Error case: valid PEM but invalid key data
	invalidPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid key data")})
	_, err = GetPublicKeyFromPem(invalidPem)
	if err == nil {
		t.Error("Expected error for invalid key data in PEM")
	}
}

func TestGetDerivedKey(t *testing.T) {
	keySizes := []int{16, 24, 32}

	for _, size := range keySizes {
		key, err := GetDerivedKey(size)
		if err != nil {
			t.Errorf("GetDerivedKey(%d) failed: %v", size, err)
		}
		if len(key) != size {
			t.Errorf("Expected key size %d, got %d", size, len(key))
		}
	}
}
