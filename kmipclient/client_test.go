/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package kmipclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"intel/kbs/v1/constant"
)

func TestNewKmipClient(t *testing.T) {
	client := NewKmipClient()
	if client == nil {
		t.Error("NewKmipClient() should return non-nil client")
	}
}

func TestKmipClient_InitializeClient_Success(t *testing.T) {
	caCert, clientCert, clientKey, cleanup := createTestCertificates(t)
	defer cleanup()

	client := NewKmipClient()
	err := client.InitializeClient(constant.KMIP14, "127.0.0.1", "5696", "localhost", "user", "pass", clientKey, clientCert, caCert)
	if err != nil {
		t.Errorf("InitializeClient() error = %v", err)
	}
}

func TestKmipClient_InitializeClient_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{"Invalid version", "1.0", true},
		{"Valid KMIP 1.4", constant.KMIP14, false},
		{"Valid KMIP 2.0", constant.KMIP20, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCert, clientCert, clientKey, cleanup := createTestCertificates(t)
			defer cleanup()

			client := NewKmipClient()
			err := client.InitializeClient(tt.version, "127.0.0.1", "5696", "localhost", "", "", clientKey, clientCert, caCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitializeClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKmipClient_InitializeClient_MissingParameters(t *testing.T) {
	caCert, clientCert, clientKey, cleanup := createTestCertificates(t)
	defer cleanup()

	tests := []struct {
		name        string
		serverIP    string
		serverPort  string
		clientKey   string
		clientCert  string
		rootCert    string
		wantErr     bool
		errContains string
	}{
		{"Missing server IP", "", "5696", clientKey, clientCert, caCert, true, "server address"},
		{"Missing server port", "127.0.0.1", "", clientKey, clientCert, caCert, true, "server port"},
		{"Missing client cert", "127.0.0.1", "5696", clientKey, "", caCert, true, "client certificate"},
		{"Missing client key", "127.0.0.1", "5696", "", clientCert, caCert, true, "client key"},
		{"Missing root cert", "127.0.0.1", "5696", clientKey, clientCert, "", true, "root certificate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewKmipClient()
			err := client.InitializeClient(constant.KMIP14, tt.serverIP, tt.serverPort, "localhost", "", "", tt.clientKey, tt.clientCert, tt.rootCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitializeClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" && !contains(err.Error(), tt.errContains) {
				t.Errorf("InitializeClient() error = %v, want to contain %s", err, tt.errContains)
			}
		})
	}
}

func TestKmipClient_InitializeClient_InvalidCertPaths(t *testing.T) {
	client := NewKmipClient()
	err := client.InitializeClient(constant.KMIP14, "127.0.0.1", "5696", "localhost", "", "",
		"/nonexistent/key.pem", "/nonexistent/cert.pem", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("InitializeClient() should return error for invalid certificate paths")
	}
}

func TestKmipClient_InitializeClient_KMIP20(t *testing.T) {
	caCert, clientCert, clientKey, cleanup := createTestCertificates(t)
	defer cleanup()

	client := NewKmipClient()
	err := client.InitializeClient(constant.KMIP20, "127.0.0.1", "5696", "", "testuser", "testpass", clientKey, clientCert, caCert)
	if err != nil {
		t.Errorf("InitializeClient() with KMIP 2.0 error = %v", err)
	}
}

func TestKmipClient_InitializeClient_WithCredentials(t *testing.T) {
	caCert, clientCert, clientKey, cleanup := createTestCertificates(t)
	defer cleanup()

	client := NewKmipClient()
	err := client.InitializeClient(constant.KMIP14, "127.0.0.1", "5696", "test-host", "user", "password", clientKey, clientCert, caCert)
	if err != nil {
		t.Errorf("InitializeClient() with credentials error = %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func createTestCertificates(t *testing.T) (string, string, string, func()) {
	tempDir, err := os.MkdirTemp("", "kmip-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)

	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertFile, _ := os.Create(caCertPath)
	pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})
	caCertFile.Close()

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Client"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientCertBytes, _ := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)

	clientCertPath := filepath.Join(tempDir, "client.pem")
	clientCertFile, _ := os.Create(clientCertPath)
	pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
	clientCertFile.Close()

	clientKeyPath := filepath.Join(tempDir, "client-key.pem")
	clientKeyFile, _ := os.Create(clientKeyPath)
	pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	clientKeyFile.Close()

	cleanup := func() { os.RemoveAll(tempDir) }
	return caCertPath, clientCertPath, clientKeyPath, cleanup
}
