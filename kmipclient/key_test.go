/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package kmipclient

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"intel/kbs/v1/constant"

	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
)

// Helper functions for test setup and common operations
// writeServerCAToFile writes a certificate to a temporary file and returns the path
func writeServerCAToFile(cert *x509.Certificate) string {
	serverCAFile, _ := os.CreateTemp("", "server-ca-*.pem")
	serverCAPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	os.WriteFile(serverCAFile.Name(), serverCAPEM, 0644)
	return serverCAFile.Name()
}

// setupMockServerWithResponse creates a mock KMIP server with the given response and returns initialized client
func setupMockServerWithResponse(t *testing.T, version string, response kmip.ResponseMessage) (*kmipClient, func()) {
	caCert, clientCert, clientKey, certCleanup := createTestCertificates(t)

	mockServer := createMockKMIPServer(t, caCert, response)
	host, port, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	serverCAFile := writeServerCAToFile(mockServer.ServerCert)

	kc := &kmipClient{}
	err := kc.InitializeClient(version, host, port, "", "", "", clientKey, clientCert, serverCAFile)
	if err != nil {
		t.Fatalf("InitializeClient() failed: %v", err)
	}

	cleanup := func() {
		certCleanup()
		os.Remove(serverCAFile)
		mockServer.Close()
	}

	return kc, cleanup
}

// setupInvalidServerClient creates a client configured with an unreachable server for error testing
func setupInvalidServerClient(t *testing.T, version string) *kmipClient {
	caCert, clientCert, clientKey, cleanup := createTestCertificates(t)
	defer cleanup()

	kc := &kmipClient{
		KMIPVersion: version,
		ServerIP:    "invalid.server.test",
		ServerPort:  "9999",
	}

	err := kc.InitializeClient(version, "invalid.server.test", "9999", "", "", "", clientKey, clientCert, caCert)
	if err != nil {
		t.Skip("Skipping network error test - initialization failed")
	}

	return kc
}

// createSuccessResponse creates a standard success response message
func createSuccessResponse(version string, payload interface{}) kmip.ResponseMessage {
	major, minor := 1, 4
	if version == constant.KMIP20 {
		major, minor = 2, 0
	}

	return kmip.ResponseMessage{
		ResponseHeader: kmip.ResponseHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: major,
				ProtocolVersionMinor: minor,
			},
			BatchCount: 1,
			TimeStamp:  time.Now(),
		},
		BatchItem: []kmip.ResponseBatchItem{
			{
				ResultStatus:    kmip14.ResultStatusSuccess,
				ResponsePayload: payload,
			},
		},
	}
}

// Test key operations - these will test the request payload construction logic
func TestKmipClient_CreateSymmetricKey_NetworkError(t *testing.T) {
	tests := []struct {
		name    string
		version string
		keySize int
	}{
		{"KMIP 2.0", constant.KMIP20, 256},
		{"KMIP 1.4", constant.KMIP14, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := setupInvalidServerClient(t, tt.version)
			_, err := kc.CreateSymmetricKey(tt.keySize)
			if err == nil {
				t.Error("CreateSymmetricKey() should return error when server is unreachable")
			}
		})
	}
}

func TestKmipClient_CreateAsymmetricKeyPair_NetworkError(t *testing.T) {
	tests := []struct {
		name    string
		version string
		keySize int
	}{
		{"KMIP 2.0", constant.KMIP20, 2048},
		{"KMIP 1.4", constant.KMIP14, 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := setupInvalidServerClient(t, tt.version)
			_, err := kc.CreateAsymmetricKeyPair("RSA", "", tt.keySize)
			if err == nil {
				t.Error("CreateAsymmetricKeyPair() should return error when server is unreachable")
			}
		})
	}
}

func TestKmipClient_GetKey_NetworkError(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"AES", constant.CRYPTOALGAES},
		{"RSA", constant.CRYPTOALGRSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := setupInvalidServerClient(t, constant.KMIP14)
			_, err := kc.GetKey("test-key-id", tt.algorithm)
			if err == nil {
				t.Errorf("GetKey() with %s should return error when server is unreachable", tt.name)
			}
		})
	}
}

func TestKmipClient_DeleteKey_NetworkError(t *testing.T) {
	kc := setupInvalidServerClient(t, constant.KMIP14)
	err := kc.DeleteKey("test-key-id")
	if err == nil {
		t.Error("DeleteKey() should return error when server is unreachable")
	}
}

// Test SendRequest with mock KMIP server
func TestKmipClient_SendRequest_Success(t *testing.T) {
	responsePayload := CreateResponsePayload{
		UniqueIdentifier: "mock-key-id-123",
	}
	responseData, _ := ttlv.Marshal(responsePayload)

	responseMessage := kmip.ResponseMessage{
		ResponseHeader: kmip.ResponseHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 4,
			},
			BatchCount: 1,
			TimeStamp:  time.Now(),
		},
		BatchItem: []kmip.ResponseBatchItem{
			{
				ResultStatus:    kmip14.ResultStatusSuccess,
				ResultMessage:   "Success",
				ResponsePayload: ttlv.TTLV(responseData),
			},
		},
	}

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, responseMessage)
	defer cleanup()

	// Test SendRequest
	createRequest := kmip.CreateRequestPayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
	}

	batchItem, decoder, err := kc.SendRequest(createRequest, kmip14.OperationCreate)
	if err != nil {
		t.Fatalf("SendRequest() error = %v", err)
	}

	if batchItem == nil {
		t.Fatal("SendRequest() returned nil batch item")
	}

	if batchItem.ResultStatus != kmip14.ResultStatusSuccess {
		t.Errorf("Expected ResultStatusSuccess, got %v", batchItem.ResultStatus)
	}

	if decoder == nil {
		t.Error("SendRequest() returned nil decoder")
	}
}

func TestKmipClient_SendRequest_FailureStatus(t *testing.T) {
	responseMessage := kmip.ResponseMessage{
		ResponseHeader: kmip.ResponseHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 4,
			},
			BatchCount: 1,
			TimeStamp:  time.Now(),
		},
		BatchItem: []kmip.ResponseBatchItem{
			{
				ResultStatus:  kmip14.ResultStatusOperationFailed,
				ResultMessage: "Operation failed for testing",
			},
		},
	}

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, responseMessage)
	defer cleanup()

	createRequest := kmip.CreateRequestPayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
	}

	_, _, err := kc.SendRequest(createRequest, kmip14.OperationCreate)
	if err == nil {
		t.Error("SendRequest() should return error when result status is failure")
	}

	if err != nil && !contains(err.Error(), "failed") {
		t.Errorf("Expected error to contain 'failed', got: %v", err)
	}
}

// Helper function to create a mock KMIP server
func createMockKMIPServer(t *testing.T, caCertPath string, response kmip.ResponseMessage) *mockKMIPTLSServer {
	// Create a new CA for the mock server
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Mock KMIP CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertBytes)

	// Create server certificate signed by the CA
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Mock KMIP Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	serverCertBytes, _ := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)

	serverCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes, caCertBytes}, // Include CA cert in chain
		PrivateKey:  serverKey,
	}

	// Create CA pool for client verification
	clientCACertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read client CA cert: %v", err)
	}
	clientCACertPool := x509.NewCertPool()
	clientCACertPool.AppendCertsFromPEM(clientCACertPEM)

	// Create CA pool for client to verify server
	serverCACertPool := x509.NewCertPool()
	serverCACertPool.AddCert(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCACertPool,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}

	server := &mockKMIPTLSServer{
		Listener:   listener,
		response:   response,
		ServerCA:   serverCACertPool,
		ServerCert: caCert,
	}

	go server.serve()

	return server
}

type mockKMIPTLSServer struct {
	Listener   net.Listener
	response   kmip.ResponseMessage
	ServerCA   *x509.CertPool
	ServerCert *x509.Certificate
}

func (s *mockKMIPTLSServer) serve() {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *mockKMIPTLSServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read request (we don't validate it, just send response)
	reader := bufio.NewReader(conn)
	decoder := ttlv.NewDecoder(reader)
	_, _ = decoder.NextTTLV() // Read and ignore request

	// Send response
	responseBytes, _ := ttlv.Marshal(s.response)
	conn.Write(responseBytes)
}

func (s *mockKMIPTLSServer) Close() {
	s.Listener.Close()
}

// Test CreateSymmetricKey with successful response
func TestKmipClient_CreateSymmetricKey_Success(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		expectedKeyID string
	}{
		{"KMIP 2.0", constant.KMIP20, "symmetric-key-123"},
		{"KMIP 1.4", constant.KMIP14, "symmetric-key-456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := createSuccessResponse(tt.version, CreateResponsePayload{
				UniqueIdentifier: tt.expectedKeyID,
			})

			kc, cleanup := setupMockServerWithResponse(t, tt.version, response)
			defer cleanup()

			keyID, err := kc.CreateSymmetricKey(256)
			if err != nil {
				t.Fatalf("CreateSymmetricKey() error = %v", err)
			}

			if keyID != tt.expectedKeyID {
				t.Errorf("Expected keyID '%s', got '%s'", tt.expectedKeyID, keyID)
			}
		})
	}
}

// Test CreateAsymmetricKeyPair with successful response
func TestKmipClient_CreateAsymmetricKeyPair_Success(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		expectedKeyID string
		publicKeyID   string
	}{
		{"KMIP 2.0", constant.KMIP20, "private-key-789", "public-key-790"},
		{"KMIP 1.4", constant.KMIP14, "private-key-111", "public-key-222"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := createSuccessResponse(tt.version, CreateKeyPairResponsePayload{
				PrivateKeyUniqueIdentifier: tt.expectedKeyID,
				PublicKeyUniqueIdentifier:  tt.publicKeyID,
			})

			kc, cleanup := setupMockServerWithResponse(t, tt.version, response)
			defer cleanup()

			keyID, err := kc.CreateAsymmetricKeyPair("RSA", "", 2048)
			if err != nil {
				t.Fatalf("CreateAsymmetricKeyPair() error = %v", err)
			}

			if keyID != tt.expectedKeyID {
				t.Errorf("Expected keyID '%s', got '%s'", tt.expectedKeyID, keyID)
			}
		})
	}
}

// Test GetKey for AES key
func TestKmipClient_GetKey_AES_Success(t *testing.T) {
	keyMaterial := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	keyValue := KeyValue{KeyMaterial: keyMaterial}
	keyValueData, _ := ttlv.Marshal(keyValue)

	response := createSuccessResponse(constant.KMIP14, GetResponsePayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
		SymmetricKey: kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyValue: ttlv.TTLV(keyValueData),
			},
		},
	})

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, response)
	defer cleanup()

	key, err := kc.GetKey("test-key-id", constant.CRYPTOALGAES)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if len(key) != len(keyMaterial) {
		t.Errorf("Expected key length %d, got %d", len(keyMaterial), len(key))
	}
}

// Test GetKey for RSA private key
func TestKmipClient_GetKey_RSA_Success(t *testing.T) {
	keyMaterial := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	keyValue := KeyValue{KeyMaterial: keyMaterial}
	keyValueData, _ := ttlv.Marshal(keyValue)

	response := createSuccessResponse(constant.KMIP14, GetResponsePayload{
		ObjectType: kmip14.ObjectTypePrivateKey,
		PrivateKey: kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyValue: ttlv.TTLV(keyValueData),
			},
		},
	})

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, response)
	defer cleanup()

	key, err := kc.GetKey("test-key-id", constant.CRYPTOALGRSA)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if len(key) != len(keyMaterial) {
		t.Errorf("Expected key length %d, got %d", len(keyMaterial), len(key))
	}
}

// Test GetKey with unsupported algorithm
func TestKmipClient_GetKey_UnsupportedAlgorithm(t *testing.T) {
	keyMaterial := []byte{0x01, 0x02, 0x03, 0x04}
	keyValue := KeyValue{KeyMaterial: keyMaterial}
	keyValueData, _ := ttlv.Marshal(keyValue)

	response := createSuccessResponse(constant.KMIP14, GetResponsePayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
		SymmetricKey: kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyValue: ttlv.TTLV(keyValueData),
			},
		},
	})

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, response)
	defer cleanup()

	_, err := kc.GetKey("test-key-id", "UNSUPPORTED_ALG")
	if err == nil {
		t.Error("GetKey() should return error for unsupported algorithm")
	}
	if err != nil && !contains(err.Error(), "unsupported") {
		t.Errorf("Expected error about unsupported algorithm, got: %v", err)
	}
}

// Test GetKey with unsupported object type
func TestKmipClient_GetKey_UnsupportedObjectType(t *testing.T) {
	response := createSuccessResponse(constant.KMIP14, GetResponsePayload{
		ObjectType: kmip14.ObjectTypePublicKey, // Unsupported for RSA retrieval
	})

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, response)
	defer cleanup()

	_, err := kc.GetKey("test-key-id", constant.CRYPTOALGRSA)
	if err == nil {
		t.Error("GetKey() should return error for unsupported object type")
	}
	if err != nil && !contains(err.Error(), "unsupported object type") {
		t.Errorf("Expected error about unsupported object type, got: %v", err)
	}
}

// Test DeleteKey success
func TestKmipClient_DeleteKey_Success(t *testing.T) {
	response := createSuccessResponse(constant.KMIP14, nil)

	kc, cleanup := setupMockServerWithResponse(t, constant.KMIP14, response)
	defer cleanup()

	err := kc.DeleteKey("test-key-id")
	if err != nil {
		t.Errorf("DeleteKey() error = %v, expected nil", err)
	}
}
