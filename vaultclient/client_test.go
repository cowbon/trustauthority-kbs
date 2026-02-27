/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package vaultclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	constants "intel/kbs/v1/constant"
	"intel/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
)

func TestNewVaultClient(t *testing.T) {
	client := NewVaultClient()
	if client == nil {
		t.Error("NewVaultClient() should return a non-nil client")
	}
}

func TestVaultClient_InitializeClient(t *testing.T) {
	client := &vaultClient{}

	err := client.InitializeClient("127.0.0.1", "8200", "test-token")
	if err != nil {
		t.Errorf("InitializeClient() error = %v", err)
	}

	if client.c == nil {
		t.Error("InitializeClient() should set the logical client")
	}
}

func TestVaultClient_CreateKey(t *testing.T) {
	keyID := uuid.New()
	attrs := &model.KeyAttributes{
		ID:        keyID,
		Algorithm: "RSA",
		KeyLength: 2048,
		CreatedAt: time.Now(),
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			t.Errorf("expected PUT or POST request, got %s", r.Method)
		}
		expectedPath := "/v1/" + constants.VAULT_KEY_ROOT_PATH + keyID.String()
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %s, want %s", r.URL.Path, expectedPath)
		}

		// Verify request body
		var reqData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		payload, ok := reqData[keyID.String()].(string)
		if !ok {
			t.Fatal("payload missing for key")
		}

		var received model.KeyAttributes
		if err := json.Unmarshal([]byte(payload), &received); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}

		if received.ID != keyID || received.Algorithm != attrs.Algorithm {
			t.Errorf("unexpected payload: %+v", received)
		}

		// Send success response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	if err := client.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() returned error: %v", err)
	}
}

func TestVaultClient_DeleteKey(t *testing.T) {
	keyID := uuid.NewString()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE request, got %s", r.Method)
		}
		expectedPath := "/v1/" + constants.VAULT_KEY_ROOT_PATH + keyID
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %s, want %s", r.URL.Path, expectedPath)
		}

		// Send success response
		w.WriteHeader(http.StatusNoContent)
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	if err := client.DeleteKey(keyID); err != nil {
		t.Fatalf("DeleteKey() returned error: %v", err)
	}
}

func TestVaultClient_GetKey(t *testing.T) {
	keyID := uuid.NewString()
	expectedData := []byte(`{"algorithm":"AES","key_length":256}`)

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != http.MethodGet {
			t.Errorf("expected GET request, got %s", r.Method)
		}
		expectedPath := "/v1/" + constants.VAULT_KEY_ROOT_PATH + keyID
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %s, want %s", r.URL.Path, expectedPath)
		}

		// Send mock response
		response := map[string]interface{}{
			"data": map[string]interface{}{
				keyID: string(expectedData),
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	value, err := client.GetKey(keyID)
	if err != nil {
		t.Fatalf("GetKey() returned error: %v", err)
	}

	if string(value) != string(expectedData) {
		t.Fatalf("GetKey() = %s, want %s", string(value), string(expectedData))
	}
}

func TestVaultClient_GetKey_NotFound(t *testing.T) {
	keyID := uuid.NewString()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Return 404 to simulate key not found
		w.WriteHeader(http.StatusNotFound)
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	_, err := client.GetKey(keyID)
	if err == nil {
		t.Fatal("GetKey() should return error when key is not found")
	}
}

func TestVaultClient_ListKeys(t *testing.T) {
	expectedKeys := []interface{}{"key1", "key2", "key3"}

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != "LIST" && r.Method != http.MethodGet {
			t.Errorf("expected LIST or GET request, got %s", r.Method)
		}
		// Note: Vault LIST operations strip the trailing slash
		if r.URL.Path != "/v1/"+constants.VAULT_KEY_ROOT_PATH &&
			r.URL.Path != "/v1/keybroker" {
			t.Errorf("unexpected path: got %s", r.URL.Path)
		}

		// Send mock response
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"keys": expectedKeys,
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	keys, err := client.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() returned error: %v", err)
	}

	if len(keys) != len(expectedKeys) {
		t.Fatalf("ListKeys() returned %d keys, want %d", len(keys), len(expectedKeys))
	}

	for i, key := range keys {
		if key != expectedKeys[i] {
			t.Errorf("ListKeys()[%d] = %v, want %v", i, key, expectedKeys[i])
		}
	}
}

func TestVaultClient_CreateKey_Error(t *testing.T) {
	keyID := uuid.New()
	attrs := &model.KeyAttributes{
		ID:        keyID,
		Algorithm: "RSA",
		KeyLength: 2048,
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Return error response
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"internal server error"},
		})
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	err := client.CreateKey(attrs)
	if err == nil {
		t.Fatal("CreateKey() should return error when vault returns error")
	}
}

func TestVaultClient_DeleteKey_Error(t *testing.T) {
	keyID := uuid.NewString()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Return error response
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"permission denied"},
		})
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	err := client.DeleteKey(keyID)
	if err == nil {
		t.Fatal("DeleteKey() should return error when vault returns error")
	}
}

func TestVaultClient_ListKeys_Error(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Return error response
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"unauthorized"},
		})
	}

	client, server := setupMockVaultServer(handler)
	defer server.Close()

	_, err := client.ListKeys()
	if err == nil {
		t.Fatal("ListKeys() should return error when vault returns error")
	}
}

// setupMockVaultServer creates a test HTTP server and returns a configured vault client
func setupMockVaultServer(handler http.HandlerFunc) (*vaultClient, *httptest.Server) {
	server := httptest.NewServer(handler)

	config := &api.Config{
		Address: server.URL,
	}
	vaultAPIClient, _ := api.NewClient(config)
	vaultAPIClient.SetToken("test-token")

	client := &vaultClient{
		c: vaultAPIClient.Logical(),
	}

	return client, server
}
