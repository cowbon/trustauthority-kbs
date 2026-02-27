/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package directory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"intel/kbs/v1/model"

	"github.com/google/uuid"
)

// setupTestDir creates a temporary directory for testing
func setupTestDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "key-store-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}

// cleanupTestDir removes the test directory
func cleanupTestDir(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Errorf("Failed to cleanup test dir: %v", err)
	}
}

// createSampleKey creates a sample KeyAttributes for testing
func createSampleKey() *model.KeyAttributes {
	return &model.KeyAttributes{
		ID:               uuid.New(),
		Algorithm:        "RSA",
		KeyLength:        2048,
		KmipKeyID:        "kmip-test-123",
		TransferPolicyId: uuid.New(),
		CreatedAt:        time.Now(),
	}
}

func TestNewKeyStore(t *testing.T) {
	dir := "/test/dir"
	ks := NewKeyStore(dir)

	if ks == nil {
		t.Fatal("Expected non-nil keyStore")
	}

	if ks.dir != dir {
		t.Errorf("Expected dir %s, got %s", dir, ks.dir)
	}
}

func TestKeyStore_Create_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	key := createSampleKey()

	result, err := ks.Create(key)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.ID != key.ID {
		t.Errorf("Expected ID %v, got %v", key.ID, result.ID)
	}

	// Verify file was created
	filePath := filepath.Join(dir, key.ID.String())
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify file contents
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	var savedKey model.KeyAttributes
	if err := json.Unmarshal(data, &savedKey); err != nil {
		t.Fatalf("Failed to unmarshal key: %v", err)
	}

	if savedKey.ID != key.ID {
		t.Errorf("Saved key ID mismatch")
	}
}

func TestKeyStore_Create_InvalidDirectory(t *testing.T) {
	ks := NewKeyStore("/nonexistent/invalid/path")
	key := createSampleKey()

	_, err := ks.Create(key)
	if err == nil {
		t.Error("Expected error for invalid directory")
	}
}

func TestKeyStore_Retrieve_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	originalKey := createSampleKey()

	// Create the key first
	_, err := ks.Create(originalKey)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Retrieve the key
	retrievedKey, err := ks.Retrieve(originalKey.ID)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}

	if retrievedKey == nil {
		t.Fatal("Expected non-nil retrieved key")
	}

	if retrievedKey.ID != originalKey.ID {
		t.Errorf("Expected ID %v, got %v", originalKey.ID, retrievedKey.ID)
	}

	if retrievedKey.Algorithm != originalKey.Algorithm {
		t.Errorf("Expected Algorithm %s, got %s", originalKey.Algorithm, retrievedKey.Algorithm)
	}

	if retrievedKey.KeyLength != originalKey.KeyLength {
		t.Errorf("Expected KeyLength %d, got %d", originalKey.KeyLength, retrievedKey.KeyLength)
	}
}

func TestKeyStore_Retrieve_NotFound(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	nonExistentID := uuid.New()

	_, err := ks.Retrieve(nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	if err.Error() != RecordNotFound {
		t.Errorf("Expected '%s' error, got '%v'", RecordNotFound, err)
	}
}

func TestKeyStore_Retrieve_CorruptedFile(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	keyID := uuid.New()

	// Write corrupted data
	filePath := filepath.Join(dir, keyID.String())
	if err := os.WriteFile(filePath, []byte("corrupted json data"), 0600); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	_, err := ks.Retrieve(keyID)
	if err == nil {
		t.Error("Expected error for corrupted file")
	}
}

func TestKeyStore_Delete_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	key := createSampleKey()

	// Create the key
	_, err := ks.Create(key)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Delete the key
	err = ks.Delete(key.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file was deleted
	filePath := filepath.Join(dir, key.ID.String())
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("Key file still exists after deletion")
	}
}

func TestKeyStore_Delete_NotFound(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	nonExistentID := uuid.New()

	err := ks.Delete(nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	if err.Error() != RecordNotFound {
		t.Errorf("Expected '%s' error, got '%v'", RecordNotFound, err)
	}
}

func TestKeyStore_Update_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	originalKey := createSampleKey()

	// Create the key
	_, err := ks.Create(originalKey)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Update the key
	originalKey.TransferPolicyId = uuid.New()
	originalKey.TransferLink = "https://updated.com"

	updatedKey, err := ks.Update(originalKey)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if updatedKey.TransferLink != "https://updated.com" {
		t.Errorf("Expected TransferLink 'https://updated.com', got '%s'", updatedKey.TransferLink)
	}

	// Retrieve and verify
	retrievedKey, err := ks.Retrieve(originalKey.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated key: %v", err)
	}

	if retrievedKey.TransferLink != "https://updated.com" {
		t.Errorf("Updated value not persisted")
	}
}

func TestKeyStore_Update_NonExistent(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)
	key := createSampleKey()

	_, err := ks.Update(key)
	if err == nil {
		t.Error("Expected error for updating non-existent key")
	}
}

func TestKeyStore_Search_EmptyStore(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	keys, err := ks.Search(nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected empty result, got %d keys", len(keys))
	}
}

func TestKeyStore_Search_AllKeys(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create multiple keys
	key1 := createSampleKey()
	key1.Algorithm = "RSA"
	key1.KeyLength = 2048

	key2 := createSampleKey()
	key2.Algorithm = "AES"
	key2.KeyLength = 256

	key3 := createSampleKey()
	key3.Algorithm = "EC"
	key3.CurveType = "secp384r1"

	for _, key := range []*model.KeyAttributes{key1, key2, key3} {
		if _, err := ks.Create(key); err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
	}

	// Search without criteria
	keys, err := ks.Search(nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}
}

func TestKeyStore_Search_ByAlgorithm(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create keys with different algorithms
	rsaKey := createSampleKey()
	rsaKey.Algorithm = "RSA"

	aesKey := createSampleKey()
	aesKey.Algorithm = "AES"

	for _, key := range []*model.KeyAttributes{rsaKey, aesKey, createSampleKey()} {
		if _, err := ks.Create(key); err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
	}

	// Search for RSA keys
	criteria := &model.KeyFilterCriteria{Algorithm: "RSA"}
	keys, err := ks.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 RSA keys, got %d", len(keys))
	}

	for _, key := range keys {
		if key.Algorithm != "RSA" {
			t.Errorf("Expected RSA algorithm, got %s", key.Algorithm)
		}
	}
}

func TestKeyStore_Search_ByKeyLength(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create keys with different lengths
	key1 := createSampleKey()
	key1.KeyLength = 2048

	key2 := createSampleKey()
	key2.KeyLength = 2048

	key3 := createSampleKey()
	key3.KeyLength = 4096

	for _, key := range []*model.KeyAttributes{key1, key2, key3} {
		if _, err := ks.Create(key); err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
	}

	// Search for 2048-bit keys
	criteria := &model.KeyFilterCriteria{KeyLength: 2048}
	keys, err := ks.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys with length 2048, got %d", len(keys))
	}
}

func TestKeyStore_Search_ByCurveType(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create EC keys with different curves
	key1 := createSampleKey()
	key1.CurveType = "secp384r1"

	key2 := createSampleKey()
	key2.CurveType = "secp256r1"

	for _, key := range []*model.KeyAttributes{key1, key2} {
		if _, err := ks.Create(key); err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
	}

	// Search for specific curve
	criteria := &model.KeyFilterCriteria{CurveType: "secp384r1"}
	keys, err := ks.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("Expected 1 key with curve secp384r1, got %d", len(keys))
	}

	if keys[0].CurveType != "secp384r1" {
		t.Errorf("Expected curve secp384r1, got %s", keys[0].CurveType)
	}
}

func TestKeyStore_Search_ByTransferPolicyId(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	policyID := uuid.New()

	// Create keys with different policy IDs
	key1 := createSampleKey()
	key1.TransferPolicyId = policyID

	key2 := createSampleKey()
	key2.TransferPolicyId = policyID

	key3 := createSampleKey()
	key3.TransferPolicyId = uuid.New()

	for _, key := range []*model.KeyAttributes{key1, key2, key3} {
		if _, err := ks.Create(key); err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
	}

	// Search by policy ID
	criteria := &model.KeyFilterCriteria{TransferPolicyId: policyID}
	keys, err := ks.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys with policy ID, got %d", len(keys))
	}
}

func TestKeyStore_Search_MultipleCriteria(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create keys with various attributes
	key1 := createSampleKey()
	key1.Algorithm = "RSA"
	key1.KeyLength = 2048

	key2 := createSampleKey()
	key2.Algorithm = "RSA"
	key2.KeyLength = 4096

	key3 := createSampleKey()
	key3.Algorithm = "AES"
	key3.KeyLength = 2048

	for _, key := range []*model.KeyAttributes{key1, key2, key3} {
		if _, err := ks.Create(key); err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
	}

	// Search with multiple criteria
	criteria := &model.KeyFilterCriteria{
		Algorithm: "RSA",
		KeyLength: 2048,
	}
	keys, err := ks.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("Expected 1 key matching criteria, got %d", len(keys))
	}

	if keys[0].Algorithm != "RSA" || keys[0].KeyLength != 2048 {
		t.Error("Returned key doesn't match criteria")
	}
}

func TestKeyStore_Search_EmptyCriteria(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create a key
	key := createSampleKey()
	if _, err := ks.Create(key); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Search with empty criteria
	criteria := &model.KeyFilterCriteria{}
	keys, err := ks.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("Expected 1 key with empty criteria, got %d", len(keys))
	}
}

func TestKeyStore_Search_InvalidFileName(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create a file with invalid UUID name
	invalidFile := filepath.Join(dir, "not-a-uuid.txt")
	if err := os.WriteFile(invalidFile, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create invalid file: %v", err)
	}

	_, err := ks.Search(nil)
	if err == nil {
		t.Error("Expected error for invalid file name")
	}
}

func TestKeyStore_Search_CorruptedFile(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	ks := NewKeyStore(dir)

	// Create a valid key
	key := createSampleKey()
	if _, err := ks.Create(key); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Create a corrupted key file
	corruptedID := uuid.New()
	corruptedFile := filepath.Join(dir, corruptedID.String())
	if err := os.WriteFile(corruptedFile, []byte("corrupted"), 0600); err != nil {
		t.Fatalf("Failed to create corrupted file: %v", err)
	}

	_, err := ks.Search(nil)
	if err == nil {
		t.Error("Expected error for corrupted file during search")
	}
}

func TestFilterKeys_NilCriteria(t *testing.T) {
	keys := []model.KeyAttributes{
		{ID: uuid.New(), Algorithm: "RSA"},
		{ID: uuid.New(), Algorithm: "AES"},
	}

	result := filterKeys(keys, nil)
	if len(result) != 2 {
		t.Errorf("Expected 2 keys with nil criteria, got %d", len(result))
	}
}

func TestFilterKeys_EmptyCriteria(t *testing.T) {
	keys := []model.KeyAttributes{
		{ID: uuid.New(), Algorithm: "RSA"},
		{ID: uuid.New(), Algorithm: "AES"},
	}

	criteria := &model.KeyFilterCriteria{}
	result := filterKeys(keys, criteria)
	if len(result) != 2 {
		t.Errorf("Expected 2 keys with empty criteria, got %d", len(result))
	}
}
