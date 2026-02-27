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

// Test helper to create temp directory for key transfer policy tests
func setupKTPTestDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "ktp-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	return dir
}

// Test helper to clean up temp directory
func cleanupKTPTestDir(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Errorf("Failed to remove temp directory: %v", err)
	}
}

func TestKeyTransferPolicyStore_Create_Success(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a test policy
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner:     []string{"test-mrsigner"},
				IsvProductId: []uint16{1},
			},
		},
	}

	createdPolicy, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify ID and timestamp were set
	if createdPolicy.ID == uuid.Nil {
		t.Error("Created policy should have non-nil ID")
	}
	if createdPolicy.CreatedAt.IsZero() {
		t.Error("Created policy should have CreatedAt timestamp")
	}

	// Verify file was created
	filePath := filepath.Join(dir, createdPolicy.ID.String())
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Errorf("Policy file should exist at %s", filePath)
	}
}

func TestKeyTransferPolicyStore_Create_TDXPolicy(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a TDX policy
	enforceTcb := true
	seamSvn := uint16(258)
	policy := &model.KeyTransferPolicy{
		AttestationType: model.TDX,
		TDX: &model.TdxPolicy{
			Attributes: &model.TdxAttributes{
				MrSignerSeam:       []string{"test-mrsigner-seam"},
				MrSeam:             []string{"test-mrseam"},
				SeamSvn:            &seamSvn,
				MRTD:               []string{"test-mrtd"},
				RTMR0:              "test-rtmr0",
				RTMR1:              "test-rtmr1",
				EnforceTCBUptoDate: &enforceTcb,
			},
			PolicyIds: []uuid.UUID{uuid.New(), uuid.New()},
		},
	}

	createdPolicy, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify policy was created with TDX attributes
	if createdPolicy.AttestationType != model.TDX {
		t.Error("Policy should have TDX attestation type")
	}
	if createdPolicy.TDX == nil {
		t.Error("TDX policy should not be nil")
	}
}

func TestKeyTransferPolicyStore_Create_InvalidDirectory(t *testing.T) {
	// Use a non-existent directory
	store := NewKeyTransferPolicyStore("/invalid/non-existent/path")

	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
	}

	_, err := store.Create(policy)
	if err == nil {
		t.Error("Create() should fail with invalid directory")
	}
}

func TestKeyTransferPolicyStore_Retrieve_Success(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a policy first
	originalPolicy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner:     []string{"test-mrsigner"},
				MrEnclave:    []string{"test-mrenclave"},
				IsvProductId: []uint16{1, 2},
			},
		},
	}
	created, err := store.Create(originalPolicy)
	if err != nil {
		t.Fatalf("Setup: failed to create policy: %v", err)
	}

	// Retrieve the policy
	retrieved, err := store.Retrieve(created.ID)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	// Verify the retrieved policy matches
	if retrieved.ID != created.ID {
		t.Errorf("Retrieved ID = %v, want %v", retrieved.ID, created.ID)
	}
	if retrieved.AttestationType != created.AttestationType {
		t.Errorf("AttestationType = %v, want %v", retrieved.AttestationType, created.AttestationType)
	}
}

func TestKeyTransferPolicyStore_Retrieve_NotFound(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Try to retrieve non-existent policy
	nonExistentID := uuid.New()
	_, err := store.Retrieve(nonExistentID)
	if err == nil {
		t.Error("Retrieve() should return error for non-existent policy")
	}
	if err.Error() != RecordNotFound {
		t.Errorf("Expected RecordNotFound error, got: %v", err)
	}
}

func TestKeyTransferPolicyStore_Retrieve_CorruptedFile(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a corrupted file
	testID := uuid.New()
	filePath := filepath.Join(dir, testID.String())
	err := os.WriteFile(filePath, []byte("invalid json content"), 0600)
	if err != nil {
		t.Fatalf("Setup: failed to create corrupted file: %v", err)
	}

	// Try to retrieve the corrupted policy
	_, err = store.Retrieve(testID)
	if err == nil {
		t.Error("Retrieve() should fail with corrupted JSON file")
	}
}

func TestKeyTransferPolicyStore_Delete_Success(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a policy first
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
	}
	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Setup: failed to create policy: %v", err)
	}

	// Delete the policy
	err = store.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify file was deleted
	filePath := filepath.Join(dir, created.ID.String())
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("Policy file should be deleted")
	}
}

func TestKeyTransferPolicyStore_Delete_NotFound(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Try to delete non-existent policy
	nonExistentID := uuid.New()
	err := store.Delete(nonExistentID)
	if err == nil {
		t.Error("Delete() should return error for non-existent policy")
	}
	if err.Error() != RecordNotFound {
		t.Errorf("Expected RecordNotFound error, got: %v", err)
	}
}

func TestKeyTransferPolicyStore_Search_EmptyDirectory(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Search in empty directory
	policies, err := store.Search(&model.KeyTransferPolicyFilterCriteria{})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if len(policies) != 0 {
		t.Errorf("Search() returned %d policies, want 0", len(policies))
	}
}

func TestKeyTransferPolicyStore_Search_MultiplePolices(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create multiple policies
	policy1 := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner: []string{"signer1"},
			},
		},
	}
	policy2 := &model.KeyTransferPolicy{
		AttestationType: model.TDX,
		TDX: &model.TdxPolicy{
			Attributes: &model.TdxAttributes{
				MrSignerSeam: []string{"signer2"},
			},
		},
	}
	policy3 := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner: []string{"signer3"},
			},
		},
	}

	_, err := store.Create(policy1)
	if err != nil {
		t.Fatalf("Setup: failed to create policy1: %v", err)
	}
	_, err = store.Create(policy2)
	if err != nil {
		t.Fatalf("Setup: failed to create policy2: %v", err)
	}
	_, err = store.Create(policy3)
	if err != nil {
		t.Fatalf("Setup: failed to create policy3: %v", err)
	}

	// Search for all policies
	policies, err := store.Search(&model.KeyTransferPolicyFilterCriteria{})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if len(policies) != 3 {
		t.Errorf("Search() returned %d policies, want 3", len(policies))
	}
}

func TestKeyTransferPolicyStore_Search_WithNilCriteria(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a policy
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
	}
	_, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Setup: failed to create policy: %v", err)
	}

	// Search with nil criteria
	policies, err := store.Search(nil)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("Search() with nil criteria returned %d policies, want 1", len(policies))
	}
}

func TestKeyTransferPolicyStore_Search_InvalidFileName(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a file with invalid UUID name
	invalidFilePath := filepath.Join(dir, "not-a-valid-uuid.txt")
	err := os.WriteFile(invalidFilePath, []byte("test"), 0600)
	if err != nil {
		t.Fatalf("Setup: failed to create invalid file: %v", err)
	}

	// Search should fail due to invalid UUID
	_, err = store.Search(&model.KeyTransferPolicyFilterCriteria{})
	if err == nil {
		t.Error("Search() should fail with invalid UUID filename")
	}
}

func TestKeyTransferPolicyStore_Search_CorruptedFile(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a valid policy first
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
	}
	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Setup: failed to create policy: %v", err)
	}

	// Corrupt the file
	filePath := filepath.Join(dir, created.ID.String())
	err = os.WriteFile(filePath, []byte("corrupted json"), 0600)
	if err != nil {
		t.Fatalf("Setup: failed to corrupt file: %v", err)
	}

	// Search should fail when trying to retrieve corrupted file
	_, err = store.Search(&model.KeyTransferPolicyFilterCriteria{})
	if err == nil {
		t.Error("Search() should fail when encountering corrupted file")
	}
}

func TestKeyTransferPolicyStore_ComplexSGXPolicy(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a complex SGX policy with all attributes
	enforceTcb := true
	isvSvn := uint16(5)
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner:           []string{"signer1", "signer2", "signer3"},
				IsvProductId:       []uint16{1, 2, 3, 4},
				MrEnclave:          []string{"enclave1", "enclave2"},
				IsvSvn:             &isvSvn,
				EnforceTCBUptoDate: &enforceTcb,
			},
			PolicyIds: []uuid.UUID{uuid.New(), uuid.New(), uuid.New()},
		},
	}

	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Retrieve and verify all attributes
	retrieved, err := store.Retrieve(created.ID)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if retrieved.SGX == nil {
		t.Fatal("SGX policy should not be nil")
	}
	if len(retrieved.SGX.Attributes.MrSigner) != 3 {
		t.Errorf("MrSigner count = %d, want 3", len(retrieved.SGX.Attributes.MrSigner))
	}
	if len(retrieved.SGX.Attributes.IsvProductId) != 4 {
		t.Errorf("IsvProductId count = %d, want 4", len(retrieved.SGX.Attributes.IsvProductId))
	}
	if *retrieved.SGX.Attributes.IsvSvn != isvSvn {
		t.Errorf("IsvSvn = %d, want %d", *retrieved.SGX.Attributes.IsvSvn, isvSvn)
	}
	if *retrieved.SGX.Attributes.EnforceTCBUptoDate != enforceTcb {
		t.Errorf("EnforceTCBUptoDate = %v, want %v", *retrieved.SGX.Attributes.EnforceTCBUptoDate, enforceTcb)
	}
}

func TestKeyTransferPolicyStore_ComplexTDXPolicy(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a complex TDX policy with all RTMR values
	enforceTcb := false
	seamSvn := uint16(300)
	policy := &model.KeyTransferPolicy{
		AttestationType: model.TDX,
		TDX: &model.TdxPolicy{
			Attributes: &model.TdxAttributes{
				MrSignerSeam:       []string{"seam-signer-1", "seam-signer-2"},
				MrSeam:             []string{"seam-value-1"},
				SeamSvn:            &seamSvn,
				MRTD:               []string{"mrtd-value-1", "mrtd-value-2"},
				RTMR0:              "rtmr0-value",
				RTMR1:              "rtmr1-value",
				RTMR2:              "rtmr2-value",
				RTMR3:              "rtmr3-value",
				EnforceTCBUptoDate: &enforceTcb,
			},
		},
	}

	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Retrieve and verify all RTMR values
	retrieved, err := store.Retrieve(created.ID)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if retrieved.TDX == nil {
		t.Fatal("TDX policy should not be nil")
	}
	attrs := retrieved.TDX.Attributes
	if attrs.RTMR0 != "rtmr0-value" {
		t.Errorf("RTMR0 = %s, want rtmr0-value", attrs.RTMR0)
	}
	if attrs.RTMR1 != "rtmr1-value" {
		t.Errorf("RTMR1 = %s, want rtmr1-value", attrs.RTMR1)
	}
	if attrs.RTMR2 != "rtmr2-value" {
		t.Errorf("RTMR2 = %s, want rtmr2-value", attrs.RTMR2)
	}
	if attrs.RTMR3 != "rtmr3-value" {
		t.Errorf("RTMR3 = %s, want rtmr3-value", attrs.RTMR3)
	}
	if *attrs.SeamSvn != seamSvn {
		t.Errorf("SeamSvn = %d, want %d", *attrs.SeamSvn, seamSvn)
	}
}

func TestKeyTransferPolicyStore_MultipleOperations(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create multiple policies
	var createdIDs []uuid.UUID
	for i := 0; i < 5; i++ {
		policy := &model.KeyTransferPolicy{
			AttestationType: model.SGX,
		}
		created, err := store.Create(policy)
		if err != nil {
			t.Fatalf("Create() iteration %d error = %v", i, err)
		}
		createdIDs = append(createdIDs, created.ID)
	}

	// Search and verify count
	policies, err := store.Search(&model.KeyTransferPolicyFilterCriteria{})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(policies) != 5 {
		t.Errorf("Search() returned %d policies, want 5", len(policies))
	}

	// Delete some policies
	err = store.Delete(createdIDs[0])
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	err = store.Delete(createdIDs[2])
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Search again and verify count
	policies, err = store.Search(&model.KeyTransferPolicyFilterCriteria{})
	if err != nil {
		t.Fatalf("Search() after delete error = %v", err)
	}
	if len(policies) != 3 {
		t.Errorf("Search() after delete returned %d policies, want 3", len(policies))
	}
}

func TestKeyTransferPolicyStore_TimestampPersistence(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a policy
	before := time.Now().UTC().Add(-time.Second)
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
	}
	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	// Verify timestamp is within expected range
	if created.CreatedAt.Before(before) || created.CreatedAt.After(after) {
		t.Errorf("CreatedAt timestamp %v not within expected range [%v, %v]", created.CreatedAt, before, after)
	}

	// Retrieve and verify timestamp persisted correctly
	retrieved, err := store.Retrieve(created.ID)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	// Compare timestamps (allowing for minor differences due to marshaling)
	if retrieved.CreatedAt.Unix() != created.CreatedAt.Unix() {
		t.Errorf("Retrieved timestamp %v differs from created timestamp %v", retrieved.CreatedAt, created.CreatedAt)
	}
}

func TestKeyTransferPolicyStore_FilePermissions(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a policy
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
	}
	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Check file permissions
	filePath := filepath.Join(dir, created.ID.String())
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	expectedPerm := os.FileMode(0600)
	if fileInfo.Mode().Perm() != expectedPerm {
		t.Errorf("File permissions = %v, want %v", fileInfo.Mode().Perm(), expectedPerm)
	}
}

func TestKeyTransferPolicyStore_JSONMarshaling(t *testing.T) {
	dir := setupKTPTestDir(t)
	defer cleanupKTPTestDir(t, dir)

	store := NewKeyTransferPolicyStore(dir)

	// Create a policy with specific values
	policy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrSigner:     []string{"test-signer"},
				IsvProductId: []uint16{123, 456},
			},
		},
	}
	created, err := store.Create(policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Read the raw file and verify JSON structure
	filePath := filepath.Join(dir, created.ID.String())
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	// Unmarshal to verify valid JSON
	var unmarshaled model.KeyTransferPolicy
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify specific values
	if unmarshaled.AttestationType != model.SGX {
		t.Errorf("Unmarshaled AttestationType = %v, want %v", unmarshaled.AttestationType, model.SGX)
	}
	if len(unmarshaled.SGX.Attributes.MrSigner) != 1 {
		t.Errorf("Unmarshaled MrSigner length = %d, want 1", len(unmarshaled.SGX.Attributes.MrSigner))
	}
}
