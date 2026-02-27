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

// createSampleUser creates a sample UserInfo for testing
func createSampleUser(username string) *model.UserInfo {
	return &model.UserInfo{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: []byte("hashed_password"),
		PasswordCost: 10,
		Permissions:  []string{"keys:create", "keys:search"},
	}
}

func TestNewUserStore(t *testing.T) {
	dir := "/test/dir"
	us := NewUserStore(dir)

	if us == nil {
		t.Fatal("Expected non-nil userStore")
	}

	if us.dir != dir {
		t.Errorf("Expected dir %s, got %s", dir, us.dir)
	}
}

func TestUserStore_Create_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	user := createSampleUser("testuser")
	user.ID = uuid.Nil // Test auto-generation of ID

	result, err := us.Create(user)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.ID == uuid.Nil {
		t.Error("Expected ID to be auto-generated")
	}

	if result.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	if result.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", result.Username)
	}

	// Verify file was created
	filePath := filepath.Join(dir, result.ID.String())
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("User file was not created")
	}
}

func TestUserStore_Create_WithExistingID(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	user := createSampleUser("admin")
	originalID := user.ID

	result, err := us.Create(user)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if result.ID != originalID {
		t.Error("User ID should not change when already set")
	}

	if result.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
}

func TestUserStore_Create_InvalidDirectory(t *testing.T) {
	us := NewUserStore("/nonexistent/invalid/path")
	user := createSampleUser("testuser")

	_, err := us.Create(user)
	if err == nil {
		t.Error("Expected error for invalid directory")
	}
}

func TestUserStore_Retrieve_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	originalUser := createSampleUser("retrievetest")

	// Create the user first
	created, err := us.Create(originalUser)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Retrieve the user
	retrievedUser, err := us.Retrieve(created.ID)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}

	if retrievedUser == nil {
		t.Fatal("Expected non-nil retrieved user")
	}

	if retrievedUser.ID != created.ID {
		t.Errorf("Expected ID %v, got %v", created.ID, retrievedUser.ID)
	}

	if retrievedUser.Username != originalUser.Username {
		t.Errorf("Expected username %s, got %s", originalUser.Username, retrievedUser.Username)
	}

	if len(retrievedUser.Permissions) != len(originalUser.Permissions) {
		t.Errorf("Expected %d permissions, got %d", len(originalUser.Permissions), len(retrievedUser.Permissions))
	}
}

func TestUserStore_Retrieve_NotFound(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	nonExistentID := uuid.New()

	_, err := us.Retrieve(nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent user")
	}

	if err.Error() != RecordNotFound {
		t.Errorf("Expected '%s' error, got '%v'", RecordNotFound, err)
	}
}

func TestUserStore_Retrieve_CorruptedFile(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	userID := uuid.New()

	// Write corrupted data
	filePath := filepath.Join(dir, userID.String())
	if err := os.WriteFile(filePath, []byte("corrupted json data"), 0600); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	_, err := us.Retrieve(userID)
	if err == nil {
		t.Error("Expected error for corrupted file")
	}
}

func TestUserStore_Delete_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	user := createSampleUser("deletetest")

	// Create the user
	created, err := us.Create(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Delete the user
	err = us.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file was deleted
	filePath := filepath.Join(dir, created.ID.String())
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("User file still exists after deletion")
	}
}

func TestUserStore_Delete_NotFound(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	nonExistentID := uuid.New()

	err := us.Delete(nonExistentID)
	if err == nil {
		t.Error("Expected error for non-existent user")
	}

	if err.Error() != RecordNotFound {
		t.Errorf("Expected '%s' error, got '%v'", RecordNotFound, err)
	}
}

func TestUserStore_Update_Success(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	originalUser := createSampleUser("updatetest")

	// Create the user
	created, err := us.Create(originalUser)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Wait a bit to ensure UpdatedAt is different
	time.Sleep(time.Millisecond * 10)

	// Update the user
	created.Permissions = []string{"keys:create", "keys:search", "keys:delete"}
	created.PasswordCost = 12

	updatedUser, err := us.Update(created)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if updatedUser.PasswordCost != 12 {
		t.Errorf("Expected PasswordCost 12, got %d", updatedUser.PasswordCost)
	}

	if len(updatedUser.Permissions) != 3 {
		t.Errorf("Expected 3 permissions, got %d", len(updatedUser.Permissions))
	}

	if updatedUser.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	if !updatedUser.UpdatedAt.After(updatedUser.CreatedAt) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	// Retrieve and verify
	retrievedUser, err := us.Retrieve(created.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user: %v", err)
	}

	if len(retrievedUser.Permissions) != 3 {
		t.Error("Updated permissions not persisted")
	}

	if retrievedUser.PasswordCost != 12 {
		t.Error("Updated password cost not persisted")
	}
}

func TestUserStore_Update_NonExistent(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	user := createSampleUser("nonexistent")

	_, err := us.Update(user)
	if err == nil {
		t.Error("Expected error for updating non-existent user")
	}
}

func TestUserStore_Search_EmptyStore(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	users, err := us.Search(nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("Expected empty result, got %d users", len(users))
	}
}

func TestUserStore_Search_AllUsers(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create multiple users
	user1 := createSampleUser("admin")
	user2 := createSampleUser("operator")
	user3 := createSampleUser("viewer")

	for _, user := range []*model.UserInfo{user1, user2, user3} {
		if _, err := us.Create(user); err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
	}

	// Search without criteria
	users, err := us.Search(nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}
}

func TestUserStore_Search_EmptyCriteria(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create users
	user1 := createSampleUser("user1")
	user2 := createSampleUser("user2")

	for _, user := range []*model.UserInfo{user1, user2} {
		if _, err := us.Create(user); err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
	}

	// Search with empty criteria
	criteria := &model.UserFilterCriteria{}
	users, err := us.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(users) != 2 {
		t.Errorf("Expected 2 users with empty criteria, got %d", len(users))
	}
}

func TestUserStore_Search_ByUsername(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create users
	admin := createSampleUser("admin")
	operator := createSampleUser("operator")
	viewer := createSampleUser("viewer")

	for _, user := range []*model.UserInfo{admin, operator, viewer} {
		if _, err := us.Create(user); err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
	}

	// Search for specific username
	criteria := &model.UserFilterCriteria{Username: "operator"}
	users, err := us.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}

	if users[0].Username != "operator" {
		t.Errorf("Expected username 'operator', got '%s'", users[0].Username)
	}
}

func TestUserStore_Search_UsernameNotFound(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create a user
	user := createSampleUser("admin")
	if _, err := us.Create(user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Search for non-existent username
	criteria := &model.UserFilterCriteria{Username: "nonexistent"}
	users, err := us.Search(criteria)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("Expected 0 users, got %d", len(users))
	}
}

func TestUserStore_Search_InvalidFileName(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create a file with invalid UUID name
	invalidFile := filepath.Join(dir, "not-a-uuid.txt")
	if err := os.WriteFile(invalidFile, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create invalid file: %v", err)
	}

	_, err := us.Search(nil)
	if err == nil {
		t.Error("Expected error for invalid file name")
	}
}

func TestUserStore_Search_CorruptedFile(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create a valid user
	user := createSampleUser("validuser")
	if _, err := us.Create(user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a corrupted user file
	corruptedID := uuid.New()
	corruptedFile := filepath.Join(dir, corruptedID.String())
	if err := os.WriteFile(corruptedFile, []byte("corrupted"), 0600); err != nil {
		t.Fatalf("Failed to create corrupted file: %v", err)
	}

	_, err := us.Search(nil)
	if err == nil {
		t.Error("Expected error for corrupted file during search")
	}
}

func TestUserStore_Create_PersistenceVerification(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)
	user := createSampleUser("persisttest")
	user.Permissions = []string{"keys:create", "keys:delete", "users:search"}

	created, err := us.Create(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Read file directly to verify data
	filePath := filepath.Join(dir, created.ID.String())
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read user file: %v", err)
	}

	var savedUser model.UserInfo
	if err := json.Unmarshal(data, &savedUser); err != nil {
		t.Fatalf("Failed to unmarshal user: %v", err)
	}

	if savedUser.Username != "persisttest" {
		t.Error("Username not persisted correctly")
	}

	if len(savedUser.Permissions) != 3 {
		t.Error("Permissions not persisted correctly")
	}

	if savedUser.PasswordCost != 10 {
		t.Error("PasswordCost not persisted correctly")
	}
}

func TestUserStore_MultipleOperations(t *testing.T) {
	dir := setupTestDir(t)
	defer cleanupTestDir(t, dir)

	us := NewUserStore(dir)

	// Create multiple users
	users := []*model.UserInfo{
		createSampleUser("user1"),
		createSampleUser("user2"),
		createSampleUser("user3"),
	}

	var createdIDs []uuid.UUID
	for _, user := range users {
		created, err := us.Create(user)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
		createdIDs = append(createdIDs, created.ID)
	}

	// Update one user
	updateUser, err := us.Retrieve(createdIDs[1])
	if err != nil {
		t.Fatalf("Failed to retrieve user for update: %v", err)
	}
	updateUser.Permissions = []string{"admin"}
	if _, err := us.Update(updateUser); err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	// Delete one user
	if err := us.Delete(createdIDs[2]); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	// Search to verify state
	allUsers, err := us.Search(nil)
	if err != nil {
		t.Fatalf("Failed to search users: %v", err)
	}

	if len(allUsers) != 2 {
		t.Errorf("Expected 2 users remaining, got %d", len(allUsers))
	}

	// Verify updated user
	updatedUser, err := us.Retrieve(createdIDs[1])
	if err != nil {
		t.Fatalf("Failed to retrieve updated user: %v", err)
	}

	if len(updatedUser.Permissions) != 1 || updatedUser.Permissions[0] != "admin" {
		t.Error("User update not reflected correctly")
	}
}
