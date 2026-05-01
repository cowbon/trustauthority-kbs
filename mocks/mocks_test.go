/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"testing"

	"github.com/google/uuid"
	"github.com/onsi/gomega"

	"intel/kbs/v1/model"
	"intel/kbs/v1/repository/directory"
)

// ---------------------------------------------------------------------------
// MockKeyStore
// ---------------------------------------------------------------------------

func TestMockKeyStore_CreateAndRetrieve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyStore{KeyStore: make(map[uuid.UUID]*model.KeyAttributes)}
	id := uuid.New()
	ka := &model.KeyAttributes{ID: id, Algorithm: "AES", KeyLength: 256}

	created, err := store.Create(ka)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(created.ID).To(gomega.Equal(id))

	retrieved, err := store.Retrieve(id)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(retrieved.Algorithm).To(gomega.Equal("AES"))
}

func TestMockKeyStore_RetrieveNotFound(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyStore{KeyStore: make(map[uuid.UUID]*model.KeyAttributes)}
	_, err := store.Retrieve(uuid.New())
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring(directory.RecordNotFound))
}

func TestMockKeyStore_Update(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyStore{KeyStore: make(map[uuid.UUID]*model.KeyAttributes)}
	id := uuid.New()
	store.KeyStore[id] = &model.KeyAttributes{ID: id, Algorithm: "AES", KeyLength: 256}

	updated, err := store.Update(&model.KeyAttributes{ID: id, Algorithm: "RSA", KeyLength: 3072})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(updated.Algorithm).To(gomega.Equal("RSA"))
}

func TestMockKeyStore_Delete(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyStore{KeyStore: make(map[uuid.UUID]*model.KeyAttributes)}
	id := uuid.New()
	store.KeyStore[id] = &model.KeyAttributes{ID: id}

	err := store.Delete(id)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	err = store.Delete(id) // already deleted
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestMockKeyStore_Search(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyStore{KeyStore: make(map[uuid.UUID]*model.KeyAttributes)}
	id := uuid.New()
	policyID := uuid.New()
	store.KeyStore[id] = &model.KeyAttributes{
		ID: id, Algorithm: "AES", KeyLength: 256,
		CurveType: "", TransferPolicyId: policyID,
	}

	// nil criteria → all keys
	keys, err := store.Search(nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(keys)).To(gomega.Equal(1))

	// empty criteria → error
	_, err = store.Search(&model.KeyFilterCriteria{})
	g.Expect(err).To(gomega.HaveOccurred())

	// filter by algorithm
	keys, err = store.Search(&model.KeyFilterCriteria{Algorithm: "AES"})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(keys)).To(gomega.Equal(1))

	// filter by key length
	keys, err = store.Search(&model.KeyFilterCriteria{KeyLength: 256})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(keys)).To(gomega.Equal(1))

	// filter by curve type (no match)
	keys, err = store.Search(&model.KeyFilterCriteria{CurveType: "P-384"})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(keys)).To(gomega.Equal(0))

	// filter by transfer policy
	keys, err = store.Search(&model.KeyFilterCriteria{TransferPolicyId: policyID})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(keys)).To(gomega.Equal(1))
}

func TestNewFakeKeyStore(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewFakeKeyStore()
	g.Expect(store).NotTo(gomega.BeNil())
	g.Expect(len(store.KeyStore)).To(gomega.BeNumerically(">", 0))
}

// ---------------------------------------------------------------------------
// MockKeyTransferPolicyStore
// ---------------------------------------------------------------------------

func TestMockKeyTransferPolicyStore_CreateAndRetrieve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyTransferPolicyStore{KeyTransferPolicyStore: make(map[uuid.UUID]*model.KeyTransferPolicy)}
	id := uuid.New()
	policy := &model.KeyTransferPolicy{ID: id, AttestationType: model.AttesterTypes{model.SGX}}

	created, err := store.Create(policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(created.ID).To(gomega.Equal(id))

	retrieved, err := store.Retrieve(id)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(retrieved.ID).To(gomega.Equal(id))
}

func TestMockKeyTransferPolicyStore_RetrieveNotFound(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyTransferPolicyStore{KeyTransferPolicyStore: make(map[uuid.UUID]*model.KeyTransferPolicy)}
	_, err := store.Retrieve(uuid.New())
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestMockKeyTransferPolicyStore_UpdateDeleteSearch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockKeyTransferPolicyStore{KeyTransferPolicyStore: make(map[uuid.UUID]*model.KeyTransferPolicy)}
	id := uuid.New()
	policy := &model.KeyTransferPolicy{ID: id, AttestationType: model.AttesterTypes{model.SGX}}
	store.KeyTransferPolicyStore[id] = policy

	// Update existing
	_, err := store.Update(&model.KeyTransferPolicy{ID: id})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Update non-existent
	_, err = store.Update(&model.KeyTransferPolicy{ID: uuid.New()})
	g.Expect(err).To(gomega.HaveOccurred())

	// Search nil → all
	policies, err := store.Search(nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(policies)).To(gomega.BeNumerically(">=", 1))

	// Search empty criteria → all
	policies, err = store.Search(&model.KeyTransferPolicyFilterCriteria{})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(policies)).To(gomega.BeNumerically(">=", 1))

	// Delete
	err = store.Delete(id)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Delete again → error
	err = store.Delete(id)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestNewFakeKeyTransferPolicyStore(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewFakeKeyTransferPolicyStore()
	g.Expect(store).NotTo(gomega.BeNil())
	g.Expect(len(store.KeyTransferPolicyStore)).To(gomega.BeNumerically(">", 0))
}

// ---------------------------------------------------------------------------
// MockUserStore
// ---------------------------------------------------------------------------

func TestMockUserStore_CRUD(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockUserStore{UserStore: make(map[uuid.UUID]*model.UserInfo)}
	id := uuid.New()
	user := &model.UserInfo{ID: id, Username: "testuser"}

	created, err := store.Create(user)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(created.ID).To(gomega.Equal(id))

	retrieved, err := store.Retrieve(id)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(retrieved.Username).To(gomega.Equal("testuser"))

	user.Username = "updated"
	_, err = store.Update(user)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	err = store.Delete(id)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	_, err = store.Retrieve(id)
	g.Expect(err).To(gomega.HaveOccurred())

	err = store.Delete(id)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestMockUserStore_Search(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := &MockUserStore{UserStore: make(map[uuid.UUID]*model.UserInfo)}
	id := uuid.New()
	store.UserStore[id] = &model.UserInfo{ID: id, Username: "alice"}

	// nil criteria → all
	users, err := store.Search(nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(users)).To(gomega.Equal(1))

	// empty criteria → all
	users, err = store.Search(&model.UserFilterCriteria{})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(users)).To(gomega.Equal(1))

	// search by username — match
	users, err = store.Search(&model.UserFilterCriteria{Username: "alice"})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(users)).To(gomega.Equal(1))

	// search by username — no match
	users, err = store.Search(&model.UserFilterCriteria{Username: "bob"})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(users)).To(gomega.Equal(0))
}

func TestNewFakeUserStore(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewFakeUserStore()
	g.Expect(store).NotTo(gomega.BeNil())
	g.Expect(len(store.UserStore)).To(gomega.BeNumerically(">", 0))
}

// ---------------------------------------------------------------------------
// MockClient
// ---------------------------------------------------------------------------

func TestNewMockClient(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	client := NewMockClient()
	g.Expect(client).NotTo(gomega.BeNil())
}
