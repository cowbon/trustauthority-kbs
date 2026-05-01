/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/json"
	"intel/kbs/v1/mocks"
	"intel/kbs/v1/model"
	"intel/kbs/v1/repository"
	"testing"

	"github.com/google/uuid"
	"github.com/onsi/gomega"
)

var userID uuid.UUID
var userStore *mocks.MockUserStore = mocks.NewFakeUserStore()
var svcUserTestInstance Service = service{
	itaClient: itaClientConnector,
	repository: &repository.Repository{
		UserStore:              userStore,
		KeyStore:               keyStore,
		KeyTransferPolicyStore: keyTransPolicyStore,
	},
	remoteManager: kRemoteManager,
	config:        nil,
}

func TestUserCreate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	var request *model.User
	userJson := `{
			"username": "keysAdmin", 
			"password" : "keysAdminPassword", 
			"permissions" : ["keys:create"]
        }`

	json.Unmarshal([]byte(userJson), &request)
	response, err := svc.CreateUser(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	userID = response.ID
}

func TestUserCreateExistingUsername(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	var request *model.User
	userJson := `{
			"username": "keyManager"
        }`

	json.Unmarshal([]byte(userJson), &request)
	_, err := svc.CreateUser(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestUserUpdate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.UpdateUserRequest{
		ID: userID,
		UpdateUser: &model.User{
			Username:    "updatedKeyUsername",
			Password:    "updatedKeyPassword",
			Permissions: []string{"keys:update"},
		},
	}

	_, err := svc.UpdateUser(context.Background(), &request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserUpdateExistingUsername(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.UpdateUserRequest{
		ID: userID,
		UpdateUser: &model.User{
			Username: "keyManager",
		},
	}

	_, err := svc.UpdateUser(context.Background(), &request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestUserUpdateInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.UpdateUserRequest{
		ID: uuid.New(),
	}

	_, err := svc.UpdateUser(context.Background(), &request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestUserSearch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.UserFilterCriteria{}
	_, err := svc.SearchUser(context.Background(), &request)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	request = model.UserFilterCriteria{
		Username: "keyAdmin",
	}
	_, err = svc.SearchUser(context.Background(), &request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserRetrieve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	_, err := svc.RetrieveUser(context.Background(), userID)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserRetrieveInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	tmpId := uuid.New()
	_, err := svc.RetrieveUser(context.Background(), tmpId)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestUserDelete(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	_, err := svc.DeleteUser(context.Background(), userID)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserDeleteInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	tmpId := uuid.New()
	_, err := svc.DeleteUser(context.Background(), tmpId)
	g.Expect(err).To(gomega.HaveOccurred())
}
