/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"intel/kbs/v1/mocks"
	"testing"

	"github.com/onsi/gomega"
)

func TestCreateAdminUser(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var userStore *mocks.MockUserStore = mocks.NewFakeUserStore()
	ac := CreateAdminUser{
		AdminUsername: "testAdmin",
		AdminPassword: "testPassword",
		UserStore:     userStore,
	}

	err := ac.CreateAdminUser()
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestCreateAdminUserWithInvalidCreds(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var userStore *mocks.MockUserStore = mocks.NewFakeUserStore()
	ac := CreateAdminUser{
		AdminUsername: "",
		AdminPassword: "",
		UserStore:     userStore,
	}

	err := ac.CreateAdminUser()
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestCreateAdminUserWithSameName(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var userStore *mocks.MockUserStore = mocks.NewFakeUserStore()
	ac := CreateAdminUser{
		AdminUsername: "userAdmin",
		AdminPassword: "testPassword",
		UserStore:     userStore,
	}

	err := ac.CreateAdminUser()
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
