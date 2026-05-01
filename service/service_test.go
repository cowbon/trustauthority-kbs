/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"intel/kbs/v1/config"
	"intel/kbs/v1/keymanager"
	"intel/kbs/v1/mocks"
	"intel/kbs/v1/repository"
	"testing"

	"github.com/onsi/gomega"
)

func TestNewValidService(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	conf := config.Configuration{}
	itaClient := mocks.NewMockClient()
	conf = config.Configuration{BearerTokenValidityInMinutes: 5}
	_, err := NewService(itaClient,
		&repository.Repository{},
		&keymanager.RemoteManager{},
		&conf)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestStatusCode(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	he := HandledError{
		Code:    400,
		Message: "Bad Request",
	}
	g.Expect(he.StatusCode()).To(gomega.Equal(400))
	g.Expect(he.Error()).NotTo(gomega.BeNil())
}
