/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/stretchr/testify/mock"
)

// MockClient is a mock of ITAClient interface
type MockClient struct {
	mock.Mock
}

// NewMockClient creates a new mock instance
func NewMockClient() *MockClient {
	return &MockClient{}
}

// VerifyToken mocks base method
func (m *MockClient) VerifyToken(token string) (*jwt.Token, error) {
	args := m.Called(token)
	return args.Get(0).(*jwt.Token), args.Error(1)
}

// AttestEvidence mocks base method
func (m *MockClient) AttestEvidence(evidence interface{}, cloudProvider string, reqId string) (itaConnector.AttestResponse, error) {
	args := m.Called(evidence, cloudProvider, reqId)
	return args.Get(0).(itaConnector.AttestResponse), args.Error(1)
}

// GetAKCertificate mocks base method
func (m *MockClient) GetAKCertificate(ekCert *x509.Certificate, akTpmtPublic []byte) ([]byte, []byte, []byte, error) {
	args := m.Called(ekCert, akTpmtPublic)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Get(2).([]byte), args.Error(3)
}

// GetToken mocks base method
func (m *MockClient) GetToken(tokenArgs itaConnector.GetTokenArgs) (itaConnector.GetTokenResponse, error) {
	args := m.Called(tokenArgs)
	return args.Get(0).(itaConnector.GetTokenResponse), args.Error(1)
}

// GetNonce mocks base method
func (m *MockClient) GetNonce(nonceArgs itaConnector.GetNonceArgs) (itaConnector.GetNonceResponse, error) {
	args := m.Called(nonceArgs)
	return args.Get(0).(itaConnector.GetNonceResponse), args.Error(1)
}

func (m *MockClient) GetTokenSigningCertificates() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) Attest(args itaConnector.AttestArgs) (itaConnector.AttestResponse, error) {
	//TODO implement me
	panic("implement me")
}
