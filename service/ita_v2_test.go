/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/json"
	"intel/kbs/v1/config"
	"intel/kbs/v1/model"
	"net/http"
	"testing"

	"github.com/google/uuid"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"intel/kbs/v1/mocks"
)

// newV2MockService creates a service instance wired with a MockClient.
func newV2MockService(mockClient *mocks.MockClient) service {
	return service{
		itaClient:     mockClient,
		repository:    svcInstance.(service).repository,
		remoteManager: svcInstance.(service).remoteManager,
		config: &config.Configuration{
			TrustAuthorityApiUrl: "https://api.trustauthority.intel.com",
			TrustAuthorityApiKey: "test-api-key",
		},
	}
}

// TestBuildITAV2EndpointURL checks that the helper appends the correct v2 path,
// handles a trailing slash, and strips any existing versioned path so that a
// pre-configured v1 URL does not produce a double-path like .../appraisal/v1/appraisal/v2/attest.
func TestBuildITAV2EndpointURL(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	got := buildITAV2EndpointURL("https://api.trustauthority.intel.com", "/attest")
	g.Expect(got).To(gomega.Equal("https://api.trustauthority.intel.com/appraisal/v2/attest"))

	// Trailing slash should be stripped before appending the path.
	got = buildITAV2EndpointURL("https://api.trustauthority.intel.com/", "/attest")
	g.Expect(got).To(gomega.Equal("https://api.trustauthority.intel.com/appraisal/v2/attest"))

	// A URL pre-configured with a v1 path must not produce a double path.
	got = buildITAV2EndpointURL("https://api.trustauthority.intel.com/appraisal/v1", "/attest")
	g.Expect(got).To(gomega.Equal("https://api.trustauthority.intel.com/appraisal/v2/attest"))
}

// TestGetTokenV2_Success verifies that the composite TDX+NVGPU path delegates to
// itaClient.AttestEvidence and returns the token from the response.
func TestGetTokenV2_Success(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockClient := mocks.NewMockClient()
	mockClient.On("AttestEvidence", mock.Anything, "", mock.AnythingOfType("string")).
		Return(itaConnector.AttestResponse{Token: "tdx-nvgpu-token"}, nil)

	svc := newV2MockService(mockClient)

	token, err := svc.getTokenV2(
		context.Background(),
		[]byte("tdxquote"),
		[]byte("runtimedata"),
		[]byte("eventlog"),
		nil,
		json.RawMessage(`{"test":"nvgpu"}`),
		"req-id",
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(token).To(gomega.Equal("tdx-nvgpu-token"))
	mockClient.AssertExpectations(t)
}

// TestGetTokenV2SGX_Success verifies that the SGX V2 path delegates to
// itaClient.AttestEvidence and returns the token from the response.
func TestGetTokenV2SGX_Success(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockClient := mocks.NewMockClient()
	mockClient.On("AttestEvidence", mock.Anything, "", mock.AnythingOfType("string")).
		Return(itaConnector.AttestResponse{Token: "sgx-v2-token"}, nil)

	svc := newV2MockService(mockClient)

	token, err := svc.getTokenV2SGX(
		context.Background(),
		[]byte("sgxquote"),
		[]byte("runtimedata"),
		nil,
		"req-id",
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(token).To(gomega.Equal("sgx-v2-token"))
	mockClient.AssertExpectations(t)
}

// TestTransferKeyWithEvidence_NVGPUWithV2SGX_Rejected verifies the defense-in-depth
// guard that rejects requests carrying both NVGPU evidence and the V2SGX flag.
func TestTransferKeyWithEvidence_NVGPUWithV2SGX_Rejected(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)

	transReq := &model.KeyTransferRequest{
		Quote: []byte("sgxquote"),
		NVGPU: json.RawMessage(`{"test":"nvgpu"}`),
		V2SGX: true,
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
	handledErr, ok := err.(*HandledError)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(handledErr.Code).To(gomega.Equal(http.StatusBadRequest))
	g.Expect(handledErr.Message).To(gomega.ContainSubstring("nvgpu"))
}
