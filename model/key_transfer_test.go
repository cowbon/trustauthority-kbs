/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/onsi/gomega"
)

func TestKeyTransferRequestUnmarshalJSON_AttestationToken(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{"attestation_token":"my.token.here"}`)
	var req KeyTransferRequest
	err := json.Unmarshal(data, &req)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(req.AttestationToken).To(gomega.Equal("my.token.here"))
}

func TestKeyTransferRequestUnmarshalJSON_NestedTDX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	data := []byte(`{"tdx":{"quote":"dGVzdA==","runtime_data":"cnVudGltZQ==","event_log":"ZXZlbnQ="}}`)
	var req KeyTransferRequest
	err := json.Unmarshal(data, &req)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(req.Quote).To(gomega.Equal([]byte("test")))
	g.Expect(req.RuntimeData).To(gomega.Equal([]byte("runtime")))
	g.Expect(req.EventLog).To(gomega.Equal([]byte("event")))
	g.Expect(req.V2SGX).To(gomega.BeFalse())
}

func TestKeyTransferRequestUnmarshalJSON_SGXWithNVGPUReturnsError(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	// SGX and NVGPU together must be rejected.
	data := []byte(`{"sgx":{"quote":"dGVzdA=="},"nvgpu":{"test":"data"}}`)
	var req KeyTransferRequest
	err := json.Unmarshal(data, &req)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("nvgpu"))
}

func TestKeyTransferRequestUnmarshalJSON_SGXAndTDXReturnsError(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	// Both sgx and tdx nested objects are ambiguous — must be rejected.
	data := []byte(`{"sgx":{"quote":"dGVzdA=="},"tdx":{"quote":"dGVzdA=="}}`)
	var req KeyTransferRequest
	err := json.Unmarshal(data, &req)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("sgx and tdx"))
}

func TestKeyAttributesToKeyResponse(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	id := uuid.New()
	policyId := uuid.New()
	ka := &KeyAttributes{
		ID:               id,
		Algorithm:        "AES",
		KeyLength:        256,
		TransferPolicyId: policyId,
		TransferLink:     "https://example.com/keys/" + id.String() + "/transfer",
	}
	resp := ka.ToKeyResponse()
	g.Expect(resp).NotTo(gomega.BeNil())
	g.Expect(resp.ID).To(gomega.Equal(id))
	g.Expect(resp.KeyInfo).NotTo(gomega.BeNil())
	g.Expect(resp.KeyInfo.Algorithm).To(gomega.Equal("AES"))
	g.Expect(resp.KeyInfo.KeyLength).To(gomega.Equal(256))
	g.Expect(resp.TransferPolicyID).To(gomega.Equal(policyId))
}
