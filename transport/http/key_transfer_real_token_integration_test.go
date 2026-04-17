/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"intel/kbs/v1/clients/ita"
	"intel/kbs/v1/config"
	"intel/kbs/v1/keymanager"
	"intel/kbs/v1/kmipclient"
	"intel/kbs/v1/model"
	"intel/kbs/v1/repository"
	repomocks "intel/kbs/v1/repository/mocks"
	"intel/kbs/v1/service"
)

func TestHTTPTransferWithRealTokenTDXAndNVGPUPolicy(t *testing.T) {
	token := os.Getenv("KBS_REAL_TOKEN")
	if token == "" {
		t.Skip("set KBS_REAL_TOKEN to run real-token HTTP transfer integration test")
	}

	g := gomega.NewGomegaWithT(t)

	v2Claims := decodeV2ClaimsFromTokenHTTP(t, token)
	legacyClaims := v2Claims.ToAttestationTokenClaim()
	tokenHasHeldData := legacyClaims.AttesterHeldData != ""
	policy := buildPolicyFromRealTokenClaimsHTTP(v2Claims, legacyClaims)

	keyID := uuid.New()
	policyID := uuid.New()
	policy.ID = policyID

	itaClient := ita.NewMockClient()
	itaClient.On("VerifyToken", token).Return(&jwtlib.Token{}, nil).Once()

	keyStore := repomocks.NewFakeKeyStore()
	policyStore := repomocks.NewFakeKeyTransferPolicyStore()
	_, err := policyStore.Create(policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	_, err = keyStore.Create(&model.KeyAttributes{
		ID:               keyID,
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "e2e-http-real-token-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)
	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)

	svc, err := service.NewService(
		itaClient,
		itaClient,
		&repository.Repository{KeyStore: keyStore, KeyTransferPolicyStore: policyStore},
		remoteMgr,
		&config.Configuration{},
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	handler, err := NewHTTPHandler(svc, &config.Configuration{ServicePort: 12780, LogCaller: true, LogLevel: "debug"}, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	requestBody := map[string]interface{}{
		"attestation_token": token,
	}
	requestBytes, err := json.Marshal(requestBody)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, err := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyID.String()+"/transfer", bytes.NewReader(requestBytes))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if !tokenHasHeldData {
		g.Expect(recorder.Code).To(gomega.Equal(http.StatusInternalServerError))
		return
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))

	res := recorder.Result()
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	transferResp := &model.KeyTransferResponse{}
	err = json.Unmarshal(data, transferResp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(len(transferResp.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(transferResp.WrappedSWK)).To(gomega.BeNumerically(">", 0))
}

func decodeV2ClaimsFromTokenHTTP(t *testing.T, token string) *model.AttestationTokenV2Claim {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT payload: %v", err)
	}

	v2Claims := &model.AttestationTokenV2Claim{}
	if err := json.Unmarshal(payload, v2Claims); err != nil {
		t.Fatalf("failed to unmarshal v2 claims: %v", err)
	}

	return v2Claims
}

func buildPolicyFromRealTokenClaimsHTTP(v2 *model.AttestationTokenV2Claim, legacy *model.AttestationTokenClaim) *model.KeyTransferPolicy {
	enforceTrue := true

	policyID := uuid.New()
	if len(legacy.PolicyIdsMatched) > 0 {
		policyID = legacy.PolicyIdsMatched[0].Id
	}

	hwModelSet := map[string]bool{}
	for _, detail := range v2.NVGPU.ClaimDetails {
		if detail.HwModel != "" {
			hwModelSet[detail.HwModel] = true
		}
	}
	hwModels := make([]string, 0, len(hwModelSet))
	for m := range hwModelSet {
		hwModels = append(hwModels, m)
	}
	sort.Strings(hwModels)

	return &model.KeyTransferPolicy{
		AttestationType: model.AttesterTypes{model.TDX, model.NVGPU},
		TDX: &model.TdxPolicy{Attributes: &model.TdxAttributes{
			MrSignerSeam:       []string{legacy.TdxMrSignerSeam},
			MrSeam:             []string{legacy.TdxMrSeam},
			SeamSvn:            &legacy.TdxSeamSvn,
			MRTD:               []string{legacy.TdxMRTD},
			RTMR0:              legacy.TdxRTMR0,
			RTMR1:              legacy.TdxRTMR1,
			RTMR2:              legacy.TdxRTMR2,
			RTMR3:              legacy.TdxRTMR3,
			EnforceTCBUptoDate: &enforceTrue,
		}},
		NVGPU: &model.NvgpuPolicy{
			PolicyIds: []uuid.UUID{policyID},
			Attributes: &model.NvgpuAttributes{
				EnforceOverallAttestationResult: &enforceTrue,
				RequireSecureBoot:               &enforceTrue,
				HwModel:                         hwModels,
			},
		},
	}
}

func serviceGenerateTDXHeldDataPublicKeyBase64(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	pubBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pubBytes, uint32(key.PublicKey.E))
	pubBytes = append(pubBytes, key.PublicKey.N.Bytes()...)

	return base64.StdEncoding.EncodeToString(pubBytes)
}
