/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"intel/kbs/v1/clients/ita"
	"intel/kbs/v1/config"
	"intel/kbs/v1/keymanager"
	"intel/kbs/v1/kmipclient"
	"intel/kbs/v1/model"
	"intel/kbs/v1/repository"
	repomocks "intel/kbs/v1/repository/mocks"
	cns "intel/kbs/v1/repository/mocks/constants"
)

const (
	defaultITAAPIURL  = "https://api-dev02-user2.ita-dev.adsdcsp.com/appraisal/v2"
	defaultITABaseURL = "https://amber-dev02-user2.ita-dev.adsdcsp.com"
	defaultITAAPIKey  = "djI6YWU1NzE4MmUtMDMyMy00ZGQwLTkxMTctNTYyNTRkYzQ1NWVlOnB0S3hoZWtINGkxTEJ4QjFPQ2R6c0tqRG5rSG5KcFE1WHBVVHpiemM="
)

func TestE2EKeyReleaseWithTDXAndNVGPUPolicy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClient := ita.NewMockClient()
	keyStore := repomocks.NewFakeKeyStore()
	policyStore := repomocks.NewFakeKeyTransferPolicyStore()

	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)

	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)
	svc := service{
		itaApiClient:           itaClient,
		itaTokenVerifierClient: itaClient,
		repository: &repository.Repository{
			KeyStore:               keyStore,
			KeyTransferPolicyStore: policyStore,
		},
		remoteManager: remoteMgr,
	}

	nvgpuPolicyID := uuid.New()
	policyID := uuid.New()
	keyID := uuid.New()
	enforceTrue := true
	seamSvn := uint16(0)

	_, err := policyStore.Create(&model.KeyTransferPolicy{
		ID:              policyID,
		AttestationType: model.AttesterTypes{model.TDX, model.NVGPU},
		TDX: &model.TdxPolicy{Attributes: &model.TdxAttributes{
			MrSignerSeam:       []string{cns.ValidMrSignerSeam},
			MrSeam:             []string{cns.ValidMrSeam},
			SeamSvn:            &seamSvn,
			MRTD:               []string{cns.ValidMRTD},
			RTMR0:              cns.ValidRTMR0,
			RTMR1:              cns.ValidRTMR1,
			RTMR2:              cns.ValidRTMR2,
			RTMR3:              cns.ValidRTMR3,
			EnforceTCBUptoDate: &enforceTrue,
		}},
		NVGPU: &model.NvgpuPolicy{
			PolicyIds: []uuid.UUID{nvgpuPolicyID},
			Attributes: &model.NvgpuAttributes{
				EnforceOverallAttestationResult: &enforceTrue,
				RequireSecureBoot:               &enforceTrue,
				HwModel:                         []string{"GB100"},
			},
		},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	_, err = keyStore.Create(&model.KeyAttributes{
		ID:               keyID,
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "e2e-local-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	token := buildTDXNVGPUV2TokenForE2E(t, nvgpuPolicyID)
	itaClient.On("VerifyToken", token).Return(&jwtlib.Token{}, nil).Once()

	resp, err := svc.TransferKeyWithEvidence(context.Background(), TransferKeyRequest{
		KeyId: keyID,
		KeyTransferRequest: &model.KeyTransferRequest{
			AttestationToken: token,
		},
	})

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp).NotTo(gomega.BeNil())
	g.Expect(resp.KeyTransferResponse).NotTo(gomega.BeNil())
	g.Expect(len(resp.KeyTransferResponse.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(resp.KeyTransferResponse.WrappedSWK)).To(gomega.BeNumerically(">", 0))
}

func buildTDXNVGPUV2TokenForE2E(t *testing.T, nvgpuPolicyID uuid.UUID) string {
	t.Helper()
	tdxHeldData := generateTDXHeldDataPublicKeyBase64(t)

	header := map[string]interface{}{
		"alg": "PS384",
		"typ": "JWT",
	}
	payload := map[string]interface{}{
		"ver":         "2.0.0",
		"eat_profile": "https://example.com/eat_profile.html",
		"intuse":      "generic",
		"policy_ids_matched": []map[string]interface{}{
			{"id": nvgpuPolicyID.String(), "version": "v1"},
		},
		"tdx": map[string]interface{}{
			"attester_type":       "TDX",
			"attester_tcb_status": "UpToDate",
			"attester_held_data":  tdxHeldData,
			"tdx_mrseam":          cns.ValidMrSeam,
			"tdx_mrsignerseam":    cns.ValidMrSignerSeam,
			"tdx_mrtd":            cns.ValidMRTD,
			"tdx_rtmr0":           cns.ValidRTMR0,
			"tdx_rtmr1":           cns.ValidRTMR1,
			"tdx_rtmr2":           cns.ValidRTMR2,
			"tdx_rtmr3":           cns.ValidRTMR3,
			"tdx_seamsvn":         0,
		},
		"nvgpu": map[string]interface{}{
			"attester_type":               "NVGPU",
			"x-nvidia-overall-att-result": true,
			"claim_details": map[string]interface{}{
				"GPU-0": map[string]interface{}{"hwmodel": "GB100", "secboot": true, "dbgstat": "disabled", "measres": "success"},
			},
		},
	}

	hdrBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal jwt header: %v", err)
	}
	plBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal jwt payload: %v", err)
	}

	// Signature is unused in mocked verifier path; only JWT structure and claims payload matter.
	return base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(plBytes) + ".sig"
}

func generateTDXHeldDataPublicKeyBase64(t *testing.T) string {
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

func TestE2EKeyReleaseWithRealTokenTDXAndNVGPUPolicy(t *testing.T) {
	token := getTokenFromEnvOrReqJSON(t)

	g := gomega.NewGomegaWithT(t)

	v2Claims := decodeV2ClaimsFromToken(t, token)
	g.Expect(v2Claims.TDX).NotTo(gomega.BeNil())
	g.Expect(v2Claims.NVGPU).NotTo(gomega.BeNil())

	legacyClaims := v2Claims.ToAttestationTokenClaim()
	if legacyClaims.AttesterHeldData == "" && getAttesterRuntimePublicKey(legacyClaims) == "" {
		// Some ITA V2 tokens may omit held-data; inject one for wrap-key verification.
		legacyClaims.AttesterHeldData = generateTDXHeldDataPublicKeyBase64(t)
	}

	policy := buildPolicyFromRealTokenClaims(v2Claims, legacyClaims)

	keyID := uuid.New()
	policyID := uuid.New()
	policy.ID = policyID

	keyStore := repomocks.NewFakeKeyStore()
	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)
	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)

	_, err := keyStore.Create(&model.KeyAttributes{
		ID:               keyID,
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "e2e-real-token-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	svc := service{remoteManager: remoteMgr}
	resp, status, err := svc.validateClaimsAndGetKey(legacyClaims, policy, "AES", legacyClaims.AttesterHeldData, keyID)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(status).To(gomega.Equal(200))
	g.Expect(resp).NotTo(gomega.BeNil())

	transferResp, ok := resp.(*model.KeyTransferResponse)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(len(transferResp.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(transferResp.WrappedSWK)).To(gomega.BeNumerically(">", 0))
}

func TestE2ETransferKeyWithEvidenceRealToken(t *testing.T) {
	token := getTokenFromEnvOrReqJSON(t)

	g := gomega.NewGomegaWithT(t)

	v2Claims := decodeV2ClaimsFromToken(t, token)
	g.Expect(v2Claims.TDX).NotTo(gomega.BeNil())
	g.Expect(v2Claims.NVGPU).NotTo(gomega.BeNil())

	legacyClaims := v2Claims.ToAttestationTokenClaim()
	policy := buildPolicyFromRealTokenClaims(v2Claims, legacyClaims)

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
		KmipKeyID:        "e2e-real-token-transfer-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)
	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)

	svc := service{
		itaApiClient:           itaClient,
		itaTokenVerifierClient: itaClient,
		repository: &repository.Repository{
			KeyStore:               keyStore,
			KeyTransferPolicyStore: policyStore,
		},
		remoteManager: remoteMgr,
	}

	resp, err := svc.TransferKeyWithEvidence(context.Background(), TransferKeyRequest{
		KeyId: keyID,
		KeyTransferRequest: &model.KeyTransferRequest{
			AttestationToken: token,
		},
	})

	if legacyClaims.AttesterHeldData == "" && getAttesterRuntimePublicKey(legacyClaims) == "" {
		g.Expect(err).To(gomega.HaveOccurred())
		g.Expect(err.Error()).To(gomega.ContainSubstring("Error in getting public key"))
		return
	}

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp).NotTo(gomega.BeNil())
	g.Expect(resp.KeyTransferResponse).NotTo(gomega.BeNil())
	g.Expect(len(resp.KeyTransferResponse.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(resp.KeyTransferResponse.WrappedSWK)).To(gomega.BeNumerically(">", 0))
}

func TestE2ETransferKeyWithEvidenceRealVerifier(t *testing.T) {
	token := getTokenFromEnvOrReqJSON(t)
	apiURL := firstNonEmpty(os.Getenv("KBS_ITA_API_URL"), defaultITAAPIURL)
	baseURL := firstNonEmpty(os.Getenv("KBS_ITA_BASE_URL"), defaultITABaseURL)
	apiKey := firstNonEmpty(os.Getenv("KBS_ITA_API_KEY"), defaultITAAPIKey)

	g := gomega.NewGomegaWithT(t)

	v2Claims := decodeV2ClaimsFromToken(t, token)
	legacyClaims := v2Claims.ToAttestationTokenClaim()
	policy := buildPolicyFromRealTokenClaims(v2Claims, legacyClaims)

	keyID := uuid.New()
	policyID := uuid.New()
	policy.ID = policyID

	keyStore := repomocks.NewFakeKeyStore()
	policyStore := repomocks.NewFakeKeyTransferPolicyStore()
	_, err := policyStore.Create(policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	_, err = keyStore.Create(&model.KeyAttributes{
		ID:               keyID,
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "e2e-real-verifier-transfer-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)
	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)

	taConf := &config.Configuration{
		TrustAuthorityApiUrl:  apiURL,
		TrustAuthorityBaseUrl: baseURL,
		TrustAuthorityApiKey:  apiKey,
	}
	verifierClient, err := ita.NewITAClient(taConf, hostFromURL(t, baseURL))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	svc := service{
		itaApiClient:           verifierClient,
		itaTokenVerifierClient: verifierClient,
		repository: &repository.Repository{
			KeyStore:               keyStore,
			KeyTransferPolicyStore: policyStore,
		},
		remoteManager: remoteMgr,
		config:        taConf,
	}

	resp, err := svc.TransferKeyWithEvidence(context.Background(), TransferKeyRequest{
		KeyId: keyID,
		KeyTransferRequest: &model.KeyTransferRequest{
			AttestationToken: token,
		},
	})

	if legacyClaims.AttesterHeldData == "" && getAttesterRuntimePublicKey(legacyClaims) == "" {
		g.Expect(err).To(gomega.HaveOccurred())
		g.Expect(err.Error()).To(gomega.ContainSubstring("Error in getting public key"))
		return
	}

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp).NotTo(gomega.BeNil())
	g.Expect(resp.KeyTransferResponse).NotTo(gomega.BeNil())
	g.Expect(len(resp.KeyTransferResponse.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(resp.KeyTransferResponse.WrappedSWK)).To(gomega.BeNumerically(">", 0))
}

func TestE2ETransferKeyWithEvidence_GetTokenPath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClient := ita.NewMockClient()
	keyStore := repomocks.NewFakeKeyStore()
	policyStore := repomocks.NewFakeKeyTransferPolicyStore()

	policyID := uuid.New()
	keyID := uuid.New()
	_, err := policyStore.Create(&model.KeyTransferPolicy{
		ID:              policyID,
		AttestationType: model.AttesterTypes{model.TDX},
		TDX:             &model.TdxPolicy{Attributes: &model.TdxAttributes{}},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	_, err = keyStore.Create(&model.KeyAttributes{
		ID:               keyID,
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "e2e-gettoken-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)
	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)

	tdxPolicyID := uuid.New()
	token := buildTDXNVGPUV2TokenForE2E(t, tdxPolicyID)
	itaClient.On("GetToken", mock.AnythingOfType("connector.GetTokenArgs")).Return(itaConnector.GetTokenResponse{Token: token}, nil).Once()
	itaClient.On("VerifyToken", token).Return(&jwtlib.Token{}, nil).Once()

	svc := service{
		itaApiClient:           itaClient,
		itaTokenVerifierClient: itaClient,
		repository: &repository.Repository{
			KeyStore:               keyStore,
			KeyTransferPolicyStore: policyStore,
		},
		remoteManager: remoteMgr,
	}

	resp, err := svc.TransferKeyWithEvidence(context.Background(), TransferKeyRequest{
		KeyId:           keyID,
		AttestationType: model.TDX.String(),
		KeyTransferRequest: &model.KeyTransferRequest{
			Quote:         []byte("fake-quote"),
			RuntimeData:   []byte("fake-runtime"),
			EventLog:      []byte("fake-eventlog"),
			VerifierNonce: &itaConnector.VerifierNonce{},
		},
	})

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp).NotTo(gomega.BeNil())
	g.Expect(resp.KeyTransferResponse).NotTo(gomega.BeNil())
	g.Expect(len(resp.KeyTransferResponse.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(resp.KeyTransferResponse.WrappedSWK)).To(gomega.BeNumerically(">", 0))
	itaClient.AssertExpectations(t)
}

func TestE2ETransferKeyWithEvidence_GetTokenV2Path_MissingHeldDataFallsBackToRuntimeData(t *testing.T) {
	reqJSONPath := firstNonEmpty(os.Getenv("KBS_REQ_JSON_PATH"), filepath.Join("..", "transport", "http", "req.json"))
	reqBytes, err := os.ReadFile(reqJSONPath)
	if err != nil {
		t.Skipf("unable to read req.json for v2 evidence test: %v", err)
	}

	var rawReq struct {
		NVGPU json.RawMessage `json:"nvgpu"`
	}
	if err := json.Unmarshal(reqBytes, &rawReq); err != nil {
		t.Fatalf("failed to parse req.json: %v", err)
	}

	g := gomega.NewGomegaWithT(t)

	mockToken := buildTDXNVGPUV2TokenNoHeldDataWithRuntimeDataForE2E(t)
	v2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockToken})
	}))
	defer v2Server.Close()

	keyStore := repomocks.NewFakeKeyStore()
	policyStore := repomocks.NewFakeKeyTransferPolicyStore()

	policyID := uuid.New()
	keyID := uuid.New()
	_, err = policyStore.Create(&model.KeyTransferPolicy{
		ID:              policyID,
		AttestationType: model.AttesterTypes{model.NVGPU},
		NVGPU:           &model.NvgpuPolicy{Attributes: &model.NvgpuAttributes{}},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	_, err = keyStore.Create(&model.KeyAttributes{
		ID:               keyID,
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "e2e-gettokenv2-key",
		TransferPolicyId: policyID,
		TransferLink:     "/kbs/v1/keys/" + keyID.String() + "/transfer",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	kmipClient := kmipclient.MockKmipClient{}
	kmipMgr := keymanager.NewMockKmipManager(kmipClient)
	kmipMgr.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil)
	remoteMgr := keymanager.NewRemoteManager(keyStore, kmipMgr)

	itaClient := ita.NewMockClient()
	itaClient.On("VerifyToken", mockToken).Return(&jwtlib.Token{}, nil).Once()

	taConf := &config.Configuration{
		TrustAuthorityApiUrl: v2Server.URL + "/appraisal/v2",
		TrustAuthorityApiKey: "test-key",
	}

	svc := service{
		itaApiClient:           itaClient,
		itaTokenVerifierClient: itaClient,
		repository: &repository.Repository{
			KeyStore:               keyStore,
			KeyTransferPolicyStore: policyStore,
		},
		remoteManager: remoteMgr,
		config:        taConf,
	}

	resp, err := svc.TransferKeyWithEvidence(context.Background(), TransferKeyRequest{
		KeyId:           keyID,
		AttestationType: model.NVGPU.String(),
		KeyTransferRequest: &model.KeyTransferRequest{
			NVGPU: rawReq.NVGPU,
		},
	})

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp).NotTo(gomega.BeNil())
	g.Expect(resp.KeyTransferResponse).NotTo(gomega.BeNil())
	g.Expect(len(resp.KeyTransferResponse.WrappedKey)).To(gomega.BeNumerically(">", 0))
	g.Expect(len(resp.KeyTransferResponse.WrappedSWK)).To(gomega.BeNumerically(">", 0))
	itaClient.AssertExpectations(t)
}

func buildTDXNVGPUV2TokenNoHeldDataWithRuntimeDataForE2E(t *testing.T) string {
	t.Helper()
	tdxHeldData := generateTDXHeldDataPublicKeyPEM(t)

	header := map[string]interface{}{"alg": "PS384", "typ": "JWT"}
	payload := map[string]interface{}{
		"ver":         "2.0.0",
		"eat_profile": "https://example.com/eat_profile.html",
		"intuse":      "generic",
		"tdx": map[string]interface{}{
			"attester_type":       "TDX",
			"attester_tcb_status": "UpToDate",
			"attester_runtime_data": map[string]interface{}{
				"kbs-session-id": "jnjknjnwcooednciko",
				"public-key":     tdxHeldData,
			},
			"tdx_mrseam":       cns.ValidMrSeam,
			"tdx_mrsignerseam": cns.ValidMrSignerSeam,
			"tdx_mrtd":         cns.ValidMRTD,
			"tdx_rtmr0":        cns.ValidRTMR0,
			"tdx_rtmr1":        cns.ValidRTMR1,
			"tdx_rtmr2":        cns.ValidRTMR2,
			"tdx_rtmr3":        cns.ValidRTMR3,
			"tdx_seamsvn":      0,
		},
		"nvgpu": map[string]interface{}{
			"attester_type":               "NVGPU",
			"x-nvidia-overall-att-result": true,
			"claim_details": map[string]interface{}{
				"GPU-0": map[string]interface{}{"hwmodel": "GB100", "secboot": true, "dbgstat": "disabled", "measres": "success"},
			},
		},
	}

	hdrBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal jwt header: %v", err)
	}
	plBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal jwt payload: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(plBytes) + ".sig"
}

func generateTDXHeldDataPublicKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal rsa public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))
}

func getAttesterRuntimePublicKey(claims *model.AttestationTokenClaim) string {
	if claims == nil || len(claims.AttesterRuntime) == 0 {
		return ""
	}

	publicKey, ok := claims.AttesterRuntime["public-key"]
	if !ok {
		return ""
	}

	value, ok := publicKey.(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func getTokenFromEnvOrReqJSON(t *testing.T) string {
	t.Helper()

	if token := strings.TrimSpace(os.Getenv("KBS_REAL_TOKEN")); token != "" {
		return token
	}

	apiURL := firstNonEmpty(os.Getenv("KBS_ITA_API_URL"), defaultITAAPIURL)
	apiKey := firstNonEmpty(os.Getenv("KBS_ITA_API_KEY"), defaultITAAPIKey)
	reqPath := firstNonEmpty(os.Getenv("KBS_REQ_JSON_PATH"), "../transport/http/req.json")

	reqBytes, err := os.ReadFile(reqPath)
	if err != nil {
		t.Skipf("set KBS_REAL_TOKEN or make %s available: %v", reqPath, err)
	}

	body := map[string]interface{}{}
	if err := json.Unmarshal(reqBytes, &body); err != nil {
		t.Fatalf("failed to parse %s: %v", reqPath, err)
	}

	finalReq, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal attest request body: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(apiURL, "/")+"/attest", bytes.NewBuffer(finalReq))
	if err != nil {
		t.Fatalf("failed to build attest request: %v", err)
	}
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Skipf("failed to call ITA attest endpoint: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Skipf("ITA attest call failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		t.Fatalf("failed to decode attest response: %v", err)
	}
	if strings.TrimSpace(tokenResp.Token) == "" {
		t.Fatalf("ITA attest response token is empty")
	}

	return tokenResp.Token
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func hostFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("invalid URL %q: %v", rawURL, err)
	}
	return u.Hostname()
}

func decodeV2ClaimsFromToken(t *testing.T, token string) *model.AttestationTokenV2Claim {
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

func buildPolicyFromRealTokenClaims(v2 *model.AttestationTokenV2Claim, legacy *model.AttestationTokenClaim) *model.KeyTransferPolicy {
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
