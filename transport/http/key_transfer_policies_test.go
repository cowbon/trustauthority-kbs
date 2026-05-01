/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"bytes"
	cns "intel/kbs/v1/mocks"
	"intel/kbs/v1/model"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestKeyTransferPolicyDeleteHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyTransferPolicy{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveKeyTransferPolicy", mock.Anything, mock.Anything).Return(resp, nil)
	mockService.On("DeleteKeyTransferPolicy", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodDelete, "/kbs/v1/key-transfer-policies/"+keyId.String(), nil)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusNoContent))
}

func TestKeyTransferPolicyRetrieveHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyTransferPolicy{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveKeyTransferPolicy", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/key-transfer-policies/"+keyId.String(), nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyTransferPolicySearchHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []model.KeyTransferPolicy

	mockService := &MockService{}
	mockService.On("SearchKeyTransferPolicies", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/key-transfer-policies", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	q := req.URL.Query()
	q.Add(Algorithm, "AES")
	q.Add(KeyLength, "128")
	req.URL.RawQuery = q.Encode()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyTransferPolicySearchHandlerInvalidAcceptHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []model.KeyTransferPolicy

	mockService := &MockService{}
	mockService.On("SearchKeyTransferPolicies", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/key-transfer-policies", nil)
	req.Header.Set("Accept", "test/plain")
	req.Header.Set("Authorization", "Bearer "+authToken)

	q := req.URL.Query()
	q.Add(Algorithm, "AES")
	q.Add(KeyLength, "128")
	req.URL.RawQuery = q.Encode()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyTransferPolicyCreateValidSGXData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
			"attestation_type": "SGX",
			"sgx": {
				  "attributes": {
					    "enforce_tcb_upto_date": true,
					    "isvprodid": [
					      0
					    ],
					    "isvsvn": 0,
					    "mrenclave": [
					      "` + cns.ValidMrEnclave + `"
					    ],
					    "mrsigner": [
					      "` + cns.ValidMrSigner + `"
					    ]
				    }
			}
		}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusCreated))
}

func TestKeyTransferPolicyCreateValidTDXData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
			"attestation_type": "TDX",
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["` + cns.ValidMrSeam + `"],
					    "seamsvn": 0,
					    "mrtd": ["` + cns.ValidMRTD + `"],
					    "rtmr0": "` + cns.ValidRTMR0 + `",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "` + cns.ValidRTMR2 + `",
					    "rtmr3": "` + cns.ValidRTMR3 + `",
					    "enforce_tcb_upto_date": false
				    }
			}
		}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusCreated))
}

func TestKeyTransferPolicyCreateInvalidContentTypeHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", "plain/text")
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyTransferPolicyCreateInvalidAcceptHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", "plain/text")
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyTransferPolicyCreateInvalidContentLength(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferPolicyCreateInvalidRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
		"attestation_type": "TPM"
	}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
		"attester_type": "TDX"
	}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferPolicyCreateInvalidSGXData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"attestation_type": "SGX",
		"sgx": {
			  "attributes": {
					"enforce_tcb_upto_date": true,
					"isvsvn": 0,
					"mrenclave": [
					  "InvalidMrEnclave"
					],
					"mrsigner": [
					  "` + cns.ValidMrSigner + `"
					]
				}
		}
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
		"attestation_type": "SGX",
		"sgx": {
			  "attributes": {
					"enforce_tcb_upto_date": true,
					"isvprodid": [
					  0
					],
					"isvsvn": 0,
					"mrenclave": [
					  "InvalidMrEnclave"
					]
				}
		}
	}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
		"attestation_type": "SGX",
		"sgx": {
			  "attributes": {
					"enforce_tcb_upto_date": true,
					"isvprodid": [
					  0
					],
					"isvsvn": 0,
					"mrenclave": [
					  "InvalidMrEnclave"
					],
					"mrsigner": [
					  "` + cns.ValidMrSigner + `"
					]
				}
		}
	}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
		"attestation_type": "SGX",
		"sgx": {
			  "attributes": {
					"enforce_tcb_upto_date": true,
					"isvprodid": [
					  0
					],
					"isvsvn": 0,
					"mrenclave": [
						"` + cns.ValidMrEnclave + `"
					],
					"mrsigner": [
					  "InvalidMrSigner"
					]
				}
		}
	}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferPolicyCreateInvalidTDXData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"attestation_type": "TDX",
		"tdx": {
			  "attributes": {
					"mrsignerseam": ["0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
					"mrseam": ["` + cns.ValidMrSeam + `"],
					"seamsvn": 0,
					"mrtd": ["` + cns.ValidMRTD + `"],
					"rtmr0": "` + cns.ValidRTMR0 + `",
					"rtmr1": "` + cns.ValidRTMR1 + `",
					"rtmr2": "` + cns.ValidRTMR2 + `",
					"rtmr3": "` + cns.ValidRTMR3 + `",
					"enforce_tcb_upto_date": false
				}
		}
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
			"attestation_type":"TDX",
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["qf3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"],
					    "seamsvn": 0,
					    "mrtd": ["` + cns.ValidMRTD + `"],
					    "rtmr0": "` + cns.ValidRTMR0 + `",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "` + cns.ValidRTMR2 + `",
					    "rtmr3": "` + cns.ValidRTMR3 + `",
					    "enforce_tcb_upto_date": false
				    }
			}
		}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
			"attestation_type": "TDX",
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["` + cns.ValidMrSeam + `"],
					    "seamsvn": 0,
					    "mrtd": ["invaliddddddddddddd"],
					    "rtmr0": "` + cns.ValidRTMR0 + `",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "` + cns.ValidRTMR2 + `",
					    "rtmr3": "` + cns.ValidRTMR3 + `",
					    "enforce_tcb_upto_date": false
				    }
			}
		}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
			"attestation_type": "TDX",
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["` + cns.ValidMrSeam + `"],
					    "seamsvn": 0,
					    "mrtd": ["` + cns.ValidMRTD + `"],
					    "rtmr0": "invaliddddddddddddd",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "` + cns.ValidRTMR2 + `",
					    "rtmr3": "` + cns.ValidRTMR3 + `",
					    "enforce_tcb_upto_date": false
				    }
			}
		}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
			"attestation_type": "TDX",
			"tdx": {
				  "attributes": {
						"mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
						"mrseam": ["` + cns.ValidMrSeam + `"],
						"seamsvn": 0,
						"mrtd": ["` + cns.ValidMRTD + `"],
						"rtmr0": "` + cns.ValidRTMR0 + `",
						"rtmr1": "98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9e",
						"rtmr2": "` + cns.ValidRTMR2 + `",
						"rtmr3": "` + cns.ValidRTMR3 + `",
						"enforce_tcb_upto_date": false
					}
			}
		}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
			"attestation_type": "TDX",
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["` + cns.ValidMrSeam + `"],
					    "seamsvn": 0,
					    "mrtd": ["` + cns.ValidMRTD + `"],
					    "rtmr0": "` + cns.ValidRTMR0 + `",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					    "rtmr3": "` + cns.ValidRTMR3 + `",
					    "enforce_tcb_upto_date": false
				    }
			}
		}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))

	keyJson = `{
			"attestation_type": "TDX",
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["` + cns.ValidMrSeam + `"],
					    "seamsvn": 0,
					    "mrtd": ["` + cns.ValidMRTD + `"],
					    "rtmr0": "` + cns.ValidRTMR0 + `",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "` + cns.ValidRTMR2 + `",
					    "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					    "enforce_tcb_upto_date": false
				    }
			}
		}`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

// TestKeyTransferPolicyCreateNVGPUWithoutSubPolicy verifies that a policy whose
// attestation_type includes NVGPU is rejected when the nvgpu sub-policy is absent.
func TestKeyTransferPolicyCreateNVGPUWithoutSubPolicy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// TDX+NVGPU in attestation_type but no nvgpu object.
	keyJson := `{
		"attestation_type": ["TDX","NVGPU"],
		"tdx": {
			"attributes": {}
		}
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

// TestKeyTransferPolicyCreateValidTDXNVGPUData verifies that a composite TDX+NVGPU
// policy with an nvgpu sub-policy present is accepted.
func TestKeyTransferPolicyCreateValidTDXNVGPUData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"attestation_type": ["TDX","NVGPU"],
		"tdx": {
			"attributes": {}
		},
		"nvgpu": {}
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusCreated))
}

// TestKeyTransferPolicyCreateSGXAndTDX verifies that a policy combining SGX and TDX
// is rejected because the two attester types are mutually exclusive for key wrapping.
func TestKeyTransferPolicyCreateSGXAndTDX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"attestation_type": ["SGX","TDX"],
		"sgx": {},
		"tdx": {}
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

// TestKeyTransferPolicyCreateNVGPUWithSGX verifies that NVGPU+SGX is rejected
// because NVGPU can only accompany TDX.
func TestKeyTransferPolicyCreateNVGPUWithSGX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	res1 := &model.KeyTransferPolicy{}

	mockService := &MockService{}
	mockService.On("CreateKeyTransferPolicy", mock.Anything, mock.Anything).Return(res1, nil)
	handler := createMockHandler(mockService)

	err := setKeyTransferPolicyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"attestation_type": ["SGX","NVGPU"],
		"sgx": {},
		"nvgpu": {}
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/key-transfer-policies", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}
