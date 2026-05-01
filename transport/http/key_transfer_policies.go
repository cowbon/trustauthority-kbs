/*
 *   Copyright (c) 2024-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"context"
	"encoding/json"
	"net/http"

	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"intel/kbs/v1/service"

	"github.com/go-kit/kit/endpoint"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func setKeyTransferPolicyHandler(svc service.Service, router *mux.Router, options []httpTransport.ServerOption, auth *model.JwtAuthz) error {

	keyTransferPolicyIdExpr := "/key-transfer-policies/" + idReg

	CreateKeyTransferPolicyHandler := httpTransport.NewServer(
		makeCreateKeyTransferPolicyEndpoint(svc),
		decodeCreateKeyTransferPolicyHTTPRequest,
		encodeCreateKeyTransferPolicyHTTPResponse,
		options...,
	)

	router.Handle("/key-transfer-policies", authMiddleware(CreateKeyTransferPolicyHandler, auth)).Methods(http.MethodPost)

	GetKeyTransferPolicyHandler := httpTransport.NewServer(
		makeRetrieveKeyTransferPolicyEndpoint(svc),
		decodeRetrieveHTTPRequest,
		encodeRetrieveHTTPResponse,
		options...,
	)

	router.Handle(keyTransferPolicyIdExpr, authMiddleware(GetKeyTransferPolicyHandler, auth)).Methods(http.MethodGet)

	DeleteKeyTransferPolicyHandler := httpTransport.NewServer(
		makeDeleteKeyTransferPolicyEndpoint(svc),
		decodeDeleteHTTPRequest,
		encodeDeleteHTTPResponse,
		options...,
	)

	router.Handle(keyTransferPolicyIdExpr, authMiddleware(DeleteKeyTransferPolicyHandler, auth)).Methods(http.MethodDelete)

	SearchKeyTransferPoliciesHandler := httpTransport.NewServer(
		makeSearchKeyTransferPoliciesEndpoint(svc),
		decodeSearchKeyTransferPoliciesHTTPRequest,
		encodeSearchKeyTransferPoliciesHTTPResponse,
		options...,
	)

	router.Handle("/key-transfer-policies", authMiddleware(SearchKeyTransferPoliciesHandler, auth)).Methods(http.MethodGet)

	return nil
}

func makeCreateKeyTransferPolicyEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(model.KeyTransferPolicy)
		return svc.CreateKeyTransferPolicy(ctx, req)
	}
}

func makeSearchKeyTransferPoliciesEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		filter := request.(*model.KeyTransferPolicyFilterCriteria)
		return svc.SearchKeyTransferPolicies(ctx, filter)
	}
}

func makeDeleteKeyTransferPolicyEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		id := request.(uuid.UUID)
		return svc.DeleteKeyTransferPolicy(ctx, id)
	}
}

func makeRetrieveKeyTransferPolicyEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		id := request.(uuid.UUID)
		return svc.RetrieveKeyTransferPolicy(ctx, id)
	}
}

func decodeCreateKeyTransferPolicyHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyContentType) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidContentTypeHeader.Error())
		return nil, ErrInvalidContentTypeHeader
	}

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	if r.ContentLength == 0 {
		log.Error(ErrEmptyRequestBody.Error())
		return nil, ErrEmptyRequestBody
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var policyCreateReq model.KeyTransferPolicy
	err := dec.Decode(&policyCreateReq)
	if err != nil {
		log.WithError(err).Error(ErrJsonDecodeFailed.Error())
		return nil, ErrJsonDecodeFailed
	}

	if err := validateKeyTransferPolicy(policyCreateReq); err != nil {
		log.WithError(err).Error(ErrInvalidRequest.Error())
		return nil, ErrInvalidRequest
	}

	return policyCreateReq, nil
}

func decodeSearchKeyTransferPoliciesHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	// search query params not yet supported
	var criteria *model.KeyTransferPolicyFilterCriteria
	return criteria, nil
}

func encodeCreateKeyTransferPolicyHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(*model.KeyTransferPolicy)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusCreated)

	return encodeJsonResponse(ctx, w, resp)
}

func encodeSearchKeyTransferPoliciesHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.([]model.KeyTransferPolicy)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusOK)

	return encodeJsonResponse(ctx, w, resp)
}

func validateKeyTransferPolicy(policyCreateReq model.KeyTransferPolicy) error {

	if len(policyCreateReq.AttestationType) == 0 {
		return errors.New("attestation_type must be specified")
	}

	for _, attType := range policyCreateReq.AttestationType {
		if !attType.Valid() {
			return errors.New("Invalid attestation type")
		}
	}

	// SGX and TDX are mutually exclusive key-wrapping attester types.
	if policyCreateReq.AttestationType.Contains(model.SGX) && policyCreateReq.AttestationType.Contains(model.TDX) {
		return errors.New("attestation_type cannot include both SGX and TDX")
	}
	// NVGPU can only accompany TDX, not SGX.
	if policyCreateReq.AttestationType.Contains(model.NVGPU) && !policyCreateReq.AttestationType.Contains(model.TDX) {
		return errors.New("attestation_type includes NVGPU but does not include required TDX")
	}

	// NVGPU-only policy is not allowed (no key-wrapping attester present).
	if _, err := policyCreateReq.AttestationType.KeyWrappingAttesterType(); err != nil {
		return errors.New("Policy must contain at least one key-wrapping attester type (TDX or SGX)")
	}

	// Require sub-policy objects to be present whenever their type is declared.
	if policyCreateReq.AttestationType.Contains(model.SGX) && policyCreateReq.SGX == nil {
		return errors.New("sgx policy details are required when attestation_type includes SGX")
	}
	if policyCreateReq.AttestationType.Contains(model.TDX) && policyCreateReq.TDX == nil {
		return errors.New("tdx policy details are required when attestation_type includes TDX")
	}

	if policyCreateReq.AttestationType.Contains(model.SGX) && policyCreateReq.SGX != nil && policyCreateReq.SGX.Attributes != nil {
		if err := validateSGXAttributes(policyCreateReq.SGX.Attributes); err != nil {
			return errors.Wrap(err, "Input validation failed for SGX Attributes")
		}
	}

	if policyCreateReq.AttestationType.Contains(model.TDX) && policyCreateReq.TDX != nil && policyCreateReq.TDX.Attributes != nil {
		if err := validateTDXAttributes(policyCreateReq.TDX.Attributes); err != nil {
			return errors.Wrap(err, "Input validation failed for TDX Attributes")
		}
	}

	// When NVGPU is part of the policy the nvgpu sub-policy must be present;
	// otherwise the policy will always fail at key-transfer time.
	if policyCreateReq.AttestationType.Contains(model.NVGPU) && policyCreateReq.NVGPU == nil {
		return errors.New("nvgpu policy details are required when attestation_type includes NVGPU")
	}

	return nil
}

func validateSGXAttributes(sgxPolicyAttributes *model.SgxAttributes) error {

	for _, mrSigner := range sgxPolicyAttributes.MrSigner {
		if err := ValidateSha256HexString(mrSigner); err != nil {
			return errors.Wrap(err, "Input validation failed for MR Signer")
		}
	}

	if sgxPolicyAttributes.MrEnclave != nil {
		for _, mrEnclave := range sgxPolicyAttributes.MrEnclave {
			if err := ValidateSha256HexString(mrEnclave); err != nil {
				return errors.Wrap(err, "Input validation failed for MR Enclave")
			}
		}
	}

	return nil
}

func validateTDXAttributes(tdxPolicyAttributes *model.TdxAttributes) error {

	for _, mrSignerSeam := range tdxPolicyAttributes.MrSignerSeam {
		if err := ValidateSha384HexString(mrSignerSeam); err != nil {
			return errors.Wrap(err, "Input validation failed for MR Signer seam")
		}
	}

	for _, mrSeam := range tdxPolicyAttributes.MrSeam {
		if err := ValidateSha384HexString(mrSeam); err != nil {
			return errors.Wrap(err, "Input validation failed for MR Seam")
		}
	}

	if tdxPolicyAttributes.MRTD != nil {
		for _, mrTd := range tdxPolicyAttributes.MRTD {
			if err := ValidateSha384HexString(mrTd); err != nil {
				return errors.Wrap(err, "Input validation failed for MRTD")
			}
		}
	}

	if tdxPolicyAttributes.RTMR0 != "" {
		if err := ValidateSha384HexString(tdxPolicyAttributes.RTMR0); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR0")
		}
	}

	if tdxPolicyAttributes.RTMR1 != "" {
		if err := ValidateSha384HexString(tdxPolicyAttributes.RTMR1); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR1")
		}
	}

	if tdxPolicyAttributes.RTMR2 != "" {
		if err := ValidateSha384HexString(tdxPolicyAttributes.RTMR2); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR2")
		}
	}

	if tdxPolicyAttributes.RTMR3 != "" {
		if err := ValidateSha384HexString(tdxPolicyAttributes.RTMR3); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR3")
		}
	}

	return nil
}
