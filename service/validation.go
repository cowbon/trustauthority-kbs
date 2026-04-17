/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"reflect"
	"strings"

	_ "github.com/shaj13/libcache/fifo"
	"github.com/sirupsen/logrus"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func validateAttestationTokenClaims(tokenClaims *model.AttestationTokenClaim, transferPolicy *model.KeyTransferPolicy) error {
	for _, attType := range transferPolicy.AttestationType {
		if err := validateAttestationTokenClaimsByType(tokenClaims, transferPolicy, attType); err != nil {
			return err
		}
	}
	return nil
}

func validateAttestationTokenClaimsByType(tokenClaims *model.AttestationTokenClaim, transferPolicy *model.KeyTransferPolicy, attType model.AttesterType) error {
	switch attType {
	case model.SGX:
		if transferPolicy.SGX == nil {
			return errors.New("sgx policy is missing from key-transfer policy")
		}
		if tokenClaims.PolicyIdsMatched != nil && transferPolicy.SGX.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.SGX.PolicyIds) {
				return nil
			} else {
				return errors.New("None of the policy-id in token claim policy_ids_matched matched with policy_ids attribute in key-transfer policy")
			}
		}
		return validateSGXTokenClaims(tokenClaims, transferPolicy.SGX.Attributes)

	case model.TDX:
		if transferPolicy.TDX == nil {
			return errors.New("tdx policy is missing from key-transfer policy")
		}
		if tokenClaims.PolicyIdsMatched != nil && transferPolicy.TDX.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.TDX.PolicyIds) {
				return nil
			} else {
				return errors.New("None of the policy-id in token claim policy_ids_matched matched with policy_ids_matched attribute in key-transfer policy")
			}
		}
		return validateTDXTokenClaims(tokenClaims, transferPolicy.TDX.Attributes)

	case model.NVGPU:
		if transferPolicy.NVGPU == nil {
			return errors.New("nvgpu policy is missing from key-transfer policy")
		}
		if tokenClaims.PolicyIdsMatched != nil && transferPolicy.NVGPU.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.NVGPU.PolicyIds) {
				return nil
			}
		}
		return validateNVGPUTokenClaims(tokenClaims, transferPolicy.NVGPU.Attributes)

	default:
		return errors.New("Unsupported attestation-type")
	}
}

func validateNVGPUTokenClaims(tokenClaims *model.AttestationTokenClaim, nvgpuAttributes *model.NvgpuAttributes) error {
	if nvgpuAttributes == nil {
		return errors.New("nvgpu attributes are missing from key transfer policy")
	}

	if nvgpuAttributes.EnforceOverallAttestationResult != nil && *nvgpuAttributes.EnforceOverallAttestationResult {
		if tokenClaims.NVGPUOverallAttResult == nil || !*tokenClaims.NVGPUOverallAttResult {
			return errors.New("nvgpu overall attestation result is not true")
		}
	}

	if nvgpuAttributes.RequireSecureBoot != nil && *nvgpuAttributes.RequireSecureBoot {
		if len(tokenClaims.NVGPUClaimDetails) == 0 {
			return errors.New("nvgpu claim_details are missing from attestation token")
		}
		for _, detail := range tokenClaims.NVGPUClaimDetails {
			if !detail.SecBoot {
				return errors.New("nvgpu secure boot validation failed")
			}
		}
	}

	if len(nvgpuAttributes.HwModel) > 0 {
		if len(tokenClaims.NVGPUClaimDetails) == 0 {
			return errors.New("nvgpu claim_details are missing from attestation token")
		}
		for _, detail := range tokenClaims.NVGPUClaimDetails {
			if !contains(nvgpuAttributes.HwModel, detail.HwModel) {
				return errors.New("nvgpu hwmodel in attestation token does not match key transfer policy")
			}
		}
	}

	logrus.Debug("All nvgpu attributes in attestation token matches with attributes in key transfer policy")
	return nil
}

func isPolicyIdMatched(tokenPolicyIds []model.PolicyClaim, keyPolicyIds []uuid.UUID) bool {
	for _, tokenPolicyId := range tokenPolicyIds {
		if contains(keyPolicyIds, tokenPolicyId.Id) {
			return true
		}
	}
	return false
}

func validateSGXTokenClaims(tokenClaims *model.AttestationTokenClaim, sgxAttributes *model.SgxAttributes) error {
	if tokenClaims == nil || tokenClaims.SGXClaims == nil {
		return errors.New("sgx claims are missing from attestation token")
	}
	if sgxAttributes == nil {
		return errors.New("sgx attributes are missing from key transfer policy")
	}

	if validateMrSigner(tokenClaims.SgxMrSigner, sgxAttributes.MrSigner) &&
		validateIsvProdId(tokenClaims.SgxIsvProdId, sgxAttributes.IsvProductId) &&
		validateMrEnclave(tokenClaims.SgxMrEnclave, sgxAttributes.MrEnclave) &&
		validateIsvSvn(tokenClaims.SgxIsvSvn, sgxAttributes.IsvSvn) &&
		validateTcbStatus(tokenClaims.AttesterTcbStatus, sgxAttributes.EnforceTCBUptoDate) {
		logrus.Debug("All sgx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("sgx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSigner - Function to Validate SignerMeasurement
func validateMrSigner(tokenMrSigner string, policyMrSigner []string) bool {

	// if MrSigner is not provided in policy, it should not be evaluated
	if len(policyMrSigner) == 0 {
		logrus.Debug("MrSigner is not provided in key transfer policy, skipping MrSigner match against the token")
		return true
	}

	if contains(policyMrSigner, tokenMrSigner) {
		logrus.Debug("MrSigner in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("MrSigner in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvProdId - Function to Validate IsvProdId
func validateIsvProdId(tokenIsvProdId uint16, policyIsvProdIds []uint16) bool {

	// if IsvProdId is not provided in policy, it should not be evaluated
	if len(policyIsvProdIds) == 0 {
		logrus.Debug("IsvProdIds is not provided in key transfer policy, skipping IsvProdId match against the token")
		return true
	}

	if contains(policyIsvProdIds, tokenIsvProdId) {
		logrus.Debug("Isv Product Id in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("Isv Product Id in attestation token does not match with the key transfer policy")
	return false
}

// validateMrEnclave - Function to Validate EnclaveMeasurement
func validateMrEnclave(tokenMrEnclave string, policyMrEnclave []string) bool {

	// if MrEnclave is not provided in policy, it should not be evaluated
	if len(policyMrEnclave) == 0 {
		logrus.Debug("MrEnclave is not provided in key transfer policy, skipping MrEnclave match against the token")
		return true
	}

	if contains(policyMrEnclave, tokenMrEnclave) {
		logrus.Debug("Enclave Measurement in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("Enclave Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvSvn- Function to Validate isvSvn
func validateIsvSvn(tokenIsvSvn uint16, policyIsvSvn *uint16) bool {

	// if IsvSvn is not provided in policy, it should not be evaluated
	if policyIsvSvn == nil {
		logrus.Debug("IsvSvn is not provided in key transfer policy, skipping IsvSvn match against the token")
		return true
	}

	if tokenIsvSvn == *policyIsvSvn {
		logrus.Debug("IsvSvn in attestation token matches with the key transfer policy")
		return true
	}
	logrus.Error("IsvSvn in attestation token does not match with the key transfer policy")
	return false
}

// validateTcbStatus- Function to Validate tcbStatus
func validateTcbStatus(tcbStatus string, enforceTcbUptoDate *bool) bool {

	if enforceTcbUptoDate == nil {
		logrus.Debug("enforceTcbUptoDate is not provided in key transfer policy, skipping enforceTcbUptoDate match against the token")
		return true
	}

	if *enforceTcbUptoDate && tcbStatus != constant.TCBStatusUpToDate && !strings.EqualFold(tcbStatus, "UpToDate") {
		logrus.Error("TCB is not Up-to-Date")
		return false
	}
	return true
}

func validateTDXTokenClaims(tokenClaims *model.AttestationTokenClaim, tdxAttributes *model.TdxAttributes) error {
	if tokenClaims == nil || tokenClaims.TDXClaims == nil {
		return errors.New("tdx claims are missing from attestation token")
	}
	if tdxAttributes == nil {
		return errors.New("tdx attributes are missing from key transfer policy")
	}

	if validateMrSignerSeam(tokenClaims.TdxMrSignerSeam, tdxAttributes.MrSignerSeam) &&
		validateMrSeam(tokenClaims.TdxMrSeam, tdxAttributes.MrSeam) &&
		validateSeamSvn(tokenClaims.TdxSeamSvn, tdxAttributes.SeamSvn) &&
		validateMrTD(tokenClaims.TdxMRTD, tdxAttributes.MRTD) &&
		validateRTMR(tokenClaims.TdxRTMR0, tdxAttributes.RTMR0) &&
		validateRTMR(tokenClaims.TdxRTMR1, tdxAttributes.RTMR1) &&
		validateRTMR(tokenClaims.TdxRTMR2, tdxAttributes.RTMR2) &&
		validateRTMR(tokenClaims.TdxRTMR3, tdxAttributes.RTMR3) &&
		validateTcbStatus(tokenClaims.AttesterTcbStatus, tdxAttributes.EnforceTCBUptoDate) {
		logrus.Debug("All tdx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("tdx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSignerSeam - Function to Validate MrSignerSeam
func validateMrSignerSeam(tokenMrSignerSeam string, policyMrSignerSeam []string) bool {

	// if MrSignerSeam is not provided in policy, it should not be evaluated
	if len(policyMrSignerSeam) == 0 {
		logrus.Debug("MrSignerSeam is not provided in key transfer policy, skipping MrSignerSeam match against the token")
		return true
	}

	if contains(policyMrSignerSeam, tokenMrSignerSeam) {
		logrus.Debug("MrSignerSeam in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("MrSignerSeam in attestation token does not match with the key transfer policy")
	return false
}

// validateMrSeam - Function to Validate SeamMeasurement
func validateMrSeam(tokenMrSeam string, policyMrSeam []string) bool {

	// if MrSeam is not provided in policy, it should not be evaluated
	if len(policyMrSeam) == 0 {
		logrus.Debug("MrSeam is not provided in key transfer policy, skipping MrSeam match against the token")
		return true
	}

	if contains(policyMrSeam, tokenMrSeam) {
		logrus.Debug("Seam Measurement in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("Seam Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateSeamSvn- Function to Validate seamSvn
func validateSeamSvn(tokenSeamSvn uint16, policySeamSvn *uint16) bool {

	// if SeamSvn is not provided in policy, it should not be evaluated
	if policySeamSvn == nil {
		logrus.Debug("SeamSvn is not provided in key transfer policy, skipping SeamSvn match against the token")
		return true
	}

	if tokenSeamSvn == *policySeamSvn {
		logrus.Debug("Seam Svn in attestation token matches with the key transfer policy")
		return true
	}
	logrus.Error("Seam Svn in attestation token does not match with the key transfer policy")
	return false
}

// validateMrTD - Function to Validate TDMeasurement
func validateMrTD(tokenMrTD string, policyMrTD []string) bool {

	// if MrTD is not provided in policy, it should not be evaluated
	if len(policyMrTD) == 0 {
		logrus.Debug("MrTD is not provided in key transfer policy, skipping MrTD match against the token")
		return true
	}

	if contains(policyMrTD, tokenMrTD) {
		logrus.Debug("TD Measurement in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("TD Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateRTMR - Function to Validate RTMR
func validateRTMR(tokenRTMR string, policyRTMR string) bool {

	// if RTMR is not provided in policy, it should not be evaluated
	if policyRTMR == "" {
		return true
	}

	if tokenRTMR == policyRTMR {
		logrus.Debug("RTMR in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("RTMR in attestation token does not match with the key transfer policy")
	return false
}

func contains(s interface{}, elem interface{}) bool {
	slice := reflect.ValueOf(s)
	if slice.Kind() == reflect.Slice {
		for index := 0; index < slice.Len(); index++ {
			//panics if slice element points to an unexported struct field
			if slice.Index(index).Interface() == elem {
				return true
			}
		}
	}
	return false
}
