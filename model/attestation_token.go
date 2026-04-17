/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"github.com/google/uuid"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
)

type AttestationTokenV2Claim struct {
	Appraisal           map[string]interface{}      `json:"appraisal,omitempty"`
	EatProfile          string                      `json:"eat_profile,omitempty"`
	IntUse              string                      `json:"intuse,omitempty"`
	PolicyIdsMatched    []PolicyClaim               `json:"policy_ids_matched,omitempty"`
	PolicyIdsUnmatched  []PolicyClaim               `json:"policy_ids_unmatched,omitempty"`
	PolicyDefinedClaims *map[string]interface{}     `json:"policy_defined_claims,omitempty"`
	TDX                 *AttestationTokenV2TDXClaim `json:"tdx,omitempty"`
	NVGPU               *AttestationTokenV2NVGPU    `json:"nvgpu,omitempty"`
	VerifierInstanceIds []uuid.UUID                 `json:"verifier_instance_ids,omitempty"`
	Version             string                      `json:"ver"`
}

type AttestationTokenV2Common struct {
	AttesterHeldData    string       `json:"attester_held_data,omitempty"`
	AttesterTcbStatus   string       `json:"attester_tcb_status,omitempty"`
	AttesterType        AttesterType `json:"attester_type,omitempty"`
	VerifierInstanceIds []uuid.UUID  `json:"verifier_instance_ids,omitempty"`
}

type AttestationTokenV2TDXClaim struct {
	AttestationTokenV2Common
	TDXClaims
}

type AttestationTokenV2NVGPU struct {
	AttestationTokenV2Common
	ClaimDetails            map[string]AttestationTokenV2NVGPUClaimDetail `json:"claim_details,omitempty"`
	Submods                 map[string]interface{}                        `json:"submods,omitempty"`
	XNVidiaOverallAttResult bool                                          `json:"x-nvidia-overall-att-result"`
}

type AttestationTokenV2NVGPUClaimDetail struct {
	DbgStat string `json:"dbgstat,omitempty"`
	HwModel string `json:"hwmodel,omitempty"`
	SecBoot bool   `json:"secboot"`
	MeasRes string `json:"measres,omitempty"`
}

func (v2 *AttestationTokenV2Claim) ToAttestationTokenClaim() *AttestationTokenClaim {
	legacy := &AttestationTokenClaim{
		EatProfile:          v2.EatProfile,
		IntUse:              v2.IntUse,
		PolicyIdsMatched:    v2.PolicyIdsMatched,
		PolicyIdsUnmatched:  v2.PolicyIdsUnmatched,
		PolicyDefinedClaims: v2.PolicyDefinedClaims,
		VerifierInstanceIds: v2.VerifierInstanceIds,
		Version:             v2.Version,
	}

	if v2.TDX != nil {
		tdx := v2.TDX.TDXClaims
		legacy.TDXClaims = &tdx
		if legacy.AttesterHeldData == "" {
			legacy.AttesterHeldData = v2.TDX.AttesterHeldData
		}
		if legacy.AttesterTcbStatus == "" {
			legacy.AttesterTcbStatus = v2.TDX.AttesterTcbStatus
		}
		if legacy.AttesterType == "" {
			if v2.TDX.AttesterType != "" {
				legacy.AttesterType = v2.TDX.AttesterType
			} else {
				legacy.AttesterType = TDX
			}
		}
		if len(legacy.VerifierInstanceIds) == 0 {
			legacy.VerifierInstanceIds = v2.TDX.VerifierInstanceIds
		}
	}

	if v2.NVGPU != nil {
		if len(v2.NVGPU.ClaimDetails) > 0 {
			legacy.NVGPUClaimDetails = make(map[string]NVGPUClaimDetail, len(v2.NVGPU.ClaimDetails))
			for k, d := range v2.NVGPU.ClaimDetails {
				legacy.NVGPUClaimDetails[k] = NVGPUClaimDetail{
					DbgStat: d.DbgStat,
					HwModel: d.HwModel,
					SecBoot: d.SecBoot,
					MeasRes: d.MeasRes,
				}
			}
		}
		overall := v2.NVGPU.XNVidiaOverallAttResult
		legacy.NVGPUOverallAttResult = &overall
		if legacy.AttesterType == "" {
			if v2.NVGPU.AttesterType != "" {
				legacy.AttesterType = v2.NVGPU.AttesterType
			} else {
				legacy.AttesterType = NVGPU
			}
		}
	}

	return legacy
}

type AttestationTokenClaim struct {
	*SGXClaims
	*TDXClaims
	NVGPUClaimDetails     map[string]NVGPUClaimDetail     `json:"nvgpu_claim_details,omitempty"`
	NVGPUOverallAttResult *bool                            `json:"x-nvidia-overall-att-result,omitempty"`
	AttesterHeldData    string                      `json:"attester_held_data,omitempty"` // Is this finalized?
	AttesterInittime    map[string]interface{}      `json:"attester_inittime_data,omitempty"`
	AttesterRuntime     map[string]interface{}      `json:"attester_runtime_data,omitempty"`
	VerifierNonce       *itaConnector.VerifierNonce `json:"verifier_nonce,omitempty"`
	PolicyIdsMatched    []PolicyClaim               `json:"policy_ids_matched,omitempty"`
	PolicyIdsUnmatched  []PolicyClaim               `json:"policy_ids_unmatched,omitempty"`
	PolicyDefinedClaims *map[string]interface{}     `json:"policy_defined_claims,omitempty"`
	AttesterTcbStatus   string                      `json:"attester_tcb_status"`
	AttesterAdvisoryIds []string                    `json:"attester_advisory_ids,omitempty"`
	AttesterType        AttesterType                `json:"attester_type"`
	VerifierInstanceIds []uuid.UUID                 `json:"verifier_instance_ids"`
	DbgStat             string                      `json:"dbgstat,omitempty"`     // EAT claims
	EatProfile          string                      `json:"eat_profile,omitempty"` // EAT claims
	IntUse              string                      `json:"intuse,omitempty"`      // EAT claims
	Version             string                      `json:"ver"`
}

type NVGPUClaimDetail struct {
	DbgStat string `json:"dbgstat,omitempty"`
	HwModel string `json:"hwmodel,omitempty"`
	SecBoot bool   `json:"secboot"`
	MeasRes string `json:"measres,omitempty"`
}

type SGXClaims struct {
	SgxMrEnclave    string                       `json:"sgx_mrenclave"`
	SgxMrSigner     string                       `json:"sgx_mrsigner"`
	SgxIsvProdId    uint16                       `json:"sgx_isvprodid"`
	SgxIsvSvn       uint16                       `json:"sgx_isvsvn"`
	SgxReportData   string                       `json:"sgx_report_data,omitempty"`
	SgxConfigId     string                       `json:"sgx_config_id,omitempty"`
	SgxIsDebuggable bool                         `json:"sgx_is_debuggable"`
	SgxCollateral   *QuoteVerificationCollateral `json:"sgx_collateral,omitempty"`
}

type TDXClaims struct {
	TdxTeeTcbSvn          string                       `json:"tdx_tee_tcb_svn"`
	TdxMrSeam             string                       `json:"tdx_mrseam"`
	TdxMrSignerSeam       string                       `json:"tdx_mrsignerseam"`
	TdxSeamAttributes     string                       `json:"tdx_seam_attributes"`
	TdxAttributes         string                       `json:"tdx_td_attributes"`
	TdxXfam               string                       `json:"tdx_xfam"`
	TdxMRTD               string                       `json:"tdx_mrtd"`
	TdxMrConfigId         string                       `json:"tdx_mrconfigid"`
	TdxMrOwner            string                       `json:"tdx_mrowner"`
	TdxMrOwnerConfig      string                       `json:"tdx_mrownerconfig"`
	TdxRTMR0              string                       `json:"tdx_rtmr0"`
	TdxRTMR1              string                       `json:"tdx_rtmr1"`
	TdxRTMR2              string                       `json:"tdx_rtmr2"`
	TdxRTMR3              string                       `json:"tdx_rtmr3"`
	TdxReportData         string                       `json:"tdx_report_data,omitempty"`
	TdxSeamSvn            uint16                       `json:"tdx_seamsvn"`
	TdxTDAttributeDebug   bool                         `json:"tdx_td_attributes_debug"`
	TdxTDAttributesSeptVe bool                         `json:"tdx_td_attributes_septve_disable"`
	TdxTDAttributePKS     bool                         `json:"tdx_td_attributes_protection_keys"`
	TdxTDAttributeKL      bool                         `json:"tdx_td_attributes_key_locker"`
	TdxTDAttributePerfmon bool                         `json:"tdx_td_attributes_perfmon"`
	TdxIsDebuggable       bool                         `json:"tdx_is_debuggable"`
	TdxCollateral         *QuoteVerificationCollateral `json:"tdx_collateral,omitempty"`
}

type PolicyClaim struct {
	Id      uuid.UUID `json:"id"`
	Version string    `json:"version"`
}

type QuoteVerificationCollateral struct {
	QeIdCertHash    string `json:"qeidcerthash"`
	QeIdCrlHash     string `json:"qeidcrlhash"`
	QeIdHash        string `json:"qeidhash"`
	QuoteHash       string `json:"quotehash"`
	TcbInfoCertHash string `json:"tcbinfocerthash"`
	TcbInfoCrlHash  string `json:"tcbinfocrlhash"`
	TcbInfoHash     string `json:"tcbinfohash"`
}
