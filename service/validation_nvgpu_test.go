/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"testing"

	"intel/kbs/v1/model"
	cns "intel/kbs/v1/repository/mocks/constants"

	"github.com/google/uuid"
	"github.com/onsi/gomega"
)

func TestValidateAttestationTokenClaimsNVGPUByPolicyID(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	policyID := uuid.New()

	policy := &model.KeyTransferPolicy{
		AttestationType: model.AttesterTypes{model.NVGPU},
		NVGPU: &model.NvgpuPolicy{
			PolicyIds: []uuid.UUID{policyID},
		},
	}

	claims := &model.AttestationTokenClaim{
		PolicyIdsMatched: []model.PolicyClaim{{Id: policyID, Version: "v1"}},
		AttesterType:     model.NVGPU,
	}

	err := validateAttestationTokenClaims(claims, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	claims.PolicyIdsMatched = []model.PolicyClaim{{Id: uuid.New(), Version: "v1"}}
	err = validateAttestationTokenClaims(claims, policy)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestValidateAttestationTokenClaimsTDXAndNVGPU(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	nvgpuPolicyID := uuid.New()
	enforce := true
	seam := uint16(0)

	policy := &model.KeyTransferPolicy{
		AttestationType: model.AttesterTypes{model.TDX, model.NVGPU},
		TDX: &model.TdxPolicy{Attributes: &model.TdxAttributes{
			MrSignerSeam:       []string{cns.ValidMrSignerSeam},
			MrSeam:             []string{cns.ValidMrSeam},
			SeamSvn:            &seam,
			MRTD:               []string{cns.ValidMRTD},
			RTMR0:              cns.ValidRTMR0,
			RTMR1:              cns.ValidRTMR1,
			RTMR2:              cns.ValidRTMR2,
			RTMR3:              cns.ValidRTMR3,
			EnforceTCBUptoDate: &enforce,
		}},
		NVGPU: &model.NvgpuPolicy{PolicyIds: []uuid.UUID{nvgpuPolicyID}},
	}

	claims := &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      seam,
		},
		PolicyIdsMatched:  []model.PolicyClaim{{Id: nvgpuPolicyID, Version: "v1"}},
		AttesterTcbStatus: "OK",
	}

	err := validateAttestationTokenClaims(claims, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
