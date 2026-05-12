/*
 *   Copyright (c) 2024 Intel Corporation
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

func TestAttestationTokenV2TDXToLegacy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	instanceID := uuid.New().String()
	claimJSON := `{
		"eat_profile": "https://example.com/eat_profile.html",
		"tdx": {
			"attester_type": "TDX",
			"attester_tcb_status": "UpToDate",
			"attester_held_data": "ita_v2_held_data",
			"attester_runtime_data": {
				"kbs-session-id": "ita_v2_session_id",
				"public-key": "ita_v2_runtime_public_key"
			},
			"verifier_instance_ids": ["` + instanceID + `"],
			"tdx_mrseam": "tdx-mrseam",
			"tdx_mrsignerseam": "tdx-mrsignerseam",
			"tdx_mrtd": "tdx-mrtd",
			"tdx_rtmr0": "tdx-rtmr0",
			"tdx_rtmr1": "tdx-rtmr1",
			"tdx_rtmr2": "tdx-rtmr2",
			"tdx_rtmr3": "tdx-rtmr3",
			"tdx_seamsvn": 7,
			"tdx_tee_tcb_svn": "0d010400000000000000000000000000"
		},
		"ver": "2.0.0"
	}`

	v2Claims := &AttestationTokenV2Claim{}
	err := json.Unmarshal([]byte(claimJSON), v2Claims)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	legacy := v2Claims.ToAttestationTokenClaim()
	g.Expect(legacy.AttesterType).To(gomega.Equal(TDX))
	g.Expect(legacy.AttesterTcbStatus).To(gomega.Equal("UpToDate"))
	g.Expect(legacy.AttesterHeldData).To(gomega.Equal("ita_v2_held_data"))
	g.Expect(legacy.AttesterRuntime).To(gomega.HaveKeyWithValue("kbs-session-id", "ita_v2_session_id"))
	g.Expect(legacy.AttesterRuntime).To(gomega.HaveKeyWithValue("public-key", "ita_v2_runtime_public_key"))
	g.Expect(legacy.VerifierInstanceIds).To(gomega.HaveLen(1))
	g.Expect(legacy.VerifierInstanceIds[0].String()).To(gomega.Equal(instanceID))
	g.Expect(legacy.TDXClaims).NotTo(gomega.BeNil())
	g.Expect(legacy.TdxMrSeam).To(gomega.Equal("tdx-mrseam"))
	g.Expect(legacy.TdxMrSignerSeam).To(gomega.Equal("tdx-mrsignerseam"))
	g.Expect(legacy.TdxMRTD).To(gomega.Equal("tdx-mrtd"))
	g.Expect(legacy.TdxSeamSvn).To(gomega.Equal(uint16(7)))
	g.Expect(legacy.Version).To(gomega.Equal("2.0.0"))
}
