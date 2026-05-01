/*
 *   Copyright (c) 2024-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"encoding/json"
	cns "intel/kbs/v1/mocks"
	"intel/kbs/v1/model"
	"testing"

	"github.com/google/uuid"
	"github.com/onsi/gomega"
)

var zeroVal uint16 = 0
var oneVal uint16 = 1

func TestValidateAttestationTokenClaimsSGX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	policyReqJsonStr := `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type":"SGX",
		"sgx": {
		    "attributes" : {}
		}
	}`

	tokenClaims := &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	policyReqJsonStr = `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type": "SGX",
		"sgx":{
			"attributes":{
				"mrsigner":["` + cns.ValidMrSigner + `"],
				"isvprodid":[1],
				"mrenclave":["` + cns.ValidMrEnclave + `"],
				"isvsvn":1,
				"enforce_tcb_upto_date":true
			},
			"policy_ids": ["4517534b-a758-4447-7d2f-3e5606152ed6", "34568456-2398-3875-7453-395766152ed6"]
		}
	}`

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	// policy_ids are configured in policy but token has no PolicyIdsMatched: must fail (conjunctive enforcement)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: "11c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  "dd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: zeroVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OUT_OF_DATE",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		PolicyIdsMatched: []model.PolicyClaim{
			{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v1"},
			{Id: uuid.MustParse("34568456-2398-3875-7453-395766152ed6"), Version: "v1"},
		},
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	// policy_ids match but token has no SGX claims; attrs are configured: must fail (conjunctive enforcement)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		PolicyIdsMatched: []model.PolicyClaim{},
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestValidateAttestationTokenClaimsTDX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	policyReqJsonStr := `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type": "TDX",
		"tdx": {
			"attributes": {}
		}
	}`

	tokenClaims := &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	policyReqJsonStr = `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
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
				"enforce_tcb_upto_date": true
			},
			"policy_ids": ["4517534b-a758-4447-7d2f-3e5606152ed6", "34568456-2398-3875-7453-395766152ed6"]
		}
	}`

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	// policy_ids are configured in policy but token has no PolicyIdsMatched: must fail (conjunctive enforcement)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       "1f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         "df656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        "d90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        "b53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9e",
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OUT_OF_DATE",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		PolicyIdsMatched: []model.PolicyClaim{
			{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v1"},
			{Id: uuid.MustParse("34568456-2398-3875-7453-395766152ed6"), Version: "v1"},
		},
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	// policy_ids match but token has no TDX claims; attrs are configured: must fail (conjunctive enforcement)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		PolicyIdsMatched: []model.PolicyClaim{},
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}

// TestValidateAttestationTokenClaimsSGXMixedPolicy verifies that when a key-transfer policy
// specifies both policy_ids and SGX attributes, BOTH must be satisfied conjunctively.
func TestValidateAttestationTokenClaimsSGXMixedPolicy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mixedPolicyJSON := `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type": "SGX",
		"sgx": {
			"attributes": {
				"mrsigner":  ["` + cns.ValidMrSigner + `"],
				"isvprodid": [1],
				"mrenclave": ["` + cns.ValidMrEnclave + `"],
				"isvsvn":    1,
				"enforce_tcb_upto_date": false
			},
			"policy_ids": ["4517534b-a758-4447-7d2f-3e5606152ed6"]
		}
	}`

	transferPolicy := &model.KeyTransferPolicy{}
	json.Unmarshal([]byte(mixedPolicyJSON), transferPolicy)

	// Case 1: matching policy_id AND valid SGX attributes — should succeed.
	tokenClaims := &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		PolicyIdsMatched: []model.PolicyClaim{
			{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v1"},
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 2: matching policy_id BUT wrong mrenclave — should fail.
	// This is the reported vulnerability: policy_id match must NOT short-circuit attribute validation.
	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb",
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		PolicyIdsMatched: []model.PolicyClaim{
			{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v1"},
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	// Case 3: valid SGX attributes BUT no policy_id match — should fail.
	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}

// TestValidateAttestationTokenClaimsTDXMixedPolicy verifies that when a key-transfer policy
// specifies both policy_ids and TDX attributes, BOTH must be satisfied conjunctively.
func TestValidateAttestationTokenClaimsTDXMixedPolicy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mixedPolicyJSON := `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type": "TDX",
		"tdx": {
			"attributes": {
				"mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
				"mrseam":       ["` + cns.ValidMrSeam + `"],
				"seamsvn":      0,
				"mrtd":         ["` + cns.ValidMRTD + `"],
				"rtmr0": "` + cns.ValidRTMR0 + `",
				"rtmr1": "` + cns.ValidRTMR1 + `",
				"rtmr2": "` + cns.ValidRTMR2 + `",
				"rtmr3": "` + cns.ValidRTMR3 + `",
				"enforce_tcb_upto_date": false
			},
			"policy_ids": ["4517534b-a758-4447-7d2f-3e5606152ed6"]
		}
	}`

	transferPolicy := &model.KeyTransferPolicy{}
	json.Unmarshal([]byte(mixedPolicyJSON), transferPolicy)

	// Case 1: matching policy_id AND valid TDX attributes — should succeed.
	tokenClaims := &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		PolicyIdsMatched: []model.PolicyClaim{
			{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v1"},
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 2: matching policy_id BUT wrong mrseam — should fail.
	// This is the reported vulnerability: policy_id match must NOT short-circuit attribute validation.
	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad",
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		PolicyIdsMatched: []model.PolicyClaim{
			{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v1"},
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	// Case 3: valid TDX attributes BUT no policy_id match — should fail.
	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestValidateAttestationTokenClaims(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	policyReqJsonStr := string(`{
		"attestation_type":"TPM"
	}`)

	tokenClaims := &model.AttestationTokenClaim{}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	// SGX attestation_type with no sgx object must return an explicit error, not panic.
	transferPolicy = &model.KeyTransferPolicy{AttestationType: model.AttesterTypes{model.SGX}}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("sgx policy details missing"))

	// TDX attestation_type with no tdx object must return an explicit error, not panic.
	transferPolicy = &model.KeyTransferPolicy{AttestationType: model.AttesterTypes{model.TDX}}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("tdx policy details missing"))
}

func boolPtr(b bool) *bool { return &b }

// TestValidateNVGPUClaims covers the NVGPU-specific validation paths in
// validateNVGPUClaims and validateAttestationTokenClaims (NVGPU branch).
func TestValidateNVGPUClaims(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	trueVal := true
	falseVal := false

	// helper: a valid TDX+NVGPU composite policy
	makeCompositePolicy := func(nvgpu *model.NvgpuPolicy) *model.KeyTransferPolicy {
		return &model.KeyTransferPolicy{
			AttestationType: model.AttesterTypes{model.TDX, model.NVGPU},
			TDX:             &model.TdxPolicy{},
			NVGPU:           nvgpu,
		}
	}

	// helper: base token with TDX attester type and an NVGPU overall result
	makeToken := func(overallResult *bool, details map[string]model.NVGPUClaimDetail) *model.AttestationTokenClaim {
		return &model.AttestationTokenClaim{
			AttesterType:          model.TDX,
			TDXClaims:             &model.TDXClaims{},
			NVGPUOverallAttResult: overallResult,
			NVGPUClaimDetails:     details,
		}
	}

	// Case 1: NVGPU policy present but token has no NVGPUOverallAttResult — must fail.
	policy := makeCompositePolicy(&model.NvgpuPolicy{})
	token := makeToken(nil, nil)
	err := validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("nvgpu overall attestation result is missing"))

	// Case 2: Empty NVGPU policy, token has overall result — must succeed.
	policy = makeCompositePolicy(&model.NvgpuPolicy{})
	token = makeToken(&trueVal, nil)
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 3: EnforceOverallAttestationResult=true, token result is false — must fail.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{EnforceOverallAttestationResult: &trueVal},
	})
	token = makeToken(&falseVal, nil)
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("NVGPU overall attestation result is not true"))

	// Case 4: EnforceOverallAttestationResult=true, token result is true — must succeed.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{EnforceOverallAttestationResult: &trueVal},
	})
	token = makeToken(&trueVal, nil)
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 5: RequireSecureBoot=true, token has no claim_details — must fail (fail-closed).
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{RequireSecureBoot: &trueVal},
	})
	token = makeToken(&trueVal, nil)
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("nvgpu claim_details are missing"))

	// Case 6: RequireSecureBoot=true, one GPU has secboot=false — must fail.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{RequireSecureBoot: &trueVal},
	})
	token = makeToken(&trueVal, map[string]model.NVGPUClaimDetail{
		"GPU-0": {SecBoot: false, HwModel: "H100"},
	})
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("does not have secure boot enabled"))

	// Case 7: RequireSecureBoot=true, all GPUs have secboot=true — must succeed.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{RequireSecureBoot: &trueVal},
	})
	token = makeToken(&trueVal, map[string]model.NVGPUClaimDetail{
		"GPU-0": {SecBoot: true, HwModel: "H100"},
		"GPU-1": {SecBoot: true, HwModel: "H100"},
	})
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 8: HwModel allowlist, GPU has model not in list — must fail.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{HwModel: []string{"H100"}},
	})
	token = makeToken(&trueVal, map[string]model.NVGPUClaimDetail{
		"GPU-0": {SecBoot: true, HwModel: "A100"},
	})
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("not in the allowlist"))

	// Case 9: HwModel allowlist, all GPUs in list — must succeed.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		Attributes: &model.NvgpuAttributes{HwModel: []string{"H100", "H200"}},
	})
	token = makeToken(&trueVal, map[string]model.NVGPUClaimDetail{
		"GPU-0": {SecBoot: true, HwModel: "H100"},
		"GPU-1": {SecBoot: true, HwModel: "H200"},
	})
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 10: Policy ID mismatch — must fail.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		PolicyIds: []uuid.UUID{uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6")},
	})
	token = makeToken(&trueVal, nil)
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("policy-id"))

	// Case 11: Policy ID match — must succeed.
	policy = makeCompositePolicy(&model.NvgpuPolicy{
		PolicyIds: []uuid.UUID{uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6")},
	})
	token = makeToken(&trueVal, nil)
	token.PolicyIdsMatched = []model.PolicyClaim{
		{Id: uuid.MustParse("4517534b-a758-4447-7d2f-3e5606152ed6"), Version: "v2"},
	}
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Case 12: Token attester_type mismatch (SGX token against TDX+NVGPU policy) — must fail.
	policy = makeCompositePolicy(&model.NvgpuPolicy{})
	token = makeToken(&trueVal, nil)
	token.AttesterType = model.SGX
	err = validateAttestationTokenClaims(token, policy)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("attester_type"))
}
