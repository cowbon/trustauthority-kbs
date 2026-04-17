/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/json"
	"fmt"
)

type AttesterType string

type AttesterTypes []AttesterType

const (
	TDX   AttesterType = "TDX"
	SGX   AttesterType = "SGX"
	NVGPU AttesterType = "NVGPU"
)

func (at AttesterType) String() string {
	return string(at)
}

func (at AttesterType) Valid() bool {
	switch at {
	case TDX, SGX, NVGPU:
		return true
	}
	return false
}

func (ats AttesterTypes) First() AttesterType {
	if len(ats) == 0 {
		return ""
	}
	return ats[0]
}

func (ats AttesterTypes) Contains(attType AttesterType) bool {
	for _, t := range ats {
		if t == attType {
			return true
		}
	}
	return false
}

func (ats *AttesterTypes) UnmarshalJSON(data []byte) error {
	var list []AttesterType
	if err := json.Unmarshal(data, &list); err == nil {
		*ats = list
		return nil
	}

	var single AttesterType
	if err := json.Unmarshal(data, &single); err == nil {
		*ats = []AttesterType{single}
		return nil
	}

	return fmt.Errorf("attestation_type must be a string or array of strings")
}
