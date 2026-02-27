/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ita

import (
	"testing"

	"intel/kbs/v1/config"
)

func TestNewITAClient_Success(t *testing.T) {
	cfg := &config.Configuration{
		TrustAuthorityBaseUrl: "https://api.trustauthority.intel.com",
		TrustAuthorityApiUrl:  "https://api.trustauthority.intel.com/appraisal/v1",
		TrustAuthorityApiKey:  "test-api-key-12345",
	}

	serverName := "api.trustauthority.intel.com"

	connector, err := NewITAClient(cfg, serverName)
	if err != nil {
		t.Errorf("NewITAClient() error = %v, want nil", err)
	}

	if connector == nil {
		t.Error("NewITAClient() should return non-nil connector")
	}
}

func TestNewITAClient_InvalidURLs(t *testing.T) {
	tests := []struct {
		name    string
		baseUrl string
		apiUrl  string
	}{
		{
			name:    "Invalid base URL scheme",
			baseUrl: "ftp://api.example.com",
			apiUrl:  "https://api.example.com/v1",
		},
		{
			name:    "Malformed base URL",
			baseUrl: "not-a-valid-url",
			apiUrl:  "https://api.example.com/v1",
		},
	}

	serverName := "api.example.com"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Configuration{
				TrustAuthorityBaseUrl: tt.baseUrl,
				TrustAuthorityApiUrl:  tt.apiUrl,
				TrustAuthorityApiKey:  "test-key",
			}

			_, err := NewITAClient(cfg, serverName)
			// Invalid URLs should cause errors
			if err == nil {
				t.Errorf("NewITAClient() with invalid URL %s should return error", tt.baseUrl)
			}
		})
	}
}
