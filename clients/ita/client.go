/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ita

import (
	"crypto/tls"
	"intel/kbs/v1/config"

	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

// NewITAClient creates a new Intel Trust Authority connector for the given configuration.
// The TLS ServerName is intentionally left empty — Go's TLS stack derives it automatically
// from the URL hostname, so no explicit override is needed for normal production use.
func NewITAClient(cfg *config.Configuration) (itaConnector.Connector, error) {

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	connectorCfg := itaConnector.Config{
		BaseUrl:     cfg.TrustAuthorityBaseUrl,
		TlsCfg:      tlsConfig,
		ApiUrl:      cfg.TrustAuthorityApiUrl,
		ApiKey:      cfg.TrustAuthorityApiKey,
		RetryConfig: nil,
	}

	connector, err := itaConnector.New(&connectorCfg)
	if err != nil {
		return nil, errors.Wrap(err, "error creating TrustAuthority connector")
	}
	return connector, nil
}
