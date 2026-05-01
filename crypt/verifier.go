/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

type Token struct {
	jwtToken         *jwt.Token
	registeredClaims *jwt.RegisteredClaims
	customClaims     interface{}
}

func GetTokenClaims(parsedToken *jwt.Token, tokenString string, customClaims interface{}) (*Token, error) {

	token := Token{}
	token.registeredClaims = &jwt.RegisteredClaims{}
	token.jwtToken = parsedToken

	// so far we have only got the standardClaims parsed. We need to now fill the customClaims
	parts := strings.Split(tokenString, ".")

	// parse Claims
	var claimBytes []byte
	var err error

	if claimBytes, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, errors.Wrap(err, "could not decode claims part of the jwt token")
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	err = dec.Decode(customClaims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode token claims as json")
	}
	token.customClaims = customClaims

	return &token, nil
}
