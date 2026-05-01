/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type TestClaims struct {
	jwt.RegisteredClaims
	CustomField string `json:"custom_field"`
}

func TestGetTokenClaims(t *testing.T) {
	// Success case
	claims := TestClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "test-subject"},
		CustomField:      "test-value",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	parsedToken, _ := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	customClaims := &TestClaims{}
	result, err := GetTokenClaims(parsedToken, tokenString, customClaims)
	if err != nil {
		t.Fatalf("GetTokenClaims failed: %v", err)
	}
	if result == nil || customClaims.CustomField != "test-value" {
		t.Error("Failed to parse token claims correctly")
	}

	// Error cases
	_, err = GetTokenClaims(&jwt.Token{}, "invalid.token", &TestClaims{})
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}
