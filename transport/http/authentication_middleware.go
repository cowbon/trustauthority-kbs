/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/shaj13/go-guardian/v2/auth"
	log "github.com/sirupsen/logrus"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
)

func authMiddleware(next http.Handler, authz *model.JwtAuthz) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strategy := authz.AuthZStrategy
		user, err := strategy.Authenticate(r.Context(), r)
		if err != nil {
			log.WithError(err).Error("Request unauthorized")
			code := http.StatusUnauthorized
			http.Error(w, http.StatusText(code), code)
			return
		}
		// Verify the authenticated user still exists in the store.
		// This ensures tokens belonging to deleted users are rejected.
		if authz.UserExistsFunc != nil {
			userID, parseErr := uuid.Parse(user.GetID())
			if parseErr != nil {
				log.WithError(parseErr).Error("Request unauthorized: invalid user ID claim")
				code := http.StatusUnauthorized
				http.Error(w, http.StatusText(code), code)
				return
			}
			userExists, lookupErr := authz.UserExistsFunc(userID)
			if lookupErr != nil {
				log.WithError(lookupErr).WithField("user_id", userID.String()).Error("Request failed: unable to validate JWT subject")
				code := http.StatusServiceUnavailable
				http.Error(w, http.StatusText(code), code)
				return
			}
			if !userExists {
				log.WithField("user_id", userID.String()).Error("Request unauthorized: user no longer exists")
				code := http.StatusUnauthorized
				http.Error(w, http.StatusText(code), code)
				return
			}
		}
		r = auth.RequestWithUser(user, r)
		ctx := r.Context()
		ctx = context.WithValue(ctx, constant.LogUserID, user.GetID())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
