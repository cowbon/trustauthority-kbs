/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package version

import (
	"testing"

	"intel/kbs/v1/constant"
)

func TestGetVersion(t *testing.T) {
	v := GetVersion()
	if v == nil {
		t.Fatal("GetVersion() returned nil")
	}

	if v.Name != constant.ExplicitServiceName {
		t.Errorf("Name = %s, want %s", v.Name, constant.ExplicitServiceName)
	}

	s := constant.ExplicitServiceName + " " + Version + "-" + GitHash + " [" + BuildDate + "]"
	if s != v.String() {
		t.Errorf("String = %s, want %s", v.String(), s)
	}
}
