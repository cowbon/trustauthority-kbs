/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"testing"

	"github.com/onsi/gomega"
)

func TestAttesterTypeString(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	g.Expect(TDX.String()).To(gomega.Equal("TDX"))
	g.Expect(SGX.String()).To(gomega.Equal("SGX"))
	g.Expect(NVGPU.String()).To(gomega.Equal("NVGPU"))
}

func TestAttesterTypeValid(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	g.Expect(TDX.Valid()).To(gomega.BeTrue())
	g.Expect(SGX.Valid()).To(gomega.BeTrue())
	g.Expect(NVGPU.Valid()).To(gomega.BeTrue())
	g.Expect(AttesterType("TPM").Valid()).To(gomega.BeFalse())
	g.Expect(AttesterType("").Valid()).To(gomega.BeFalse())
}

func TestAttesterTypesContains(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	types := AttesterTypes{TDX, NVGPU}
	g.Expect(types.Contains(TDX)).To(gomega.BeTrue())
	g.Expect(types.Contains(NVGPU)).To(gomega.BeTrue())
	g.Expect(types.Contains(SGX)).To(gomega.BeFalse())

	empty := AttesterTypes{}
	g.Expect(empty.Contains(TDX)).To(gomega.BeFalse())
}

func TestAttesterTypesKeyWrappingAttesterType(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	// Single TDX entry
	at, err := AttesterTypes{TDX}.KeyWrappingAttesterType()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(at).To(gomega.Equal(TDX))

	// Single SGX entry
	at, err = AttesterTypes{SGX}.KeyWrappingAttesterType()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(at).To(gomega.Equal(SGX))

	// NVGPU before TDX — first TDX/SGX element is returned
	at, err = AttesterTypes{NVGPU, TDX}.KeyWrappingAttesterType()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(at).To(gomega.Equal(TDX))

	// Composite TDX+NVGPU
	at, err = AttesterTypes{TDX, NVGPU}.KeyWrappingAttesterType()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(at).To(gomega.Equal(TDX))

	// NVGPU only — no key-wrapping type available
	_, err = AttesterTypes{NVGPU}.KeyWrappingAttesterType()
	g.Expect(err).To(gomega.HaveOccurred())

	// Empty slice — no key-wrapping type available
	_, err = AttesterTypes{}.KeyWrappingAttesterType()
	g.Expect(err).To(gomega.HaveOccurred())
}
