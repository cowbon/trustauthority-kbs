/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"errors"
	"testing"

	"intel/kbs/v1/mocks"
	"intel/kbs/v1/model"

	"github.com/stretchr/testify/mock"
)

func TestKmipManagerCreateKey(t *testing.T) {

	type args struct {
		algorithm string
		keyLength int
		funcName  string
		kmipId    string
		err       error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "create symmetric key",
			args: args{
				algorithm: "AES",
				keyLength: 256,
				funcName:  "CreateSymmetricKey",
				kmipId:    "1",
				err:       nil,
			},
			wantErr: false,
		},
		{
			name: "create asymmetric key",
			args: args{
				algorithm: "RSA",
				keyLength: 2048,
				funcName:  "CreateAsymmetricKeyPair",
				kmipId:    "1",
				err:       nil,
			},
			wantErr: false,
		},
		{
			name: "negative test - algorithm not supported",
			args: args{
				algorithm: "ECB",
			},
			wantErr: true,
		},
		{
			name: "negative test - create symmetric key failure",
			args: args{
				algorithm: "AES",
				keyLength: 256,
				funcName:  "CreateSymmetricKey",
				err:       errors.New("failed to create symmetric key"),
			},
			wantErr: true,
		},
		{
			name: "negative test - create asymmetric key failure",
			args: args{
				algorithm: "RSA",
				keyLength: 2048,
				funcName:  "CreateAsymmetricKeyPair",
				err:       errors.New("failed to create asymmetric key"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyInfo := &model.KeyInfo{
				Algorithm: tt.args.algorithm,
				KeyLength: tt.args.keyLength,
			}

			keyRequest := &model.KeyRequest{
				KeyInfo: keyInfo,
			}

			mockClient := mocks.NewMockKmipClient()
			mockClient.On(tt.args.funcName, mock.Anything).Return(tt.args.kmipId, tt.args.err)
			keyManager := &KmipManager{mockClient}
			_, err := keyManager.CreateKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKmipManagerDeleteKey(t *testing.T) {

	type args struct {
		kmipKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "delete key",
			args: args{
				kmipKeyID: "1",
			},
			wantErr: false,
		},
		{
			name: "negative test - kmipKeyID is empty",
			args: args{
				kmipKeyID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyAttributes := &model.KeyAttributes{
				KmipKeyID: tt.args.kmipKeyID,
			}
			mockClient := mocks.NewMockKmipClient()
			mockClient.On("DeleteKey", mock.Anything).Return(nil)
			keyManager := &KmipManager{mockClient}
			err := keyManager.DeleteKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKmipManagerRegisterKey(t *testing.T) {

	type args struct {
		algorithm string
		kmipKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "register key",
			args: args{
				algorithm: "AES",
				kmipKeyID: "1",
			},
			wantErr: false,
		},
		{
			name: "negative testing - kmipKeyID is empty",
			args: args{
				algorithm: "AES",
				kmipKeyID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyInfo := &model.KeyInfo{
				Algorithm: tt.args.algorithm,
				KmipKeyID: tt.args.kmipKeyID,
			}

			keyRequest := &model.KeyRequest{
				KeyInfo: keyInfo,
			}

			mockClient := mocks.NewMockKmipClient()
			keyManager := &KmipManager{mockClient}
			_, err := keyManager.RegisterKey(keyRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKmipManagerTransferKey(t *testing.T) {

	type args struct {
		algorithm string
		kmipKeyID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get symmetric key",
			args: args{
				algorithm: "AES",
				kmipKeyID: "1",
			},
			wantErr: false,
		},
		{
			name: "get asymmetric key",
			args: args{
				algorithm: "RSA",
				kmipKeyID: "2",
			},
			wantErr: false,
		},
		{
			name: "negative testing - algorithm not supported",
			args: args{
				algorithm: "ECB",
				kmipKeyID: "1",
			},
			wantErr: true,
		},
		{
			name: "negative testing - kmipKeyID is empty",
			args: args{
				algorithm: "AES",
				kmipKeyID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			keyAttributes := &model.KeyAttributes{
				Algorithm: tt.args.algorithm,
				KmipKeyID: tt.args.kmipKeyID,
			}

			mockClient := mocks.NewMockKmipClient()
			mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
			keyManager := &KmipManager{mockClient}
			_, err := keyManager.TransferKey(keyAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
