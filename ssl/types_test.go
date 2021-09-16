/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"crypto/x509"
	"go-scans/utils"
	"testing"
)

func Test_makeKeyUsage(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		logger utils.Logger
		input  x509.KeyUsage
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// The invalid tests will produce some warnings
		{"zero", args{testLogger, 0}, []string{}},
		{"invalid 1", args{testLogger, -1}, []string{}},
		{"invalid 2", args{testLogger, 513}, []string{}},
		{"invalid 3", args{testLogger, 512}, []string{}},
		{"valid 1", args{testLogger, 81}, []string{"Digital Signature", "Key Agreement", "CRL Sign"}},
		{"valid 2", args{testLogger, 436}, []string{"Key Encipherment", "Key Agreement", "Cert Sign", "Encipher Only", "Decipher Only"}},
		{"valid 3", args{testLogger, 511}, []string{"Digital Signature", "Content Commitment", "Key Encipherment", "Data Encipherment", "Key Agreement", "Cert Sign", "CRL Sign", "Encipher Only", "Decipher Only"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := makeKeyUsageSlice(tt.args.logger, tt.args.input)
			if !utils.Equals(res, tt.want) {
				t.Errorf("res %v != want = '%v' ", res, tt.want)
			}
		})
	}
}

func Test_makeExtKeyUsage(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		logger utils.Logger
		input  []x509.ExtKeyUsage
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// The invalid tests will produce some warnings
		{"empty", args{testLogger, []x509.ExtKeyUsage{}}, []string{}},
		{"invalid lower bound", args{testLogger, []x509.ExtKeyUsage{-1}}, []string{}},
		{"invalid upper bound", args{testLogger, []x509.ExtKeyUsage{14}}, []string{}},
		{"invalid mixed", args{testLogger, []x509.ExtKeyUsage{-1, 3}}, []string{}},
		{"valid all", args{testLogger, []x509.ExtKeyUsage{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}}, []string{"Any", "Server Auth", "Client Auth", "Code Signing", "Email Protection", "IP SEC End System", "IP SEC Tunnel", "IP SEC User", "Time Stamping", "OCSP Signing", "Microsoft Server Gated Crypto", "Netscape Server Gated Crypto", "Microsoft Commercial Code Signing", "Microsoft Kernel Code Signing"}},
		{"valid order", args{testLogger, []x509.ExtKeyUsage{2, 12, 6, 9, 13, 10, 3, 7, 0, 1, 4, 8, 5, 11}}, []string{"Any", "Server Auth", "Client Auth", "Code Signing", "Email Protection", "IP SEC End System", "IP SEC Tunnel", "IP SEC User", "Time Stamping", "OCSP Signing", "Microsoft Server Gated Crypto", "Netscape Server Gated Crypto", "Microsoft Commercial Code Signing", "Microsoft Kernel Code Signing"}},
		{"valid some & order", args{testLogger, []x509.ExtKeyUsage{2, 12, 6, 9, 3, 7, 0, 11}}, []string{"Any", "Client Auth", "Code Signing", "IP SEC Tunnel", "IP SEC User", "OCSP Signing", "Netscape Server Gated Crypto", "Microsoft Commercial Code Signing"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := makeExtKeyUsageSlice(tt.args.logger, tt.args.input)
			if !utils.Equals(res, tt.want) {
				t.Errorf("res %v != want = '%v' ", res, tt.want)
			}
		})
	}
}
