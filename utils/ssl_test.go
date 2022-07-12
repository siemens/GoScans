/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestInsecureTlsConfig(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name           string
		wantSkipVerify bool
		wantMinVersion uint16
		wantMaxVersion uint16
		wantCiphers    []uint16
	}{
		{"valid", true, tls.VersionSSL30, tls.VersionTLS12, []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InsecureTlsConfigFactory()
			if got.InsecureSkipVerify != tt.wantSkipVerify {
				t.Errorf("InsecureTlsConfigFactory() InsecureSkipVerify = '%v', want = '%v'", got.InsecureSkipVerify, tt.wantSkipVerify)
			}
			if got.MinVersion != tt.wantMinVersion {
				t.Errorf("InsecureTlsConfigFactory() MinVersion = '%v', want = '%v'", got.MinVersion, tt.wantMinVersion)
			}
			if got.MaxVersion != tt.wantMaxVersion {
				t.Errorf("InsecureTlsConfigFactory() MaxVersion = '%v', want = '%v'", got.MaxVersion, tt.wantMaxVersion)
			}
			if !reflect.DeepEqual(got.CipherSuites, tt.wantCiphers) {
				t.Errorf("InsecureTlsConfigFactory() Ciphers = '%v', want = '%v'", got.CipherSuites, tt.wantCiphers)
			}
		})
	}
}
