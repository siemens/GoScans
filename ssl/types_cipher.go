/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"fmt"
)

// Before changing this command read the comment in types.go
//go:generate stringer -linecomment -output=types_cipher_string.go -type=Protocol,Encryption,EncryptionMode,Authentication,KeyExchange,Mac,Prf ./

// CipherInfo holds cipher suite details for our mapping.
type CipherInfo struct {
	Id          string         `json:"cipher_suite"` // Cipher suite id
	OpensslName string         `json:"openssl_name"` // OpenSSL name of the cipher (SSLyze uses it)
	IanaName    string         `json:"iana_name"`    // IANA name
	Kx          KeyExchange    `json:"kx"`           // Key exchange protocol
	Au          Authentication `json:"au"`           // Key exchange authentication
	Enc         Encryption     `json:"enc"`          // (Bulk) encryption algorithm
	EncBits     int            `json:"enc_bits"`     //
	EncMode     EncryptionMode `json:"enc_mode"`     //
	Mac         Mac            `json:"mac"`          // Message authentication code algorithm
	Prf         Prf            `json:"prf"`          // Pseudorandom function family if existing
	Export      bool           `json:"export"`       // export indicator, if the string is not empty it's an exportable cipher
}

const CipherPreferenceClient = "client" // Client-selected cipher preference
const CipherPreferenceServer = "server" // Server-selected cipher preference

const (
	PROTO_Unknown Protocol = iota //
	Sslv2                         // SSLv2
	Sslv3                         // SSLv3
	Tlsv1_0                       // TLSv1.0
	Tlsv1_1                       // TLSv1.1
	Tlsv1_2                       // TLSv1.2
	Tlsv1_3                       // TLSv1.3
)

// Protocol identifies a supported SSL or TLS protocol version
type Protocol uint8

// IsValidProtocol reports whether the Protocol has a known, non-unknown value.
func IsValidProtocol(p Protocol) bool {
	return p > 0 && p <= Tlsv1_3
}

// KEX_ECMQV: https://tools.ietf.org/html/draft-campagna-tls-ecmqv-ecqv-01
// KEX_GOSTR341001: elliptic curve version
const (
	KEX_DH           KeyExchange = iota + 1 // DH
	KEX_DHE                                 // DHE
	KEX_ECDH                                // ECDH
	KEX_ECDHE                               // ECDHE
	KEX_ECMQV                               // ECMQV
	KEX_ECCPWD                              // ECCPWD
	KEX_FORTEZZA_KEA                        // FORTEZZA_KEA
	KEX_GOSTR341001                         // GOST R 34.10-2001
	KEX_GOSTR341094                         // GOST R 34.10.1994
	KEX_KRB5                                // KRB5
	KEX_PSK                                 // PSK
	KEX_RSA                                 // RSA
	KEX_SRP_SHA                             // SRP_SHA
	KEX_TLSv1_3                             // (EC)DHE / PSK / PSK + (EC)DHE
)

// KeyExchange represents algorithms used for the key exchange.
type KeyExchange uint8

// IsValidKeyExchange reports whether the KeyExchange has a known, non-zero value.
func IsValidKeyExchange(k KeyExchange) bool {
	return k > 0 && k <= KEX_TLSv1_3
}

// providesForwardSecrecy reports whether the key exchange algorithm provides forward secrecy.
func (k KeyExchange) providesForwardSecrecy() bool {
	return k == KEX_DHE || k == KEX_ECDHE || k == KEX_ECMQV
}

// getStrength returns the effective security strength in bits for the given key size.
func (k KeyExchange) getStrength(size uint64) (float64, error) {
	if size <= 0 {
		return 0, fmt.Errorf("key size has to be greater than 0, is %d", size)
	}

	switch k {
	case KEX_DH, KEX_DHE, KEX_FORTEZZA_KEA, KEX_GOSTR341094, KEX_RSA, KEX_SRP_SHA:
		return gnfsComplexity(size)
	case KEX_ECDH, KEX_ECDHE, KEX_ECMQV, KEX_ECCPWD, KEX_GOSTR341001:
		return eccComplexity(size), nil
	case KEX_KRB5, KEX_TLSv1_3:
		// KEX_KRB5: multiple different algorithms supported -> no way to know how to compute the strength
		// KEX_TLSv1_3: The receiver should never have this type. Before the scan we don't know whether DHE or ECDHE
		// will be used, as TLS 1.3 support either. So we have to get the information during the scan aka. from SSLyze,
		// but then we also get the type of key exchange and can use the correct receiver.
		return 0, nil
		// TODO: Last but not least figure out the psk
	case KEX_PSK:
		return 0, fmt.Errorf("unknown key strength for kex exchange algorithm '%s'", k)
	default:
		return 0, fmt.Errorf("unknown key exchange algorithm '%s'", k)
	}
}

// AUTH_GOSTR341001: elliptic curve version
const (
	AUTH_NONE         Authentication = iota + 1 // No authentication
	AUTH_TLSv1_3                                // RSA / ECDSA / RSA-PSS / EdDSA / PSK
	AUTH_DSS                                    // DSS
	AUTH_ECDSA                                  // ECDSA
	AUTH_ECNRA                                  // ECNRA
	AUTH_FORTEZZA_KEA                           // FORTEZZA_KEA
	AUTH_GOSTR341001                            // GOST R 34.10.2001
	AUTH_GOSTR341094                            // GOST R 34.10.1994
	AUTH_KRB5                                   // KRB5
	AUTH_PSK                                    // PSK
	AUTH_RSA                                    // RSA
	AUTH_SRP_SHA                                // SRP_SHA
)

// Authentication represents algorithms used to authenticate the server and optionally client.
type Authentication uint8

// IsValidAuthentication reports whether the Authentication has a known, non-zero value.
func IsValidAuthentication(auth Authentication) bool {
	return auth > 0 && auth <= AUTH_SRP_SHA
}

const (
	ENC_NONE       Encryption = iota + 1 // No encryption
	ENC_DES                              // DES
	ENC_RC2                              // RC2
	ENC_TRIPLE_DES                       // 3DES
	ENC_SKIPJACK                         // FORTEZZA
	ENC_SEED                             // SEED
	ENC_IDEA                             // IDEA
	ENC_CAMELLIA                         // Camellia
	ENC_ARIA                             // ARIA
	ENC_GOST28147                        // GOST 28147
	ENC_AES                              // AES

	// Stream ciphers
	ENC_RC4      // RC4
	ENC_CHACHA20 // ChaCha20
)

// Encryption represents an encryption algorithm used by a cipher suite
type Encryption uint8

// IsValidEncryption reports whether the Encryption has a known, non-zero value.
func IsValidEncryption(enc Encryption) bool {
	return enc > 0 && enc <= ENC_CHACHA20
}

// isBlockCipher returns true if the cipher is a block cipher.
// CAUTION: A 'false' return value does not guarantee for the encryption to be a stream cipher. It could also be
// 'ENC_NONE' or an unknown encryption.
func (e Encryption) isBlockCipher() bool {
	switch e {
	case ENC_DES, ENC_RC2, ENC_TRIPLE_DES, ENC_SKIPJACK, ENC_SEED,
		ENC_IDEA, ENC_CAMELLIA, ENC_ARIA, ENC_GOST28147, ENC_AES:
		return true
	default:
		return false
	}
}

// isStreamCipher returns true if the cipher is a stream cipher.
// CAUTION: A 'false' return value does not guarantee for the encryption to be a block cipher. It could also be
// 'ENC_NONE' or an unknown encryption.
func (e Encryption) isStreamCipher() bool {
	switch e {
	case ENC_RC4, ENC_CHACHA20:
		return true
	default:
		return false
	}
}

// getBlockSize returns the block size of the encryption algorithm in bits, or 0 if not applicable.
func (e Encryption) getBlockSize() int {
	switch e {
	case ENC_DES, ENC_RC2, ENC_TRIPLE_DES, ENC_SKIPJACK, ENC_IDEA, ENC_GOST28147:
		return 64
	case ENC_SEED, ENC_CAMELLIA, ENC_ARIA, ENC_AES:
		return 128
	default:
		return 0
	}
}

// getStrength returns the effective strength of the encryption. This relies on the key size, as some encryption
// algorithms have a variable key size and a fixed strength adjustment (e.g. 3DES).
func (e Encryption) getStrength(keySize int) int {
	if e == ENC_NONE {
		return 0
	}

	if e == ENC_TRIPLE_DES {
		return 112 // Meet-in-the-middle attack.
	}

	return keySize
}

// CNT mode for GOST ciphers, see https://tools.ietf.org/html/rfc5830#page-6
const (
	ENC_M_NONE     EncryptionMode = iota + 1 // No encryption mode
	ENC_M_CBC                                // CBC
	ENC_M_CCM                                // CCM
	ENC_M_CCM_8                              // CCM8
	ENC_M_GCM                                // GCM
	ENC_M_POLY1305                           // Poly1305
	ENC_M_CNT                                // CNT
)

// EncryptionMode represents modes of operation for block ciphers.
type EncryptionMode uint8

// IsValidEncryptionMode reports whether the EncryptionMode has a known, non-zero value.
func IsValidEncryptionMode(encMode EncryptionMode) bool {
	return encMode > 0 && encMode <= ENC_M_CNT
}

const (
	MAC_AEAD        Mac = iota + 1 // AEAD
	MAC_MD2                        // MD2
	MAC_MD5                        // MD5
	MAC_SHA1                       // SHA1
	MAC_SHA224                     // SHA224
	MAC_SHA256                     // SHA256
	MAC_SHA384                     // SHA384
	MAC_SHA512                     // SHA512
	MAC_RIPEMD160                  // RMD
	MAC_GOSTR341194                // GOSTR341194
	MAC_GOST28147                  // GOST28147
	MAC_STREEBOG256                // Streeborg256
	MAC_BLAKE2B                    // BLAKE2b
	MAC_BLAKE2S                    // BLAKE2s
)

// Mac represents hash algorithms used for message authentication codes.
type Mac uint8

// IsValidMac reports whether the Mac has a known, non-zero value.
func IsValidMac(m Mac) bool {
	return m > 0 && m <= MAC_BLAKE2S
}

// getDigestSize returns the digest size. In the case of Blake2* the digest size is variable and the maximum of 512 is
// returned. The digest size is also used for computing the strength of the message authentication mode.
func (m Mac) getDigestSize() int {
	switch m {
	case MAC_MD2, MAC_MD5:
		return 128
	case MAC_SHA1, MAC_RIPEMD160:
		return 160
	case MAC_SHA224:
		return 224
	case MAC_SHA256, MAC_GOSTR341194:
		return 256
	case MAC_SHA384:
		return 384
	case MAC_SHA512, MAC_BLAKE2B, MAC_BLAKE2S:
		return 512
	default:
		return 0
	}
}

// getHmacStrength returns the computed hash-based MAC strength in bits.
func (m Mac) getHmacStrength() int {
	return m.getDigestSize()
}

const (
	PRF_NONE      Prf = iota + 1 //
	PRF_MD2                      // MD2
	PRF_MD5                      // MD5
	PRF_SHA1                     // SHA1
	PRF_SHA224                   // SHA224
	PRF_SHA256                   // SHA256
	PRF_SHA384                   // SHA384
	PRF_SHA512                   // SHA512
	PRF_RIPEMD160                // RMD
	PRF_GOST28147                // IMIT GOST28147
	PRF_BLAKE2B                  // BLAKE2b
	PRF_BLAKE2S                  // BLAKE2s
)

// Prf represents hash algorithms used as pseudo-random functions.
type Prf uint8

// IsValidPrf reports whether the Prf has a known, non-zero value.
func IsValidPrf(p Prf) bool {
	return p > 0 && p <= PRF_BLAKE2S
}

// getDigestSize returns the digest size. In the case of Blake2* the digest size is variable and the maximum of 512 is
// returned. The digest size is also used as the hmac strength.
func (p Prf) getDigestSize() int {
	switch p {
	case PRF_MD2, PRF_MD5:
		return 128
	case PRF_SHA1, PRF_RIPEMD160:
		return 160
	case PRF_SHA224:
		return 224
	case PRF_SHA256, PRF_GOST28147:
		return 256
	case PRF_SHA384:
		return 384
	case PRF_SHA512, PRF_BLAKE2B, PRF_BLAKE2S:
		return 512
	default:
		return 0
	}
}

// getHmacStrength returns the computed hash-based PRF strength in bits.
func (p Prf) getHmacStrength() int {
	return p.getDigestSize()
}
