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
	"fmt"
)

// Before changing this command read the comment in types.go
//go:generate stringer -linecomment -output=types_cipher_string.go -type=Protocol,Encryption,EncryptionMode,Authentication,KeyExchange,Mac,Prf ./

// Struct used for our cipher suite mapping.
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

// Cipher preferences
const (
	CipherPreferenceClient = "client"
	CipherPreferenceServer = "server"
)

type Protocol uint8

const (
	PROTO_Unknown Protocol = iota //
	Sslv2                         // SSLv2
	Sslv3                         // SSLv3
	Tlsv1_0                       // TLSv1.0
	Tlsv1_1                       // TLSv1.1
	Tlsv1_2                       // TLSv1.2
	Tlsv1_3                       // TLSv1.3
)

func IsValidProtocol(p Protocol) bool {
	return p > 0 && p <= Tlsv1_3
}

//  Algorithms used for the key exchange.
type KeyExchange uint8

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

func IsValidKeyExchange(k KeyExchange) bool {
	return k > 0 && k <= KEX_TLSv1_3
}

func (k KeyExchange) providesForwardSecrecy() bool {
	return k == KEX_DHE || k == KEX_ECDHE || k == KEX_ECMQV
}

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

//  Algorithms used to authenticate the server and (optionally) client.
type Authentication uint8

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

func IsValidAuthentication(auth Authentication) bool {
	return auth > 0 && auth <= AUTH_SRP_SHA
}

// Encryption algorithms
type Encryption uint8

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

func IsValidEncryption(enc Encryption) bool {
	return enc > 0 && enc <= ENC_CHACHA20
}

// IsBlockCipher return true if the cipher is a block cipher.
// CAUTION: A 'false' return value does not guarantee for the encryption to be a stream cipher. It could also be
// 'ENC_NONE' or an unknown encryption!
func (e Encryption) isBlockCipher() bool {
	switch e {
	case ENC_DES, ENC_RC2, ENC_TRIPLE_DES, ENC_SKIPJACK, ENC_SEED,
		ENC_IDEA, ENC_CAMELLIA, ENC_ARIA, ENC_GOST28147, ENC_AES:
		return true
	default:
		return false
	}
}

// IsStreamCipher return true if the cipher is a stream cipher.
// CAUTION: A 'false' return value does not guarantee for the encryption to be a block cipher. It could also be
// 'ENC_NONE' or an unknown encryption!
func (e Encryption) isStreamCipher() bool {
	switch e {
	case ENC_RC4, ENC_CHACHA20:
		return true
	default:
		return false
	}
}

// BlockSize returns the block size, 0 else
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

// Strength returns the strength of the encryption. This is relying on the key size. We can't derive the it from the
// encryption's name, As some encryption algorithms have a variable key size. That's why we get it from our mapping.
func (e Encryption) getStrength(keySize int) int {
	if e == ENC_NONE {
		return 0
	}

	if e == ENC_TRIPLE_DES {
		return 112 // Meet-in-the-middle attack.
	}

	return keySize
}

// Modes of operation for block ciphers.
type EncryptionMode uint8

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

func IsValidEncryptionMode(encMode EncryptionMode) bool {
	return encMode > 0 && encMode <= ENC_M_CNT
}

// Hash algorithms
type Mac uint8

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

func IsValidMac(m Mac) bool {
	return m > 0 && m <= MAC_BLAKE2S
}

// GetDigestSize returns the digest size. In the case of Blake2* the digest size is variable and the maximum of 512 is
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

// GetStrength returns the computed hash based mac strength.
func (m Mac) getHmacStrength() int {
	return m.getDigestSize()
}

// Hash algorithms
type Prf uint8

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

func IsValidPrf(p Prf) bool {
	return p > 0 && p <= PRF_BLAKE2S
}

// GetDigestSize returns the digest size. In the case of Blake2* the digest size is variable and the maximum of 512 is
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

// GetStrength returns the computed hash based mac strength.
func (p Prf) getHmacStrength() int {
	return p.getDigestSize()
}
