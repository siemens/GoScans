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
	"fmt"
	"github.com/siemens/GoScans/utils"
)

// Before changing this command read the comment in types.go
//go:generate stringer -linecomment -output=types_certificate_string.go -type=PublicKey,SignatureAlgorithm,SignatureHash ./

// Certificate types
const (
	certificateTypeRoot         = "root"
	certificateTypeIntermediate = "intermediate"
	certificateTypeLeaf         = "leaf"
)

type PublicKey uint8

const (
	PUB_K_Unknown     PublicKey = iota //
	PUB_K_RSA                          // RSA
	PUB_K_DSA                          // DSA
	PUB_K_ECDSA                        // ECDSA
	PUB_K_ED25519                      // Ed25519
	PUB_K_ED448                        // Ed448
	PUB_K_GOSTR341001                  // GOSTR341001
	PUB_K_GOSTR341094                  // GOSTR341094
)

func makePublicKeyFromX509(logger utils.Logger, alg x509.PublicKeyAlgorithm) PublicKey {

	switch alg {
	case x509.RSA:
		return PUB_K_RSA
	case x509.DSA:
		return PUB_K_DSA
	case x509.ECDSA:
		return PUB_K_ECDSA
	case x509.Ed25519:
		return PUB_K_ED25519
	case x509.UnknownPublicKeyAlgorithm:
		// TODO, nice to have: Implement GOST detection, return appropriate public key
		logger.Warningf("(Golang) unknown public key algorithm '%s'.", alg)
		return PUB_K_Unknown
	default:
		logger.Warningf("Unknown public key algorithm '%s'.", alg)
		return PUB_K_Unknown
	}
}

func makePublicKey(logger utils.Logger, alg string) PublicKey {

	switch alg {
	case "_RSAPublicKey":
		return PUB_K_RSA
	case "_DSAPublicKey":
		return PUB_K_DSA
	case "_EllipticCurvePublicKey":
		return PUB_K_ECDSA
	case "_Ed25519PublicKey":
		return PUB_K_ED25519
	case "_Ed448PublicKey":
		return PUB_K_ED448
	case "Unexpected key algorithm":
		// TODO, nice to have: Implement GOST detection, return appropriate public key
		logger.Warningf("(SSLyze) unknown public key algorithm '%s'.", alg)
		return PUB_K_Unknown
	default:
		logger.Warningf("Unknown public key algorithm '%s'.", alg)
		return PUB_K_Unknown
	}
}

type SignatureAlgorithm uint8

const (
	SIG_A_Unknown SignatureAlgorithm = iota //
	SIG_A_RSA                               // RSA
	SIG_A_DSA                               // DSA
	SIG_A_ECDSA                             // ECDSA
	SIG_A_RSAPSS                            // RSAPSS
)

func (a SignatureAlgorithm) IsValidSignatureAlgo() bool {
	return a > 0 && a <= SIG_A_RSAPSS
}

func makeSignatureAlgorithmFromX509(logger utils.Logger, alg x509.SignatureAlgorithm) SignatureAlgorithm {

	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return SIG_A_RSA
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		return SIG_A_DSA
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return SIG_A_ECDSA
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return SIG_A_RSAPSS
	case x509.UnknownSignatureAlgorithm:
		logger.Warningf("(Golang) unknown signature algorithm '%s'.", alg)
		return SIG_A_Unknown
	default:
		logger.Warningf("Unknown signature algorithm '%s'.", alg)
		return SIG_A_Unknown
	}
}

// Signature hash algorithms
type SignatureHash uint8

// BLAKE2*: has a variable digest size, 512 is the maximum.
// SIG_H_None happen if the signature does not use a separate hash (ED25519, ED448).
const (
	SIG_H_Unknown   SignatureHash = iota //
	SIG_H_None                           // None
	SIG_H_MD2                            // MD2
	SIG_H_MD5                            // MD5
	SIG_H_SHA1                           // SHA1
	SIG_H_SHA224                         // SHA224
	SIG_H_SHA256                         // SHA256
	SIG_H_SHA384                         // SHA384
	SIG_H_SHA512                         // SHA512
	SIG_H_RIPEMD160                      // RMD
	SIG_H_GOSTR3411                      // GOSTR3411
	SIG_H_BLAKE2B                        // BLAKE2b
	SIG_H_BLAKE2S                        // BLAKE2s
)

func (h SignatureHash) IsValidSignatureHash() bool {
	return h > 0 && h <= SIG_H_BLAKE2S
}

func makeSignatureHash(logger utils.Logger, alg string) SignatureHash {

	switch alg {
	case "":
		return SIG_H_None
	case "md2":
		return SIG_H_MD2
	case "md5":
		return SIG_H_MD5
	case "sha", "sha1":
		return SIG_H_SHA1
	case "sha256":
		return SIG_H_SHA256
	case "sha384":
		return SIG_H_SHA384
	case "sha512":
		return SIG_H_SHA512
	default:
		logger.Warningf("Unknown signature hash algo '%s'.", alg)
		return SIG_H_Unknown
	}
}

func makeSignatureHashFromX509(logger utils.Logger, alg x509.SignatureAlgorithm) SignatureHash {

	switch alg {
	case x509.MD2WithRSA:
		return SIG_H_MD2
	case x509.MD5WithRSA:
		return SIG_H_MD5
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return SIG_H_SHA1
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		return SIG_H_SHA256
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return SIG_H_SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return SIG_H_SHA512
	default:
		logger.Warningf("Unknown signature hash algo '%s'.", alg)
		return SIG_H_Unknown
	}
}

// GetDigestSize returns the digest size. In the case of Blake2* the digest size is variable and the maximum of 512 is
// returned. The digest size is also used as the hmac strength.
func (h SignatureHash) getDigestSize() int {

	switch h {
	case SIG_H_MD2, SIG_H_MD5:
		return 128
	case SIG_H_SHA1, SIG_H_RIPEMD160:
		return 160
	case SIG_H_SHA224:
		return 224
	case SIG_H_SHA256, SIG_H_GOSTR3411:
		return 256
	case SIG_H_SHA384:
		return 384
	case SIG_H_SHA512, SIG_H_BLAKE2B, SIG_H_BLAKE2S:
		return 512
	default:
		return 0
	}
}

// GetStrength returns the strength of the hash.
func (h SignatureHash) getStrength() int {
	return h.getDigestSize() / 2
}

// Curves used for elliptic curve cryptography (ECDHE, ECDSA).
// see http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// This custom type is not transformed to an integer type as we only have one significant method declared for it and we
// only get a string from SSLyze. Therefore we'd have to create a mapping to our type in order to use a integer
// representation.
type Curve string

const (
	SECT163K1       Curve = "sect163k1"
	SECT163R1       Curve = "sect163r1"
	SECT163R2       Curve = "sect163r2"
	SECT193R1       Curve = "sect193r1"
	SECT193R2       Curve = "sect193r2"
	SECT233K1       Curve = "sect233k1"
	SECT233R1       Curve = "sect233r1"
	SECT239K1       Curve = "sect239k1"
	SECT283K1       Curve = "sect283k1"
	SECT283R1       Curve = "sect283r1"
	SECT409K1       Curve = "sect409k1"
	SECT409R1       Curve = "sect409r1"
	SECT571K1       Curve = "sect571k1"
	SECT571R1       Curve = "sect571r1"
	SECP160K1       Curve = "secp160k1"
	SECP160R1       Curve = "secp160r1"
	SECP160R2       Curve = "secp160r2"
	SECP192K1       Curve = "secp192k1"
	SECP192R1       Curve = "secp192r1"
	SECP224K1       Curve = "secp224k1"
	SECP224R1       Curve = "secp224r1"
	SECP256K1       Curve = "secp256k1"
	SECP256R1       Curve = "secp256r1"
	SECP384R1       Curve = "secp384r1"
	SECP521R1       Curve = "secp521r1"
	BRAINPOOLP256R1 Curve = "brainpoolP256r1"
	BRAINPOOLP384R1 Curve = "brainpoolP384r1"
	BRAINPOOLP512R1 Curve = "brainpoolP512r1"
	ECDH_X25519     Curve = "ecdh_x25519"
)

func (c Curve) IsValidCurve() bool {

	switch c {
	case
		SECT163K1, SECT163R1, SECT163R2, SECT193R1, SECT193R2,
		SECT233K1, SECT233R1, SECT239K1, SECT283K1, SECT283R1,
		SECT409K1, SECT409R1, SECT571K1, SECT571R1, SECP160K1,
		SECP160R1, SECP160R2, SECP192K1, SECP192R1, SECP224K1,
		SECP224R1, SECP256K1, SECP256R1, SECP384R1, SECP521R1,
		BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1, ECDH_X25519:
		return true
	default:
		return false
	}
}

// makeCurve creates a curve corresponding to the given string.
func makeCurve(logger utils.Logger, cv string) Curve {

	c := Curve(cv)
	switch c {
	case
		SECT163K1, SECT163R1, SECT163R2, SECT193R1, SECT193R2,
		SECT233K1, SECT233R1, SECT239K1, SECT283K1, SECT283R1,
		SECT409K1, SECT409R1, SECT571K1, SECT571R1, SECP160K1,
		SECP160R1, SECP160R2, SECP192K1, SECP192R1, SECP224K1,
		SECP224R1, SECP256K1, SECP256R1, SECP384R1, SECP521R1,
		BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1, ECDH_X25519:
		return c
	default:
		logger.Warningf("Unknown curve '%s'.", cv)
		return ""
	}
}

// We have to create our own String() function, as the Curve is a string alias and stringer can't process those.
func (c Curve) String() string {

	switch c {
	case
		SECT163K1, SECT163R1, SECT163R2, SECT193R1, SECT193R2,
		SECT233K1, SECT233R1, SECT239K1, SECT283K1, SECT283R1,
		SECT409K1, SECT409R1, SECT571K1, SECT571R1, SECP160K1,
		SECP160R1, SECP160R2, SECP192K1, SECP192R1, SECP224K1,
		SECP224R1, SECP256K1, SECP256R1, SECP384R1, SECP521R1,
		BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1, ECDH_X25519:
		return string(c)
	default:
		return fmt.Sprintf("Curve(\"%s\")", string(c))
	}
}

// GetPrimeFieldSize returns prime field size of the given curve.
func (c Curve) getPrimeFieldSize() int {

	switch c {
	case SECT163K1, SECT163R1, SECT163R2:
		return 163
	case SECT193R1, SECT193R2:
		return 193
	case SECT233K1, SECT233R1:
		return 233
	case SECT239K1:
		return 239
	case SECT283K1, SECT283R1:
		return 283
	case SECT409K1, SECT409R1:
		return 409
	case SECT571K1, SECT571R1:
		return 571
	case SECP160K1, SECP160R1, SECP160R2:
		return 160
	case SECP192K1, SECP192R1:
		return 192
	case SECP224K1, SECP224R1:
		return 224
	case SECP256K1, SECP256R1, BRAINPOOLP256R1, ECDH_X25519:
		return 256
	case SECP384R1, BRAINPOOLP384R1:
		return 384
	case SECP521R1:
		return 521
	case BRAINPOOLP512R1:
		return 512
	default:
		return 0
	}
}

// GetStrength returns the computed strength. The second return value signalizes whether the fieldSize is 0.
func (c Curve) getStrength() float64 {
	return float64(c.getPrimeFieldSize()) / 2.
}

var keyUsageMap = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Content Commitment",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Cert Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

func makeKeyUsageSlice(logger utils.Logger, in x509.KeyUsage) []string {

	// Check that the values are in the correct range. (Hint 2^9 = 512)
	if int(in) < 0 || int(in) >= 512 {
		logger.Warningf("Unknown key usage bits set in '%b'.", in)
		return []string{}
	}

	// No bits in bitmap set -> return.
	if in == 0 {
		return []string{}
	}

	// Initialize the result struct
	ret := make([]string, 0, 2)

	for ku, str := range keyUsageMap {
		if ku&in == 0 {
			continue
		}

		// Bit is set -> add the corresponding string to our slice.
		ret = append(ret, str)

		// Clear the currently considered bit in order to detect unconsidered bits at the end.
		in = in &^ ku

		// Early break if the bit map is 0.
		if in == 0 {
			break
		}
	}

	return ret
}

var extKeyUsageMap = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "Server Auth",
	x509.ExtKeyUsageClientAuth:                     "Client Auth",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IP SEC End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IP SEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IP SEC User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

func makeExtKeyUsageSlice(logger utils.Logger, in []x509.ExtKeyUsage) []string {

	// Go through the extended key usages and add the corresponding string for every one of them to the result slice.
	ret := make([]string, 0, len(in))
	for _, k := range in {
		if str, ok := extKeyUsageMap[k]; ok {
			ret = append(ret, str)
			continue
		} else {
			// Unknown extended key usage, return an empty slice as we can't be sure to have valid values.
			logger.Warningf("Unknown extended key usage '%d'.", k)
			return []string{}
		}
	}
	return ret
}
