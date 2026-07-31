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

	gosslyze "github.com/noneymous/GoSslyze"
)

// parseIssues creates and returns an issues struct with information on possible vulnerabilities.
func parseIssues(cr *gosslyze.CommandResults) (*Issues, error) {

	// Initialize the return structure.
	issues := &Issues{}

	// Check for nil pointer exceptions.
	if cr == nil {
		return issues, fmt.Errorf("provided SSLyze result is nil")
	}

	// General information
	if cr.EarlyData != nil && cr.EarlyData.Result != nil {
		issues.EarlyDataSupported = cr.EarlyData.Result.IsSupported
	}

	// Renegotiation information
	if cr.Renegotiation != nil && cr.Renegotiation.Result != nil {
		issues.ClientRenegotiationDos = cr.Renegotiation.Result.VulnerableToClientRenegotiation
	}

	// Vulnerability information
	if cr.Heartbleed != nil && cr.Heartbleed.Result != nil {
		issues.Heartbleed = cr.Heartbleed.Result.IsVulnerable
	}
	if cr.OpensslCcs != nil && cr.OpensslCcs.Result != nil {
		issues.CcsInjection = cr.OpensslCcs.Result.IsVulnerable
	}
	if cr.Compression != nil && cr.Compression.Result != nil {
		issues.Crime = cr.Compression.Result.IsSupported
	}
	if cr.Robot != nil && cr.Robot.Result != nil {
		issues.Robot = robotResultToBool(cr.Robot.Result.IsVulnerable)
	}

	// Return issues
	return issues, nil
}

// parseIssuesCiphers derives vulnerability flags from the accepted cipher suites in sslData.
func parseIssuesCiphers(sslData *Data) error {

	// Check for nil pointer exceptions.
	if sslData == nil {
		return fmt.Errorf("provided data is nil")
	}

	for _, cipher := range sslData.Ciphers {

		// Check if the cipher has forward secrecy
		if !cipher.ForwardSecrecy {
			sslData.Issues.NoPerfectForwardSecrecy = true
		}

		// Is there an export cipher suite supported?
		if cipher.Export {
			sslData.Issues.ExportSuite = true
		}

		// Is there a draft cipher suite supported?
		if cipher.Draft {
			sslData.Issues.DraftSuite = true
		}

		// Is there a cipher suite with sslv2 enabled?
		if cipher.Protocol == Sslv2 {
			sslData.Issues.Sslv2Enabled = true
		}

		// Is there a cipher suite with sslv3 enabled?
		if cipher.Protocol == Sslv3 {
			sslData.Issues.Sslv3Enabled = true

			// Is poodle vulnerable
			// Affects all block ciphers in SSLv3.
			if cipher.BlockCipher {
				sslData.Issues.Poodle = true
			}
		}

		// Is there a cipher suite with TLS 1.0 enabled?
		if cipher.Protocol == Tlsv1_0 {
			sslData.Issues.Tlsv1_0Enabled = true
		}

		// Is there a cipher suite with TLS 1.1 enabled?
		if cipher.Protocol == Tlsv1_1 {
			sslData.Issues.Tlsv1_1Enabled = true
		}

		// Is there a cipher suite with RC4 enabled?
		if cipher.Encryption == ENC_RC4 {
			sslData.Issues.Rc4Enabled = true
		}

		// Is there a cipher suite with a MD2 hash?
		if cipher.Mac == MAC_MD2 || (cipher.Mac == MAC_AEAD && cipher.Prf == PRF_MD2) {
			sslData.Issues.Md2Enabled = true
		}

		// Is there a cipher suite with a MD5 hash?
		if cipher.Mac == MAC_MD5 || (cipher.Mac == MAC_AEAD && cipher.Prf == PRF_MD5) {
			sslData.Issues.Md5Enabled = true
		}

		// Is shattered vulnerable / Does a cipher suite use SHA-1?
		// SHA-1 has been broken, see if the mac/prf is sha1 based. https://shattered.io/
		if cipher.Mac == MAC_SHA1 || (cipher.Mac == MAC_AEAD && cipher.Prf == PRF_SHA1) {
			sslData.Issues.Sha1Enabled = true
		}

		// Is Beast vulnerable
		// BEAST uses issues with the TLS 1.0 implementation of Cipher Block Chaining (CBC).
		// The vulnerability is mitigated on the client-side on modern browsers.
		if cipher.Protocol == Sslv3 || cipher.Protocol == Tlsv1_0 {
			if cipher.EncryptionMode == ENC_M_CBC {
				sslData.Issues.Beast = true
			}
		}

		// Is Lucky13 vulnerable
		// Lucky13 is a timing attack and a more advanced padding oracle. It can be used against Cipher Block
		// Chaining (CBC) mode of operation.
		// The vulnerability affects the TLS 1.1 and 1.2 version as well as earlier specifications with countermeasures
		// for previous passing oracle attacks in place.
		if cipher.Protocol == Sslv3 || cipher.Protocol == Tlsv1_0 ||
			cipher.Protocol == Tlsv1_1 || cipher.Protocol == Tlsv1_2 {
			if cipher.EncryptionMode == ENC_M_CBC {
				sslData.Issues.Lucky13 = true
			}
		}

		// Is freak vulnerable
		// Check if 512-bit RSA_EXPORT keys are supported.
		if cipher.KeyExchange == KEX_RSA && cipher.KeyExchangeBits <= 512 {
			sslData.Issues.Freak = true
		}

		// Is logjam vulnerable
		// True if the server uses DH parameters smaller (or equal) to 1024 bits. We also need to check whether the
		// number of key bits is actually greater than 0 because this information will not always be set.
		// Actually common DH primes should get checked, but this information is (currently) not feasible.
		if (cipher.KeyExchange == KEX_DHE || cipher.KeyExchange == KEX_DH) &&
			cipher.KeyExchangeBits <= 1024 && cipher.KeyExchangeBits > 0 {
			sslData.Issues.Logjam = true
		}

		// Is sweet32 vulnerable
		// Sweet32 is a birthday attack and 3DES in CBC mode is vulnerable because of it's mere 64-bit block size.
		if cipher.Encryption == ENC_TRIPLE_DES && cipher.EncryptionMode == ENC_M_CBC {
			sslData.Issues.Sweet32 = true
		}

		// Is drown vulnerable
		// The server additionally has to use the same private key for another connection (in which the attacker is
		// actually interested).
		if cipher.KeyExchange == KEX_RSA && cipher.Export && cipher.Protocol == Sslv2 {
			sslData.Issues.Drown = true
		}
	}

	// Return nil as everything went fine
	return nil
}

// robotResultToBool Helper function to convert ROBOT result string to boolean: see https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html#robot
func robotResultToBool(output string) bool {
	switch output {
	case "VULNERABLE_WEAK_ORACLE", "VULNERABLE_STRONG_ORACLE":
		return true
	case "NOT_VULNERABLE_NO_ORACLE", "NOT_VULNERABLE_RSA_NOT_SUPPORTED", "UNKNOWN_INCONSISTENT_RESULTS":
		return false
	default:
		return false // For any unknown value, consider it as not vulnerable
	}
}

// parseMinStrength sets the corresponding field in BasicData to the lowest value of key exchange, encryption,
// mac or the certificates public key. If a strength is not set a default 0 will be returned.
func parseMinStrength(sslData *Data) error {

	// Check for nil pointer exceptions.
	if sslData == nil {
		return fmt.Errorf("provided data is nil")
	}

	minCertStrength := 0
	// Find the minimum strength in the certificate chain.
	for _, deployment := range sslData.Chains {
		for _, cert := range deployment.Certificates {
			// Simply set the first valid value
			if minCertStrength == 0 {
				minCertStrength = cert.PublicKeyStrength
				continue
			}

			if cert.PublicKeyStrength > 0 && cert.PublicKeyStrength < minCertStrength {
				minCertStrength = cert.PublicKeyStrength
			}
		}
	}

	first := true
	minKexStrength := 0
	minEncStrength := 0
	minMacStrength := 0

	// Find the minimum strength in the accepted cipher suites.
	for _, cipher := range sslData.Ciphers {

		// We can't be sure to have information on the key exchange strength. Therefore we might have to check multiple
		// ciphers until we find a valid value and can't simply use the first one.
		if minKexStrength == 0 {
			minKexStrength = cipher.KeyExchangeStrength
		}

		// Simply set the first value
		if first {
			first = false

			// Set the encryption and mac (/prf) strength
			minEncStrength = cipher.EncryptionStrength
			if cipher.Mac != MAC_AEAD {
				minMacStrength = cipher.MacStrength
			} else {
				minMacStrength = cipher.PrfStrength
			}

			// Continue with next cipher
			continue
		}

		// Again we have to check whether the key exchange strength is valid in the first place
		if cipher.KeyExchangeStrength > 0 && cipher.KeyExchangeStrength < minKexStrength {
			minKexStrength = cipher.KeyExchangeStrength
		}

		// Set the encryption and mac (/prf) strength
		if cipher.EncryptionStrength < minEncStrength {
			minEncStrength = cipher.EncryptionStrength
		}
		if cipher.Mac != MAC_AEAD {
			if cipher.MacStrength < minMacStrength {
				minMacStrength = cipher.MacStrength
			}
		} else {
			if cipher.PrfStrength < minMacStrength {
				minMacStrength = cipher.PrfStrength
			}
		}
	}

	// Determine the smallest value of encryption, mac and the certificates public key (= authentication and/or encryption)
	minStrength := minCertStrength
	if minEncStrength < minStrength {
		minStrength = minEncStrength
	}
	if minMacStrength < minStrength {
		minStrength = minMacStrength
	}

	// The key exchange strength is only valid if it's greater than 0. Otherwise, we did not get any information on it.
	if minKexStrength > 0 && minKexStrength < minStrength {
		minStrength = minKexStrength
	}

	// The same procedure as with the minKexStrength.
	if minCertStrength > 0 && minCertStrength < minStrength {
		minStrength = minCertStrength
	}

	sslData.Settings.MinStrength = minStrength

	// Below 128 bits is considered cryptographically weak
	if minStrength < 128 {
		sslData.Issues.LowEncryptionStrength = true
	}

	// Return nil as everything went fine
	return nil
}
