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
	"encoding/base64"
	"fmt"
	"github.com/noneymous/GoSslyze"
	"github.com/siemens/GoScans/utils"
	"reflect"
)

// parseCiphers evaluates the accepted ciphers and returns the information about those ciphers as well as the cipher
// preference and lowest supported protocol version.
func parseCiphers(
	logger utils.Logger,
	targetName string,
	cr *gosslyze.CommandResults,
) (map[string]*Cipher, Protocol, error) {

	lowest := PROTO_Unknown
	ciphers := make(map[string]*Cipher)

	if cr == nil {
		return ciphers, lowest, fmt.Errorf("provided SSLyze result is nil")
	}

	// SSLv2
	if cr.SslV2 != nil && cr.SslV2.Result != nil {

		for _, acceptedCipher := range cr.SslV2.Result.AcceptedCiphers {
			cipher, errGet := getCipher(logger, &acceptedCipher, Sslv2)
			if errGet != nil {
				logger.Warningf("Could not parse and will therefore skip cipher suite '%s': %s",
					acceptedCipher.Cipher.OpensslName, errGet)
				continue
			}
			ciphers[Sslv2.String()+"|"+cipher.Id] = cipher

			// Set lowest protocol if there wasn't a lower one before
			if lowest == PROTO_Unknown || Sslv2 < lowest {
				lowest = Sslv2
			}
		}
	}

	// SSLv3
	if cr.SslV3 != nil && cr.SslV3.Result != nil {

		for _, acceptedCipher := range cr.SslV3.Result.AcceptedCiphers {
			cipher, errGet := getCipher(logger, &acceptedCipher, Sslv3)
			if errGet != nil {
				logger.Warningf("Could not parse and will therefore skip cipher suite '%s': %s",
					acceptedCipher.Cipher.OpensslName, errGet)
				continue
			}
			ciphers[Sslv3.String()+"|"+cipher.Id] = cipher

			// Set lowest protocol if there wasn't a lower one before
			if lowest == PROTO_Unknown || Sslv3 < lowest {
				lowest = Sslv3
			}
		}
	}

	// TlsV1.0
	if cr.TlsV1_0 != nil && cr.TlsV1_0.Result != nil {

		for _, acceptedCipher := range cr.TlsV1_0.Result.AcceptedCiphers {
			cipher, errGet := getCipher(logger, &acceptedCipher, Tlsv1_0)
			if errGet != nil {
				logger.Warningf("Could not parse and will therefore skip cipher suite '%s': %s",
					acceptedCipher.Cipher.OpensslName, errGet)
				continue
			}
			ciphers[Tlsv1_0.String()+"|"+cipher.Id] = cipher

			// Set lowest protocol if there wasn't a lower one before
			if lowest == PROTO_Unknown || Tlsv1_0 < lowest {
				lowest = Tlsv1_0
			}
		}
	}

	// TLSv1.1
	if cr.TlsV1_1 != nil && cr.TlsV1_1.Result != nil {

		for _, acceptedCipher := range cr.TlsV1_1.Result.AcceptedCiphers {
			cipher, errGet := getCipher(logger, &acceptedCipher, Tlsv1_1)
			if errGet != nil {
				logger.Warningf("Could not parse and will therefore skip cipher suite '%s': %s",
					acceptedCipher.Cipher.OpensslName, errGet)
				continue
			}
			ciphers[Tlsv1_1.String()+"|"+cipher.Id] = cipher

			// Set lowest protocol if there wasn't a lower one before
			if lowest == PROTO_Unknown || Tlsv1_1 < lowest {
				lowest = Tlsv1_1
			}
		}
	}

	// TLSv1.2
	if cr.TlsV1_2 != nil && cr.TlsV1_2.Result != nil {

		for _, acceptedCipher := range cr.TlsV1_2.Result.AcceptedCiphers {
			cipher, errGet := getCipher(logger, &acceptedCipher, Tlsv1_2)
			if errGet != nil {
				logger.Warningf("Could not parse and will therefore skip cipher suite '%s': %s",
					acceptedCipher.Cipher.OpensslName, errGet)
				continue
			}
			ciphers[Tlsv1_2.String()+"|"+cipher.Id] = cipher

			// Set lowest protocol if there wasn't a lower one before
			if lowest == PROTO_Unknown || Tlsv1_2 < lowest {
				lowest = Tlsv1_2
			}
		}
	}

	// TLSv1.3
	if cr.TlsV1_3 != nil && cr.TlsV1_3.Result != nil {

		for _, acceptedCipher := range cr.TlsV1_3.Result.AcceptedCiphers {
			cipher, errGet := getCipher(logger, &acceptedCipher, Tlsv1_3)
			if errGet != nil {
				logger.Warningf("Could not parse and will therefore skip cipher suite '%s': %s",
					acceptedCipher.Cipher.OpensslName, errGet)
				continue
			}
			ciphers[Tlsv1_3.String()+"|"+cipher.Id] = cipher

			// Set lowest protocol if there wasn't a lower one before
			if lowest == PROTO_Unknown || Tlsv1_3 < lowest {
				lowest = Tlsv1_3
			}
		}
	}

	return ciphers, lowest, nil
}

// getCipher returns the cipher suite according to the provided SSLyze cipher. In order to be a match the openssl
// name has to be the same. Additionally, some sanity as well as consistency checks will be done.
// Caution: preferredCipher can be nil, this indicates, that the the server follows the client's preference or none of
// the (presented) cipher suites are supported.
func getCipher(
	logger utils.Logger,
	acceptedCipher *gosslyze.AcceptedCipher,
	protocol Protocol,
) (*Cipher, error) {

	if acceptedCipher == nil {
		return nil, fmt.Errorf("provided cipher is nil")
	}

	sslyzeCipher := acceptedCipher.Cipher

	// Retrieve the cipher suite from our info mapping and set the missing protocol.
	cipher := getCipherByName(logger, sslyzeCipher.OpensslName, protocol)

	if IsValidProtocol(protocol) {
		cipher.Protocol = protocol
	} else {
		logger.Warningf("Invalid TLS version '%s'.", protocol)
	}

	// Check the inconsistencies in the key size
	// Actually 3DES has a key size of 168, but there's a Meet-in-the-middle attack which effectively get's that number
	// down to 112. SSLyze returns this 112 bit key size. Nonetheless we have separate fields for key size and strength.
	// Therefore we want to have:
	// EncryptionBits:		168
	// EncryptionStrength: 	112
	if cipher.EncryptionBits != sslyzeCipher.KeySize &&
		!(cipher.Encryption == ENC_TRIPLE_DES && cipher.EncryptionBits == 168 && sslyzeCipher.KeySize == 112) {
		// We already had one occasion where SSLyze returned a wrong size, therefore we stay with our result but still
		// log the event in order to inspect it.
		logger.Warningf("Encryption key size returned by SSLyze does not match with our info for cipher '%s'.",
			sslyzeCipher.OpensslName)

	}

	// Add the additional key info into the cipher
	cipher.KeyExchangeBits,
		cipher.KeyExchangeStrength,
		cipher.KeyExchangeInfo = parseEphemeralKeyInfo(logger, acceptedCipher.EphemeralKey)

	return cipher, nil
}

// parseEphemeralKeyInfo parses the EphemeralKeyInfo struct provided by SSLyze and returns the key size, strength as
// well as additional information (depending on the concrete EphemeralKeyInfo).
func parseEphemeralKeyInfo(logger utils.Logger, info gosslyze.EphemeralKeyInfo) (int, int, []string) {

	strength := 0
	size := 0
	extras := make([]string, 0, 5)

	if info == nil {
		// We expect the ephemeral key info to be nil for non-ephemeral key exchanges
		logger.Debugf("Ephemeral key info is not available.")
		return 0, 0, []string{}
	}

	// Small helper called for every type of ephemeral key info.
	parseBase := func(i *gosslyze.BaseKeyInfo) {
		size = i.Size
		extras = append(extras, "PublicBytes: "+base64.StdEncoding.EncodeToString(i.PublicBytes))
	}

	var kex KeyExchange

	switch info.(type) {
	case *gosslyze.BaseKeyInfo:
		// We shouldn't get a plain BaseKeyInfo, but it's possible
		i := info.(*gosslyze.BaseKeyInfo)
		parseBase(i)

		// We can not calculate the key strength, because we don't know which method is used
		return size, 0, extras

	case *gosslyze.EcDhKeyInfo:
		i := info.(*gosslyze.EcDhKeyInfo)
		parseBase(&i.BaseKeyInfo)
		extras = append(extras, "CurveName: "+i.CurveName)

		kex = KEX_ECDHE

	case *gosslyze.NistEcDhKeyInfo:
		i := info.(*gosslyze.NistEcDhKeyInfo)
		parseBase(&i.BaseKeyInfo)
		extras = append(extras, "CurveName: "+i.CurveName)
		extras = append(extras, "X: "+base64.StdEncoding.EncodeToString(i.X))
		extras = append(extras, "Y: "+base64.StdEncoding.EncodeToString(i.Y))

		kex = KEX_ECDHE

	case *gosslyze.DhKeyInfo:
		i := info.(*gosslyze.DhKeyInfo)
		parseBase(&i.BaseKeyInfo)

		extras = append(extras, "Prime: "+base64.StdEncoding.EncodeToString(i.Prime))
		extras = append(extras, "Generator: "+base64.StdEncoding.EncodeToString(i.Generator))

		kex = KEX_DHE

	default:
		logger.Warningf("Ephemeral key info has invalid type: '%s'", reflect.TypeOf(info))
		return 0, 0, []string{}
	}

	// Compute the key strength
	str, errStrength := kex.getStrength(uint64(size))
	if errStrength != nil {
		logger.Warningf("Could not compute key exchange strength: '%s'",
			errStrength)
	}
	strength = int(str)

	return size, strength, extras
}
