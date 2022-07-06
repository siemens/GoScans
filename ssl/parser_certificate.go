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
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/noneymous/GoSslyze"
	"go-scans/utils"
	"reflect"
)

// SSLyze can return multiple certificate chains (deployments). This happens if the server returns different leaf
// certificates to clients (e.g. in order to support older clients). Unfortunately the association between the
// configuration that led to the specific certificate chain (e.g. supported cipher suites / hostname used for SNI) is
// not returned by SSLyze and therefore we can only save the chains themselves.
func parseCertificateChains(
	logger utils.Logger,
	cr *gosslyze.CommandResults,
	targetName string,
) ([]*CertDeployment, bool, bool, error) {

	// Check for nil pointer exceptions.
	if cr == nil {
		return make([]*CertDeployment, 0), false, false, fmt.Errorf("provided SSLyze result is nil")
	}
	if cr.CertInfo == nil {
		return make([]*CertDeployment, 0), false, false, fmt.Errorf("povided SSLyze result has no certificate info")
	}

	// Initialize the return variables.
	deployments := make([]*CertDeployment, 0, len(cr.CertInfo.Result.Deployments))
	anyInvalid := false
	anyInvalidOrder := false

	for _, deployment := range cr.CertInfo.Result.Deployments {
		deploy := &CertDeployment{
			Certificates:  make([]*Certificate, 0, len(deployment.CertificateChain)),
			HasValidOrder: deployment.HasValidOrder,
			ValidatedBy:   make([]string, 0, 2),
		}

		if !deployment.HasValidOrder {
			anyInvalidOrder = true
		}

		// Check whether any trust store was able to validate this deployment, if so save it's name.
		valid := false
		for _, validation := range deployment.PathValidation {
			if validation.VerifiedChain != nil && len(*validation.VerifiedChain) > 0 {
				valid = true
				deploy.ValidatedBy = append(deploy.ValidatedBy, validation.TrustStore.Name)
			}
		}
		if !valid {
			anyInvalid = true
		}

		lastCertIdx := len(deployment.CertificateChain) - 1
		for i, cert := range deployment.CertificateChain {

			// Get certificate info from SSLyze data
			certificate, errCert := parseCertificate(logger, &cert, targetName)
			if errCert != nil {
				logger.Warningf("Could not parse certificate: %s", errCert)
				continue
			}

			// Save the position in the certificate chain.
			if i == lastCertIdx {
				certificate.Type = certificateTypeRoot
			} else if i == 0 {
				certificate.Type = certificateTypeLeaf
			} else {
				certificate.Type = certificateTypeIntermediate
			}

			// Save the certificate
			deploy.Certificates = append(deploy.Certificates, certificate)
		}

		deployments = append(deployments, deploy)
	}
	return deployments, anyInvalid, anyInvalidOrder, nil
}

func parseCertificate(logger utils.Logger, sslyzeCert *gosslyze.Certificate, targetName string) (*Certificate, error) {

	// Initialize the return structure.
	if sslyzeCert == nil {
		return nil, fmt.Errorf("provided certificate is nil")
	}

	// Initialize our certificate.
	certificate := Certificate{
		Serial:                 sslyzeCert.Serial,
		AlternativeNames:       sslyzeCert.SubjectAltName.Dns,
		PublicKeyAlgorithm:     makePublicKey(logger, sslyzeCert.PublicKey.Algorithm),
		SignatureHashAlgorithm: makeSignatureHash(logger, sslyzeCert.SignatureHashAlgo.Name),
	}

	// Set the validity times
	certificate.ValidFrom = sslyzeCert.NotValidBefore.Time
	certificate.ValidTo = sslyzeCert.NotValidAfter.Time

	// Set subject and issuer information
	certificate.SubjectCN, certificate.Subject = parseEntity(logger, sslyzeCert.Subject)
	certificate.IssuerCN, certificate.Issuer = parseEntity(logger, sslyzeCert.Issuer)

	// Retrieve the size and set it.
	if sslyzeCert.PublicKey.Size < 0 {
		logger.Warningf("expected public key size greater than zero, is %d", sslyzeCert.PublicKey.Size)
	} else {
		certificate.PublicKeyBits = uint64(sslyzeCert.PublicKey.Size)
	}

	// Variable that holds the curve name in case we need it (when we want to reset the info string).
	var curve Curve

	// Calculate the strength according to the public key algorithm and set the info string.
	if certificate.PublicKeyAlgorithm == PUB_K_ECDSA ||
		certificate.PublicKeyAlgorithm == PUB_K_ED25519 ||
		certificate.PublicKeyAlgorithm == PUB_K_ED448 {

		certificate.PublicKeyStrength = int(eccComplexity(certificate.PublicKeyBits))

		curve = makeCurve(logger, sslyzeCert.PublicKey.Curve)
		certificate.PublicKeyInfo = fmt.Sprintf("Curve: %s", curve)

	} else if certificate.PublicKeyAlgorithm == PUB_K_RSA || certificate.PublicKeyAlgorithm == PUB_K_DSA {
		strength, errGnfs := gnfsComplexity(certificate.PublicKeyBits)
		if errGnfs != nil {
			logger.Warningf("Could not compute GNFS complexity: %s", errGnfs)
			strength = 0
		}
		certificate.PublicKeyStrength = int(strength)

		if sslyzeCert.PublicKey.Exponent < 0 {
			logger.Warningf("expected public key exponent greater than zero, is %d", sslyzeCert.PublicKey.Exponent)
		} else if sslyzeCert.PublicKey.Exponent != 0 {
			certificate.PublicKeyInfo = fmt.Sprintf("E: %d", sslyzeCert.PublicKey.Exponent)
		}
	}

	// Here begins the part for the variables that are not returned by SSLyze. We can currently only retrieve these
	// information by using the parser provided by Go's x509 package.

	// Decode the PEM formatted block and parse it to a the Certificate structure defined in the x509 package.
	block, _ := pem.Decode([]byte(sslyzeCert.Pem))
	if block == nil {
		return nil, fmt.Errorf("can not decode PEM block of certificate for target '%s'", targetName)
	}

	// Calculate the fingerprint of the raw certificate.
	certificate.Sha1Fingerprint = utils.HashSha1(block.Bytes, ":")

	// This is the function that will return an error if for example a elliptic curve is used that is unknown to go.
	x509Cert, errCert := x509.ParseCertificate(block.Bytes)
	if errCert != nil {
		return nil, fmt.Errorf("can not parse certificate for target '%s': %s", targetName, errCert.Error())
	} else {

		// Add the x509 certificate version.
		certificate.Version = x509Cert.Version

		// Add certificate revocation/status info.
		certificate.CrlUrls = x509Cert.CRLDistributionPoints
		certificate.OcspUrls = x509Cert.OCSPServer

		// Handle the key usage and the extended key usage bits.
		certificate.KeyUsage = makeKeyUsageSlice(logger, x509Cert.KeyUsage)
		certificate.ExtendedKeyUsage = makeExtKeyUsageSlice(logger, x509Cert.ExtKeyUsage)

		// Check the public key for inconsistency. Golang does not support the Curve448 yet and will probably also not
		// for the near future. Therefore we have to exclude that one from the check.
		publicKeyAlg := makePublicKeyFromX509(logger, x509Cert.PublicKeyAlgorithm)
		if publicKeyAlg != certificate.PublicKeyAlgorithm && certificate.PublicKeyAlgorithm != PUB_K_ED448 {
			logger.Warningf("Inconsistency between SSLyze and Golang: Public key algorithm '%s' != '%s'.",
				certificate.PublicKeyAlgorithm, publicKeyAlg)

			// Set the certificates field, as we trust golang more for now. Also recalculate the strength as the old
			// one might have used the wrong algorithm.
			certificate.PublicKeyAlgorithm = publicKeyAlg
			if certificate.PublicKeyAlgorithm == PUB_K_ECDSA || certificate.PublicKeyAlgorithm == PUB_K_ED25519 {
				certificate.PublicKeyStrength = int(eccComplexity(certificate.PublicKeyBits))

			} else if certificate.PublicKeyAlgorithm == PUB_K_RSA || certificate.PublicKeyAlgorithm == PUB_K_DSA {
				strength, errGnfs := gnfsComplexity(certificate.PublicKeyBits)
				if errGnfs != nil {
					logger.Warningf("Could not compute GNFS complexity: %s", errGnfs)
					strength = 0
				}
				certificate.PublicKeyStrength = int(strength)
			}
		}

		// Check the signature hash algorithm for inconsistency.
		sigHashAlg := makeSignatureHashFromX509(logger, x509Cert.SignatureAlgorithm)
		if sigHashAlg != certificate.SignatureHashAlgorithm {
			logger.Warningf("Inconsistency between SSLyze and Golang: Signature hash algorithm '%s' != '%s'",
				certificate.SignatureHashAlgorithm, sigHashAlg)

			// Set the certificates field, as we trust golang more for now.
			certificate.SignatureHashAlgorithm = sigHashAlg
		}

		// Set the signature algorithm. We can not get this one from SSLyze.
		certificate.SignatureAlgorithm = makeSignatureAlgorithmFromX509(logger, x509Cert.SignatureAlgorithm)

		// Get some additional information about the public key.
		// Theoretically the PublicKey could also be of non pointer type. But I haven't come across such a key yet and in
		// all type assertions in the (relevant) crypto packages I haven't seen a check for a non pointer.
		switch x509Cert.PublicKey.(type) {
		case *rsa.PublicKey:
			pubKey := x509Cert.PublicKey.(*rsa.PublicKey)
			certificate.PublicKeyInfo = fmt.Sprintf("N: %s\nE: %d", pubKey.N.String(), pubKey.E)

		case *dsa.PublicKey:
			pubKey := x509Cert.PublicKey.(*dsa.PublicKey)
			certificate.PublicKeyInfo = fmt.Sprintf("P: %s\nQ: %s\nG: %s\nY: %s",
				pubKey.P.String(), pubKey.Q.String(), pubKey.G.String(), pubKey.Y.String(),
			)

		case *ecdsa.PublicKey:
			pubKey := x509Cert.PublicKey.(*ecdsa.PublicKey)
			// We want to use the name provided by SSLyze in order to be more consistent.
			certificate.PublicKeyInfo = fmt.Sprintf("Curve: %s\nX: %s\nY: %s", curve, pubKey.X.String(), pubKey.Y.String())

		default:
			logger.Warningf("Unknown public key algo '%s' for certificate '%s' for '%s'.", reflect.TypeOf(x509Cert.PublicKey), sslyzeCert.Serial, targetName)
			// TODO, nice to have: go doesnt know about GOSTR341001, GOSTR341094, GOSTR341012 so these will need to be detected&hardcoded
			//		We'll have to implement those by ourselves- ideas:
			//		- fork x509
			//		- try to get most of the data from the SSLyze result and parse the certificate by ourselves
		}

		// We only want to set the "basic constraint extension" variables if they are valid.
		if x509Cert.BasicConstraintsValid {
			certificate.BasicConstraintsValid = true
			certificate.Ca = x509Cert.IsCA
			certificate.MaxPathLength = x509Cert.MaxPathLen
		}
	}

	return &certificate, nil
}

// getEntityString extracts the OIDs (+ their values) contained in the Entity struct and formats them into one string.
// Additionally, the 'Common Name' value is returned separately
func parseEntity(logger utils.Logger, entity gosslyze.Entity) (string, []string) {

	cn := ""
	var oids []string

	if entity.Attributes == nil || len(*entity.Attributes) < 1 {
		logger.Warningf("SSLyze entity has no attributes.")
		return cn, oids
	}

	var commonName, country, organization, organizationalUnit string
	var locality, province, streetAddress string
	var postalCode, serialNumber, emailAddress string

	for _, attr := range *entity.Attributes {

		switch attr.Oid.Name {
		case "commonName":
			cn = attr.Value
			commonName = fmt.Sprintf("CommonName: %s", attr.Value)
		case "countryName":
			country = fmt.Sprintf("Country: %s", attr.Value)
		case "organizationName":
			organization = fmt.Sprintf("Organization: %s", attr.Value)
		case "organizationalUnitName":
			organizationalUnit = fmt.Sprintf("OrganizationalUnit: %s", attr.Value)
		case "localityName":
			locality = fmt.Sprintf("Locality: %s", attr.Value)
		case "stateOrProvinceName":
			province = fmt.Sprintf("Province: %s", attr.Value)
		// Haven't seen the next two during testing but here's an example posted on the relevant repo:
		// https://github.com/pyca/cryptography/issues/3857#issuecomment-387464519
		case "streetAddress":
			streetAddress = fmt.Sprintf("StreetAddress: %s", attr.Value)
		case "postalCode":
			postalCode = fmt.Sprintf("PostalCode: %s", attr.Value)
		case "emailAddress":
			emailAddress = fmt.Sprintf("EmailAddress: %s", attr.Value)
		case "serialNumber":
			serialNumber = fmt.Sprintf("SerialNumber: %s", attr.Value)
		case "domainComponent":
			// We're not interested in this.
		case "userID":
			// We're not interested in this.
		default:
			logger.Infof("Unknown OID '%s' with value '%s'.", attr.Oid.Name, attr.Value)
		}
	}

	oids = []string{commonName, country, organization, organizationalUnit, locality, province,
		streetAddress, postalCode, emailAddress, serialNumber,
	}

	return cn, utils.Filter(oids, func(s string) bool { return s != "" })
}
