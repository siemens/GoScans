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
	"github.com/cockroachdb/apd"
	"go-scans/utils"
	"math"
	"sync"
)

// DO NOT alter!
// Some of the most common key lengths mapping to their strength when using the GNFS.
var commonGnfsComplexities = map[uint64]float64{
	512:   63.929344,
	1024:  86.7661192,
	2048:  116.883813,
	3072:  138.736281,
	4096:  156.496953,
	7680:  203.018736,
	8192:  208.472486,
	15360: 269.384773,
	16384: 276.518407,
}

// DO NOT alter!
// Some constants that are used during the computation of the GNFS complexity.
var (
	once          sync.Once
	two           *apd.Decimal
	sixtyfournine = new(apd.Decimal)
	onethird      = new(apd.Decimal)
	twothirds     = new(apd.Decimal)
	log10two      = new(apd.Decimal)
	initSuccess   = false
)

const acceptableConditions = apd.Inexact | apd.Rounded

func initGnfsComplexity(c apd.Context) (err error) {

	two = apd.New(2, 0)

	sixtyfournine, err = sixtyfournine.SetFloat64(64. / 9.)
	if err != nil {
		return fmt.Errorf("can not set 64/9: %s", err)
	}

	onethird, err = onethird.SetFloat64(1. / 3.)
	if err != nil {
		return fmt.Errorf("can not set 64/9: %s", err)
	}

	twothirds, err = twothirds.SetFloat64(2. / 3.)
	if err != nil {
		return fmt.Errorf("can not set 64/9: %s", err)
	}

	// log10(z)
	res, err := c.Log10(log10two, two)
	if err != nil {
		return fmt.Errorf("can not compute Log10(2): %s", err)
	}
	if errCond := checkConditions(res); errCond != nil {
		return fmt.Errorf("can not compute Log10(2): %s", errCond)
	}

	initSuccess = true

	return nil
}

// Strength computation helper
// gnfsComplexity calculates the complexity of the 'general number field sieve'. GNFS is the most efficient classical
// algorithm for factoring integers larger than 10^100 [wikipedia]
// We have to use a third party package, because math/big does not have a log function. The apd package which we use
// does not seem perfect in every way. A lot of it seems to be based on rob pikes ivy calculator (which is not inherently
// bad, but he's not sure about precision himself). Though for our case it should be sufficient.
func gnfsComplexity(length uint64) (float64, error) {

	// Skip the costly computation if we have a common (pre-calculated) complexity.
	if complexity, ok := commonGnfsComplexities[length]; ok {
		return complexity, nil
	}

	// Init the context and it's precision.
	c := apd.BaseContext
	c.Precision = 7

	var err error

	// Wrap the init function in order to handle the errors here.
	wrappedInit := func() {
		err = initGnfsComplexity(c)
		if err != nil {
			err = fmt.Errorf("could not init GNFS constants: %s", err)
		}
	}

	// Init the constants if not done yet.
	once.Do(wrappedInit)
	if err != nil {
		return -1, err
	}

	if !initSuccess {
		return -1, fmt.Errorf("can not compute GNFS complexity, because init failed previously")
	}

	// Init the length - check for a possible integer overflow before the conversion.
	if length > math.MaxInt64 {
		return 0, fmt.Errorf("length is too big to be converted to int64")
	}
	l := apd.New(int64(length), 0)

	// Variable for (intermediate) results.
	n := new(apd.Decimal)
	x := new(apd.Decimal)
	y := new(apd.Decimal)
	z := new(apd.Decimal)

	// 2^length = 1 << length
	res, err := c.Pow(n, two, l)
	if err != nil {
		return -1., fmt.Errorf("can not compute 2^[key size]: %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute 2^[key size]: %s", errCond)
	}

	// Ln(n)
	// This is the last step we can safe in n as the second component also needs Ln(2^length)
	res, err = c.Ln(n, n)
	if err != nil {
		return -1., fmt.Errorf("can not compute Ln(n): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute Ln(n): %s", errCond)
	}

	// 64 / 9 * x
	res, err = c.Mul(x, sixtyfournine, n)
	if err != nil {
		return -1., fmt.Errorf("can not compute 64 / 9 * x: %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute 64 / 9 * x: %s", errCond)
	}

	// x^(1/3)
	res, err = c.Pow(x, x, onethird)
	if err != nil {
		return -1., fmt.Errorf("can not compute x^(1/3): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute x^(1/3): %s", errCond)
	}

	// Ln(n)
	// Yes we need to take the Ln again
	res, err = c.Ln(y, n)
	if err != nil {
		return -1., fmt.Errorf("can not compute Ln(n): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute Ln(n): %s", errCond)
	}

	// y^(2/3)
	res, err = c.Pow(y, y, twothirds)
	if err != nil {
		return -1., fmt.Errorf("can not compute y^(2/3): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute y^(2/3): %s", errCond)
	}

	// x * y
	res, err = c.Mul(z, x, y)
	if err != nil {
		return -1., fmt.Errorf("can not compute x * y: %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute x * y: %s", errCond)
	}

	// exp(z)
	res, err = c.Exp(z, z)
	if err != nil {
		return -1., fmt.Errorf("can not compute Ln(n): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute Ln(n): %s", errCond)
	}

	// log2(z)
	// We have to do a base change because apd doesn't support log2. (Log10(2) is computed during the initialization.)

	// log10(z)
	res, err = c.Log10(z, z)
	if err != nil {
		return -1., fmt.Errorf("can not compute Log10(z): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute Log10(z): %s", errCond)
	}

	// log2(z) = log10(z) / log10(2)
	res, err = c.Quo(z, z, log10two)
	if err != nil {
		return -1., fmt.Errorf("can not compute Log2(z): %s", err)
	}

	if errCond := checkConditions(res); errCond != nil {
		return -1, fmt.Errorf("can not compute Log2(z): %s", errCond)
	}

	// Get the float64 value and return it.
	ret, err := z.Float64()
	if err != nil {
		return -1., fmt.Errorf("can not get the result's float value: %s", err)
	}

	return ret, nil
}

// checkConditions is a helper function for the apd package operations.
func checkConditions(condition apd.Condition) error {
	unacceptableConditions := condition &^ acceptableConditions // AND NOT
	if unacceptableConditions > 0 {
		return fmt.Errorf("unacceptable conditions were returned (%s)", unacceptableConditions)
	}
	return nil
}

// Strength computation helper
// eccComplexity calculates the complexity of elliptic curve cryptography (ECC) algorithms. A method that seems a bit more
// accurate is described here: https://crypto.stackexchange.com/questions/31439/how-do-i-get-the-equivalent-strength-of-an-ecc-key,
// but it's just a slightly shifted line which doesn't seem to justify the overhead.
func eccComplexity(length uint64) float64 {

	return math.Floor(float64(length) / 2.)
}

// isDuplicate checks all the slice of previously found results and compares it to the new result. If their fields match
// true will be returned.
func isDuplicate(prevResults []*Data, currResult *Data) bool {
	for _, d := range prevResults {
		if compareResultData(d, currResult) {
			return true
		}
	}
	return false
}

// compareResultData actually compares two results and is called by isDuplicate.
func compareResultData(data1, data2 *Data) bool {
	// Check the Data struct
	if data1 == nil && data2 == nil {
		return true
	}

	if data1 == nil || data2 == nil {
		return false
	}

	// Compare Issues
	if (data1.Issues == nil || data2.Issues == nil) && !(data1.Issues == nil && data2.Issues == nil) || // XOR
		*data1.Issues != *data2.Issues {
		return false
	}

	// Check Ciphers
	if len(data1.Ciphers) != len(data2.Ciphers) {
		return false
	}

	for cipherId, cipher1 := range data1.Ciphers {
		var cipher2 *Cipher
		ok := false
		if cipher2, ok = data2.Ciphers[cipherId]; !ok {
			return false
		}

		if !compareCipher(cipher1, cipher2) {
			return false
		}
	}

	// Compare certificates deployments
	if (data1.CertDeployments == nil) != (data2.CertDeployments == nil) {
		return false
	}

	if len(data1.CertDeployments) != len(data2.CertDeployments) {
		return false
	}

	// Compare the actual deployments and their certificates. Order does not matter here
	used := make(map[int]struct{}, len(data2.CertDeployments))
	for _, d1 := range data1.CertDeployments {
		found := false

		for i, d2 := range data2.CertDeployments {
			if _, ok := used[i]; ok {
				continue
			}

			if d1 == nil && d2 == nil {
				found = true
				used[i] = struct{}{}
				break
			}

			if d1.HasValidOrder != d2.HasValidOrder {
				continue
			}

			if utils.Equals(d1.ValidatedBy, d2.ValidatedBy) {
				continue
			}

			if !compareCerts(d1.Certificates, d2.Certificates) {
				continue
			}

			found = true
			used[i] = struct{}{}
			break
		}

		if !found {
			return false
		}
	}

	// No more checks to do, the structs are equal.
	return true
}

func compareCipher(cipher1, cipher2 *Cipher) bool {

	// Check for nil pointers
	if (cipher1 == nil) && (cipher2 == nil) {
		return true
	}
	if (cipher1 == nil) || (cipher2 == nil) {
		return false
	}

	// Compare the+ actual fields
	c1 := *cipher1
	c2 := *cipher2
	return c1.Id == c2.Id &&
		c1.OpensslName == c2.OpensslName &&
		c1.IanaName == c2.IanaName &&
		c1.Protocol == c2.Protocol &&
		c1.KeyExchange == c2.KeyExchange &&
		c1.KeyExchangeBits == c2.KeyExchangeBits &&
		c1.KeyExchangeStrength == c2.KeyExchangeStrength &&
		c1.ForwardSecrecy == c2.ForwardSecrecy &&
		c1.Authentication == c2.Authentication &&
		c1.Encryption == c2.Encryption &&
		c1.EncryptionMode == c2.EncryptionMode &&
		c1.EncryptionBits == c2.EncryptionBits &&
		c1.EncryptionStrength == c2.EncryptionStrength &&
		c1.BlockCipher == c2.BlockCipher &&
		c1.BlockSize == c2.BlockSize &&
		c1.StreamCipher == c2.StreamCipher &&
		c1.Mac == c2.Mac &&
		c1.MacBits == c2.MacBits &&
		c1.MacStrength == c2.MacStrength &&
		c1.Prf == c2.Prf &&
		c1.PrfBits == c2.PrfBits &&
		c1.PrfStrength == c2.PrfStrength &&
		c1.Export == c2.Export &&
		c1.Draft == c2.Draft &&
		utils.Equals(c1.KeyExchangeInfo, c2.KeyExchangeInfo)
}

func compareCerts(certs1, certs2 []*Certificate) bool {

	// Compare the arrays
	if (certs1 == nil) != (certs2 == nil) {
		return false
	}

	if len(certs1) != len(certs2) {
		return false
	}

	// Compare the certificates within
	used := make(map[int]struct{}, len(certs2))
	for _, c1 := range certs1 {
		found := false

		for i, c2 := range certs2 {
			// Check whether we already 'used' this certificate
			if _, ok := used[i]; ok {
				continue
			}

			if c1 == nil && c2 == nil {
				found = true
				used[i] = struct{}{}
				break
			}

			// Check the easy types first
			if c1.Type != c2.Type ||
				c1.Version != c2.Version ||
				c1.Serial.Cmp(&c2.Serial) != 0 ||
				c1.SubjectCN != c2.SubjectCN ||
				c1.IssuerCN != c2.IssuerCN ||
				c1.PublicKeyAlgorithm != c2.PublicKeyAlgorithm ||
				c1.PublicKeyInfo != c2.PublicKeyInfo ||
				c1.PublicKeyBits != c2.PublicKeyBits ||
				c1.SignatureAlgorithm != c2.SignatureAlgorithm ||
				c1.SignatureHashAlgorithm != c2.SignatureHashAlgorithm ||
				c1.BasicConstraintsValid != c2.BasicConstraintsValid ||
				c1.Ca != c2.Ca ||
				c1.MaxPathLength != c2.MaxPathLength ||
				c1.Sha1Fingerprint != c2.Sha1Fingerprint {

				continue
			}

			// Compare the valid time span.
			// This does NOT take the timezones into account (e.g. 6:00 +0200 CEST and 4:00 UTC are Equal). If we want
			// to consider this case as an equality, we'd have to use time.Equal().
			if c1.ValidFrom != c2.ValidFrom || c1.ValidTo != c2.ValidTo {
				continue
			}

			// Check the string slices. The order does not matter.
			if !utils.Equals(c1.Subject, c2.Subject) ||
				!utils.Equals(c1.Issuer, c2.Issuer) ||
				!utils.Equals(c1.AlternativeNames, c2.AlternativeNames) ||
				!utils.Equals(c1.CrlUrls, c2.CrlUrls) ||
				!utils.Equals(c1.OcspUrls, c2.OcspUrls) ||
				!utils.Equals(c1.KeyUsage, c2.KeyUsage) ||
				!utils.Equals(c1.ExtendedKeyUsage, c2.ExtendedKeyUsage) {
				continue
			}

			found = true
			used[i] = struct{}{}
			break
		}

		// There's no matching certificate and therefore our results have to be different.
		if !found {
			return false
		}
	}

	return true
}
