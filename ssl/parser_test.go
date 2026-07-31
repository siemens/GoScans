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
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	gosslyze "github.com/noneymous/GoSslyze"
	"github.com/siemens/GoScans/utils"
)

// TestGetStringOids verifies that parseEntity extracts the expected OID strings and common name from certificate entities.
func TestGetStringOids(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	empty := ""
	nameStr := "CN=Company Issuing CA Intranet Server 2017"
	name := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.3", Name: "commonName"},
		RfcString: nameStr,
		Value:     "Company Issuing CA Intranet Server 2017",
	}}
	countryStr := "C=Spain"
	country := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.6", Name: "countryName"},
		RfcString: countryStr,
		Value:     "Spain",
	}}
	orgaStr := "O=Company"
	orga := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.10", Name: "organizationName"},
		RfcString: orgaStr,
		Value:     "Company",
	}}
	orgaUnitStr := "OU=Company Trust Center"
	orgaUnit := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.11", Name: "organizationalUnitName"},
		RfcString: orgaUnitStr,
		Value:     "Company Trust Center",
	}}
	localityStr := "L=Muenchen"
	locality := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.7", Name: "localityName"},
		RfcString: localityStr,
		Value:     "Muenchen",
	}}
	provinceStr := "ST=Bayern"
	province := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.8", Name: "stateOrProvinceName"},
		RfcString: provinceStr,
		Value:     "Bayern",
	}}
	streetStr := "STREET=Somestr. 8"
	street := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.9", Name: "streetAddress"},
		RfcString: streetStr,
		Value:     "Somestr. 8",
	}}
	postalStr := "postalCode=54321"
	postal := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.17", Name: "postalCode"},
		RfcString: postalStr,
		Value:     "54321",
	}}
	serialStr := "SerialNumber=007"
	serial := &[]gosslyze.Attribute{{Oid: gosslyze.Oid{DotNotation: "2.5.4.5", Name: "serialNumber"},
		RfcString: serialStr,
		Value:     "007",
	}}
	allStr := strings.Join([]string{nameStr, countryStr, orgaStr, orgaUnitStr, localityStr, provinceStr, streetStr, postalStr, serialStr}, ", ")
	all := append(*name, (*country)[0], (*orga)[0], (*orgaUnit)[0], (*locality)[0], (*province)[0], (*street)[0], (*postal)[0], (*serial)[0])

	// Prepare and run test cases
	type args struct {
		entity gosslyze.Entity
	}
	tests := []struct {
		name    string
		args    args
		wantCn  string
		wantOid []string
	}{
		{
			name:    "common-name-only",
			args:    args{entity: gosslyze.Entity{Attributes: name, RfcString: nameStr}},
			wantCn:  "Company Issuing CA Intranet Server 2017",
			wantOid: []string{"CommonName: Company Issuing CA Intranet Server 2017"},
		},
		{
			name:    "country-only",
			args:    args{entity: gosslyze.Entity{Attributes: country, RfcString: countryStr}},
			wantCn:  "",
			wantOid: []string{"Country: Spain"},
		},
		{
			name:    "organization-only",
			args:    args{entity: gosslyze.Entity{Attributes: orga, RfcString: orgaStr}},
			wantCn:  "",
			wantOid: []string{"Organization: Company"},
		},
		{
			name:    "organizational-unit-only",
			args:    args{entity: gosslyze.Entity{Attributes: orgaUnit, RfcString: orgaUnitStr}},
			wantCn:  "",
			wantOid: []string{"OrganizationalUnit: Company Trust Center"},
		},
		{
			name:    "locality-only",
			args:    args{entity: gosslyze.Entity{Attributes: locality, RfcString: localityStr}},
			wantCn:  "",
			wantOid: []string{"Locality: Muenchen"},
		},
		{
			name:    "province-only",
			args:    args{entity: gosslyze.Entity{Attributes: province, RfcString: provinceStr}},
			wantCn:  "",
			wantOid: []string{"Province: Bayern"},
		},
		{
			name:    "street-address-only",
			args:    args{entity: gosslyze.Entity{Attributes: street, RfcString: streetStr}},
			wantCn:  "",
			wantOid: []string{"StreetAddress: Somestr. 8"},
		},
		{
			name:    "postal-code-only",
			args:    args{entity: gosslyze.Entity{Attributes: postal, RfcString: postalStr}},
			wantCn:  "",
			wantOid: []string{"PostalCode: 54321"},
		},
		{
			name:    "serial-number-only",
			args:    args{entity: gosslyze.Entity{Attributes: serial, RfcString: serialStr}},
			wantCn:  "",
			wantOid: []string{"SerialNumber: 007"},
		},
		{
			name:    "all",
			args:    args{entity: gosslyze.Entity{Attributes: &all, RfcString: allStr}},
			wantCn:  "Company Issuing CA Intranet Server 2017",
			wantOid: []string{"CommonName: Company Issuing CA Intranet Server 2017", "Country: Spain", "Organization: Company", "OrganizationalUnit: Company Trust Center", "Locality: Muenchen", "Province: Bayern", "StreetAddress: Somestr. 8", "PostalCode: 54321", "SerialNumber: 007"},
		},

		{
			name:    "error-empty",
			args:    args{entity: gosslyze.Entity{Attributes: orga, RfcString: orgaStr}},
			wantCn:  "",
			wantOid: []string{"Organization: Company"},
		},
		{
			name:    "nil-attributes",
			args:    args{entity: gosslyze.Entity{Attributes: nil, RfcString: empty}},
			wantCn:  "",
			wantOid: []string{},
		},
		{
			name:    "no-attributes",
			args:    args{entity: gosslyze.Entity{Attributes: &[]gosslyze.Attribute{}, RfcString: empty}},
			wantCn:  "",
			wantOid: []string{},
		},
		{
			name:    "all-nil",
			args:    args{entity: gosslyze.Entity{Attributes: nil, RfcString: empty}},
			wantCn:  "",
			wantOid: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			stringDn, stringOid := parseEntity(testLogger, tt.args.entity)

			if !reflect.DeepEqual(stringOid, tt.wantOid) {
				t.Errorf("getStringOids() got =\n'%v' should return=\n'%v'", stringOid, tt.wantOid)
				return
			}
			if !reflect.DeepEqual(stringDn, tt.wantCn) {
				t.Errorf("getStringOids() got =\n'%v' should return=\n'%v'", stringDn, tt.wantCn)
				return
			}
		})
	}
}

// Test_parseEphemeralKeyInfo verifies that parseEphemeralKeyInfo returns the correct key size, security bits, and extras for each key type.
func Test_parseEphemeralKeyInfo(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	pubBytesStr := "BGmPpYCH6H/+MJe8LPmizckyCjXtqeGT4vc7z1GcP+Ji9hdxRZ151Y57Hj5LbdcaWKr0D6cdnyzHgThaGJMA+Do="
	pubBytes, errPubBytes := base64.StdEncoding.DecodeString(pubBytesStr)
	if errPubBytes != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", pubBytes, errPubBytes)
	}
	xStr := "aY+lgIfof/4wl7ws+aLNyTIKNe2p4ZPi9zvPUZw/4mI="
	x, errX := base64.StdEncoding.DecodeString(xStr)
	if errX != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", xStr, errX)
	}
	yStr := "9hdxRZ151Y57Hj5LbdcaWKr0D6cdnyzHgThaGJMA+Do="
	y, errY := base64.StdEncoding.DecodeString(yStr)
	if errY != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", yStr, errY)
	}
	genStr := "rEAy708tmuOd8wtcj/2sUGzevnuJmYyvdIZqCM/k/+OmgkpOELmm8N2SHwGnDEr6q3OddwDCn1LFfbF8YgqGUr5ekAGo1mrXwXZpEBmZAkr00CcnWsE0i7inYtBSG8mK4kcVBCLqHtQJk51U2nRgzbX2xrJQcXy+8YDrNBGOmNEZUppF1vg0Vm4wJeMWozDvu3eobwwasVsFGuPUKMj4rLcKgTcVC47rEOGD7dGZY93Z4mPkdwWJ72qiHn9fL/OBtTnM40CdE81Wavu0jWwBkYHhvP6UswJp7f5y/ptqpL17Wg8ccc//TBnEGOH27AF5gbwIfypwZbOEuJDTGR8r+g=="
	gen, errGen := base64.StdEncoding.DecodeString(genStr)
	if errGen != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", gen, errGen)
	}
	primeStr := "rRB+HpEjqdDWYPqnlVnFH6INZOVoO5/RtUsVl7YdCnXm+hQd+VpW26+aPEB7od8V6z1oijCcGA4d5rhaEnSgpm0/gVKtasISkDfJ7e/aTfjZHo/vVbc5S3rVt9C2wSIHyfmNEe002/bGugssi7wnvmoA4KC5xJcIs7+KMXCRiDaBKGEwvImF2xYC5xRBXZMwJ4Jzx94x79xzEPcSH9WgdBWYfZrcCkhtzfk6zEQyg4cxXXXhmMZBpIDNhqG55YfovmDmnMkosrnFIXLkEwQumyPxCw4W55djybU9z0uoCinj+3PBa451uX7zY+L/ox9xz53lOE5xuBwKxN/+DBDmTw=="
	prime, errPrime := base64.StdEncoding.DecodeString(primeStr)
	if errPrime != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", prime, errPrime)
	}

	base := gosslyze.BaseKeyInfo{
		TypeName:    "ECDH",
		Size:        256,
		PublicBytes: pubBytes,
	}

	ecdh := gosslyze.EcdhKeyInfo{
		BaseKeyInfo: base,
		CurveName:   "prime256v1",
	}

	nist := gosslyze.NistEcdhKeyInfo{
		EcdhKeyInfo: ecdh,
		X:           x,
		Y:           y,
	}

	dh := gosslyze.DhKeyInfo{
		BaseKeyInfo: base,
		Prime:       prime,
		Generator:   gen,
	}
	dh.TypeName = "DH"
	dh.Size = 512

	nistExtrasRes := []string{
		"PublicBytes: " + pubBytesStr,
		"CurveName: prime256v1",
		"X: " + xStr,
		"Y: " + yStr,
	}

	baseExtrasRes := nistExtrasRes[:1]
	ecdhExtrasRes := nistExtrasRes[:2]
	dhExtrasRes := append([]string{}, baseExtrasRes...) // Copy the slice so we don't alter the underlying slice
	dhExtrasRes = append(dhExtrasRes, "Prime: "+primeStr, "Generator: "+genStr)

	// Helper struct that
	type incorrectStruct struct {
		gosslyze.EphemeralKeyInfo
		Asdf int
	}

	type args struct {
		info gosslyze.EphemeralKeyInfo
	}
	tests := []struct {
		name  string
		args  args
		want  int
		want1 int
		want2 []string
	}{
		{
			name:  "base-info",
			args:  args{info: &base},
			want:  256,
			want1: 0,
			want2: baseExtrasRes,
		},
		{
			name:  "ecdh-info",
			args:  args{info: &ecdh},
			want:  256,
			want1: 128,
			want2: ecdhExtrasRes,
		},
		{
			name:  "nist-ecdh-info",
			args:  args{info: &nist},
			want:  256,
			want1: 128,
			want2: nistExtrasRes,
		},
		{
			name:  "nist-dh-info",
			args:  args{info: &dh},
			want:  512,
			want1: 63,
			want2: dhExtrasRes,
		},
		{
			name:  "error-incorrect-interface",
			args:  args{info: &incorrectStruct{Asdf: 2}},
			want:  0,
			want1: 0,
			want2: []string{},
		},
		{
			name:  "error-interface-non-pointer",
			args:  args{info: dh},
			want:  0,
			want1: 0,
			want2: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := parseEphemeralKeyInfo(testLogger, tt.args.info)
			if got != tt.want {
				t.Errorf("parseEphemeralKeyInfo() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("parseEphemeralKeyInfo() got1 = %v, want %v", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("parseEphemeralKeyInfo() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

// TestGnfsComplexity verifies that gnfsComplexity returns accurate security bit estimates for standard key sizes.
func TestGnfsComplexity(t *testing.T) {

	tests := []struct {
		name           string
		keySize        uint64
		expectedResult float64
		epsilon        float64
		wantErr        error
	}{
		{name: "512", keySize: 512, expectedResult: 63.929344, epsilon: 0.01, wantErr: nil},
		{name: "1024", keySize: 1024, expectedResult: 86.7661192, epsilon: 0.01, wantErr: nil},
		{name: "2048", keySize: 2048, expectedResult: 116.883813, epsilon: 0.01, wantErr: nil},
		{name: "3072", keySize: 3072, expectedResult: 138.736281, epsilon: 0.01, wantErr: nil},
		{name: "4096", keySize: 4096, expectedResult: 156.496953, epsilon: 0.01, wantErr: nil},
		{name: "7680", keySize: 7680, expectedResult: 203.018736, epsilon: 0.01, wantErr: nil},
		{name: "8192", keySize: 8192, expectedResult: 208.472486, epsilon: 0.01, wantErr: nil},
		{name: "15360", keySize: 15360, expectedResult: 269.384773, epsilon: 0.01, wantErr: nil},
		{name: "16384", keySize: 16384, expectedResult: 276.518407, epsilon: 0.01, wantErr: nil},

		{name: "500", keySize: 500, expectedResult: 63.2550403, epsilon: 0.01, wantErr: nil},
		{name: "1000", keySize: 1000, expectedResult: 85.8754464, epsilon: 0.01, wantErr: nil},
		{name: "2000", keySize: 2000, expectedResult: 115.7106783, epsilon: 0.01, wantErr: nil},
		{name: "3100", keySize: 3100, expectedResult: 139.2663292, epsilon: 0.01, wantErr: nil},
		{name: "4100", keySize: 4100, expectedResult: 156.5606913, epsilon: 0.01, wantErr: nil},
		{name: "7700", keySize: 7700, expectedResult: 203.2358751, epsilon: 0.01, wantErr: nil},
		{name: "8200", keySize: 8200, expectedResult: 208.5560244, epsilon: 0.01, wantErr: nil},
		{name: "15400", keySize: 15400, expectedResult: 269.6688214, epsilon: 0.01, wantErr: nil},
		{name: "16400", keySize: 16400, expectedResult: 276.6276667, epsilon: 0.01, wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength, errStrength := gnfsComplexity(tt.keySize)
			if errStrength != tt.wantErr {
				t.Errorf("gnfsComplexity(%d) error = '%v', wantErr = '%v'", tt.keySize, errStrength, tt.wantErr)
				return
			}

			if strength-tt.expectedResult > tt.epsilon {
				t.Errorf("gnfsComplexity(%d) expected result %f, got %f", tt.keySize, tt.expectedResult, strength)
				return
			}
		})
	}
}

// Benchmarks

// Variable that will be set in the benchmark in order for compiler to not be able to eliminate the benchmark itself.
var strength float64

// benchmarkGnfsComplexity is a shared helper that runs the gnfsComplexity benchmark for a given key size.
func benchmarkGnfsComplexity(keySize uint64, b *testing.B) {
	var res float64
	var errRes error
	for n := 0; n < b.N; n++ {
		res, errRes = gnfsComplexity(keySize)
		if errRes != nil {
			b.Errorf("gnfsComplexity(%d) error: %s", keySize, errRes)
		}
	}
	strength = res
}

// BenchmarkGnfsComplexity512 benchmarks gnfsComplexity with a 512-bit key.
func BenchmarkGnfsComplexity512(b *testing.B) { benchmarkGnfsComplexity(512, b) }

// BenchmarkGnfsComplexity1024 benchmarks gnfsComplexity with a 1024-bit key.
func BenchmarkGnfsComplexity1024(b *testing.B) { benchmarkGnfsComplexity(1024, b) }

// BenchmarkGnfsComplexity2048 benchmarks gnfsComplexity with a 2048-bit key.
func BenchmarkGnfsComplexity2048(b *testing.B) { benchmarkGnfsComplexity(2048, b) }

// BenchmarkGnfsComplexity3072 benchmarks gnfsComplexity with a 3072-bit key.
func BenchmarkGnfsComplexity3072(b *testing.B) { benchmarkGnfsComplexity(3072, b) }

// BenchmarkGnfsComplexity4096 benchmarks gnfsComplexity with a 4096-bit key.
func BenchmarkGnfsComplexity4096(b *testing.B) { benchmarkGnfsComplexity(4096, b) }

// BenchmarkGnfsComplexity7680 benchmarks gnfsComplexity with a 7680-bit key.
func BenchmarkGnfsComplexity7680(b *testing.B) { benchmarkGnfsComplexity(7680, b) }

// BenchmarkGnfsComplexity8192 benchmarks gnfsComplexity with an 8192-bit key.
func BenchmarkGnfsComplexity8192(b *testing.B) { benchmarkGnfsComplexity(8192, b) }

// BenchmarkGnfsComplexity15360 benchmarks gnfsComplexity with a 15360-bit key.
func BenchmarkGnfsComplexity15360(b *testing.B) { benchmarkGnfsComplexity(15360, b) }

// BenchmarkGnfsComplexity16384 benchmarks gnfsComplexity with a 16384-bit key.
func BenchmarkGnfsComplexity16384(b *testing.B) { benchmarkGnfsComplexity(16384, b) }

// BenchmarkGnfsComplexity500 benchmarks gnfsComplexity with a 500-bit key.
func BenchmarkGnfsComplexity500(b *testing.B) { benchmarkGnfsComplexity(500, b) }

// BenchmarkGnfsComplexity1000 benchmarks gnfsComplexity with a 1000-bit key.
func BenchmarkGnfsComplexity1000(b *testing.B) { benchmarkGnfsComplexity(1000, b) }

// BenchmarkGnfsComplexity2000 benchmarks gnfsComplexity with a 2000-bit key.
func BenchmarkGnfsComplexity2000(b *testing.B) { benchmarkGnfsComplexity(2000, b) }

// BenchmarkGnfsComplexity3100 benchmarks gnfsComplexity with a 3100-bit key.
func BenchmarkGnfsComplexity3100(b *testing.B) { benchmarkGnfsComplexity(3100, b) }

// BenchmarkGnfsComplexity4100 benchmarks gnfsComplexity with a 4100-bit key.
func BenchmarkGnfsComplexity4100(b *testing.B) { benchmarkGnfsComplexity(4100, b) }

// BenchmarkGnfsComplexity7700 benchmarks gnfsComplexity with a 7700-bit key.
func BenchmarkGnfsComplexity7700(b *testing.B) { benchmarkGnfsComplexity(7700, b) }

// BenchmarkGnfsComplexity8200 benchmarks gnfsComplexity with an 8200-bit key.
func BenchmarkGnfsComplexity8200(b *testing.B) { benchmarkGnfsComplexity(8200, b) }

// BenchmarkGnfsComplexity15400 benchmarks gnfsComplexity with a 15400-bit key.
func BenchmarkGnfsComplexity15400(b *testing.B) { benchmarkGnfsComplexity(15400, b) }

// BenchmarkGnfsComplexity16400 benchmarks gnfsComplexity with a 16400-bit key.
func BenchmarkGnfsComplexity16400(b *testing.B) { benchmarkGnfsComplexity(16400, b) }
