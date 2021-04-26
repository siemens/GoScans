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
	"github.com/noneymous/GoSslyze"
	"go-scans/utils"
	"reflect"
	"strings"
	"testing"
)

func TestGetStringOids(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	empty := ""
	errStr := "error with some explanation"
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
		{"common-name-only", args{gosslyze.Entity{Attributes: name, RfcString: &nameStr, ParsingError: nil}}, "Company Issuing CA Intranet Server 2017", []string{"CommonName: Company Issuing CA Intranet Server 2017"}},
		{"country-only", args{gosslyze.Entity{Attributes: country, RfcString: &countryStr, ParsingError: nil}}, "", []string{"Country: Spain"}},
		{"organization-only", args{gosslyze.Entity{Attributes: orga, RfcString: &orgaStr, ParsingError: nil}}, "", []string{"Organization: Company"}},
		{"organizational-unit-only", args{gosslyze.Entity{Attributes: orgaUnit, RfcString: &orgaUnitStr, ParsingError: nil}}, "", []string{"OrganizationalUnit: Company Trust Center"}},
		{"locality-only", args{gosslyze.Entity{Attributes: locality, RfcString: &localityStr, ParsingError: nil}}, "", []string{"Locality: Muenchen"}},
		{"province-only", args{gosslyze.Entity{Attributes: province, RfcString: &provinceStr, ParsingError: nil}}, "", []string{"Province: Bayern"}},
		{"street-address-only", args{gosslyze.Entity{Attributes: street, RfcString: &streetStr, ParsingError: nil}}, "", []string{"StreetAddress: Somestr. 8"}},
		{"postal-code-only", args{gosslyze.Entity{Attributes: postal, RfcString: &postalStr, ParsingError: nil}}, "", []string{"PostalCode: 54321"}},
		{"serial-number-only", args{gosslyze.Entity{Attributes: serial, RfcString: &serialStr, ParsingError: nil}}, "", []string{"SerialNumber: 007"}},
		{"all", args{gosslyze.Entity{Attributes: &all, RfcString: &allStr, ParsingError: nil}}, "Company Issuing CA Intranet Server 2017", []string{"CommonName: Company Issuing CA Intranet Server 2017", "Country: Spain", "Organization: Company", "OrganizationalUnit: Company Trust Center", "Locality: Muenchen", "Province: Bayern", "StreetAddress: Somestr. 8", "PostalCode: 54321", "SerialNumber: 007"}},

		{"error-empty", args{gosslyze.Entity{Attributes: orga, RfcString: &orgaStr, ParsingError: &empty}}, "", []string{"Organization: Company"}},
		{"error", args{gosslyze.Entity{Attributes: orga, RfcString: &orgaStr, ParsingError: &errStr}}, "", []string{}},
		{"nil-attributes", args{gosslyze.Entity{Attributes: nil, RfcString: &empty, ParsingError: nil}}, "", []string{}},
		{"no-attributes", args{gosslyze.Entity{Attributes: &[]gosslyze.Attribute{}, RfcString: &empty, ParsingError: nil}}, "", []string{}},
		{"all-nil", args{gosslyze.Entity{Attributes: nil, RfcString: nil, ParsingError: nil}}, "", []string{}},
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

func Test_parseEphemeralKeyInfo(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	pubBytesStr := "BGmPpYCH6H/+MJe8LPmizckyCjXtqeGT4vc7z1GcP+Ji9hdxRZ151Y57Hj5LbdcaWKr0D6cdnyzHgThaGJMA+Do="
	pubBytes, errDecode := base64.StdEncoding.DecodeString(pubBytesStr)
	if errDecode != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", pubBytes, errDecode)
	}
	xStr := "aY+lgIfof/4wl7ws+aLNyTIKNe2p4ZPi9zvPUZw/4mI="
	x, errDecode := base64.StdEncoding.DecodeString(xStr)
	if errDecode != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", xStr, errDecode)
	}
	yStr := "9hdxRZ151Y57Hj5LbdcaWKr0D6cdnyzHgThaGJMA+Do="
	y, errDecode := base64.StdEncoding.DecodeString(yStr)
	if errDecode != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", yStr, errDecode)
	}
	genStr := "rEAy708tmuOd8wtcj/2sUGzevnuJmYyvdIZqCM/k/+OmgkpOELmm8N2SHwGnDEr6q3OddwDCn1LFfbF8YgqGUr5ekAGo1mrXwXZpEBmZAkr00CcnWsE0i7inYtBSG8mK4kcVBCLqHtQJk51U2nRgzbX2xrJQcXy+8YDrNBGOmNEZUppF1vg0Vm4wJeMWozDvu3eobwwasVsFGuPUKMj4rLcKgTcVC47rEOGD7dGZY93Z4mPkdwWJ72qiHn9fL/OBtTnM40CdE81Wavu0jWwBkYHhvP6UswJp7f5y/ptqpL17Wg8ccc//TBnEGOH27AF5gbwIfypwZbOEuJDTGR8r+g=="
	gen, errDecode := base64.StdEncoding.DecodeString(genStr)
	if errDecode != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", gen, errDecode)
	}
	primeStr := "rRB+HpEjqdDWYPqnlVnFH6INZOVoO5/RtUsVl7YdCnXm+hQd+VpW26+aPEB7od8V6z1oijCcGA4d5rhaEnSgpm0/gVKtasISkDfJ7e/aTfjZHo/vVbc5S3rVt9C2wSIHyfmNEe002/bGugssi7wnvmoA4KC5xJcIs7+KMXCRiDaBKGEwvImF2xYC5xRBXZMwJ4Jzx94x79xzEPcSH9WgdBWYfZrcCkhtzfk6zEQyg4cxXXXhmMZBpIDNhqG55YfovmDmnMkosrnFIXLkEwQumyPxCw4W55djybU9z0uoCinj+3PBa451uX7zY+L/ox9xz53lOE5xuBwKxN/+DBDmTw=="
	prime, errDecode := base64.StdEncoding.DecodeString(primeStr)
	if errDecode != nil {
		t.Errorf("could not decode base 64 string '%s': '%s'", prime, errDecode)
	}

	base := gosslyze.BaseKeyInfo{
		Type:        408,
		TypeName:    "ECDH",
		Size:        256,
		PublicBytes: pubBytes,
	}

	ecdh := gosslyze.EcDhKeyInfo{
		BaseKeyInfo: base,
		Curve:       415,
		CurveName:   "prime256v1",
	}

	nist := gosslyze.NistEcDhKeyInfo{
		EcDhKeyInfo: ecdh,
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
		{"base-info", args{&base}, 256, 0, baseExtrasRes},
		{"ecdh-info", args{&ecdh}, 256, 128, ecdhExtrasRes},
		{"nist-ecdh-info", args{&nist}, 256, 128, nistExtrasRes},
		{"nist-ecdh-info", args{&dh}, 512, 63, dhExtrasRes},
		{"error-incorrect interface", args{&incorrectStruct{Asdf: 2}}, 0, 0, []string{}},
		{"error-interface-non-pointer", args{dh}, 0, 0, []string{}},
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

func TestGnfsComplexity(t *testing.T) {

	tests := []struct {
		name           string
		keySize        uint64
		expectedResult float64
		epsilon        float64
		wantErr        error
	}{
		{"512", 512, 63.929344, 0.01, nil},
		{"1024", 1024, 86.7661192, 0.01, nil},
		{"2048", 2048, 116.883813, 0.01, nil},
		{"3072", 3072, 138.736281, 0.01, nil},
		{"4096", 4096, 156.496953, 0.01, nil},
		{"7680", 7680, 203.018736, 0.01, nil},
		{"8192", 8192, 208.472486, 0.01, nil},
		{"15360", 15360, 269.384773, 0.01, nil},
		{"16384", 16384, 276.518407, 0.01, nil},

		{"500", 500, 63.2550403, 0.01, nil},
		{"1000", 1000, 85.8754464, 0.01, nil},
		{"2000", 2000, 115.7106783, 0.01, nil},
		{"3100", 3100, 139.2663292, 0.01, nil},
		{"4100", 4100, 156.5606913, 0.01, nil},
		{"7700", 7700, 203.2358751, 0.01, nil},
		{"8200", 8200, 208.5560244, 0.01, nil},
		{"15400", 15400, 269.6688214, 0.01, nil},
		{"16400", 16400, 276.6276667, 0.01, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength, err := gnfsComplexity(tt.keySize)
			if err != tt.wantErr {
				t.Errorf("gnfsComplexity(%d) error = '%v', wantErr = '%v'", tt.keySize, err, tt.wantErr)
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

// Variable that will be set in the benchmark in order for compiler to no be able to eliminate the benchmark itself.
var strength float64

func benchmarkGnfsComplexity(keySize uint64, b *testing.B) {
	var res float64
	var errGnfs error
	for n := 0; n < b.N; n++ {
		res, errGnfs = gnfsComplexity(keySize)
		if errGnfs != nil {
			b.Errorf("gnfsComplexity(%d) error: %s", keySize, errGnfs)
		}
	}
	strength = res
}

func BenchmarkGnfsComplexity512(b *testing.B)   { benchmarkGnfsComplexity(512, b) }
func BenchmarkGnfsComplexity1024(b *testing.B)  { benchmarkGnfsComplexity(1024, b) }
func BenchmarkGnfsComplexity2048(b *testing.B)  { benchmarkGnfsComplexity(2048, b) }
func BenchmarkGnfsComplexity3072(b *testing.B)  { benchmarkGnfsComplexity(3072, b) }
func BenchmarkGnfsComplexity4096(b *testing.B)  { benchmarkGnfsComplexity(4096, b) }
func BenchmarkGnfsComplexity7680(b *testing.B)  { benchmarkGnfsComplexity(7680, b) }
func BenchmarkGnfsComplexity8192(b *testing.B)  { benchmarkGnfsComplexity(8192, b) }
func BenchmarkGnfsComplexity15360(b *testing.B) { benchmarkGnfsComplexity(15360, b) }
func BenchmarkGnfsComplexity16384(b *testing.B) { benchmarkGnfsComplexity(16384, b) }
func BenchmarkGnfsComplexity500(b *testing.B)   { benchmarkGnfsComplexity(500, b) }
func BenchmarkGnfsComplexity1000(b *testing.B)  { benchmarkGnfsComplexity(1000, b) }
func BenchmarkGnfsComplexity2000(b *testing.B)  { benchmarkGnfsComplexity(2000, b) }
func BenchmarkGnfsComplexity3100(b *testing.B)  { benchmarkGnfsComplexity(3100, b) }
func BenchmarkGnfsComplexity4100(b *testing.B)  { benchmarkGnfsComplexity(4100, b) }
func BenchmarkGnfsComplexity7700(b *testing.B)  { benchmarkGnfsComplexity(7700, b) }
func BenchmarkGnfsComplexity8200(b *testing.B)  { benchmarkGnfsComplexity(8200, b) }
func BenchmarkGnfsComplexity15400(b *testing.B) { benchmarkGnfsComplexity(15400, b) }
func BenchmarkGnfsComplexity16400(b *testing.B) { benchmarkGnfsComplexity(16400, b) }
