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
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestExtractHtmlTitle(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"title1", []byte("<html><title>My Title</title><body></body></html>"), "My Title"},
		{"title2", []byte("<html><title > My Title</title><body></body></html>"), " My Title"},
		{"title3", []byte("<html><title> My Title</ title ><body></body></html>"), ""},                            // Completely broken, no title end tag, so no title
		{"title4", []byte("<html><title> My Title</ title ></title><body></body></html>"), " My Title</ title >"}, // Strange but still working
		{"title5", []byte("<html>< title > My Title</ title ><body></body></html>"), ""},
		{"title6", []byte("<html><title> My Title</ title ><body></title><body></body></html>"), " My Title</ title ><body>"},
		{"title7", []byte("<html><body><title>My Title</title></body></html>"), "My Title"},
		{"title8", []byte("<html><body><title>My Title</body></title></html>"), "My Title</body>"},
		{"title9", []byte("<html><body><title>My Title</body></title></body></html>"), "My Title</body>"},
		{"title10", []byte("<html><body><title>My Title</body></html>"), ""},                  // No title end tag
		{"title11", []byte("<html><title>My Title</title>><body></body></html>"), "My Title"}, // Broken HTML, but only after title
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractHtmlTitle(tt.body); got != tt.want {
				t.Errorf("ExtractHtmlTitle() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestProxyStringToUrl(t *testing.T) {
	tests := []struct {
		name    string
		proxy   string
		want    *url.URL
		wantErr bool
	}{
		{"valid-http-1", "http://localhost:8080", &url.URL{Scheme: "http", Host: "localhost:8080"}, false},
		{"valid-http-2", "http://localhost", &url.URL{Scheme: "http", Host: "localhost"}, false},
		{"valid-https", "https://localhost:8080", &url.URL{Scheme: "https", Host: "localhost:8080"}, false},
		{"valid-socks", "socks5://localhost:8080", &url.URL{Scheme: "socks5", Host: "localhost:8080"}, false},
		{"invalid-url-1", "http://not existing", nil, true},
		{"invalid-url-2", "localhost", nil, true},
		{"invalid-scheme", "ftp://localhost:8080", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProxyStringToUrl(tt.proxy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProxyStringToUrl() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProxyStringToUrl() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestAbsToRelUrl(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"invalid-url-1", "some string", "some string"},
		{"invalid-url-2", "sub.domain.tld/", "sub.domain.tld/"},
		{"invalid-url-3", "://sub.domain.tld/login/", "://sub.domain.tld/login/"},
		{"valid-absolute-1", "http://sub.domain.tld/", ""},
		{"valid-absolute-2", "http://sub.domain.tld", ""},
		{"valid-absolute-3", "http://sub.domain.tld/login/", "login/"},
		{"valid-absolute-4", "http://sub.domain.tld/../../../../", "../../../../"},
		{"valid-absolute-5", "http://sub.domain.tld/login/http://sub.domain.tld", "login/http://sub.domain.tld"},
		{"valid-absolute-6", "https://sub.domain.tld/login/", "login/"},
		{"valid-absolute-7", "ftp://sub.domain.tld/login/", "login/"},
		{"valid-absolute-8", "x://sub.domain.tld/login/", "login/"},
		{"valid-relative-8", "/login/", "login/"},
		{"valid-relative-8", "login/", "login/"},
		{"valid-relative-8", "login", "login"},
		{"valid-relative-8", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UrlToRelative(tt.path); got != tt.want {
				t.Errorf("UrlToRelative() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		want  string
		want1 int
	}{
		{"domain-http-explicit", "http://localhost:80", "localhost", 80},
		{"ipv4-http-explicit", "http://127.0.0.1:80", "127.0.0.1", 80},
		{"ipv6-http-explicit", "http://[1::]:80", "1::", 80},

		{"domain-http-implicit", "http://localhost", "localhost", 80},
		{"ipv4-http-implicit", "http://127.0.0.1", "127.0.0.1", 80},
		{"ipv6-http-implicit", "http://[1::]", "[1::]", 80},

		{"domain-https-implicit", "https://localhost", "localhost", 443},
		{"ipv4-https-implicit", "https://127.0.0.1", "127.0.0.1", 443},
		{"ipv6-https-implicit", "https://[1::]", "[1::]", 443},

		{"domain-https-explicit-other-port", "https://localhost:80", "localhost", 80},
		{"ipv4-https-explicit-other-port", "https://127.0.0.1:80", "127.0.0.1", 80},
		{"ipv6-https-explicit-other-port", "https://[1::]:80", "1::", 80},

		// Some weird input
		{"unknonw-scheme", "asfd://localhost", "localhost", 0},
		{"invalid-notation", "http://1:::80", "1:::80", 80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, errParse := url.Parse(tt.url)
			if errParse != nil {
				t.Errorf("ExtractHostPort() Could not parse URL: %v", errParse)
				return
			}
			got, got1 := ExtractHostPort(u)
			if got != tt.want {
				t.Errorf("ExtractHostPort() = '%v', want = '%v'", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ExtractHostPort() got1 = '%v', want = '%v'", got1, tt.want1)
			}
		})
	}
}

func TestSameEndpoint(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		url          string
		endpointIp   string
		endpointPort int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"invalid-url", args{"https://invalid-url", "195.54.164.39", 443}, false},
		{"implicit-port-same-1", args{"https://www.ccc.de", "195.54.164.39", 443}, true},
		{"implicit-port-same-2", args{"http://www.ccc.de", "195.54.164.39", 80}, true},
		{"explicit-port-same-1", args{"https://www.ccc.de:443", "195.54.164.39", 443}, true},
		{"explicit-port-same-2", args{"http://www.ccc.de:80", "195.54.164.39", 80}, true},
		{"implicit-port-different-1", args{"https://www.ccc.de", "195.54.164.39", 80}, false},
		{"implicit-port-different-2", args{"http://www.ccc.de", "195.54.164.39", 443}, false},
		{"explicit-port-different-1", args{"https://www.ccc.de:80", "195.54.164.39", 443}, false},
		{"explicit-port-different-2", args{"http://www.ccc.de:443", "195.54.164.39", 80}, false},
		{"different-ip-1", args{"https://www.ccc.de", "10.10.10.10", 443}, false},
		{"different-ip-2", args{"http://www.ccc.de", "10.10.10.10", 80}, false},
		{"different-omit-port-1", args{"https://www.ccc.de", "10.10.10.10", -1}, false},
		{"different-omit-ip-1", args{"https://www.ccc.de", "", 42}, false},
		{"different-omit-both-1", args{"", "", -1}, true},
		{"different-omit-both-2", args{"http://www.ccc.de", "", -1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, errParse := url.Parse(tt.args.url)
			if errParse != nil {
				t.Errorf("SameEndpoint() Could not parse URL: %v", errParse)
				return
			}

			if got := SameEndpoint(u, tt.args.endpointIp, tt.args.endpointPort); got != tt.want {
				t.Errorf("SameEndpoint() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestNewHttpFingerprint(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		respUrl      string
		responseCode int
		htmlTitle    string
		htmlContent  string
	}
	tests := []struct {
		name string
		args args
		want *HttpFingerprint
	}{
		{"example-1", args{respUrl: "https://sub.domain.tld", responseCode: 200, htmlTitle: "Title", htmlContent: "Content"}, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: len("Content")}},
		{"example-2", args{}, &HttpFingerprint{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewHttpFingerprint(tt.args.respUrl, tt.args.responseCode, tt.args.htmlTitle, tt.args.htmlContent); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHttpFingerprint() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestHttpFingerprint_Similar(t *testing.T) {
	f := &HttpFingerprint{
		RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 100,
	}

	// Prepare and run test cases
	type fields struct {
		respUrl      string
		responseCode int
		htmlTitle    string
		htmlLen      int
	}
	type args struct {
		f2             *HttpFingerprint
		lenThreadshold int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"valid-equal-length-1", fields{"https://sub.domain.tld", 200, "Title", 100}, args{f, 0}, true},
		{"valid-equal-length-2", fields{"https://sub.domain.tld", 200, "Title", 100}, args{f, 10}, true},
		{"valid-longer-length", fields{"https://sub.domain.tld", 200, "Title", 105}, args{f, 10}, true},
		{"valid-shorter-length", fields{"https://sub.domain.tld", 200, "Title", 95}, args{f, 10}, true},
		{"invalid-longer-length", fields{"https://sub.domain.tld", 200, "Title", 105}, args{f, 9}, false},
		{"invalid-shorter-length", fields{"https://sub.domain.tld", 200, "Title", 95}, args{f, 9}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &HttpFingerprint{
				RespUrl:      tt.fields.respUrl,
				ResponseCode: tt.fields.responseCode,
				HtmlTitle:    tt.fields.htmlTitle,
				HtmlLen:      tt.fields.htmlLen,
			}
			if got := f.Similar(tt.args.f2, tt.args.lenThreadshold); got != tt.want {
				t.Errorf("HttpFingerprint.Similar() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestHttpFingerprint_String(t *testing.T) {
	type fields struct {
		respUrl      string
		responseCode int
		htmlTitle    string
		htmlLen      int
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"example-1", fields{"https://sub.domain.tld", 200, "Title", 100}, "https://sub.domain.tld|200|Title|~100"},
		{"example-2", fields{"", 0, "", 0}, "|0||~0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &HttpFingerprint{
				RespUrl:      tt.fields.respUrl,
				ResponseCode: tt.fields.responseCode,
				HtmlTitle:    tt.fields.htmlTitle,
				HtmlLen:      tt.fields.htmlLen,
			}
			if got := f.String(); got != tt.want {
				t.Errorf("HttpFingerprint.String() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestFingerprintKnown(t *testing.T) {
	fps := map[string]*HttpFingerprint{
		"vname1": {RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 100},
		"vname2": {RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 2000},
		"vname3": {RespUrl: "https://sub.domain.tld", ResponseCode: 500, HtmlTitle: "Internal Error", HtmlLen: 300},
	}

	// Prepare and run test cases
	type args struct {
		fingerprints map[string]*HttpFingerprint
		fingerprint  *HttpFingerprint
		lenThreshold int
	}
	tests := []struct {
		name      string
		args      args
		wantKnown bool
		want1     string
	}{
		{"known-exactly-1", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 100}, 10}, true, "vname1"},
		{"known-exactly-2", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 500, HtmlTitle: "Internal Error", HtmlLen: 300}, 0}, true, "vname3"},
		{"known-similar", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 95}, 10}, true, "vname1"},
		{"unknown-not-similar", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 94}, 10}, false, ""},
		{"unknown-response-code", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 404, HtmlTitle: "Title", HtmlLen: 100}, 10}, false, ""},
		{"unknown-html-title", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Not Found", HtmlLen: 100}, 10}, false, ""},
		{"unknown-url", args{fps, &HttpFingerprint{RespUrl: "https://sub.domain.tld/", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 100}, 10}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := HttpFingerprintKnown(tt.args.fingerprints, tt.args.fingerprint, tt.args.lenThreshold)
			if got != tt.wantKnown {
				t.Errorf("HttpFingerprintKnown() = '%v', want = '%v'", got, tt.wantKnown)
			}
			if got1 != tt.want1 {
				t.Errorf("HttpFingerprintKnown() got1 = '%v', want = '%v'", got1, tt.want1)
			}
		})
	}
}

func TestReadBody(t *testing.T) {

	tests := []struct {
		name         string
		contentType  string
		contentBytes []byte
		wantString   string
	}{
		{
			"ISO-8859-1 Source",
			"ISO-8859-1",
			[]byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Apache HTTP Server Versión 2.4`,
		},
		{
			"ISO-8859-1 Source (with WRONG content type specification)",
			"utf-8",
			[]byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Apache HTTP Server Versión 2.4`,
		},
		{
			"ISO-8859-1 Source (with INVALID content type specification)",
			"not-existing",
			[]byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Apache HTTP Server Versión 2.4`,
		},
		{
			"ISO-8859-1 Source (with UNKNOWN content type specification)",
			"not-existing",
			[]byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			`<?xml version="1.0" encoding=""?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Apache HTTP Server Versión 2.4`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare dummy response with test data
			r := http.Response{
				Body: ioutil.NopCloser(bytes.NewReader(tt.contentBytes)),
			}
			r.Header = make(http.Header)
			r.Header.Add("Content-Type", tt.contentType)

			// Detect content type and read bytes
			got, _, err := ReadBody(&r)
			if err != nil {
				t.Errorf("ReadBody() error = %v", err)
				return
			}

			// Convert to string
			gotString := string(got)

			// Evaluate
			if !reflect.DeepEqual(gotString, tt.wantString) {
				t.Errorf("ReadBody() got = '%v', want '%v'", gotString, tt.wantString)
			}
		})
	}
}
