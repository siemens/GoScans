/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// TestExtractHtmlTitle verifies that ExtractHtmlTitle correctly extracts the HTML title tag content from various document structures.
func TestExtractHtmlTitle(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "title1",
			body: []byte("<html><title>My Title</title><body></body></html>"),
			want: "My Title",
		},
		{
			name: "title2",
			body: []byte("<html><title > My Title</title><body></body></html>"),
			want: " My Title",
		},
		{
			name: "title3",
			body: []byte("<html><title> My Title</ title ><body></body></html>"),
			want: "", // Completely broken, no title end tag, so no title
		},
		{
			name: "title4",
			body: []byte("<html><title> My Title</ title ></title><body></body></html>"),
			want: " My Title</ title >", // Strange but still working
		},
		{
			name: "title5",
			body: []byte("<html>< title > My Title</ title ><body></body></html>"),
			want: "",
		},
		{
			name: "title6",
			body: []byte("<html><title> My Title</ title ><body></title><body></body></html>"),
			want: " My Title</ title ><body>",
		},
		{
			name: "title7",
			body: []byte("<html><body><title>My Title</title></body></html>"),
			want: "My Title",
		},
		{
			name: "title8",
			body: []byte("<html><body><title>My Title</body></title></html>"),
			want: "My Title</body>",
		},
		{
			name: "title9",
			body: []byte("<html><body><title>My Title</body></title></body></html>"),
			want: "My Title</body>",
		},
		{
			name: "title10",
			body: []byte("<html><body><title>My Title</body></html>"),
			want: "", // No title end tag
		},
		{
			name: "title11",
			body: []byte("<html><title>My Title</title>><body></body></html>"),
			want: "My Title", // Broken HTML, but only after title
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractHtmlTitle(tt.body); got != tt.want {
				t.Errorf("ExtractHtmlTitle() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestProxyStringToUrl verifies that ProxyStringToUrl parses valid proxy URLs and returns errors for invalid ones.
func TestProxyStringToUrl(t *testing.T) {
	tests := []struct {
		name    string
		proxy   string
		want    *url.URL
		wantErr bool
	}{
		{
			name:    "valid-http-1",
			proxy:   "http://localhost:8080",
			want:    &url.URL{Scheme: "http", Host: "localhost:8080"},
			wantErr: false,
		},
		{
			name:    "valid-http-2",
			proxy:   "http://localhost",
			want:    &url.URL{Scheme: "http", Host: "localhost"},
			wantErr: false,
		},
		{
			name:    "valid-https",
			proxy:   "https://localhost:8080",
			want:    &url.URL{Scheme: "https", Host: "localhost:8080"},
			wantErr: false,
		},
		{
			name:    "valid-socks",
			proxy:   "socks5://localhost:8080",
			want:    &url.URL{Scheme: "socks5", Host: "localhost:8080"},
			wantErr: false,
		},
		{
			name:    "invalid-url-1",
			proxy:   "http://not existing",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid-url-2",
			proxy:   "localhost",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid-scheme",
			proxy:   "ftp://localhost:8080",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := ProxyStringToUrl(tt.proxy)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("ProxyStringToUrl() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProxyStringToUrl() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestAbsToRelUrl verifies that UrlToRelative strips scheme and host from absolute URLs and returns relative paths.
func TestAbsToRelUrl(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "invalid-url-1",
			path: "some string",
			want: "some string",
		},
		{
			name: "invalid-url-2",
			path: "sub.domain.tld/",
			want: "sub.domain.tld/",
		},
		{
			name: "invalid-url-3",
			path: "://sub.domain.tld/login/",
			want: "://sub.domain.tld/login/",
		},
		{
			name: "valid-absolute-1",
			path: "http://sub.domain.tld/",
			want: "",
		},
		{
			name: "valid-absolute-2",
			path: "http://sub.domain.tld",
			want: "",
		},
		{
			name: "valid-absolute-3",
			path: "http://sub.domain.tld/login/",
			want: "login/",
		},
		{
			name: "valid-absolute-4",
			path: "http://sub.domain.tld/../../../../",
			want: "../../../../",
		},
		{
			name: "valid-absolute-5",
			path: "http://sub.domain.tld/login/http://sub.domain.tld",
			want: "login/http://sub.domain.tld",
		},
		{
			name: "valid-absolute-6",
			path: "https://sub.domain.tld/login/",
			want: "login/",
		},
		{
			name: "valid-absolute-7",
			path: "ftp://sub.domain.tld/login/",
			want: "login/",
		},
		{
			name: "valid-absolute-8",
			path: "x://sub.domain.tld/login/",
			want: "login/",
		},
		{
			name: "valid-relative-8",
			path: "/login/",
			want: "login/",
		},
		{
			name: "valid-relative-8-2",
			path: "login/",
			want: "login/",
		},
		{
			name: "valid-relative-8-3",
			path: "login",
			want: "login",
		},
		{
			name: "valid-relative-8-4",
			path: "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UrlToRelative(tt.path); got != tt.want {
				t.Errorf("UrlToRelative() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestExtractHostPort verifies that ExtractHostPort extracts the host and port from a URL with implicit and explicit port numbers.
func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		want  string
		want1 int
	}{
		{
			name:  "domain-http-explicit",
			url:   "http://localhost:80",
			want:  "localhost",
			want1: 80,
		},
		{
			name:  "ipv4-http-explicit",
			url:   "http://127.0.0.1:80",
			want:  "127.0.0.1",
			want1: 80,
		},
		{
			name:  "ipv6-http-explicit",
			url:   "http://[1::]:80",
			want:  "1::",
			want1: 80,
		},

		{
			name:  "domain-http-implicit",
			url:   "http://localhost",
			want:  "localhost",
			want1: 80,
		},
		{
			name:  "ipv4-http-implicit",
			url:   "http://127.0.0.1",
			want:  "127.0.0.1",
			want1: 80,
		},
		{
			name:  "ipv6-http-implicit",
			url:   "http://[1::]",
			want:  "[1::]",
			want1: 80,
		},

		{
			name:  "domain-https-implicit",
			url:   "https://localhost",
			want:  "localhost",
			want1: 443,
		},
		{
			name:  "ipv4-https-implicit",
			url:   "https://127.0.0.1",
			want:  "127.0.0.1",
			want1: 443,
		},
		{
			name:  "ipv6-https-implicit",
			url:   "https://[1::]",
			want:  "[1::]",
			want1: 443,
		},

		{
			name:  "domain-https-explicit-other-port",
			url:   "https://localhost:80",
			want:  "localhost",
			want1: 80,
		},
		{
			name:  "ipv4-https-explicit-other-port",
			url:   "https://127.0.0.1:80",
			want:  "127.0.0.1",
			want1: 80,
		},
		{
			name:  "ipv6-https-explicit-other-port",
			url:   "https://[1::]:80",
			want:  "1::",
			want1: 80,
		},

		// Some weird input
		{
			name:  "unknonw-scheme",
			url:   "asfd://localhost",
			want:  "localhost",
			want1: 0,
		},
		{
			name:  "invalid-notation",
			url:   "http://1:::80",
			want:  "1:::80",
			want1: 80,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, errU := url.Parse(tt.url)
			if errU != nil {
				t.Errorf("ExtractHostPort() url.Parse error = '%v'", errU)
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

// TestSameEndpoint verifies that SameEndpoint correctly compares a URL's resolved IP and port against expected values.
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
		{
			name: "invalid-url",
			args: args{
				url:          "https://invalid-url",
				endpointIp:   "195.54.164.39",
				endpointPort: 443,
			},
			want: false,
		},
		{
			name: "implicit-port-same-1",
			args: args{
				url:          "https://www.ccc.de",
				endpointIp:   "195.54.164.39",
				endpointPort: 443,
			},
			want: true,
		},
		{
			name: "implicit-port-same-2",
			args: args{
				url:          "http://www.ccc.de",
				endpointIp:   "195.54.164.39",
				endpointPort: 80,
			},
			want: true,
		},
		{
			name: "explicit-port-same-1",
			args: args{
				url:          "https://www.ccc.de:443",
				endpointIp:   "195.54.164.39",
				endpointPort: 443,
			},
			want: true,
		},
		{
			name: "explicit-port-same-2",
			args: args{
				url:          "http://www.ccc.de:80",
				endpointIp:   "195.54.164.39",
				endpointPort: 80,
			},
			want: true,
		},
		{
			name: "implicit-port-different-1",
			args: args{
				url:          "https://www.ccc.de",
				endpointIp:   "195.54.164.39",
				endpointPort: 80,
			},
			want: false,
		},
		{
			name: "implicit-port-different-2",
			args: args{
				url:          "http://www.ccc.de",
				endpointIp:   "195.54.164.39",
				endpointPort: 443,
			},
			want: false,
		},
		{
			name: "explicit-port-different-1",
			args: args{
				url:          "https://www.ccc.de:80",
				endpointIp:   "195.54.164.39",
				endpointPort: 443,
			},
			want: false,
		},
		{
			name: "explicit-port-different-2",
			args: args{
				url:          "http://www.ccc.de:443",
				endpointIp:   "195.54.164.39",
				endpointPort: 80,
			},
			want: false,
		},
		{
			name: "different-ip-1",
			args: args{
				url:          "https://www.ccc.de",
				endpointIp:   "10.10.10.10",
				endpointPort: 443,
			},
			want: false,
		},
		{
			name: "different-ip-2",
			args: args{
				url:          "http://www.ccc.de",
				endpointIp:   "10.10.10.10",
				endpointPort: 80,
			},
			want: false,
		},
		{
			name: "different-omit-port-1",
			args: args{
				url:          "https://www.ccc.de",
				endpointIp:   "10.10.10.10",
				endpointPort: -1,
			},
			want: false,
		},
		{
			name: "different-omit-ip-1",
			args: args{
				url:          "https://www.ccc.de",
				endpointIp:   "",
				endpointPort: 42,
			},
			want: false,
		},
		{
			name: "different-omit-both-1",
			args: args{
				url:          "",
				endpointIp:   "",
				endpointPort: -1,
			},
			want: true,
		},
		{
			name: "different-omit-both-2",
			args: args{
				url:          "http://www.ccc.de",
				endpointIp:   "",
				endpointPort: -1,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, errU := url.Parse(tt.args.url)
			if errU != nil {
				t.Errorf("SameEndpoint() url.Parse error = '%v'", errU)
				return
			}

			if got := SameEndpoint(u, tt.args.endpointIp, tt.args.endpointPort); got != tt.want {
				t.Errorf("SameEndpoint() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestNewHttpFingerprint verifies that NewHttpFingerprint populates all fields correctly including the HTML content length.
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
		{
			name: "example-1",
			args: args{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlContent:  "Content",
			},
			want: &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: len("Content")},
		},
		{
			name: "example-2",
			args: args{},
			want: &HttpFingerprint{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewHttpFingerprint(tt.args.respUrl, tt.args.responseCode, tt.args.htmlTitle, tt.args.htmlContent); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHttpFingerprint() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestHttpFingerprint_Similar verifies that Similar returns true when two fingerprints match within the given HTML length threshold.
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
		{
			name: "valid-equal-length-1",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      100,
			},
			args: args{f2: f, lenThreadshold: 0},
			want: true,
		},
		{
			name: "valid-equal-length-2",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      100,
			},
			args: args{f2: f, lenThreadshold: 10},
			want: true,
		},
		{
			name: "valid-longer-length",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      105,
			},
			args: args{f2: f, lenThreadshold: 10},
			want: true,
		},
		{
			name: "valid-shorter-length",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      95,
			},
			args: args{f2: f, lenThreadshold: 10},
			want: true,
		},
		{
			name: "invalid-longer-length",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      105,
			},
			args: args{f2: f, lenThreadshold: 9},
			want: false,
		},
		{
			name: "invalid-shorter-length",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      95,
			},
			args: args{f2: f, lenThreadshold: 9},
			want: false,
		},
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

// TestHttpFingerprint_String verifies that String formats fingerprint fields into a pipe-delimited string.
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
		{
			name: "example-1",
			fields: fields{
				respUrl:      "https://sub.domain.tld",
				responseCode: 200,
				htmlTitle:    "Title",
				htmlLen:      100,
			},
			want: "https://sub.domain.tld|200|Title|~100",
		},
		{
			name: "example-2",
			fields: fields{
				respUrl:      "",
				responseCode: 0,
				htmlTitle:    "",
				htmlLen:      0,
			},
			want: "|0||~0",
		},
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

// TestHttpFingerprint_KnownIn verifies that KnownIn returns the matching vhost name when a fingerprint is similar to a known one.
func TestHttpFingerprint_KnownIn(t *testing.T) {
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
		{
			name: "known-exactly-1",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 100},
				lenThreshold: 10,
			},
			wantKnown: true,
			want1:     "vname1",
		},
		{
			name: "known-exactly-2",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 500, HtmlTitle: "Internal Error", HtmlLen: 300},
				lenThreshold: 0,
			},
			wantKnown: true,
			want1:     "vname3",
		},
		{
			name: "known-similar",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 95},
				lenThreshold: 10,
			},
			wantKnown: true,
			want1:     "vname1",
		},
		{
			name: "unknown-not-similar",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 94},
				lenThreshold: 10,
			},
			wantKnown: false,
			want1:     "",
		},
		{
			name: "unknown-response-code",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 404, HtmlTitle: "Title", HtmlLen: 100},
				lenThreshold: 10,
			},
			wantKnown: false,
			want1:     "",
		},
		{
			name: "unknown-html-title",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld", ResponseCode: 200, HtmlTitle: "Not Found", HtmlLen: 100},
				lenThreshold: 10,
			},
			wantKnown: false,
			want1:     "",
		},
		{
			name: "unknown-url",
			args: args{
				fingerprints: fps,
				fingerprint:  &HttpFingerprint{RespUrl: "https://sub.domain.tld/", ResponseCode: 200, HtmlTitle: "Title", HtmlLen: 100},
				lenThreshold: 10,
			},
			wantKnown: false,
			want1:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.args.fingerprint.KnownIn(tt.args.fingerprints, tt.args.lenThreshold)
			if got1 != tt.wantKnown {
				t.Errorf("TestHttpFingerprint_KnownIn() = '%v', want = '%v'", got, tt.wantKnown)
			}
			if got != tt.want1 {
				t.Errorf("TestHttpFingerprint_KnownIn() got1 = '%v', want = '%v'", got1, tt.want1)
			}
		})
	}
}

// TestReadBody verifies that ReadBody correctly decodes HTTP response bodies from various character encodings.
func TestReadBody(t *testing.T) {

	tests := []struct {
		name         string
		contentType  string
		contentBytes []byte
		wantString   string
	}{
		{
			name:         "iso-8859-1-source",
			contentType:  "ISO-8859-1",
			contentBytes: []byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			wantString: `<?xml version="1.0" encoding="ISO-8859-1"?>
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
			name:         "iso-8859-1-wrong-content-type",
			contentType:  "utf-8",
			contentBytes: []byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			wantString: `<?xml version="1.0" encoding="ISO-8859-1"?>
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
			name:         "iso-8859-1-invalid-content-type",
			contentType:  "not-existing",
			contentBytes: []byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 73, 83, 79, 45, 56, 56, 53, 57, 45, 49, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			wantString: `<?xml version="1.0" encoding="ISO-8859-1"?>
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
			name:         "iso-8859-1-unknown-content-type",
			contentType:  "not-existing",
			contentBytes: []byte{60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 34, 63, 62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 32, 80, 85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 87, 51, 67, 47, 47, 68, 84, 68, 32, 88, 72, 84, 77, 76, 32, 49, 46, 48, 32, 83, 116, 114, 105, 99, 116, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 84, 82, 47, 120, 104, 116, 109, 108, 49, 47, 68, 84, 68, 47, 120, 104, 116, 109, 108, 49, 45, 115, 116, 114, 105, 99, 116, 46, 100, 116, 100, 34, 62, 10, 60, 104, 116, 109, 108, 32, 120, 109, 108, 110, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 49, 57, 57, 57, 47, 120, 104, 116, 109, 108, 34, 32, 108, 97, 110, 103, 61, 34, 101, 115, 34, 32, 120, 109, 108, 58, 108, 97, 110, 103, 61, 34, 101, 115, 34, 62, 60, 104, 101, 97, 100, 62, 10, 60, 109, 101, 116, 97, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 34, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 34, 32, 47, 62, 10, 60, 33, 45, 45, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 104, 105, 115, 32, 102, 105, 108, 101, 32, 105, 115, 32, 103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 102, 114, 111, 109, 32, 120, 109, 108, 32, 115, 111, 117, 114, 99, 101, 58, 32, 68, 79, 32, 78, 79, 84, 32, 69, 68, 73, 84, 10, 32, 32, 32, 32, 32, 32, 32, 32, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 32, 32, 32, 32, 32, 45, 45, 62, 10, 60, 116, 105, 116, 108, 101, 62, 65, 112, 97, 99, 104, 101, 32, 72, 84, 84, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 243, 110, 32, 50, 46, 52},
			wantString: `<?xml version="1.0" encoding=""?>
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
				Body: io.NopCloser(bytes.NewReader(tt.contentBytes)),
			}
			r.Header = make(http.Header)
			r.Header.Add("Content-Type", tt.contentType)

			// Detect content type and read bytes
			got, _, errReadBody := ReadBody(&r)
			if errReadBody != nil {
				t.Errorf("ReadBody() error = '%v'", errReadBody)
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
