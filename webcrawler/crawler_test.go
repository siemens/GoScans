/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webcrawler

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// Test_NewCrawler verifies that NewCrawler returns an error for invalid or unreachable targets and succeeds for valid inputs.
func Test_NewCrawler(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	timeout := 10 * time.Second

	// Prepare timeout context
	ctx, ctxCancel := context.WithTimeout(context.Background(), timeout)
	defer ctxCancel()

	// Start local server to avoid live network dependency for valid-URL cases
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(localSrv.Close)

	// Prepare and run test cases
	type args struct {
		logger         utils.Logger
		baseUrl        string
		vhost          string
		https          bool
		depth          int
		followQS       bool
		storeRoot      bool
		download       bool
		outputFolder   string
		ntlmDomain     string
		ntlmUser       string
		ntlmPassword   string
		userAgent      string
		proxy          *url.URL
		requestTimeout time.Duration
		context        context.Context
		followTypes    []string
		downloadTypes  []string
		maxThreads     int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid-basic",
			args:    args{testLogger, localSrv.URL, "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, ctx, DefaultFollowContentTypes, DefaultDownloadContentTypes, 4},
			wantErr: false,
		},
		{
			name:    "negative-threads",
			args:    args{testLogger, localSrv.URL, "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, ctx, DefaultFollowContentTypes, DefaultDownloadContentTypes, -3},
			wantErr: false,
		},
		{
			name:    "dns-failure",
			args:    args{testLogger, "https://nonexistent.invalid", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, ctx, DefaultFollowContentTypes, DefaultDownloadContentTypes, 4},
			wantErr: true,
		},
		{
			name:    "no-content-types",
			args:    args{testLogger, localSrv.URL, "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, ctx, []string{}, []string{}, 4},
			wantErr: false,
		},
		{
			name:    "not-http-or-https",
			args:    args{testLogger, "ftp://192.0.2.1:80", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, ctx, []string{}, []string{}, 4},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, errU := url.Parse(tt.args.baseUrl)
			if errU != nil {
				t.Fatalf("NewCrawler() url.Parse() error = '%v', want = nil", errU)
			} else {
				_, errNewCrawler := NewCrawler(
					tt.args.logger,
					*u,
					tt.args.vhost,
					tt.args.https,
					tt.args.depth,
					tt.args.followQS,
					tt.args.storeRoot,
					tt.args.download,
					tt.args.outputFolder,
					tt.args.ntlmDomain,
					tt.args.ntlmUser,
					tt.args.ntlmPassword,
					tt.args.userAgent,
					tt.args.proxy,
					tt.args.requestTimeout,
					tt.args.followTypes,
					tt.args.downloadTypes,
					tt.args.maxThreads,
					tt.args.context,
				)
				if (errNewCrawler != nil) != tt.wantErr {
					t.Errorf("NewCrawler() error = '%v', wantErr = '%v'", errNewCrawler, tt.wantErr)
					return
				}
			}
		})
	}
}

// Test_sortQueue verifies that sortQueue orders tasks by depth and path lexicographically.
func Test_sortQueue(t *testing.T) {

	// The IDs have no effect on the sorting.
	want := []*task{
		{19, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: ""}, Depth: 0}},
		{1, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/"}, Depth: 0}},
		{42, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi"}, Depth: 1}},
		{5, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
		{7, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
		{17, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "images"}, Depth: 1}},
		{2, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/inde"}, Depth: 1}},
		{0, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/logi"}, Depth: 1}},
		{4, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 1}},
		{16, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/url"}, Depth: 1}},
		{3, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop"}, Depth: 2}},
		{13, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "data/"}, Depth: 2}},
		{23, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "data/subb"}, Depth: 2}},
		{30, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf"}, Depth: 2}},
		{11, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 2}},
		{29, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "user/home/"}, Depth: 2}},
		{22, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf/"}, Depth: 2}},
	}
	tests := []struct {
		name  string
		tasks []*task
	}{
		{
			name: "disorder-1",
			tasks: []*task{
				{22, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf/"}, Depth: 2}},
				{17, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "images"}, Depth: 1}},
				{11, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 2}},
				{2, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/inde"}, Depth: 1}},
				{1, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/"}, Depth: 0}},
				{29, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "user/home/"}, Depth: 2}},
				{0, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/logi"}, Depth: 1}},
				{5, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
				{42, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi"}, Depth: 1}},
				{3, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop"}, Depth: 2}},
				{19, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: ""}, Depth: 0}},
				{4, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 1}},
				{16, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/url"}, Depth: 1}},
				{13, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "data/"}, Depth: 2}},
				{7, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
				{23, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "data/subb"}, Depth: 2}},
				{30, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf"}, Depth: 2}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortQueue(tt.tasks)

			if len(tt.tasks) != len(want) {
				t.Errorf("sortQueue() Result length = '%v', want = '%v'", len(tt.tasks), len(want))
				return
			}

			for i := 0; i < len(tt.tasks); i++ {
				gotUrl := tt.tasks[i].page.Url.String()
				wantUrl := want[i].page.Url.String()
				gotDepth := tt.tasks[i].page.Depth
				wantDepth := want[i].page.Depth
				if gotUrl != wantUrl || gotDepth != wantDepth {
					t.Errorf("sortQueue() index %d = (url='%s', depth=%d), want = (url='%s', depth=%d)", i, gotUrl, gotDepth, wantUrl, wantDepth)
				}
			}
		})
	}
}

// Test_extractLinks verifies that extractLinks returns all expected href links from a parsed HTML document.
func Test_extractLinks(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	sampleHtml := filepath.Join(testSettings.PathDataDir, "webcrawler", "sample.html")

	// Prepare and run test cases
	tests := []struct {
		name      string
		inputFile string
		want      []string
	}{
		{
			name:      "sample",
			inputFile: sampleHtml,
			want:      []string{"/", "/scanning/monitor/", "/inventory/progress/", "/software/firmware/", "/statistics/year/", "/pentestor/hashcat/", "/profile/", "/voucher/generate/", "/admin/", "/logout/", "/toggle_admin_privileges/top/", "/toggle_fy_filter/top/", "/toggle_class_filter/top/", "/toggle_wiped_filter/anchor_jobs/", "/toggle_fy_filter/anchor_jobs/", "/toggle_class_filter/anchor_jobs/", "/toggle_wiped_filter/anchor_jobs_continuing/", "/toggle_fy_filter/anchor_jobs_continuing/", "/toggle_class_filter/anchor_jobs_continuing/", "/toggle_we_filter/anchor_last_logins/", "/toggle_class_filter/anchor_history/", "/toggle_we_filter/anchor_distribution/", "/toggle_fy_filter/anchor_distribution/", "/toggle_class_filter/anchor_distribution/", "https://www.domain.tld/service1/", "https://www.domain.tld/service2/", "https://www.domain.tld/service3/", "https://www.domain.tld/service4/", "https://www.domain.tld/service5/", "https://www.domain2.tld/1", "https://www.domain2.tld/2", "https://www.domain2.tld/3", "https://www.domain3.tld/1", "/voucher/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare IO reader
			stream, errStream := os.Open(tt.inputFile)
			if errStream != nil {
				t.Errorf("extractLinks() Could not read input file")
				return
			}

			// Parse HTLM doc from IO reader
			doc, errDoc := goquery.NewDocumentFromReader(stream)
			if errDoc != nil {
				t.Errorf("extractLinks() Could not parse input file")
				return
			}

			// Extract links
			if got := extractLinks(doc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractLinks() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_extractLinks_Inline verifies extractLinks filtering edge cases using inline HTML: nil doc, fragment-only, mailto, javascript, and empty href.
func Test_extractLinks_Inline(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name   string
		html   string
		nilDoc bool
		want   []string
	}{
		{
			name:   "nil-doc",
			nilDoc: true,
			want:   nil,
		},
		{
			name: "fragment-only",
			html: `<html><body><a href="#section">anchor</a></body></html>`,
			want: []string{},
		},
		{
			name: "mailto",
			html: `<html><body><a href="mailto:user@domain.tld">mail</a></body></html>`,
			want: []string{},
		},
		{
			name: "javascript",
			html: `<html><body><a href="javascript:void(0)">click</a></body></html>`,
			want: []string{"javascript:void(0)"},
		},
		{
			name: "empty-href",
			html: `<html><body><a href="">link</a></body></html>`,
			want: []string{""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Parse doc from inline HTML, or leave nil for the nil-doc case
			var doc *goquery.Document
			if !tt.nilDoc {
				var errDoc error
				doc, errDoc = goquery.NewDocumentFromReader(bytes.NewBufferString(tt.html))
				if errDoc != nil {
					t.Fatalf("Test_extractLinks_Inline() doc parse error = '%v', want = nil", errDoc)
				}
			}

			// Verify extracted links
			if got := extractLinks(doc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractLinks() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_extractRedirects verifies that extractRedirects returns the expected redirect URL from a parsed HTML document.
func Test_extractRedirects(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	sampleHtmlRedirect := filepath.Join(testSettings.PathDataDir, "webcrawler", "sample_redirect.html")

	// Prepare and run test cases
	tests := []struct {
		name      string
		inputFile string
		want      []string
	}{
		{
			name:      "sample",
			inputFile: sampleHtmlRedirect,
			want:      []string{"http://www.google.de/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare IO reader
			stream, errStream := os.Open(tt.inputFile)
			if errStream != nil {
				t.Errorf("extractRedirects() Could not read input file")
				return
			}

			// Parse HTLM doc from IO reader
			doc, errDoc := goquery.NewDocumentFromReader(stream)
			if errDoc != nil {
				t.Errorf("extractRedirects() Could not parse input file")
				return
			}

			// Extract links
			if got := extractRedirects(doc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractRedirects() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_extractRedirects_EdgeCases verifies extractRedirects behavior for nil doc, missing equals sign, and empty URL after equals.
func Test_extractRedirects_EdgeCases(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name   string
		html   string
		nilDoc bool
		want   []string
	}{
		{
			name:   "nil-doc",
			nilDoc: true,
			want:   nil,
		},
		{
			name: "no-equals-in-content",
			html: `<html><head><meta http-equiv="refresh" content="3"></head></html>`,
			want: []string{},
		},
		{
			name: "empty-url-after-equals",
			html: `<html><head><meta http-equiv="refresh" content="3; URL="></head></html>`,
			want: []string{},
		},
		{
			name: "valid-redirect",
			html: `<html><head><meta http-equiv="refresh" content="0; URL=http://domain.tld/"></head></html>`,
			want: []string{"http://domain.tld/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Parse doc from inline HTML, or leave nil for the nil-doc case
			var doc *goquery.Document
			if !tt.nilDoc {
				var errDoc error
				doc, errDoc = goquery.NewDocumentFromReader(bytes.NewBufferString(tt.html))
				if errDoc != nil {
					t.Fatalf("Test_extractRedirects_EdgeCases() doc parse error = '%v', want = nil", errDoc)
				}
			}

			// Verify extracted redirects
			if got := extractRedirects(doc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractRedirects() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_linksToAbsoluteUrls verifies that linksToAbsoluteUrls resolves relative and absolute links against a reference URL.
func Test_linksToAbsoluteUrls(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		links        []string
		referenceUrl *url.URL
	}
	tests := []struct {
		name string
		args args
		want []*url.URL
	}{
		{name: "rel-url-1", args: args{[]string{"/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap"}}},
		{name: "rel-url-2", args: args{[]string{"/sitemap/"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap/"}}},
		{name: "rel-url-3", args: args{[]string{"/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/home"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap"}}},
		{name: "rel-php-1", args: args{[]string{"/test.php"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/test.php", RawQuery: ""}}},
		{name: "rel-php-2", args: args{[]string{"test.php"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/test.php", RawQuery: ""}}},
		{name: "rel-url-query-string", args: args{[]string{"/sitemap?test"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap", RawQuery: "test"}}},
		{name: "rel-url-query-string-fragment", args: args{[]string{"/sitemap?test#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap", RawQuery: "test", Fragment: "frag"}}},
		{name: "rel-url-fragment", args: args{[]string{"/sitemap#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap", Fragment: "frag"}}},
		{name: "rel-query-1", args: args{[]string{"/?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/", RawQuery: "test=1"}}},
		{name: "rel-query-2", args: args{[]string{"?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php", RawQuery: "test=1"}}},
		{name: "rel-query-string-fragment", args: args{[]string{"?test#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "", RawQuery: "test", Fragment: "frag"}}},
		{name: "rel-query-string", args: args{[]string{"?test"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "", RawQuery: "test", Fragment: ""}}},
		{name: "rel-php-query-1", args: args{[]string{"/test.php?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/test.php", RawQuery: "test=1"}}},
		{name: "rel-php-query-2", args: args{[]string{"test.php?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/test.php", RawQuery: "test=1"}}},
		{name: "rel-query-port-1", args: args{[]string{"/?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com:443", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com:443", Path: "/", RawQuery: "test=1"}}},
		{name: "rel-query-port-2", args: args{[]string{"?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com:443", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com:443", Path: "", RawQuery: "test=1"}}},
		{name: "rel-url-query-port", args: args{[]string{"/asdf/?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com:443", Path: "/test"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com:443", Path: "/asdf/", RawQuery: "test=1"}}},
		{name: "rel-fragment-1", args: args{[]string{"/#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/", RawQuery: "", Fragment: "frag"}}},
		{name: "rel-fragment-2", args: args{[]string{"#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php", RawQuery: "", Fragment: "frag"}}},
		{name: "abs-url-1", args: args{[]string{"https://test.domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap"}}},
		{name: "abs-url-2", args: args{[]string{"https://test.domain.com/sitemap/"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap/"}}},

		// On absolute URLs the reference URL should be ignored
		{name: "abs-php-other-reference", args: args{[]string{"https://some.other-domain.com/test.php"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: ""}}},
		{name: "abs-php-query-other-reference", args: args{[]string{"https://some.other-domain.com/test.php?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: "test=1"}}},
		{name: "abs-fragment-other-reference", args: args{[]string{"https://some.other-domain.com/test.php#tag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: "", Fragment: "tag"}}},
		{name: "abs-query-fragment-other-reference", args: args{[]string{"https://some.other-domain.com/test.php?test=1#tag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: "test=1", Fragment: "tag"}}},
		{name: "abs-url-other-reference-1", args: args{[]string{"https://some.other-domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap"}}},
		{name: "abs-url-other-reference-2", args: args{[]string{"https://some.other-domain.com/sitemap/"}, &url.URL{Scheme: "http", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap/"}}},
		{name: "abs-url-other-reference-3", args: args{[]string{"https://some.other-domain.com/sitemap/?test#frag"}, &url.URL{Scheme: "http", Host: "test.domain.com", Path: ""}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap/", RawQuery: "test", Fragment: "frag"}}},
		{name: "abs-url-other-reference-4", args: args{[]string{"https://some.other-domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "", RawQuery: "test", Fragment: "frag"}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap"}}},
		{name: "abs-url-other-reference-5", args: args{[]string{"https://some.other-domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/home/", RawQuery: "test", Fragment: "frag"}}, want: []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap"}}},

		// Unexpected input
		{name: "unexpected-input-1", args: args{[]string{"name.surname@domain.tld"}, &url.URL{Scheme: "https", Host: "google.com"}}, want: []*url.URL{{Scheme: "https", Host: "google.com", Path: "/name.surname@domain.tld"}}},

		// Parse error -> no result (Such have been observed "in the wild")
		{name: "parse-err-1", args: args{[]string{"“https://www.domain.tld”"}, &url.URL{Scheme: "http", Host: "test.domain.tld:8010"}}, want: []*url.URL{}},
		{name: "parse-err-2", args: args{[]string{"“https://www.domain.tld”"}, &url.URL{Scheme: "http", Host: "test.domain.tld:8010"}}, want: []*url.URL{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linksToAbsoluteUrls(tt.args.links, tt.args.referenceUrl); !reflect.DeepEqual(got, tt.want) {
				if got == nil {
					t.Error("got is nil!")
				}
				t.Errorf("linksToAbsoluteUrls() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_requestImageHash verifies that requestImageHash returns the expected MD5 hash for known favicon images.
func Test_requestImageHash(t *testing.T) {

	// Prepare unit test data
	imgBytes1 := []byte("favicon-test-data-alpha")
	imgBytes2 := []byte("favicon-test-data-beta")
	h1 := md5.Sum(imgBytes1)
	h2 := md5.Sum(imgBytes2)
	wantHash1 := hex.EncodeToString(h1[:])
	wantHash2 := hex.EncodeToString(h2[:])

	// imageServer1/2 respond with image/x-icon and known bytes; noImageServer responds with text/html
	imageServer1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(imgBytes1)
	}))
	t.Cleanup(imageServer1.Close)

	imageServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(imgBytes2)
	}))
	t.Cleanup(imageServer2.Close)

	noImageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	t.Cleanup(noImageServer.Close)

	// Nil proxy so httptest servers are not routed through any corporate proxy
	testRequester := utils.NewRequester(utils.ReuseNone, "", "", "", "", nil, 5*time.Second, utils.InsecureTransportFactory, utils.ClientFactory)

	// Prepare and run test cases
	type args struct {
		requester  *utils.Requester
		requestUrl string
		vhost      string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "image-1",
			args: args{testRequester, imageServer1.URL + "/favicon.ico", ""},
			want: wantHash1,
		},
		{
			name: "image-2",
			args: args{testRequester, imageServer2.URL + "/favicon.ico", ""},
			want: wantHash2,
		},
		{
			name: "no-image-1",
			args: args{testRequester, noImageServer.URL + "/favicon.ico", ""},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestImageHash(tt.args.requester, tt.args.requestUrl, tt.args.vhost); got != tt.want {
				t.Errorf("requestImageHash() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_parseRetryAfter verifies that parseRetryAfter correctly parses integer and HTTP-date Retry-After header values.
func Test_parseRetryAfter(t *testing.T) {

	const httpDateLayout = "Mon, 02 Jan 2006 15:04:05 MST"

	// Prepare and run test cases
	type args struct {
		retryStr string
	}
	tests := []struct {
		name    string
		args    args
		want    uint64
		wantErr bool
	}{
		{
			name:    "int-1",
			args:    args{"120"},
			want:    120,
			wantErr: false,
		},
		{
			name:    "int-2",
			args:    args{"20"},
			want:    20,
			wantErr: false,
		},
		{
			name:    "int-3",
			args:    args{"-12"},
			want:    0,
			wantErr: true,
		},
		{
			name:    "time-1-format-1",
			args:    args{time.Now().UTC().Add(time.Second * 120).Format(httpDateLayout)},
			want:    120,
			wantErr: false,
		},
		{
			name:    "time-1-format-1-2",
			args:    args{time.Now().UTC().Add(time.Second * 20).Format(httpDateLayout)},
			want:    20,
			wantErr: false,
		},
		{
			name:    "time-1-format-1-3",
			args:    args{time.Now().UTC().Add(time.Second * -12).Format(httpDateLayout)},
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("retry-after", tt.args.retryStr)

			after, errAfter := parseRetryAfter(&header)
			if (errAfter != nil) != tt.wantErr {
				t.Errorf("parseRetryAfter() error = '%v', wantErr = '%v'", errAfter, tt.wantErr)
				return
			}

			if after != tt.want {
				t.Errorf("parseRetryAfter() = '%v', want = '%v'", after, tt.want)
				return
			}
		})
	}
}

// Test_parseRetryAfter_NilHeader verifies that parseRetryAfter returns an error when given a nil header pointer.
func Test_parseRetryAfter_NilHeader(t *testing.T) {

	// Verify nil header returns an error and zero duration
	after, errAfter := parseRetryAfter(nil)
	if errAfter == nil {
		t.Errorf("parseRetryAfter() error = nil, want non-nil")
	}
	if after != 0 {
		t.Errorf("parseRetryAfter() = '%v', want = '0'", after)
	}
}

// Test_makeCounter verifies that makeCounter returns sequential values starting at the given offset and is safe for concurrent use.
func Test_makeCounter(t *testing.T) {

	t.Run("sequential", func(t *testing.T) {

		// Verify sequential increments starting from the configured offset
		counter := makeCounter(1)
		for i := int32(1); i <= 5; i++ {
			if got := counter(); got != i {
				t.Errorf("makeCounter() call %d = '%v', want = '%v'", i, got, i)
			}
		}
	})

	t.Run("start-offset", func(t *testing.T) {

		// Verify that the start parameter offsets the first returned value correctly
		counter := makeCounter(10)
		if got := counter(); got != 10 {
			t.Errorf("makeCounter() first call = '%v', want = '10'", got)
		}
		if got := counter(); got != 11 {
			t.Errorf("makeCounter() second call = '%v', want = '11'", got)
		}
	})

	t.Run("concurrent", func(t *testing.T) {

		// Verify that 100 concurrent callers each receive a unique value in [1, 100]
		const goroutines = 100
		counter := makeCounter(1)
		var wg sync.WaitGroup
		results := make([]int32, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = counter()
			}(i)
		}
		wg.Wait()

		// All returned values must be unique and within [1, 100]
		seen := make(map[int32]bool, goroutines)
		for _, v := range results {
			if v < 1 || v > goroutines {
				t.Errorf("makeCounter() concurrent = '%v', want in [1, %d]", v, goroutines)
			}
			if seen[v] {
				t.Errorf("makeCounter() concurrent duplicate value = '%v'", v)
			}
			seen[v] = true
		}
	})
}

// TestCrawler_Test verifies that goroutine panics are caught and handled gracefully without propagating to the parent goroutine.
func TestCrawler_Test(t *testing.T) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Unexpected panic: %s\n%s\n", r, utils.StacktraceIndented("\t"))
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Unexpected panic: %s\n%s\n", r, utils.StacktraceIndented("\t"))
			}
		}()

		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Unexpected panic: %s\n%s\n", r, utils.StacktraceIndented("\t"))
				}
			}()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("Unexpected panic: %s%s\n", r, utils.StacktraceIndented("\t"))
						wg.Done()
					}
				}()

				a := 1
				a -= 1
				_ = 12 / a
				fmt.Println("Executing")
				wg.Done()
			}()
		}()
	}()

	fmt.Println("Waiting")
	wg.Wait()

	fmt.Println("Terminating")

}

// TestCrawler_Crawl verifies that Crawl fetches the entry page, follows links, and returns a completed result.
func TestCrawler_Crawl(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Serve two linked pages to exercise queue(), processResult(), and Crawl()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body><a href="/page2">page2</a></body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>Page 2</body></html>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	srvUrl, errSrvUrl := url.Parse(srv.URL)
	if errSrvUrl != nil {
		t.Fatalf("TestCrawler_Crawl() url.Parse() error = '%v', want = nil", errSrvUrl)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prepare and run test cases
	crawler, errCrawler := NewCrawler(
		testLogger,
		*srvUrl,
		"",
		false,
		2,
		true,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		nil,
		5*time.Second,
		DefaultFollowContentTypes,
		DefaultDownloadContentTypes,
		1,
		ctx,
	)
	if errCrawler != nil {
		t.Fatalf("NewCrawler() error = '%v', want = nil", errCrawler)
	}

	result := crawler.Crawl()

	// Verify crawl completed with pages
	if result == nil {
		t.Fatalf("Crawl() result = nil, want = non-nil")
	}
	if result.Status != utils.StatusCompleted {
		t.Errorf("Crawl() status = '%v', want = '%v'", result.Status, utils.StatusCompleted)
	}
	if len(result.Pages) < 1 {
		t.Errorf("Crawl() pages count = '%v', want >= 1", len(result.Pages))
	}
}

// TestCrawler_Crawl_Timeout verifies that Crawl returns StatusDeadline when the context expires during crawling.
func TestCrawler_Crawl_Timeout(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Slow server to trigger context deadline
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>slow</body></html>`)
	}))
	t.Cleanup(srv.Close)

	srvUrl, errSrvUrl := url.Parse(srv.URL)
	if errSrvUrl != nil {
		t.Fatalf("TestCrawler_Crawl_Timeout() url.Parse() error = '%v', want = nil", errSrvUrl)
	}

	// Context expires almost immediately
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Prepare and run test cases
	crawler, errCrawler := NewCrawler(
		testLogger,
		*srvUrl,
		"",
		false,
		2,
		true,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		nil,
		200*time.Millisecond,
		DefaultFollowContentTypes,
		DefaultDownloadContentTypes,
		1,
		ctx,
	)
	if errCrawler != nil {
		t.Fatalf("NewCrawler() error = '%v', want = nil", errCrawler)
	}

	result := crawler.Crawl()

	// Verify timeout is reported
	if result == nil {
		t.Fatalf("Crawl() result = nil, want = non-nil")
	}
	if result.Status != utils.StatusDeadline {
		t.Errorf("Crawl() status = '%v', want = '%v'", result.Status, utils.StatusDeadline)
	}
}

// TestCrawler_Crawl_Requeue verifies that Crawl retries a child page after a 429 Too Many Requests response.
func TestCrawler_Crawl_Requeue(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Root serves HTML with a link to /child; /child returns 429 on first call then 200 on subsequent calls,
	// exercising the requeue() path (child URL must be known via queue() before requeue() can re-add it)
	var childCallCount int
	var callMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Path != "/child" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><body><a href="/child">child</a></body></html>`)
			return
		}

		callMu.Lock()
		n := childCallCount
		childCallCount++
		callMu.Unlock()

		if n == 0 {
			w.WriteHeader(http.StatusTooManyRequests) // No Retry-After → 200 ms delay
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	t.Cleanup(srv.Close)

	srvUrl, errSrvUrl := url.Parse(srv.URL)
	if errSrvUrl != nil {
		t.Fatalf("TestCrawler_Crawl_Requeue() url.Parse() error = '%v', want = nil", errSrvUrl)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prepare and run test cases
	crawler, errCrawler := NewCrawler(
		testLogger,
		*srvUrl,
		"",
		false,
		1, // depth=1 so root links are followed and /child is queued via queue(), making it requeue()-eligible
		false,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		nil,
		5*time.Second,
		DefaultFollowContentTypes,
		DefaultDownloadContentTypes,
		1,
		ctx,
	)
	if errCrawler != nil {
		t.Fatalf("NewCrawler() error = '%v', want = nil", errCrawler)
	}

	result := crawler.Crawl()

	// Verify crawl completed without exception after retrying the 429
	if result == nil {
		t.Fatalf("Crawl() result = nil, want = non-nil")
	}
	if result.Status != utils.StatusCompleted {
		t.Errorf("Crawl() status = '%v', want = '%v'", result.Status, utils.StatusCompleted)
	}
}

// TestCrawler_Crawl_Download verifies that Crawl records download URLs for responses with download content types.
func TestCrawler_Crawl_Download(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Serve a page linking to a PDF to exercise the download branch in processTask()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body><a href="/doc.pdf">doc</a></body></html>`)
	})
	mux.HandleFunc("/doc.pdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = fmt.Fprint(w, "%PDF-1.4 test")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	srvUrl, errSrvUrl := url.Parse(srv.URL)
	if errSrvUrl != nil {
		t.Fatalf("TestCrawler_Crawl_Download() url.Parse() error = '%v', want = nil", errSrvUrl)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prepare and run test cases
	crawler, errCrawler := NewCrawler(
		testLogger,
		*srvUrl,
		"",
		false,
		2,
		true,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		nil,
		5*time.Second,
		DefaultFollowContentTypes,
		DefaultDownloadContentTypes,
		1,
		ctx,
	)
	if errCrawler != nil {
		t.Fatalf("NewCrawler() error = '%v', want = nil", errCrawler)
	}

	result := crawler.Crawl()

	// Verify PDF URL was discovered as a download
	if result == nil {
		t.Fatalf("Crawl() result = nil, want = non-nil")
	}
	if len(result.DiscoveredDownloads) == 0 {
		t.Errorf("Crawl() DiscoveredDownloads count = '0', want >= 1")
	}
}
