/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webcrawler

import (
	"bytes"
	"github.com/PuerkitoBio/goquery"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func Test_NewCrawler(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	timeout := 10 * time.Second

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
		deadline       time.Time
		followTypes    []string
		downloadTypes  []string
		maxThreads     int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid-basic", args{testLogger, "https://www.google.com:80", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, time.Now().Add(timeout), DefaultFollowContentTypes, DefaultDownloadContentTypes, 4}, false},
		{"negative-threads", args{testLogger, "https://www.google.com", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, time.Now().Add(timeout), DefaultFollowContentTypes, DefaultDownloadContentTypes, -3}, false},
		{"invalid-target", args{testLogger, "https://notexisting1234567890qayxsw.com", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, time.Now().Add(timeout), DefaultFollowContentTypes, DefaultDownloadContentTypes, 4}, true},
		{"no-content-types", args{testLogger, "https://www.google.com:80", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, time.Now().Add(timeout), []string{}, []string{}, 4}, false},
		{"not-http-or-https", args{testLogger, "www.google.com:80", "", true, 2, true, true, false, "", "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second * 8, time.Now().Add(timeout), []string{}, []string{}, 4}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, errParse := url.Parse(tt.args.baseUrl)
			if errParse != nil {
				t.Errorf("NewCrawler() Could not parse URL.")
			} else {
				_, err := NewCrawler(
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
					tt.args.deadline,
				)
				if (err != nil) != tt.wantErr {
					t.Errorf("NewCrawler() error = '%v', wantErr '%v'", err, tt.wantErr)
					return
				}
			}
		})
	}
}

func Test_sortQueue(t *testing.T) {

	// The IDs have no effekt on the sorting.
	want := []*task{
		{1, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/"}, Depth: 0}},
		{42, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi"}, Depth: 1}},
		{2, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/inde"}, Depth: 1}},
		{0, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/logi"}, Depth: 1}},
		{5, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
		{7, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
		{11, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 1}},
		{16, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/url"}, Depth: 1}},
		{3, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop"}, Depth: 2}},
		{4, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 2}},
		{22, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf"}, Depth: 2}},
		{30, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf/"}, Depth: 2}},
	}
	tests := []struct {
		name  string
		tasks []*task
	}{
		{
			"disorder-1",
			[]*task{
				{22, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf/"}, Depth: 2}},
				{11, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 2}},
				{2, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/inde"}, Depth: 1}},
				{1, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/"}, Depth: 0}},
				{0, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/logi"}, Depth: 1}},
				{5, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
				{42, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi"}, Depth: 1}},
				{3, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop"}, Depth: 2}},
				{4, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/"}, Depth: 1}},
				{16, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/some/subb/url"}, Depth: 1}},
				{7, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/home"}, Depth: 1}},
				{30, &Page{Url: &url.URL{Scheme: "https", Host: "domain.tld", Path: "/admi/stop/asfdasfasdf"}, Depth: 2}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortQueue(tt.tasks)

			if len(tt.tasks) != len(want) {
				t.Errorf("sortQueue() Result length = '%v', want '%v'", len(tt.tasks), len(want))
				return
			}

			for i := 0; i < len(tt.tasks); i++ {
				if tt.tasks[i].page.Url != want[i].page.Url {
					gotStr := ""
					for _, item := range tt.tasks {
						gotStr += item.page.Url.String() + "\n"
					}
					wantStr := ""
					for _, item := range want {
						wantStr += item.page.Url.String() + "\n"
					}
					if gotStr != wantStr {
						t.Errorf("sortQueue() = '%v', want '%v'", gotStr, wantStr)
						return
					}
				}
			}
		})
	}
}

func Test_extractLinks(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	sampleHtml := filepath.Join(testSettings.PathDataDir, "webcrawler", "sample.html")

	// Prepare and run test cases
	tests := []struct {
		name      string
		inputFile string
		want      []string
	}{
		{"sample", sampleHtml, []string{"/", "/scanning/monitor/", "/inventory/progress/", "/software/firmware/", "/statistics/year/", "/pentestor/hashcat/", "/profile/", "/voucher/generate/", "/admin/", "/logout/", "/toggle_admin_privileges/top/", "/toggle_fy_filter/top/", "/toggle_class_filter/top/", "/toggle_wiped_filter/anchor_jobs/", "/toggle_fy_filter/anchor_jobs/", "/toggle_class_filter/anchor_jobs/", "/toggle_wiped_filter/anchor_jobs_continuing/", "/toggle_fy_filter/anchor_jobs_continuing/", "/toggle_class_filter/anchor_jobs_continuing/", "/toggle_we_filter/anchor_last_logins/", "/toggle_class_filter/anchor_history/", "/toggle_we_filter/anchor_distribution/", "/toggle_fy_filter/anchor_distribution/", "/toggle_class_filter/anchor_distribution/", "https://www.domain.tld/service1/", "https://www.domain.tld/service2/", "https://www.domain.tld/service3/", "https://www.domain.tld/service4/", "https://www.domain.tld/service5/", "https://www.domain2.tld/1", "https://www.domain2.tld/2", "https://www.domain2.tld/3", "https://www.domain3.tld/1", "/voucher/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare IO reader
			stream, errorOpen := os.Open(tt.inputFile)
			if errorOpen != nil {
				t.Errorf("extractLinks() Could not read input file")
				return
			}

			// Parse HTLM doc from IO reader
			doc, errParse := goquery.NewDocumentFromReader(stream)
			if errParse != nil {
				t.Errorf("extractLinks() Could not parse input file")
				return
			}

			// Extract links
			if got := extractLinks(doc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractLinks() = \n 	 '%v',\n want'%v'", got, tt.want)
			}
		})
	}
}

func Test_extractRedirects(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	sampleHtmlRedirect := filepath.Join(testSettings.PathDataDir, "webcrawler", "sample_redirect.html")

	// Prepare and run test cases
	tests := []struct {
		name      string
		inputFile string
		want      []string
	}{
		{"sample", sampleHtmlRedirect, []string{"http://www.google.de/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare IO reader
			stream, errorOpen := os.Open(tt.inputFile)
			if errorOpen != nil {
				t.Errorf("extractRedirects() Could not read input file")
				return
			}

			// Parse HTLM doc from IO reader
			doc, errParse := goquery.NewDocumentFromReader(stream)
			if errParse != nil {
				t.Errorf("extractRedirects() Could not parse input file")
				return
			}

			// Extract links
			if got := extractRedirects(doc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractRedirects() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

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
		{"rel-url-1", args{[]string{"/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap"}}},
		{"rel-url-2", args{[]string{"/sitemap/"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap/"}}},
		{"rel-url-3", args{[]string{"/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/home"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap"}}},
		{"rel-php-1", args{[]string{"/test.php"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/test.php", RawQuery: ""}}},
		{"rel-php-2", args{[]string{"test.php"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/test.php", RawQuery: ""}}},
		{"rel-url-query-string", args{[]string{"/sitemap?test"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap", RawQuery: "test"}}},
		{"rel-url-query-string-fragment", args{[]string{"/sitemap?test#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap", RawQuery: "test", Fragment: "frag"}}},
		{"rel-url-fragment", args{[]string{"/sitemap#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap", Fragment: "frag"}}},
		{"rel-query-1", args{[]string{"/?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/", RawQuery: "test=1"}}},
		{"rel-query-2", args{[]string{"?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php", RawQuery: "test=1"}}},
		{"rel-query-string-fragment", args{[]string{"?test#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "", RawQuery: "test", Fragment: "frag"}}},
		{"rel-query-string", args{[]string{"?test"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "", RawQuery: "test", Fragment: ""}}},
		{"rel-php-query-1", args{[]string{"/test.php?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/test.php", RawQuery: "test=1"}}},
		{"rel-php-query-2", args{[]string{"test.php?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/test.php", RawQuery: "test=1"}}},
		{"rel-query-port-1", args{[]string{"/?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com:443", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com:443", Path: "/", RawQuery: "test=1"}}},
		{"rel-query-port-2", args{[]string{"?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com:443", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com:443", Path: "", RawQuery: "test=1"}}},
		{"rel-url-query-port", args{[]string{"/asdf/?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com:443", Path: "/test"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com:443", Path: "/asdf/", RawQuery: "test=1"}}},
		{"rel-fragment-1", args{[]string{"/#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/", RawQuery: "", Fragment: "frag"}}},
		{"rel-fragment-2", args{[]string{"#frag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php", RawQuery: "", Fragment: "frag"}}},
		{"abs-url-1", args{[]string{"https://test.domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap"}}},
		{"abs-url-2", args{[]string{"https://test.domain.com/sitemap/"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "test.domain.com", Path: "/sitemap/"}}},

		// On absolute URLs the reference URL should be ignored
		{"abs-php-other-reference", args{[]string{"https://some.other-domain.com/test.php"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: ""}}},
		{"abs-php-query-other-reference", args{[]string{"https://some.other-domain.com/test.php?test=1"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: "test=1"}}},
		{"abs-fragment-other-reference", args{[]string{"https://some.other-domain.com/test.php#tag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: "", Fragment: "tag"}}},
		{"abs-query-fragment-other-reference", args{[]string{"https://some.other-domain.com/test.php?test=1#tag"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/app/index.php"}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/test.php", RawQuery: "test=1", Fragment: "tag"}}},
		{"abs-url-other-reference-1", args{[]string{"https://some.other-domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap"}}},
		{"abs-url-other-reference-2", args{[]string{"https://some.other-domain.com/sitemap/"}, &url.URL{Scheme: "http", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap/"}}},
		{"abs-url-other-reference-3", args{[]string{"https://some.other-domain.com/sitemap/?test#frag"}, &url.URL{Scheme: "http", Host: "test.domain.com", Path: ""}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap/", RawQuery: "test", Fragment: "frag"}}},
		{"abs-url-other-reference-4", args{[]string{"https://some.other-domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "", RawQuery: "test", Fragment: "frag"}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap"}}},
		{"abs-url-other-reference-5", args{[]string{"https://some.other-domain.com/sitemap"}, &url.URL{Scheme: "https", Host: "test.domain.com", Path: "/home/", RawQuery: "test", Fragment: "frag"}}, []*url.URL{{Scheme: "https", Host: "some.other-domain.com", Path: "/sitemap"}}},

		// Unexpected input
		{"unexpected-input-1", args{[]string{"name.surname@domain.tld"}, &url.URL{Scheme: "https", Host: "google.com"}}, []*url.URL{{Scheme: "https", Host: "google.com", Path: "/name.surname@domain.tld"}}},

		// Parse error -> no result (Such have been observed "in the wild")
		{"parse-err-1", args{[]string{"“https://www.domain.tld“"}, &url.URL{Scheme: "http", Host: "test.domain.tld:8010"}}, []*url.URL{}},
		{"parse-err-2", args{[]string{"“https://www.domain.tld”"}, &url.URL{Scheme: "http", Host: "test.domain.tld:8010"}}, []*url.URL{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linksToAbsoluteUrls(tt.args.links, tt.args.referenceUrl); !reflect.DeepEqual(got, tt.want) {
				if got == nil {
					t.Error("got is nil!")
				}
				t.Errorf("linksToAbsoluteUrls() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func Test_requestImageHash(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	testRequester := utils.NewRequester(utils.ReuseNone, testSettings.HttpUserAgent, "", "", "", testSettings.HttpProxy, time.Minute, utils.InsecureTransportFactory, utils.ClientFactory)

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
		{"image-1", args{testRequester, "https://www.google.com/favicon.ico", "www.google.com"}, "8b92fa949c5562303273e59227f1e41c"},
		{"image-2", args{testRequester, "https://www.amazon.com/favicon.ico", "www.amazon.com"}, "7c444d71f48980ca76f2c33b23c8bbe1"},
		{"no-image-1", args{testRequester, "https://domain.tld/favicon.ico", ""}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestImageHash(tt.args.requester, tt.args.requestUrl, tt.args.vhost); got != tt.want {
				t.Errorf("requestImageHash() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

func Test_streamToFile(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	testContent := "teststream"

	// Prepare and run test cases
	type args struct {
		outputFolder string
		outputName   string
	}
	tests := []struct {
		name       string
		args       args
		testOutput string
		wantErr    bool
	}{
		{"simple", args{testSettings.PathTmpDir, "output.txt"}, testContent, false},
		{"complex", args{testSettings.PathTmpDir, "!\"§$%&/(()=?`*'_:;><,.-#+´ß0987654321^°|~\\}][{³²µ'`).txt"}, testContent, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oName := utils.SanitizeFilename(tt.args.outputName, "_")
			p := filepath.Join(testSettings.PathTmpDir, oName)
			source := bytes.NewReader([]byte(testContent))
			if err := streamToFile(source, tt.args.outputFolder, oName); (err != nil) != tt.wantErr {
				t.Errorf("streamToFile() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}
			content, errRead := ioutil.ReadFile(p)
			if errRead != nil {
				t.Errorf("streamToFile() errRead: Could not read output file")
				return
			}
			if string(content) != testContent {
				t.Errorf("streamToFile() = '%v', wantOutput '%v'", string(content), tt.testOutput)
				return
			}
			_ = os.Remove(p)
		})
	}
}

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
		{"int-1", args{"120"}, 120, false},
		{"int-2", args{"20"}, 20, false},
		{"int-3", args{"-12"}, 0, true},
		{"time-1-format-1", args{time.Now().Add(time.Second * 120).Format(httpDateLayout)}, 120, false},
		{"time-1-format-1", args{time.Now().Add(time.Second * 20).Format(httpDateLayout)}, 20, false},
		{"time-1-format-1", args{time.Now().Add(time.Second * -12).Format(httpDateLayout)}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("retry-after", tt.args.retryStr)

			after, errParse := parseRetryAfter(&header)
			if (errParse != nil) != tt.wantErr {
				t.Errorf("parseRetryAfter() error = '%v', wantErr '%v'", errParse, tt.wantErr)
				return
			}

			if after != tt.want {
				t.Errorf("parseRetryAfter() = '%v', want '%v'", after, tt.want)
				return
			}
		})
	}
}
