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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

const testFile = "test.csv"               // Test output filename
const testFolder = "webcrawler-test"      // Test working-directory name
const notExistingFile = "notexisting.csv" // Guaranteed-missing test filename

// TestMain initializes the test environment and runs all tests in the webcrawler package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-webcrawler-test-*")
	if errTmpDir != nil {
		panic(errTmpDir)
	}
	if errChdir := os.Chdir(tmpDir); errChdir != nil {
		panic(errChdir)
	}

	// Run tests
	code := m.Run()

	// Prepare cleanup
	_ = os.Chdir("..")
	_ = os.RemoveAll(tmpDir)

	// Return nil as everything went fine
	os.Exit(code)
}

// TestNewScanner verifies that NewScanner returns an error for invalid arguments and succeeds for valid ones.
func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	var testProxyStr string
	if testSettings.HttpProxy != nil {
		testProxyStr = testSettings.HttpProxy.String()
	}
	requestTimeout := 5 * time.Second

	// Prepare and run test cases
	type args struct {
		address      string
		outputFolder string
		download     bool
		adDomain     string
		adUser       string
		adPassword   string
		proxy        string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "simple-valid",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", testProxyStr},
			wantErr: false,
		},
		{
			name:    "invalid-folder-1",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", testProxyStr},
			wantErr: false,
		},
		{
			name:    "invalid-folder-2",
			args:    args{"domain.tld", filepath.Join(testSettings.PathTmpDir, "notexisting"), false, "", "", "", testProxyStr},
			wantErr: true,
		},
		{
			name:    "invalid-folder-3",
			args:    args{"domain.tld", filepath.Join(testSettings.PathTmpDir, "notexisting"), true, "", "", "", testProxyStr},
			wantErr: true,
		},
		{
			name:    "invalid-credentials-1",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "test", "", "", testProxyStr},
			wantErr: true,
		},
		{
			name:    "invalid-credentials-2",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "", "test", "", testProxyStr},
			wantErr: true,
		},
		{
			name:    "invalid-credentials-3",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "", "", "test", testProxyStr},
			wantErr: true,
		},
		{
			name:    "valid-credentials",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", testProxyStr},
			wantErr: false,
		},
		{
			name:    "simple-valid-ip",
			args:    args{"192.0.2.1", testSettings.PathTmpDir, false, "", "", "", testProxyStr},
			wantErr: false,
		},
		{
			name:    "simple-invalid-network",
			args:    args{"192.168.0.1/24", testSettings.PathTmpDir, false, "", "", "", testProxyStr},
			wantErr: true,
		},
		{
			name:    "invalid-proxy",
			args:    args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", "invalid-proxy"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initiate webcrawler scanner
			_, errNewScanner := NewScanner(
				testLogger,
				tt.args.address,
				443,
				[]string{"domain.tld"},
				true,
				4,
				4,
				true,
				true,
				tt.args.download,
				tt.args.outputFolder,
				tt.args.adDomain,
				tt.args.adUser,
				tt.args.adPassword,
				testSettings.HttpUserAgent,
				tt.args.proxy,
				requestTimeout,
			)
			if (errNewScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNewScanner, tt.wantErr)
				return
			}
		})
	}
}

// TestScanner_SetFollowContentTypes verifies that SetFollowContentTypes updates follow content types and rejects changes while running.
func TestScanner_SetFollowContentTypes(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	requestTimeout := 5 * time.Second

	// Prepare and run test cases
	type fields struct {
		Label         string
		ChResults     chan *Result
		Started       time.Time
		Finished      time.Time
		logger        utils.Logger
		target        string
		port          int
		vhosts        []string
		https         bool
		depth         int
		followQS      bool
		storeRoot     bool
		download      bool
		outputFolder  string
		ntlmDomain    string
		ntlmUser      string
		ntlmPassword  string
		followTypes   []string
		downloadTypes []string
		running       bool
	}
	tests := []struct {
		name                 string
		fields               fields
		responseContentTypes []string
		wantErr              bool
	}{
		{
			name:                 "valid",
			fields:               fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "domain.tld", 80, []string{}, false, 1, true, true, false, "", "", "", "", []string{}, []string{}, false},
			responseContentTypes: []string{"1", "2", "3", "4"},
			wantErr:              false,
		},
		{
			name:                 "invalid",
			fields:               fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "domain.tld", 80, []string{}, false, 1, true, true, false, "", "", "", "", []string{}, []string{}, true},
			responseContentTypes: []string{"1", "2", "3", "4"},
			wantErr:              true,
		},
	}
	for _, tt := range tests {
		// Avoid a nil pointer dereference
		proxy := ""
		if testSettings.HttpProxy != nil {
			proxy = testSettings.HttpProxy.String()
		}

		t.Run(tt.name, func(t *testing.T) {
			s, errS := NewScanner(
				tt.fields.logger,
				tt.fields.target,
				tt.fields.port,
				tt.fields.vhosts,
				tt.fields.https,
				tt.fields.depth,
				1,
				tt.fields.followQS,
				tt.fields.storeRoot,
				tt.fields.download,
				tt.fields.outputFolder,
				tt.fields.ntlmDomain,
				tt.fields.ntlmUser,
				tt.fields.ntlmPassword,
				testSettings.HttpUserAgent,
				proxy,
				requestTimeout,
			)
			if errS != nil {
				t.Errorf("Scanner.SetFollowContentTypes() Could not prepare scanner: '%v'", errS)
				return
			}

			// Set initial state
			s.followTypes = tt.fields.followTypes
			s.downloadTypes = tt.fields.downloadTypes
			s.running = tt.fields.running

			// Execute test
			if errSetFollowContentTypes := s.SetFollowContentTypes(tt.responseContentTypes); (errSetFollowContentTypes != nil) != tt.wantErr {
				t.Errorf("Scanner.SetFollowContentTypes() error = '%v', wantErr = '%v'", errSetFollowContentTypes, tt.wantErr)
			}
		})
	}
}

// TestScanner_SetDownloadContentTypes verifies that SetDownloadContentTypes updates download content types and rejects changes while running.
func TestScanner_SetDownloadContentTypes(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	requestTimeout := 5 * time.Second

	// Prepare and run test cases
	type fields struct {
		Label         string
		ChResults     chan *Result
		Started       time.Time
		Finished      time.Time
		logger        utils.Logger
		target        string
		port          int
		vhosts        []string
		https         bool
		depth         int
		followQS      bool
		storeRoot     bool
		download      bool
		outputFolder  string
		ntlmDomain    string
		ntlmUser      string
		ntlmPassword  string
		followTypes   []string
		downloadTypes []string
		running       bool
	}
	tests := []struct {
		name                 string
		fields               fields
		responseContentTypes []string
		wantErr              bool
	}{
		{
			name:                 "valid",
			fields:               fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "domain.tld", 80, []string{}, false, 1, true, true, false, testSettings.PathTmpDir, "", "", "", []string{}, []string{}, false},
			responseContentTypes: []string{"1", "2", "3", "4"},
			wantErr:              false,
		},
		{
			name:                 "invalid",
			fields:               fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "domain.tld", 80, []string{}, false, 1, true, true, false, testSettings.PathTmpDir, "", "", "", []string{}, []string{}, true},
			responseContentTypes: []string{"1", "2", "3", "4"},
			wantErr:              true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Avoid a nil pointer dereference
			proxy := ""
			if testSettings.HttpProxy != nil {
				proxy = testSettings.HttpProxy.String()
			}

			s, errS := NewScanner(
				tt.fields.logger,
				tt.fields.target,
				tt.fields.port,
				tt.fields.vhosts,
				tt.fields.https,
				tt.fields.depth,
				1,
				tt.fields.followQS,
				tt.fields.storeRoot,
				tt.fields.download,
				tt.fields.outputFolder,
				tt.fields.ntlmDomain,
				tt.fields.ntlmUser,
				tt.fields.ntlmPassword,
				testSettings.HttpUserAgent,
				proxy,
				requestTimeout,
			)
			if errS != nil {
				t.Errorf("Scanner.SetFollowContentTypes() Could not prepare scanner: '%v'", errS)
				return
			}

			// Set initial state
			s.followTypes = tt.fields.followTypes
			s.downloadTypes = tt.fields.downloadTypes
			s.running = tt.fields.running

			// Execute test
			if errSetDownloadContentTypes := s.SetDownloadContentTypes(tt.responseContentTypes); (errSetDownloadContentTypes != nil) != tt.wantErr {
				t.Errorf("Scanner.SetDownloadContentTypes() error = '%v', wantErr = '%v'", errSetDownloadContentTypes, tt.wantErr)
			}
		})
	}
}

// TestScanner_SetContext verifies that SetContext sets the inner context on the first call and is a no-op on subsequent calls.
func TestScanner_SetContext(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	s, errS := NewScanner(
		testLogger, "domain.tld", 80, []string{}, false, 1, 1, true, true, false, "",
		"", "", "", testSettings.HttpUserAgent, "", 5*time.Second,
	)
	if errS != nil {
		t.Fatalf("TestScanner_SetContext() setup error = '%v', want = nil", errS)
	}
	ctx1 := context.Background()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	// First call must set the context
	s.SetContext(ctx1)
	if s.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v'", s.contextInner, ctx1)
	}

	// Second call must be a no-op. Context must remain ctx1.
	s.SetContext(ctx2)
	if s.contextInner != ctx1 {
		t.Errorf("SetContext() second call contextInner = '%v', want = '%v'", s.contextInner, ctx1)
	}
}

// TestScanner_vhostResponseKnown verifies that vhostResponseKnown returns an empty string for new fingerprints and the prior vhost name for duplicates.
func TestScanner_vhostResponseKnown(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	s, errS := NewScanner(
		testLogger, "domain.tld", 80, []string{}, false, 1, 1, true, true, false, "",
		"", "", "", testSettings.HttpUserAgent, "", 5*time.Second,
	)
	if errS != nil {
		t.Fatalf("TestScanner_vhostResponseKnown() setup error = '%v', want = nil", errS)
	}
	mockResp := &http.Response{
		StatusCode: 200,
		Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "domain.tld", Path: "/"}},
	}
	body := []byte("<html><head><title>Test</title></head><body>Hello World</body></html>")

	// First call: new fingerprint for vhost-a. Expect empty string (fingerprint was not seen before).
	if got := s.vhostResponseKnown("vhost-a", mockResp, body); got != "" {
		t.Errorf("vhostResponseKnown() first call = '%v', want = ''", got)
	}

	// Second call: same fingerprint but different vhost-b. Expect "vhost-a" (fingerprint is known).
	if got := s.vhostResponseKnown("vhost-b", mockResp, body); got != "vhost-a" {
		t.Errorf("vhostResponseKnown() second call = '%v', want = 'vhost-a'", got)
	}

	// Third call: a different status code produces a distinct fingerprint. Expect empty string (new).
	differentResp := &http.Response{
		StatusCode: 404,
		Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "domain.tld", Path: "/"}},
	}
	if got := s.vhostResponseKnown("vhost-c", differentResp, body); got != "" {
		t.Errorf("vhostResponseKnown() third call = '%v', want = ''", got)
	}
}

// TestPrepareHrefsFile verifies that prepareHrefsFile creates the file with a header when it does not exist, and skips writing when it already exists.
func TestPrepareHrefsFile(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare cleanup
	defer func() { _ = os.Remove(testFile) }()

	// Prepare and run test cases
	type args struct {
		filePath string
		header   string
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantContent string
	}{
		{
			name:        "not-yet-existing",
			args:        args{testFile, "1;2;3"},
			wantErr:     false,
			wantContent: "1;2;3\n",
		},
		{
			name:        "existing",
			args:        args{testFile, "4;5;6"},
			wantErr:     false,
			wantContent: "1;2;3\n",
		},
		{
			name:        "folder",
			args:        args{testSettings.PathTmpDir, "..."},
			wantErr:     true,
			wantContent: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errPrepareHrefsFile := prepareHrefsFile(tt.args.filePath, tt.args.header); (errPrepareHrefsFile != nil) != tt.wantErr {
				t.Errorf("prepareHrefsFile() error = '%v', wantErr = '%v'", errPrepareHrefsFile, tt.wantErr)
			} else if !tt.wantErr {
				content, errContent := os.ReadFile(testFile)
				if errContent != nil {
					t.Errorf("prepareHrefsFile() could not read file: '%v'", errContent)
					return
				}
				contentString := string(content)
				if contentString != tt.wantContent {
					t.Errorf("prepareHrefsFile() = '%v', want = '%v'", contentString, tt.wantContent)
				}
			}
		})
	}
}

// TestAppendHrefs verifies that appendHrefsWorker writes href entries to a CSV file and handles nil entries and folder paths correctly.
func TestAppendHrefs(t *testing.T) {

	// Retrieve test logger
	testLogger := utils.NewTestLogger()

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testFilePath := filepath.Join(testSettings.PathTmpDir, testFile)
	testFolderPath := filepath.Join(testSettings.PathTmpDir, testFolder)
	notExistingFilePath := filepath.Join(testSettings.PathTmpDir, notExistingFile)

	// Remove the folder if it exists from a previous interrupted run, then recreate it.
	_ = os.RemoveAll(testFolderPath)
	errCreate := os.Mkdir(testFolderPath, 0700)
	if errCreate != nil {
		t.Errorf("Could not create folder '%v': '%v'", testFolderPath, errCreate)
		return
	}

	// Prepare cleanup
	defer func() {
		_ = os.Remove(testFilePath)
		_ = os.Remove(testFolderPath)
		_ = os.Remove(notExistingFilePath)
	}()

	// Prepare unit test data
	testTimestampFormat := "2006-01-02"
	errPrepare := prepareHrefsFile(testFilePath, "Date;URL;Required Host Header")
	if errPrepare != nil {
		t.Errorf("appendHrefs() error = Could not prepare test: %v", errPrepare)
		return
	}

	// Some of the wanted output strings
	wantHeader := "Date;URL;Required Host Header\n"
	wantA := time.Now().Format(testTimestampFormat) + ";1;A\n" + time.Now().Format(testTimestampFormat) + ";2;A\n" + time.Now().Format(testTimestampFormat) + ";3;A\n"
	wantB := time.Now().Format(testTimestampFormat) + ";4;B\n" + time.Now().Format(testTimestampFormat) + ";5;B\n" + time.Now().Format(testTimestampFormat) + ";6;B\n"
	wantC := time.Now().Format(testTimestampFormat) + ";7;C\n" + time.Now().Format(testTimestampFormat) + ";8;C\n" + time.Now().Format(testTimestampFormat) + ";9;C\n"

	// Prepare and run test cases
	type args struct {
		filePath string
		info     []*hrefInfo
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantNilErr  bool
		wantContent string
	}{
		// The file does not get reset between tests, that's why the wanted output always grows.
		{
			name:        "append-1",
			args:        args{testFilePath, []*hrefInfo{{[]string{"1", "2", "3"}, "A", time.Now()}}},
			wantErr:     false,
			wantNilErr:  false,
			wantContent: wantHeader + wantA,
		},
		{
			name:        "append-2",
			args:        args{testFilePath, []*hrefInfo{{[]string{"4", "5", "6"}, "B", time.Now()}}},
			wantErr:     false,
			wantNilErr:  false,
			wantContent: wantHeader + wantA + wantB,
		},
		{
			name:        "append-3",
			args:        args{testFilePath, []*hrefInfo{{[]string{"7", "8", "9"}, "C", time.Now()}}},
			wantErr:     false,
			wantNilErr:  false,
			wantContent: wantHeader + wantA + wantB + wantC,
		},
		{
			name:        "append-multiple",
			args:        args{testFilePath, []*hrefInfo{{[]string{"1", "2", "3"}, "A", time.Now()}, {[]string{"4", "5", "6"}, "B", time.Now()}, {[]string{"7", "8", "9"}, "C", time.Now()}}},
			wantErr:     false,
			wantNilErr:  false,
			wantContent: wantHeader + wantA + wantB + wantC + wantA + wantB + wantC,
		},
		{
			name:        "append-multiple-nil",
			args:        args{testFilePath, []*hrefInfo{{[]string{"1", "2", "3"}, "A", time.Now()}, {[]string{"4", "5", "6"}, "B", time.Now()}, {[]string{"7", "8", "9"}, "C", time.Now()}}},
			wantErr:     false,
			wantNilErr:  true,
			wantContent: wantHeader + wantA + wantB + wantC + wantA + wantB + wantC + wantA + wantB + wantC,
		},
		{
			name:        "append-nil",
			args:        args{testFilePath, nil},
			wantErr:     false,
			wantNilErr:  true,
			wantContent: wantHeader + wantA + wantB + wantC + wantA + wantB + wantC + wantA + wantB + wantC,
		},
		{
			name:        "create-file",
			args:        args{notExistingFilePath, []*hrefInfo{{[]string{"x", "y", "z"}, "-", time.Now()}}},
			wantErr:     false,
			wantNilErr:  false,
			wantContent: "Date;URL;Required Host Header\n" + time.Now().Format(testTimestampFormat) + ";x;-\n" + time.Now().Format(testTimestampFormat) + ";y;-\n" + time.Now().Format(testTimestampFormat) + ";z;-\n",
		},
		{
			name:        "opening-folder",
			args:        args{testFolderPath, []*hrefInfo{{[]string{"x", "y", "z"}, "-", time.Now()}}},
			wantErr:     true,
			wantNilErr:  false,
			wantContent: "",
		},
		{
			name:        "opening-invalid",
			args:        args{filepath.Join(testSettings.PathTmpDir, "not/notexisting.csv"), []*hrefInfo{{[]string{"x", "y", "z"}, "-", time.Now()}}},
			wantErr:     true,
			wantNilErr:  false,
			wantContent: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var appendHrefChan = make(chan *hrefInfo, 30)
			var appendHrefStopChan = make(chan struct{})
			var appendHrefErrChan = make(chan error, 1)

			// Start the worker routine.
			go appendHrefsWorker(
				testLogger,
				appendHrefStopChan,
				appendHrefErrChan,
				tt.args.filePath,
				appendHrefChan,
				testTimestampFormat,
			)

			// Append the data - we'll check the errors in the cleanUp function.
			for _, info := range tt.args.info {
				appendHrefChan <- info
			}

			time.Sleep(time.Second)

			// Stop the worker and close the info channel. The error channel will be closed by the worker.
			close(appendHrefStopChan)
			close(appendHrefChan)
			// Check if there are any errors remaining. The channel will be closed by the sender (/worker)
			fail := false
			for errAppend := range appendHrefErrChan {
				if _, ok := errAppend.(*nilInfoErr); ok != tt.wantNilErr {
					t.Errorf("appendHrefs() error = '%v', wantNilErr = '%v'", errAppend, tt.wantNilErr)
					fail = true
					continue
				}
				if (errAppend != nil) != tt.wantErr {
					t.Errorf("appendHrefs() error = '%v', wantErr = '%v'", errAppend, tt.wantErr)
					fail = true
					continue
				}
			}

			if fail {
				t.Fail()
			}

			// Check if the data written to the file is correct.
			if !tt.wantErr {
				content, errContent := os.ReadFile(tt.args.filePath)
				if errContent != nil {
					t.Errorf("appendHrefs() could not read file: '%v'", errContent)
					return
				}
				contentString := string(content)
				if contentString != tt.wantContent {
					t.Errorf("appendHrefs() = '%v', want = '%v'", contentString, tt.wantContent)
				}
			}
		})
	}
}

// TestNilInfoErr_Error verifies that nilInfoErr.Error returns the expected sentinel string.
func TestNilInfoErr_Error(t *testing.T) {

	// Prepare and run test cases
	nilErr := &nilInfoErr{}

	// Verify error message
	if got := nilErr.Error(); got != "received info is nil" {
		t.Errorf("nilInfoErr.Error() = '%v', want = 'received info is nil'", got)
	}
}

// TestScanner_Run verifies that Run executes a full crawl against an httptest server and returns a completed result.
func TestScanner_Run(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Serve a simple HTML page with one link to exercise execute() and processTask()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body><a href="/child">child</a></body></html>`)
	})
	mux.HandleFunc("/child", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>Child page</body></html>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	srvUrl, errSrvUrl := url.Parse(srv.URL)
	if errSrvUrl != nil {
		t.Fatalf("TestScanner_Run() url.Parse() error = '%v', want = nil", errSrvUrl)
	}
	host := srvUrl.Hostname()
	port, errPort := strconv.Atoi(srvUrl.Port())
	if errPort != nil {
		t.Fatalf("TestScanner_Run() port parse error = '%v', want = nil", errPort)
	}

	// Prepare and run test cases
	s, errS := NewScanner(
		testLogger,
		host,
		port,
		[]string{},
		false,
		1,
		1,
		true,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		"",
		5*time.Second,
	)
	if errS != nil {
		t.Fatalf("NewScanner() error = '%v', want = nil", errS)
	}

	// Verify result is non-nil and not an exception
	result := s.Run(30 * time.Second)
	if result == nil {
		t.Fatalf("Run() result = nil, want = non-nil")
	}
	if result.Exception {
		t.Errorf("Run() exception = 'true', want = 'false'")
	}
	if result.Status != utils.StatusCompleted {
		t.Errorf("Run() status = '%v', want = '%v'", result.Status, utils.StatusCompleted)
	}
}

// TestScanner_Run_Timeout verifies that Run returns StatusDeadline when the scan times out before all vhosts are processed.
func TestScanner_Run_Timeout(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Serve a page that stalls long enough for the scan timeout to fire
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>slow</body></html>`)
	}))
	t.Cleanup(srv.Close)

	srvUrl, errSrvUrl := url.Parse(srv.URL)
	if errSrvUrl != nil {
		t.Fatalf("TestScanner_Run_Timeout() url.Parse() error = '%v', want = nil", errSrvUrl)
	}
	host := srvUrl.Hostname()
	port, errPort := strconv.Atoi(srvUrl.Port())
	if errPort != nil {
		t.Fatalf("TestScanner_Run_Timeout() port parse error = '%v', want = nil", errPort)
	}

	// Prepare and run test cases
	s, errS := NewScanner(
		testLogger,
		host,
		port,
		[]string{},
		false,
		0,
		1,
		true,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		"",
		50*time.Millisecond,
	)
	if errS != nil {
		t.Fatalf("NewScanner() error = '%v', want = nil", errS)
	}

	// Verify result returns a non-exception status (timeout or completed)
	result := s.Run(1 * time.Millisecond)
	if result == nil {
		t.Fatalf("Run() result = nil, want = non-nil")
	}
	if result.Exception {
		t.Errorf("Run() exception = 'true', want = 'false'")
	}
}

// TestScanner_Run_NotReachable verifies that Run returns StatusNotReachable when the target cannot be reached.
func TestScanner_Run_NotReachable(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases — point at a port that has no listener
	s, errS := NewScanner(
		testLogger,
		"192.0.2.1",
		9,
		[]string{},
		false,
		0,
		1,
		true,
		true,
		false,
		"",
		"", "", "",
		testSettings.HttpUserAgent,
		"",
		100*time.Millisecond,
	)
	if errS != nil {
		t.Fatalf("NewScanner() error = '%v', want = nil", errS)
	}

	// Verify result indicates unreachable endpoint
	result := s.Run(5 * time.Second)
	if result == nil {
		t.Fatalf("Run() result = nil, want = non-nil")
	}
	if result.Status != utils.StatusNotReachable {
		t.Errorf("Run() status = '%v', want = '%v'", result.Status, utils.StatusNotReachable)
	}
}
