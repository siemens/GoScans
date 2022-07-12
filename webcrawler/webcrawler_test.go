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
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testFile = "test.csv"
const testFolder = "webcraler-test"
const notExistingFile = "notexisting.csv"

func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
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
		{"simple-valid", args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", testProxyStr}, false},
		{"invalid-folder-1", args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", testProxyStr}, false},
		{"invalid-folder-2", args{"domain.tld", filepath.Join(testSettings.PathTmpDir, "notexisting"), false, "", "", "", testProxyStr}, true},
		{"invalid-folder-3", args{"domain.tld", filepath.Join(testSettings.PathTmpDir, "notexisting"), true, "", "", "", testProxyStr}, true},
		{"invalid-credentials-1", args{"domain.tld", testSettings.PathTmpDir, false, "test", "", "", testProxyStr}, true},
		{"invalid-credentials-2", args{"domain.tld", testSettings.PathTmpDir, false, "", "test", "", testProxyStr}, true},
		{"invalid-credentials-3", args{"domain.tld", testSettings.PathTmpDir, false, "", "", "test", testProxyStr}, true},
		{"valid-credentials", args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", testProxyStr}, false},
		{"simple-valid-ip", args{"127.0.0.1", testSettings.PathTmpDir, false, "", "", "", testProxyStr}, false},
		{"simple-invalid-network", args{"192.168.0.1/24", testSettings.PathTmpDir, false, "", "", "", testProxyStr}, true},
		{"invalid-proxy", args{"domain.tld", testSettings.PathTmpDir, false, "", "", "", "invalid-proxy"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initiate webcrawler scanner
			_, err := NewScanner(
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
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanner_SetFollowContentTypes(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
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
			"valid",
			fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "localhost", 80, []string{}, false, 1, true, true, false, "", "", "", "", []string{}, []string{}, false},
			[]string{"1", "2", "3", "4"},
			false,
		},
		{
			"invalid",
			fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "localhost", 80, []string{}, false, 1, true, true, false, "", "", "", "", []string{}, []string{}, true},
			[]string{"1", "2", "3", "4"},
			true,
		},
	}
	for _, tt := range tests {
		// Avoid a nil pointer dereference
		proxy := ""
		if testSettings.HttpProxy != nil {
			proxy = testSettings.HttpProxy.String()
		}

		t.Run(tt.name, func(t *testing.T) {
			s, errNew := NewScanner(
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
			if errNew != nil {
				t.Errorf("Scanner.SetFollowContentTypes() Could not prepare scanner: '%v'", errNew)
				return
			}

			// Set initial state
			s.followTypes = tt.fields.followTypes
			s.downloadTypes = tt.fields.downloadTypes
			s.running = tt.fields.running

			// Execute test
			if err := s.SetFollowContentTypes(tt.responseContentTypes); (err != nil) != tt.wantErr {
				t.Errorf("Scanner.SetFollowContentTypes() error = '%v', wantErr '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestScanner_SetDownloadContentTypes(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
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
			"valid",
			fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "localhost", 80, []string{}, false, 1, true, true, false, testSettings.PathTmpDir, "", "", "", []string{}, []string{}, false},
			[]string{"1", "2", "3", "4"},
			false,
		},
		{
			"invalid",
			fields{"Test", make(chan *Result), time.Now(), time.Now(), testLogger, "localhost", 80, []string{}, false, 1, true, true, false, testSettings.PathTmpDir, "", "", "", []string{}, []string{}, true},
			[]string{"1", "2", "3", "4"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Avoid a nil pointer dereference
			proxy := ""
			if testSettings.HttpProxy != nil {
				proxy = testSettings.HttpProxy.String()
			}

			s, errNew := NewScanner(
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
			if errNew != nil {
				t.Errorf("Scanner.SetFollowContentTypes() Could not prepare scanner: '%v'", errNew)
				return
			}

			// Set initial state
			s.followTypes = tt.fields.followTypes
			s.downloadTypes = tt.fields.downloadTypes
			s.running = tt.fields.running

			// Execute test
			if err := s.SetDownloadContentTypes(tt.responseContentTypes); (err != nil) != tt.wantErr {
				t.Errorf("Scanner.SetDownloadContentTypes() error = '%v', wantErr '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestPrepareHrefsFile(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

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
		{"not-yet-existing", args{testFile, "1;2;3"}, false, "1;2;3\n"},
		{"existing", args{testFile, "4;5;6"}, false, "1;2;3\n"},
		{"folder", args{testSettings.PathTmpDir, "..."}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := prepareHrefsFile(tt.args.filePath, tt.args.header); (err != nil) != tt.wantErr {
				t.Errorf("prepareHrefsFile() error = '%v', wantErr '%v'", err, tt.wantErr)
			} else if !tt.wantErr {
				content, errRead := ioutil.ReadFile(testFile)
				if errRead != nil {
					t.Errorf("prepareHrefsFile() could not read file: '%v'", errRead)
					return
				}
				contentString := string(content)
				if contentString != tt.wantContent {
					t.Errorf("prepareHrefsFile() = '%v', want '%v'", contentString, tt.wantContent)
				}
			}
		})
	}
}

func TestAppendHrefs(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	testFilePath := filepath.Join(testSettings.PathTmpDir, testFile)
	testFolderPath := filepath.Join(testSettings.PathTmpDir, testFolder)
	notExistingFilePath := filepath.Join(testSettings.PathTmpDir, notExistingFile)

	// Create the folder only if it does not exist.
	if _, err := os.Stat(testFolderPath); !os.IsNotExist(err) {
		t.Errorf("The folder '%v' alread exists.", testFolderPath)
		return
	}
	errCreate := os.Mkdir(testFolderPath, os.ModeDir)
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

	// Prepare test variables
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
		{"append-1", args{testFilePath, []*hrefInfo{{[]string{"1", "2", "3"}, "A", time.Now()}}}, false, false, wantHeader + wantA},
		{"append-2", args{testFilePath, []*hrefInfo{{[]string{"4", "5", "6"}, "B", time.Now()}}}, false, false, wantHeader + wantA + wantB},
		{"append-3", args{testFilePath, []*hrefInfo{{[]string{"7", "8", "9"}, "C", time.Now()}}}, false, false, wantHeader + wantA + wantB + wantC},
		{"append-multiple", args{testFilePath, []*hrefInfo{{[]string{"1", "2", "3"}, "A", time.Now()}, {[]string{"4", "5", "6"}, "B", time.Now()}, {[]string{"7", "8", "9"}, "C", time.Now()}}}, false, false, wantHeader + wantA + wantB + wantC + wantA + wantB + wantC},
		{"append-multiple-nil", args{testFilePath, []*hrefInfo{{[]string{"1", "2", "3"}, "A", time.Now()}, {[]string{"4", "5", "6"}, "B", time.Now()}, {[]string{"7", "8", "9"}, "C", time.Now()}}}, false, true, wantHeader + wantA + wantB + wantC + wantA + wantB + wantC + wantA + wantB + wantC},
		{"append-nil", args{testFilePath, nil}, false, true, wantHeader + wantA + wantB + wantC + wantA + wantB + wantC + wantA + wantB + wantC},
		{"create-file", args{notExistingFilePath, []*hrefInfo{{[]string{"x", "y", "z"}, "-", time.Now()}}}, false, false, "Date;URL;Required Host Header\n" + time.Now().Format(testTimestampFormat) + ";x;-\n" + time.Now().Format(testTimestampFormat) + ";y;-\n" + time.Now().Format(testTimestampFormat) + ";z;-\n"},
		{"opening-folder", args{testFolderPath, []*hrefInfo{{[]string{"x", "y", "z"}, "-", time.Now()}}}, true, false, ""},
		{"opening-invalid", args{filepath.Join(testSettings.PathTmpDir, "not/notexisting.csv"), []*hrefInfo{{[]string{"x", "y", "z"}, "-", time.Now()}}}, true, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				appendHrefChan     = make(chan *hrefInfo, 30)
				appendHrefStopChan = make(chan struct{})
				appendHrefErrChan  = make(chan error, 1)
			)

			// Start the worker routine.
			go appendHrefsWorker(
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
					t.Errorf("appendHrefs() error = '%v', wantNilErr '%v'", errAppend, tt.wantNilErr)
					fail = true
					continue
				}
				if (errAppend != nil) != tt.wantErr {
					t.Errorf("appendHrefs() error = '%v', wantErr '%v'", errAppend, tt.wantErr)
					fail = true
					continue
				}
			}

			if fail {
				t.Fail()
			}

			// Check if the data written to the file is correct.
			if !tt.wantErr {
				content, errRead := ioutil.ReadFile(tt.args.filePath)
				if errRead != nil {
					t.Errorf("appendHrefs() could not read file: '%v'", errRead)
					return
				}
				contentString := string(content)
				if contentString != tt.wantContent {
					t.Errorf("appendHrefs() = '%v', want '%v'", contentString, tt.wantContent)
				}
			}
		})
	}
}
