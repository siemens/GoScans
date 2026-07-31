/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package filecrawler

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the filecrawler package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Set expected file permissions on test data — git does not preserve all Unix permission bits,
	// so we explicitly chmod to match the values asserted in the test cases (0770 = "-rwxrwx---").
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")
	testFiles := []string{
		"empty document.docx",
		"empty.txt",
		"file1.txt",
		"file_with_content.txt",
		filepath.Join("folder_with_files", "file_with_content.txt"),
	}
	for _, f := range testFiles {
		_ = os.Chmod(filepath.Join(crawlFolder, f), 0770)
	}

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-filecrawler-test-*")
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

	// Restore original file permissions
	for _, f := range testFiles {
		_ = os.Chmod(filepath.Join(crawlFolder, f), 0644)
	}

	// Return nil as everything went fine
	os.Exit(code)
}

// TestNewCrawler verifies that NewCrawler initialises fields correctly and clamps invalid thread counts.
func TestNewCrawler(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		threads int
		want    int
	}{
		{
			name:    "positive-threads",
			threads: 4,
			want:    4,
		},
		{
			name:    "zero-threads-defaults-to-one",
			threads: 0,
			want:    1,
		},
		{
			name:    "negative-threads-defaults-to-one",
			threads: -5,
			want:    1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify thread count
			c := NewCrawler(utils.NewTestLogger(), -1, nil, nil, time.Time{}, 0, false, tt.threads, context.Background())
			if c.threads != tt.want {
				t.Errorf("NewCrawler() threads = '%d', want = '%d'", c.threads, tt.want)
			}
		})
	}
}

// TestCrawler_processFolder verifies that processFolder correctly enumerates files and subdirectories.
func TestCrawler_processFolder(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Prepare and run test cases
	type fields struct {
		crawlDepth      int
		excludedFolders map[string]struct{}
	}
	type args struct {
		folderTask *task
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantNewTasks []*task
		wantReadable bool
		wantResult   *File
	}{
		{
			name: "normal",
			fields: fields{
				crawlDepth:      -1,
				excludedFolders: nil,
			},
			args: args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			wantNewTasks: []*task{
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "empty document.docx"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "empty.txt"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "file1.txt"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "file_with_content.txt"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "folder_with_files"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      true,
				},
			},
			wantReadable: true,
			wantResult:   nil,
		},
		{
			name: "excluded-folder",
			fields: fields{
				crawlDepth:      -1,
				excludedFolders: map[string]struct{}{"filecrawler": {}},
			},
			args: args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			wantNewTasks: nil,
			wantReadable: false,
			wantResult:   nil,
		},
		{
			name: "share-folder-not-excluded",
			fields: fields{
				crawlDepth:      -1,
				excludedFolders: map[string]struct{}{"filecrawler": {}},
			},
			args: args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: true, // share folders bypass the exclusion list
					depth:         0,
					share:         "folder1",
				},
			},
			wantNewTasks: []*task{
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "empty document.docx"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "empty.txt"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "file1.txt"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "file_with_content.txt"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      false,
				},
				{
					share:         "folder1",
					path:          filepath.Join(crawlFolder, "folder_with_files"),
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         1,
					isFolder:      true,
				},
			},
			wantReadable: true,
			wantResult:   nil,
		},
		{
			name: "crawl-depth-exceeded",
			fields: fields{
				crawlDepth:      0,
				excludedFolders: nil,
			},
			args: args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			wantNewTasks: nil,
			wantReadable: false,
			wantResult:   nil,
		},
		{
			name: "nonexistent-path",
			fields: fields{
				crawlDepth:      -1,
				excludedFolders: nil,
			},
			args: args{
				folderTask: &task{
					isFolder:      true,
					path:          "/does/not/exist/folder",
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			wantNewTasks: nil,
			wantReadable: false,
			wantResult:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), tt.fields.crawlDepth, tt.fields.excludedFolders, nil, time.Time{}, 0, false, 0, context.Background())
			var chProcessResults = make(chan *processResult)
			go c.processFolder(tt.args.folderTask, 0, chProcessResults)
			procRes := <-chProcessResults
			if !reflect.DeepEqual(procRes.newTasks, tt.wantNewTasks) {
				t.Errorf("Crawler.processFolder() newTasks = '%v', want = '%v'", procRes.newTasks, tt.wantNewTasks)
			}
			if !reflect.DeepEqual(procRes.isReadableDir, tt.wantReadable) {
				t.Errorf("Crawler.processFolder() isReadableDir = '%v', want = '%v'", procRes.isReadableDir, tt.wantReadable)
			}
			if !reflect.DeepEqual(procRes.data, tt.wantResult) {
				t.Errorf("Crawler.processFolder() data = '%v', want = '%v'", procRes.data, tt.wantResult)
			}
		})
	}
}

// TestGetCustomProperties verifies that getCustomProperties extracts expected metadata from Office document files.
func TestGetCustomProperties(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Prepare and run test cases
	type args struct {
		filepath string
		logger   utils.Logger
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name:    "all-value-types",
			args:    args{filepath.Join(crawlFolder, "empty document.docx"), utils.NewTestLogger()},
			want:    []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
			wantErr: false,
		},
		{
			name:    "not-a-zip",
			args:    args{filepath.Join(crawlFolder, "file_with_content.txt"), utils.NewTestLogger()},
			want:    []string{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := getCustomProperties(tt.args.filepath, tt.args.logger)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("getCustomProperties() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCustomProperties() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestGetOOXMLProperties verifies that getOOXMLProperties parses OOXML metadata correctly across file types.
func TestGetOOXMLProperties(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Create a minimal zip file without docProps/custom.xml to test the no-custom-xml path
	zipNoCustomPath, errZipNoCustomPath := filepath.Abs("no-custom-props.zip")
	if errZipNoCustomPath != nil {
		t.Fatalf("TestGetOOXMLProperties setup error = '%v'", errZipNoCustomPath)
	}
	func() {
		f, errF := os.Create(zipNoCustomPath)
		if errF != nil {
			t.Fatalf("TestGetOOXMLProperties could not create test zip: '%v'", errF)
		}
		defer func() { _ = f.Close() }()
		w := zip.NewWriter(f)
		defer func() { _ = w.Close() }()
		fw, errFw := w.Create("word/document.xml")
		if errFw != nil {
			t.Fatalf("TestGetOOXMLProperties could not write zip entry: '%v'", errFw)
		}
		_, errWrite := fw.Write([]byte("<doc/>"))
		if errWrite != nil {
			t.Fatalf("TestGetOOXMLProperties could not write zip content: '%v'", errWrite)
		}
	}()
	defer func() { _ = os.Remove(zipNoCustomPath) }()

	// Prepare and run test cases
	type args struct {
		filepath string
		logger   utils.Logger
	}
	tests := []struct {
		name    string
		args    args
		want    *OOXMLProperties
		wantErr bool
	}{
		{
			name:    "valid-docx-with-custom-xml",
			args:    args{filepath.Join(crawlFolder, "empty document.docx"), utils.NewTestLogger()},
			want:    nil, // non-nil result is verified indirectly via TestGetCustomProperties
			wantErr: false,
		},
		{
			name:    "not-a-zip",
			args:    args{filepath.Join(crawlFolder, "file_with_content.txt"), utils.NewTestLogger()},
			want:    &OOXMLProperties{},
			wantErr: false,
		},
		{
			name:    "zip-without-custom-xml",
			args:    args{zipNoCustomPath, utils.NewTestLogger()},
			want:    &OOXMLProperties{},
			wantErr: false,
		},
		{
			name:    "nonexistent-file",
			args:    args{"/does/not/exist/file.docx", utils.NewTestLogger()},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := getOOXMLProperties(tt.args.filepath, tt.args.logger)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("getOOXMLProperties() error = '%v', want = '%v'", errGot, tt.wantErr)
				return
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getOOXMLProperties() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestOOXMLProperty_GetVal verifies that GetVal returns the correct string for each supported property type.
func TestOOXMLProperty_GetVal(t *testing.T) {

	// Prepare test variables
	strVal := "label-value"
	intVal := "-10"
	dateVal := "1970-01-01T10:00:00Z"
	boolVal := "true"
	floatVal := "1.2345"

	// Prepare and run test cases
	tests := []struct {
		name string
		prop OOXMLProperty
		want string
	}{
		{
			name: "string-value",
			prop: OOXMLProperty{ValStr: &strVal},
			want: "label-value",
		},
		{
			name: "int-value",
			prop: OOXMLProperty{ValInt: &intVal},
			want: "-10",
		},
		{
			name: "date-value",
			prop: OOXMLProperty{ValDate: &dateVal},
			want: "1970-01-01T10:00:00Z",
		},
		{
			name: "bool-value",
			prop: OOXMLProperty{ValBool: &boolVal},
			want: "true",
		},
		{
			name: "float-value",
			prop: OOXMLProperty{ValFloat: &floatVal},
			want: "1.2345",
		},
		{
			name: "all-nil",
			prop: OOXMLProperty{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.prop.GetVal()
			if got != tt.want {
				t.Errorf("OOXMLProperty.GetVal() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
