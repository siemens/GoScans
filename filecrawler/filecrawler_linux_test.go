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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestCrawler_Crawl verifies that the crawler correctly traverses directories and returns expected file and folder results.
func TestCrawler_Crawl(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare exceeded context
	ctxExceeded, ctxExceededCancel := context.WithTimeout(context.Background(), -3*time.Second)
	defer ctxExceededCancel()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Prepare and run test cases
	type fields struct {
		crawlDepth                int
		excludedFolders           map[string]struct{}
		excludedExtensions        map[string]struct{}
		excludedLastModifiedBelow time.Time
		excludedFileSizeBelow     int64
		onlyAccessibleFiles       bool
		threads                   int
		context                   context.Context
	}
	type args struct {
		startInfo *EntryPoint
	}
	tests := []struct {
		name                string
		fields              fields
		args                args
		wantFoldersReadable int
		wantFilesReadable   int
		wantFilesWritable   int
		wantFileInfos       []File
		wantStatus          string
		wantException       bool
	}{
		{
			name: "normal",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   1,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "filecrawler",
				IsShare:   true,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   5,
			wantFilesWritable:   5,
			wantFileInfos: []File{
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "empty document.docx"),
					Name:       "empty document.docx",
					Extension:  "docx",
					Mime:       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "empty.txt"),
					Name:       "empty.txt",
					Extension:  "txt",
					Mime:       "text/plain",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     0,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "file1.txt"),
					Name:       "file1.txt",
					Extension:  "txt",
					Mime:       "text/plain",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     0,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "file_with_content.txt"),
					Name:       "file_with_content.txt",
					Extension:  "txt",
					Mime:       "text/csv",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     3,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "folder_with_files", "file_with_content.txt"),
					Name:       "file_with_content.txt",
					Extension:  "txt",
					Mime:       "text/plain; charset=utf-8",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     0,
					Depth:      2,
					IsSymlink:  false,
					Properties: []string{},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "excluded-folders",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           map[string]struct{}{"filecrawler": {}},
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "excluded-extensions",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        map[string]struct{}{"txt": {}},
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   1,
			wantFilesWritable:   1,
			wantFileInfos: []File{
				{
					Path:       filepath.Join(crawlFolder, "empty document.docx"),
					Name:       "empty document.docx",
					Extension:  "docx",
					Mime:       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "excluded-last-modified",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Now(),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "excluded-filesize",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     10,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   1,
			wantFilesWritable:   1,
			wantFileInfos: []File{
				{
					Path:       filepath.Join(crawlFolder, "empty document.docx"),
					Name:       "empty document.docx",
					Extension:  "docx",
					Mime:       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					Readable:   true,
					Writable:   true,
					Flags:      "-rwxrwx---",
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "deadline",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   ctxExceeded,
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusDeadline,
			wantException:       false,
		},
		{
			name: "nil-argument",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{
				startInfo: nil,
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "empty-argument",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{
				startInfo: &EntryPoint{},
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "nonexistent-path",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      "/does/not/exist/folder",
				InsideDfs: false,
				Share:     "nonexistent",
				IsShare:   false,
			}},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), tt.fields.crawlDepth, tt.fields.excludedFolders, tt.fields.excludedExtensions, tt.fields.excludedLastModifiedBelow, tt.fields.excludedFileSizeBelow, tt.fields.onlyAccessibleFiles, tt.fields.threads, tt.fields.context)
			got := c.Crawl(tt.args.startInfo)
			if len(got.Data) != len(tt.wantFileInfos) {
				t.Errorf("Crawler.Crawl() data length = '%v', want = '%v'", len(got.Data), len(tt.wantFileInfos))
				return
			}

			var gotFiles []File
			for i, obj := range got.Data {
				tt.wantFileInfos[i].LastModified = obj.LastModified
				gotFiles = append(gotFiles, *obj)
			}

			if !reflect.DeepEqual(gotFiles, tt.wantFileInfos) {
				t.Errorf("Crawler.Crawl() files = '%v', want = '%v'", gotFiles, tt.wantFileInfos)
			}
			if !reflect.DeepEqual(got.FoldersReadable, tt.wantFoldersReadable) {
				t.Errorf("Crawler.Crawl() foldersReadable = '%v', want = '%v'", got.FoldersReadable, tt.wantFoldersReadable)
			}
			if !reflect.DeepEqual(got.FilesReadable, tt.wantFilesReadable) {
				t.Errorf("Crawler.Crawl() filesReadable = '%v', want = '%v'", got.FilesReadable, tt.wantFilesReadable)
			}
			if !reflect.DeepEqual(got.FilesWritable, tt.wantFilesWritable) {
				t.Errorf("Crawler.Crawl() filesWritable = '%v', want = '%v'", got.FilesWritable, tt.wantFilesWritable)
			}
			if !reflect.DeepEqual(got.Status, tt.wantStatus) {
				t.Errorf("Crawler.Crawl() status = '%v', want = '%v'", got.Status, tt.wantStatus)
			}
			if !reflect.DeepEqual(got.Exception, tt.wantException) {
				t.Errorf("Crawler.Crawl() exception = '%v', want = '%v'", got.Exception, tt.wantException)
			}
		})
	}
}

// TestCrawler_processFile verifies that processFile correctly extracts metadata and content from individual files.
func TestCrawler_processFile(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Create a temporary symlink in the test working directory for the symlink-file test case
	symlinkPath, errSymlinkPath := filepath.Abs("symlink-to-file.txt")
	if errSymlinkPath != nil {
		t.Fatalf("TestCrawler_processFile could not resolve symlink path: '%v'", errSymlinkPath)
	}
	_ = os.Remove(symlinkPath)
	if errSym := os.Symlink(filepath.Join(crawlFolder, "file_with_content.txt"), symlinkPath); errSym != nil {
		t.Fatalf("TestCrawler_processFile could not create symlink: '%v'", errSym)
	}
	defer func() { _ = os.Remove(symlinkPath) }()

	// Prepare and run test cases
	type args struct {
		filePath string
		share    string
		isDFS    bool
		depth    int
	}
	type fields struct {
		excludedExtensions        map[string]struct{}
		excludedLastModifiedBelow time.Time
		excludedFileSizeBelow     int64
		onlyAccessibleFiles       bool
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantResult *File
		wantTasks  []*task
	}{
		{
			name: "average-case",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args: args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: &File{
				Share:           "TestShare",
				Path:            filepath.Join(crawlFolder, "file_with_content.txt"),
				Name:            "file_with_content.txt",
				Extension:       "txt",
				Mime:            "text/csv",
				Readable:        true,
				Writable:        true,
				Flags:           "-rwxrwx---",
				SizeKb:          3,
				LastModified:    time.Time{},
				Depth:           2,
				IsSymlink:       false,
				IsDfs:           false,
				NfsRestrictions: nil,
				Properties:      []string{},
			},
			wantTasks: nil,
		},
		{
			name: "excluded-extensions",
			fields: fields{
				excludedExtensions:        map[string]struct{}{"txt": {}},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args:       args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "excluded-last-modified",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Now(),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args:       args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "excluded-file-size-below",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     4,
				onlyAccessibleFiles:       true,
			},
			args:       args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "nonexistent-path",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
			},
			args:       args{"/does/not/exist/file.txt", "TestShare", false, 1},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "symlink-file",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
			},
			args: args{symlinkPath, "TestShare", false, 1},
			wantResult: &File{
				Share:           "TestShare",
				Path:            symlinkPath,
				Name:            "symlink-to-file.txt",
				Extension:       "txt",
				Mime:            "",
				Readable:        true,
				Writable:        true,
				Flags:           "Lrwxrwxrwx",
				SizeKb:          0,
				Depth:           1,
				IsSymlink:       true,
				IsDfs:           false,
				NfsRestrictions: nil,
				Properties:      nil,
			},
			wantTasks: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), 0, nil, tt.fields.excludedExtensions, tt.fields.excludedLastModifiedBelow, tt.fields.excludedFileSizeBelow, tt.fields.onlyAccessibleFiles, 0, context.Background())
			var chProcessResults = make(chan *processResult)
			go c.processFile(&task{
				isFolder:      false,
				path:          tt.args.filePath,
				isInsideDfs:   false,
				isShareFolder: false,
				depth:         tt.args.depth,
				share:         "TestShare",
			}, 0, chProcessResults)
			procRes := <-chProcessResults

			if tt.wantResult != nil && procRes.data != nil {
				tt.wantResult.LastModified = procRes.data.LastModified
			}

			if !reflect.DeepEqual(procRes.data, tt.wantResult) {
				t.Errorf("Crawler.processFile() data = '%v', want = '%v'", procRes.data, tt.wantResult)
			}
			if !reflect.DeepEqual(procRes.newTasks, tt.wantTasks) {
				t.Errorf("Crawler.processFile() newTasks = '%v', want = '%v'", procRes.newTasks, tt.wantTasks)
			}
		})
	}
}

// TestCrawler_Crawl_SymlinkLoop verifies that a self-referential symlink loop terminates via crawlDepth or context deadline and never causes unbounded traversal.
func TestCrawler_Crawl_SymlinkLoop(t *testing.T) {

	tests := []struct {
		name            string
		crawlDepth      int
		useDeadlineCtx  bool          // when true, build a context.WithTimeout per test run (cannot share across runs)
		deadline        time.Duration // only meaningful when useDeadlineCtx is true
		wantStatus      string
		wantException   bool
		wantFolders     int
		wantDataEntries int
	}{
		{
			name:            "symlink-loop",
			crawlDepth:      5,
			useDeadlineCtx:  false,
			wantStatus:      utils.StatusCompleted,
			wantException:   false,
			wantFolders:     1, // only the base dir is traversed; the loop entry is a symlink (not a folder)
			wantDataEntries: 1, // the symlink reported once with IsSymlink=true
		},
		{
			name:            "symlink-loop-deep",
			crawlDepth:      -1, // unlimited — termination relies on the symlink-not-a-folder guard, deadline is the safety net
			useDeadlineCtx:  true,
			deadline:        2 * time.Second,
			wantStatus:      utils.StatusCompleted,
			wantException:   false,
			wantFolders:     1,
			wantDataEntries: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Build a fresh cyclic symlink tree per sub-test under t.TempDir() (auto-cleaned).
			base := t.TempDir()
			loop := filepath.Join(base, "loop")
			if errSymlink := os.Symlink(base, loop); errSymlink != nil {
				t.Fatalf("failed to create self-referential symlink %s -> %s: %v", loop, base, errSymlink)
			}

			// Build the context for this sub-test (deadline contexts must not be shared across iterations).
			ctx := context.Background()
			if tt.useDeadlineCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), tt.deadline)
				defer cancel()
			}

			// Wall-clock guard: even if the crawler loops AND ignores the context (worst-case regression),
			// fail the test rather than hang the whole `go test` run. 10s is generous vs. the 2s deadline.
			done := make(chan *Result, 1)
			go func() {
				c := NewCrawler(utils.NewTestLogger(), tt.crawlDepth, nil, nil, time.Time{}, 0, false, 1, ctx)
				done <- c.Crawl(&EntryPoint{
					Path:    base,
					Share:   "filecrawler",
					IsShare: true,
				})
			}()

			var got *Result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("Crawl did not terminate within 10s on cyclic symlink %s -> %s (depth=%d) — likely unbounded traversal", loop, base, tt.crawlDepth)
			}

			if got.Status != tt.wantStatus {
				t.Errorf("Crawler.Crawl() Status = '%v', want = '%v'", got.Status, tt.wantStatus)
			}
			if got.Exception != tt.wantException {
				t.Errorf("Crawler.Crawl() Exception = '%v', want = '%v'", got.Exception, tt.wantException)
			}
			if got.FoldersReadable != tt.wantFolders {
				t.Errorf("Crawler.Crawl() FoldersReadable = '%v', want = '%v' (Data=%s)", got.FoldersReadable, tt.wantFolders, spew.Sdump(got.Data))
			}
			if len(got.Data) != tt.wantDataEntries {
				t.Errorf("Crawler.Crawl() len(Data) = '%v', want = '%v' (Data=%s)", len(got.Data), tt.wantDataEntries, spew.Sdump(got.Data))
			}
			if len(got.Data) >= 1 {
				if !got.Data[0].IsSymlink {
					t.Errorf("Crawler.Crawl() Data[0].IsSymlink = '%v', want = '%v' (entry=%v)", got.Data[0].IsSymlink, true, got.Data[0])
				}
				if got.Data[0].Path != loop {
					t.Errorf("Crawler.Crawl() Data[0].Path = '%v', want = '%v'", got.Data[0].Path, loop)
				}
			}
		})
	}
}
