/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package filecrawler

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCrawler_processFolder(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

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
			"normal",
			fields{
				crawlDepth:      -1,
				excludedFolders: nil,
			},
			args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			[]*task{
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
			true,
			nil,
		},
		{
			"excluded folder",
			fields{
				crawlDepth:      -1,
				excludedFolders: map[string]struct{}{"filecrawler": {}},
			},
			args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			nil,
			false,
			nil,
		},
		{
			"crawl depth exceeded",
			fields{
				crawlDepth:      0,
				excludedFolders: nil,
			},
			args{
				folderTask: &task{
					isFolder:      true,
					path:          crawlFolder,
					isInsideDfs:   false,
					isShareFolder: false,
					depth:         0,
					share:         "folder1",
				},
			},
			nil,
			false,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), tt.fields.crawlDepth, tt.fields.excludedFolders, nil, time.Time{}, 0, false, 0, time.Time{})
			var chProcessResults = make(chan *processResult)
			go c.processFolder(tt.args.folderTask, 0, chProcessResults)
			procRes := <-chProcessResults
			if !reflect.DeepEqual(procRes.newTasks, tt.wantNewTasks) {
				t.Errorf("SmbCrawler: processFolder(): gotNewTasks = %v, wantNewTasks = %v", spew.Sdump(procRes.newTasks), spew.Sdump(tt.wantNewTasks))
			}
			if !reflect.DeepEqual(procRes.isReadableDir, tt.wantReadable) {
				t.Errorf("SmbCrawler: processFolder(): got isReadableDir = %v, wantReadable = %v", procRes.isReadableDir, tt.wantReadable)
			}
			if !reflect.DeepEqual(procRes.data, tt.wantResult) {
				t.Errorf("SmbCrawler: processFolder(): got data = %v, wantResult = %v", procRes.data, tt.wantResult)
			}
		})
	}
}

func Test_getCustomProperties(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

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
			"all value types",
			args{filepath.Join(crawlFolder, "empty document.docx"), utils.NewTestLogger()},
			[]string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCustomProperties(tt.args.filepath, tt.args.logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCustomProperties() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCustomProperties() \ngot = %v, \nwant  %v", got, tt.want)
			}
		})
	}
}
