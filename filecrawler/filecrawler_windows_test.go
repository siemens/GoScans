package filecrawler

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/go-ole/go-ole"
	"go-scans/_test"
	"go-scans/utils"
	"go-scans/utils/windows_systemcalls"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var PropkeyPerceivedType = windows_systemcalls.PROPERTYKEY{GUID: *ole.NewGUID("28636AA6-953D-11D2-B5D6-00C04FD918D0"), PID: 9}

func TestCrawler_Crawl(t *testing.T) {

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
		crawlDepth                int
		excludedFolders           map[string]struct{}
		excludedExtensions        map[string]struct{}
		excludedLastModifiedBelow time.Time
		excludedFileSizeBelow     int64
		onlyAccessibleFiles       bool
		threads                   int
		deadline                  time.Time
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
				deadline:                  time.Time{},
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
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Enabled: true", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_SetDate: 2020-10-13T15:53:11Z", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Method: Privileged", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Name: unrestricted", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_SiteId: 38ae3bcd-9579-4fd4-adda-b42e1495d55a", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_ActionId: fde5ed73-1903-4bcf-8b1c-686fcb8beabe", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_ContentBits: 0", "Document_Confidentiality: Unrestricted"},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "empty.txt"),
					Name:       "empty.txt",
					Extension:  "txt",
					Mime:       "text/plain; charset=utf-8",
					Readable:   true,
					Writable:   true,
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
					Mime:       "text/plain; charset=utf-8",
					Readable:   true,
					Writable:   true,
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
			name: "excluded folders",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           map[string]struct{}{"filecrawler": {}},
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				deadline:                  time.Time{},
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
			name: "excluded extensions",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        map[string]struct{}{"txt": {}},
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				deadline:                  time.Time{},
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
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Enabled: true", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_SetDate: 2020-10-13T15:53:11Z", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Method: Privileged", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Name: unrestricted", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_SiteId: 38ae3bcd-9579-4fd4-adda-b42e1495d55a", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_ActionId: fde5ed73-1903-4bcf-8b1c-686fcb8beabe", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_ContentBits: 0", "Document_Confidentiality: Unrestricted"},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "excluded last modified",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Now(),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				deadline:                  time.Time{},
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
			name: "excluded filesize",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     10,
				onlyAccessibleFiles:       false,
				threads:                   0,
				deadline:                  time.Time{},
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
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Enabled: true", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_SetDate: 2020-10-13T15:53:11Z", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Method: Privileged", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_Name: unrestricted", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_SiteId: 38ae3bcd-9579-4fd4-adda-b42e1495d55a", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_ActionId: fde5ed73-1903-4bcf-8b1c-686fcb8beabe", "MSIP_Label_6f75f480-7803-4ee9-bb54-84d0635fdbe7_ContentBits: 0", "Document_Confidentiality: Unrestricted"},
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
				deadline:                  time.Now(),
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
			name: "nil argument",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				deadline:                  time.Time{},
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
			name: "empty argument",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				deadline:                  time.Time{},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), tt.fields.crawlDepth, tt.fields.excludedFolders, tt.fields.excludedExtensions, tt.fields.excludedLastModifiedBelow, tt.fields.excludedFileSizeBelow, tt.fields.onlyAccessibleFiles, tt.fields.threads, tt.fields.deadline)
			got := c.Crawl(tt.args.startInfo)
			if len(got.Data) != len(tt.wantFileInfos) {
				t.Errorf("CrawlPath() = %v, \n want (Files)%v", spew.Sdump(got.Data), spew.Sdump(tt.wantFileInfos))
				return
			}

			var gotFiles []File
			for i, obj := range got.Data {
				tt.wantFileInfos[i].LastModified = obj.LastModified
				gotFiles = append(gotFiles, *obj)
			}

			if !reflect.DeepEqual(gotFiles, tt.wantFileInfos) {
				t.Errorf("CrawlPath() = \n%v,\nwant (Files)\n%v", gotFiles, tt.wantFileInfos)
			}
			if !reflect.DeepEqual(got.FoldersReadable, tt.wantFoldersReadable) {
				t.Errorf("CrawlPath() = %v, want %v (FoldersReadable)", got.FoldersReadable, tt.wantFoldersReadable)
			}
			if !reflect.DeepEqual(got.FilesReadable, tt.wantFilesReadable) {
				t.Errorf("CrawlPath() = %v, want %v (FilesReadable)", got.FilesReadable, tt.wantFilesReadable)
			}
			if !reflect.DeepEqual(got.FilesWritable, tt.wantFilesWritable) {
				t.Errorf("CrawlPath() = %v, want %v (FilesWritable)", got.FilesWritable, tt.wantFilesWritable)
			}
			if !reflect.DeepEqual(got.Status, tt.wantStatus) {
				t.Errorf("CrawlPath() = %v, want %v (Status)", got.Status, tt.wantStatus)
			}
			if !reflect.DeepEqual(got.Exception, tt.wantException) {
				t.Errorf("CrawlPath() = %v, want %v (Exception)", got.Exception, tt.wantException)
			}
		})
	}
}

func Test_getFileProperty(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")
	var PropkeyCustomSensitivityLabel = windows_systemcalls.PROPERTYKEY{ // User defined sensitivity property
		GUID: *ole.NewGUID("D5CDD505-2E9C-101B-9397-08002B2CF9AE"),
		PID:  9,
	}

	type args struct {
		filepath    string
		propertyKey windows_systemcalls.PROPERTYKEY
		logger      utils.Logger
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"sensitivity labels string",
			args{
				filepath:    filepath.Join(crawlFolder, "empty document.docx"),
				propertyKey: PropkeyCustomSensitivityLabel,
				logger:      utils.NewTestLogger(),
			},
			"Unrestricted",
			false,
		},
		{"perceived Type int32",
			args{
				filepath:    filepath.Join(crawlFolder, "empty document.docx"),
				propertyKey: PropkeyPerceivedType,
				logger:      utils.NewTestLogger(),
			},
			int32(6),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare test
			errPrepare := prepareCrawling(tt.args.logger)
			if errPrepare != nil {
				t.Errorf("Could not prepare test: %s", errPrepare)
			}

			// Prepare test cleanup
			defer cleanupCrawling()

			// Execute test
			got, err := getFileProperty(tt.args.filepath, tt.args.propertyKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("getFileProperty() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getFileProperty() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCrawler_processFile(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

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
		{"average case",
			fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			&File{
				Share:           "TestShare",
				Path:            filepath.Join(crawlFolder, "file_with_content.txt"),
				Name:            "file_with_content.txt",
				Extension:       "txt",
				Mime:            "text/csv",
				Readable:        true,
				Writable:        true,
				SizeKb:          3,
				LastModified:    time.Time{},
				Depth:           2,
				IsSymlink:       false,
				IsDfs:           false,
				NfsRestrictions: nil,
			},
			nil,
		},
		{"excluded extensions",
			fields{
				excludedExtensions:        map[string]struct{}{"txt": {}},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			nil,
			nil,
		},
		{"excluded last modified",
			fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Now(),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			nil,
			nil,
		},
		{"excluded file size below",
			fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     4,
				onlyAccessibleFiles:       true,
			},
			args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			nil,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), 0, nil, tt.fields.excludedExtensions, tt.fields.excludedLastModifiedBelow, tt.fields.excludedFileSizeBelow, tt.fields.onlyAccessibleFiles, 0, time.Time{})
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
				t.Errorf("SmbCrawler: processFile(): data\n =   %v, \nwant %v", procRes.data, tt.wantResult)
			}
			if !reflect.DeepEqual(procRes.newTasks, tt.wantTasks) {
				t.Errorf("SmbCrawler: processFile(): newTasks\n =  %v, \nwant %v", spew.Sdump(procRes.newTasks), spew.Sdump(tt.wantTasks))
			}
		})
	}
}
