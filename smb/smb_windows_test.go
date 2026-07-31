/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smb

import (
	"reflect"
	"testing"
	"time"

	"github.com/siemens/GoScans/filecrawler"
	"github.com/siemens/GoScans/utils"
)

// TestScanner_mountAndUnmount verifies that mountShare and unmountShare return errors for unreachable hosts.
func TestScanner_mountAndUnmount(t *testing.T) {
	type args struct {
		share shareInfo
	}
	tests := []struct {
		name        string
		args        args
		wantErrConn bool
		wantErrCanc bool
	}{
		{
			name: "no-such-host",
			args: args{
				share: shareInfo{
					Name:   "qayxswedcvfrtgbnhzujm",
					Target: "qayxswedcvfrtgbnhzujm",
					Path:   "\\\\qayxswedcvfrtgbnhzujm\\qayxswedcvfrtgbnhzujm",
					IsDfs:  false,
				},
			},
			wantErrConn: true,
			wantErrCanc: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				logger: utils.NewTestLogger(),
			}
			if errMountShare := s.mountShare(tt.args.share); (errMountShare != nil) != tt.wantErrConn {
				t.Errorf("mountShare() error = '%v', wantErr = '%v'", errMountShare, tt.wantErrConn)
			}
			if errUnmountShare := s.unmountShare(tt.args.share); (errUnmountShare != nil) != tt.wantErrCanc {
				t.Errorf("unmountShare() error = '%v', wantErr = '%v'", errUnmountShare, tt.wantErrCanc)
			}
		})
	}
}

// TestScanner_getShares verifies that getShares returns an error when the target host is not reachable.
func TestScanner_getShares(t *testing.T) {
	type fields struct {
		target string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []shareInfo
		wantErr bool
	}{
		{
			name:    "not-reachable",
			fields:  fields{target: "test.sub.domain.tld"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				logger: utils.NewTestLogger(),
				target: tt.fields.target,
			}
			got, errGot := s.getShares()
			if (errGot != nil) != tt.wantErr {
				t.Errorf("getShares() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getShares() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestScanner_crawl verifies that crawl returns the expected status and empty results when the SMB host is not reachable.
func TestScanner_crawl(t *testing.T) {
	type fields struct {
		target                    string
		maxDepth                  int
		excludedShares            map[string]struct{}
		excludedFolders           map[string]struct{}
		excludedExtensions        map[string]struct{}
		excludedLastModifiedBelow time.Time
		excludedFileSizeBelow     int
		onlyAccessibleFiles       bool
		threads                   int
		smbDomain                 string
		smbUser                   string
		smbPassword               string
	}
	tests := []struct {
		name           string
		fields         fields
		want           *filecrawler.Result
		wantFilesTotal int
	}{
		{
			name: "host-not-reachable",
			fields: fields{
				target:   "qayxswedcvfrtgbnhzujm",
				maxDepth: -1,
			},
			want: &filecrawler.Result{
				Status: utils.StatusNotReachable,
				Data:   []*filecrawler.File{},
			},
			wantFilesTotal: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				logger:                    utils.NewTestLogger(),
				target:                    tt.fields.target,
				crawlDepth:                tt.fields.maxDepth,
				excludedShares:            tt.fields.excludedShares,
				excludedFolders:           tt.fields.excludedFolders,
				excludedExtensions:        tt.fields.excludedExtensions,
				excludedLastModifiedBelow: tt.fields.excludedLastModifiedBelow,
				excludedFileSizeBelow:     tt.fields.excludedFileSizeBelow,
				onlyAccessibleFiles:       tt.fields.onlyAccessibleFiles,
				smbDomain:                 tt.fields.smbDomain,
				smbUser:                   tt.fields.smbUser,
				smbPassword:               tt.fields.smbPassword,
				threads:                   tt.fields.threads,
			}
			got := s.crawl()
			if !reflect.DeepEqual(got.FoldersReadable, tt.want.FoldersReadable) {
				t.Errorf("crawl() FoldersReadable = '%v', want = '%v'", got.FoldersReadable, tt.want.FoldersReadable)
			}
			if !reflect.DeepEqual(got.FilesReadable, tt.want.FilesReadable) {
				t.Errorf("crawl() FilesReadable = '%v', want = '%v'", got.FilesReadable, tt.want.FilesReadable)
			}
			if !reflect.DeepEqual(got.FilesWritable, tt.want.FilesWritable) {
				t.Errorf("crawl() FilesWritable = '%v', want = '%v'", got.FilesWritable, tt.want.FilesWritable)
			}
			if !reflect.DeepEqual(got.Status, tt.want.Status) {
				t.Errorf("crawl() Status = '%v', want = '%v'", got.Status, tt.want.Status)
			}
			if !reflect.DeepEqual(got.Exception, tt.want.Exception) {
				t.Errorf("crawl() Exception = '%v', want = '%v'", got.Exception, tt.want.Exception)
			}
			if !reflect.DeepEqual(len(got.Data), tt.wantFilesTotal) {
				t.Errorf("crawl() FilesTotal = '%v', want = '%v'", len(got.Data), tt.wantFilesTotal)
			}
		})
	}
}
