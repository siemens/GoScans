/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smb

import (
	"go-scans/filecrawler"
	"go-scans/utils"
	"reflect"
	"testing"
	"time"
)

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
		{"no-such-host",
			args{
				share: shareInfo{
					Name:   "qayxswedcvfrtgbnhzujm",
					Target: "qayxswedcvfrtgbnhzujm",
					Path:   "\\\\qayxswedcvfrtgbnhzujm\\qayxswedcvfrtgbnhzujm",
					IsDfs:  false,
				},
			},
			true,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				logger: utils.NewTestLogger(),
			}
			if err := s.mountShare(tt.args.share); (err != nil) != tt.wantErrConn {
				t.Errorf("mountShare() error = %v, wantErr %v", err, tt.wantErrConn)
			}
			if err := s.unmountShare(tt.args.share); (err != nil) != tt.wantErrCanc {
				t.Errorf("unmountShare() error = %v, wantErr %v", err, tt.wantErrCanc)
			}
		})
	}
}

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
			"not reachable",
			fields{target: "test.sub.domain.tld"},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				logger: utils.NewTestLogger(),
				target: tt.fields.target,
			}
			got, err := s.getShares()
			if (err != nil) != tt.wantErr {
				t.Errorf("getShares() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getShares() got = %v, \n want %v", got, tt.want)
			}
		})
	}
}

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
		deadline                  time.Time
	}
	tests := []struct {
		name           string
		fields         fields
		want           *filecrawler.Result
		wantFilesTotal int
	}{
		{
			name: "host not reachable",
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
				deadline:                  tt.fields.deadline,
			}
			got := s.crawl()
			if !reflect.DeepEqual(got.FoldersReadable, tt.want.FoldersReadable) {
				t.Errorf("Crawl() = %v, want %v (FoldersReadable)", got.FoldersReadable, tt.want.FoldersReadable)
			}
			if !reflect.DeepEqual(got.FilesReadable, tt.want.FilesReadable) {
				t.Errorf("Crawl() = %v, want %v (FilesReadable)", got.FilesReadable, tt.want.FilesReadable)
			}
			if !reflect.DeepEqual(got.FilesWritable, tt.want.FilesWritable) {
				t.Errorf("Crawl() = %v, want %v (FilesWritable)", got.FilesWritable, tt.want.FilesWritable)
			}
			if !reflect.DeepEqual(got.Status, tt.want.Status) {
				t.Errorf("Crawl() = %v, want %v (Status)", got.Status, tt.want.Status)
			}
			if !reflect.DeepEqual(got.Exception, tt.want.Exception) {
				t.Errorf("Crawl() = %v, want %v (Exception)", got.Exception, tt.want.Exception)
			}
			if !reflect.DeepEqual(len(got.Data), tt.wantFilesTotal) {
				t.Errorf("Crawl() = %v, want %v (FilesTotal)", len(got.Data), tt.wantFilesTotal)
			}
		})
	}
}
