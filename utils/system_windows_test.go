package utils

import (
	"testing"
)

// TestIsValidFolder verifies that IsValidFolder returns an error for missing or non-directory paths.
func TestIsValidFolder(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "invalid-path",
			path:    `C:\notexistingfolder`,
			wantErr: true,
		},
		{
			name:    "invalid-folder",
			path:    `C:\Windows\System32\cmd.exe`,
			wantErr: true,
		},
		{
			name:    "valid-1",
			path:    `C:\Windows\System32`,
			wantErr: false,
		},
		{
			name:    "valid-2",
			path:    `C:\Windows\System32\`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errIsValidFolder := IsValidFolder(tt.path); (errIsValidFolder != nil) != tt.wantErr {
				t.Errorf("IsValidFolder() error = '%v', wantErr = '%v'", errIsValidFolder, tt.wantErr)
			}
		})
	}
}

// TestIsValidFile verifies that IsValidFile returns an error for paths that are directories or do not exist.
func TestIsValidFile(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "invalid-folder",
			path:    `C:\notexistingfolder`,
			wantErr: true,
		},
		{
			name:    "valid-file",
			path:    `C:\Windows\System32\cmd.exe`,
			wantErr: false,
		},
		{
			name:    "invalid-folder-1",
			path:    `C:\Windows\System32`,
			wantErr: true,
		},
		{
			name:    "invalid-folder-2",
			path:    `C:\Windows\System32\`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errIsValidFile := IsValidFile(tt.path); (errIsValidFile != nil) != tt.wantErr {
				t.Errorf("IsValidFile() error = '%v', wantErr = '%v'", errIsValidFile, tt.wantErr)
			}
		})
	}
}

// TestIsValidExecutable verifies that IsValidExecutable returns an error for missing or non-executable paths.
func TestIsValidExecutable(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		args    []string
		wantErr bool
	}{
		{
			name:    "executable-invalid-inexisting-folder",
			path:    `C:\notexistingfolder`,
			args:    []string{"-h"},
			wantErr: true,
		},
		{
			name:    "executable-invalid-existing-folder",
			path:    `..`,
			args:    []string{"-h"},
			wantErr: true,
		},
		{
			name:    "executable-valid",
			path:    `C:\Windows\System32\cmd.exe`,
			args:    []string{"-h"},
			wantErr: false,
		},
		{
			name:    "executable-invalid",
			path:    `C:\Windows\System32`,
			args:    []string{"-h"},
			wantErr: true,
		},
		{
			name:    "executable-from-env-path",
			path:    `cmd`,
			args:    []string{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errIsValidExecutable := IsValidExecutable(tt.path, tt.args...); (errIsValidExecutable != nil) != tt.wantErr {
				t.Errorf("IsValidExecutable() error = '%v', wantErr = '%v'", errIsValidExecutable, tt.wantErr)
			}
		})
	}
}
