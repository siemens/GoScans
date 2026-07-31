/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nfs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the nfs package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-nfs-test-*")
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

// TestNewScanner_InvalidTarget_ReturnsError verifies that NewScanner rejects targets that are not valid hostnames or IPs.
func TestNewScanner_InvalidTarget_ReturnsError(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		target string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "cidr-range",
			args: args{target: "192.0.2.0/24"},
		},
		{
			name: "empty-target",
			args: args{target: ""},
		},
		{
			name: "hostname-with-space",
			args: args{target: "invalid host"},
		},
		{
			name: "at-sign-only",
			args: args{target: "@"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify error is returned for invalid target
			_, errNewScanner := NewScanner(
				testLogger, tt.args.target, 5, 1,
				nil, nil, nil,
				time.Time{}, 0, false, 5*time.Second,
			)
			if errNewScanner == nil {
				t.Errorf("NewScanner() error = 'nil', wantErr = 'true' for target '%v'", tt.args.target)
			}
		})
	}
}

// TestNewScanner_ValidTarget_CreatesScanner verifies that NewScanner succeeds for valid hostnames and IP addresses.
func TestNewScanner_ValidTarget_CreatesScanner(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		target string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "valid-ipv4",
			args: args{target: "192.0.2.1"},
		},
		{
			name: "valid-hostname",
			args: args{target: "a.domain.tld"},
		},
		{
			name: "valid-ipv6",
			args: args{target: "2001:db8::1"},
		},
		{
			name: "localhost",
			args: args{target: "localhost"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify scanner is created without error
			scanner, errScanner := NewScanner(
				testLogger, tt.args.target, 5, 1,
				nil, nil, nil,
				time.Time{}, 0, false, 5*time.Second,
			)
			if errScanner != nil {
				t.Errorf("NewScanner() error = '%v', wantErr = 'false' for target '%v'", errScanner, tt.args.target)
				return
			}
			if scanner == nil {
				t.Errorf("NewScanner() = 'nil', want = 'non-nil scanner'")
			}
		})
	}
}

// TestNewScanner_FieldsStoredCorrectly_MatchInputArgs verifies that NewScanner stores all scalar constructor arguments unchanged.
func TestNewScanner_FieldsStoredCorrectly_MatchInputArgs(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	excludedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create scanner with non-default values to verify storage
	scanner, errScanner := NewScanner(
		testLogger, "192.0.2.1", 7, 4,
		nil, nil, nil,
		excludedTime, 1024, true, 10*time.Second,
	)
	if errScanner != nil {
		t.Errorf("NewScanner() error = '%v'", errScanner)
		return
	}

	// Verify each scalar field matches the supplied argument
	if scanner.crawlDepth != 7 {
		t.Errorf("NewScanner() crawlDepth = '%v', want = '%v'", scanner.crawlDepth, 7)
	}
	if scanner.threads != 4 {
		t.Errorf("NewScanner() threads = '%v', want = '%v'", scanner.threads, 4)
	}
	if scanner.excludedFileSizeBelow != 1024 {
		t.Errorf("NewScanner() excludedFileSizeBelow = '%v', want = '%v'", scanner.excludedFileSizeBelow, 1024)
	}
	if !scanner.onlyAccessibleFiles {
		t.Errorf("NewScanner() onlyAccessibleFiles = '%v', want = '%v'", scanner.onlyAccessibleFiles, true)
	}
	if scanner.mountTimeout != 10*time.Second {
		t.Errorf("NewScanner() mountTimeout = '%v', want = '%v'", scanner.mountTimeout, 10*time.Second)
	}
	if !scanner.excludedLastModifiedBelow.Equal(excludedTime) {
		t.Errorf("NewScanner() excludedLastModifiedBelow = '%v', want = '%v'", scanner.excludedLastModifiedBelow, excludedTime)
	}
}

// TestNewScanner_ExcludedShareNormalization_AddsSlashPrefix verifies that excluded shares without a leading slash get one prepended.
func TestNewScanner_ExcludedShareNormalization_AddsSlashPrefix(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name           string
		excludedShares []string
		wantContains   []string
		wantMissing    []string
	}{
		{
			name:           "adds-slash-to-bare-name",
			excludedShares: []string{"export"},
			wantContains:   []string{"/export"},
			wantMissing:    []string{"export"},
		},
		{
			name:           "preserves-existing-slash",
			excludedShares: []string{"/already"},
			wantContains:   []string{"/already"},
		},
		{
			name:           "mixed-with-and-without-slash",
			excludedShares: []string{"noslash", "/withslash"},
			wantContains:   []string{"/noslash", "/withslash"},
			wantMissing:    []string{"noslash"},
		},
		{
			name:           "empty-share-name-not-modified",
			excludedShares: []string{""},
			wantMissing:    []string{"/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create scanner to trigger share normalization
			scanner, errScanner := NewScanner(
				testLogger, "192.0.2.1", 5, 1,
				tt.excludedShares, nil, nil,
				time.Time{}, 0, false, 5*time.Second,
			)
			if errScanner != nil {
				t.Errorf("NewScanner() error = '%v'", errScanner)
				return
			}

			// Verify expected keys are present
			for _, key := range tt.wantContains {
				if _, ok := scanner.excludedShares[key]; !ok {
					t.Errorf("NewScanner() excludedShares missing key '%v'", key)
				}
			}

			// Verify unexpected keys are absent
			for _, key := range tt.wantMissing {
				if _, ok := scanner.excludedShares[key]; ok {
					t.Errorf("NewScanner() excludedShares unexpectedly contains key '%v'", key)
				}
			}
		})
	}
}

// TestScanner_SetContext_SetsOnFirstCallOnly verifies that SetContext assigns the context on the first call and ignores subsequent ones.
func TestScanner_SetContext_SetsOnFirstCallOnly(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name         string
		setSecondCtx bool
	}{
		{
			name:         "first-context-is-kept-when-second-is-set",
			setSecondCtx: true,
		},
		{
			name:         "single-set-assigns-context",
			setSecondCtx: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create scanner and set a first context
			scanner, errScanner := NewScanner(
				testLogger, "192.0.2.1", 5, 1,
				nil, nil, nil,
				time.Time{}, 0, false, 5*time.Second,
			)
			if errScanner != nil {
				t.Errorf("NewScanner() error = '%v'", errScanner)
				return
			}

			// Set the first context via cancellable derivation (distinct and identity-comparable)
			firstCtx, cancelFirst := context.WithCancel(context.Background())
			defer cancelFirst()
			scanner.SetContext(firstCtx)

			// Attempt to overwrite with a second context
			if tt.setSecondCtx {
				secondCtx, cancelSecond := context.WithCancel(context.Background())
				defer cancelSecond()
				scanner.SetContext(secondCtx)
			}

			// Verify the stored context is the first one
			if scanner.contextInner != firstCtx {
				t.Errorf("SetContext() context = '%v', want = '%v' (first context)", scanner.contextInner, firstCtx)
			}
		})
	}
}

// TestScanner_SanitizeShowmountOutput_ParsesOutput verifies that sanitizeShowmountOutput correctly merges continuation lines and handles edge cases.
func TestScanner_SanitizeShowmountOutput_ParsesOutput(t *testing.T) {

	// Prepare unit test data
	s := Scanner{logger: utils.NewTestLogger()}

	// Prepare and run test cases
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty-output",
			input: "",
			want:  nil,
		},
		{
			name:  "headline-only",
			input: "All mount points on server:",
			want:  nil,
		},
		{
			name:  "single-export-with-host",
			input: "All mount points on server:\n/export *",
			want:  []string{"/export *"},
		},
		{
			name:  "single-export-no-host",
			input: "Exports:\n/vol/data",
			want:  []string{"/vol/data"},
		},
		{
			name:  "multiple-exports",
			input: "Exports:\n/vol/data *\n/vol/backup 192.0.2.1,",
			want:  []string{"/vol/data *", "/vol/backup 192.0.2.1,"},
		},
		{
			name:  "multiline-host-list-merged",
			input: "Exports:\n/vol/export 192.0.2.1, 192.0.2.2,\n 192.0.2.3",
			want:  []string{"/vol/export 192.0.2.1, 192.0.2.2, 192.0.2.3"},
		},
		{
			name:  "empty-lines-are-skipped",
			input: "Exports:\n/vol/data *\n\n/vol/backup *",
			want:  []string{"/vol/data *", "/vol/backup *"},
		},
		{
			name: "windows-no-space-split-at-35-chars",
			// Export name is exactly 35 chars, then host immediately follows
			input: "Exports:\n/vol/v_vf_shc_irv05p_usirva0006gstoUSIRVA0005PSTO",
			want:  []string{"/vol/v_vf_shc_irv05p_usirva0006gsto USIRVA0005PSTO"},
		},
		{
			name: "path-continuation-merged-without-space",
			// A line that doesn't start with "/" and previous line doesn't contain ","
			// triggers path continuation merge (no separator). Use a short path (≤35 chars)
			// so the Windows 35-char host-split heuristic does not apply.
			input: "Exports:\n/vol/short_path\ncontinuation",
			want:  []string{"/vol/short_pathcontinuation"},
		},
		{
			name: "unexpected-continuation-at-start",
			// First content line does not start with "/" and there is no previous export line.
			// The function appends it as-is and logs an error (len(resultLines) < 1 branch).
			input: "Exports:\nunexpected-line-before-any-export",
			want:  []string{"unexpected-line-before-any-export"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify parsed line count and content match expectations
			got := s.sanitizeShowmountOutput(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("sanitizeShowmountOutput() len = '%v', want = '%v' (result: %v)", len(got), len(tt.want), got)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("sanitizeShowmountOutput() [%d] = '%v', want = '%v'", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestScanner_ExtractLine_ParsesExportAndHosts verifies that extractLine correctly parses export names and allowed-host lists from showmount output lines.
func TestScanner_ExtractLine_ParsesExportAndHosts(t *testing.T) {

	// Prepare unit test data
	s := Scanner{logger: utils.NewTestLogger()}

	// Prepare and run test cases
	tests := []struct {
		name          string
		line          string
		wantExport    string
		wantHostCount int
		wantHosts     []string
	}{
		{
			name:          "export-with-wildcard",
			line:          "/export *",
			wantExport:    "/export",
			wantHostCount: 1,
			wantHosts:     []string{"*"},
		},
		{
			name:          "export-with-single-host",
			line:          "/vol/data 192.0.2.1",
			wantExport:    "/vol/data",
			wantHostCount: 1,
			wantHosts:     []string{"192.0.2.1"},
		},
		{
			name:          "export-with-multiple-hosts",
			line:          "/vol/backup 192.0.2.1, 192.0.2.2, 192.0.2.3",
			wantExport:    "/vol/backup",
			wantHostCount: 3,
			wantHosts:     []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		},
		{
			name:          "export-only-no-hosts",
			line:          "/vol/nohost",
			wantExport:    "/vol/nohost",
			wantHostCount: 0,
			wantHosts:     nil,
		},
		{
			name: "export-with-multi-word-host",
			// "Alle Computer" is a multi-word hostname; no trailing comma so no empty-string host
			line:          "/share 192.0.2.1, Alle Computer",
			wantExport:    "/share",
			wantHostCount: 2,
			wantHosts:     []string{"192.0.2.1", "Alle Computer"},
		},
		{
			name:          "empty-line-returns-nothing",
			line:          "",
			wantExport:    "",
			wantHostCount: 0,
		},
		{
			name:          "invalid-line-not-starting-with-slash",
			line:          "notanexport",
			wantExport:    "",
			wantHostCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify export name and host list match expectations
			gotExport, gotHosts := s.extractLine(tt.line)
			if gotExport != tt.wantExport {
				t.Errorf("extractLine() export = '%v', want = '%v'", gotExport, tt.wantExport)
			}
			if len(gotHosts) != tt.wantHostCount {
				t.Errorf("extractLine() host count = '%v', want = '%v' (hosts: %v)", len(gotHosts), tt.wantHostCount, gotHosts)
				return
			}
			for i, host := range tt.wantHosts {
				if i >= len(gotHosts) {
					break
				}
				if gotHosts[i] != host {
					t.Errorf("extractLine() hosts[%d] = '%v', want = '%v'", i, gotHosts[i], host)
				}
			}
		})
	}
}

// TestScanner_Label_MatchesPackageConstant verifies that the scanner's Label field is initialized to the package Label constant.
func TestScanner_Label_MatchesPackageConstant(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Create scanner to verify label initialization
	scanner, errScanner := NewScanner(
		testLogger, "192.0.2.1", 5, 1,
		nil, nil, nil,
		time.Time{}, 0, false, 5*time.Second,
	)
	if errScanner != nil {
		t.Errorf("NewScanner() error = '%v'", errScanner)
		return
	}

	// Verify the scanner label matches the package constant
	if scanner.Label != Label {
		t.Errorf("Scanner.Label = '%v', want = '%v'", scanner.Label, Label)
	}
}

// TestScanner_ExcludedShareLookup_IsCaseInsensitive verifies that excluded share lookups use the lowercased form set during construction.
func TestScanner_ExcludedShareLookup_IsCaseInsensitive(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name           string
		excludedShares []string
		lookupKey      string
		wantFound      bool
	}{
		{
			name:           "uppercase-share-found-by-lowercase-key",
			excludedShares: []string{"/EXPORT"},
			lookupKey:      "/export",
			wantFound:      true,
		},
		{
			name:           "lowercase-share-found-by-lowercase-key",
			excludedShares: []string{"/export"},
			lookupKey:      "/export",
			wantFound:      true,
		},
		{
			name:           "share-not-in-list",
			excludedShares: []string{"/other"},
			lookupKey:      "/export",
			wantFound:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create scanner with the supplied excluded shares
			scanner, errScanner := NewScanner(
				testLogger, "192.0.2.1", 5, 1,
				tt.excludedShares, nil, nil,
				time.Time{}, 0, false, 5*time.Second,
			)
			if errScanner != nil {
				t.Errorf("NewScanner() error = '%v'", errScanner)
				return
			}

			// Verify lookup behavior matches expectation
			_, found := scanner.excludedShares[tt.lookupKey]
			if found != tt.wantFound {
				t.Errorf("excludedShares[%v] found = '%v', want = '%v'", tt.lookupKey, found, tt.wantFound)
			}
		})
	}
}

// TestExecCmd_MaliciousArgs_PassedAsSingleArgument verifies that execCmd passes each argument as a discrete
// element so that shell metacharacters in NFS export names cannot cause command injection.
func TestExecCmd_MaliciousArgs_PassedAsSingleArgument(t *testing.T) {

	// Prepare and run test cases with various shell injection payloads
	tests := []struct {
		name    string
		program string
		args    []string
		wantLen int
	}{
		{
			name:    "semicolon-injection",
			program: "showmount",
			args:    []string{"-e", "/export;rm -rf /"},
			wantLen: 3, // showmount, -e, "/export;rm -rf /" (or prepended with sudo)
		},
		{
			name:    "dollar-subshell-injection",
			program: "mount",
			args:    []string{"-o", "soft", "192.0.2.1:/export$(whoami)", "/mnt/point"},
			wantLen: 5,
		},
		{
			name:    "backtick-injection",
			program: "umount",
			args:    []string{"/mnt/scan_`id`_export"},
			wantLen: 2,
		},
		{
			name:    "pipe-injection",
			program: "showmount",
			args:    []string{"-a", "192.0.2.1 | cat /etc/passwd"},
			wantLen: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Build command via execCmd
			cmd := execCmd(tt.program, tt.args...)

			// Calculate expected argument count with optional sudo prefix
			expectedLen := tt.wantLen
			if adminRights != "" {
				expectedLen++ // sudo is prepended as first argument
			}

			// Verify argument count matches expected (no shell splitting occurred)
			if len(cmd.Args) != expectedLen {
				t.Errorf("execCmd() args length = %d, want = %d (args: %v)", len(cmd.Args), expectedLen, cmd.Args)
			}

			// Verify the malicious argument is passed as a single element without shell interpretation.
			// The last user-provided argument should be the last element in cmd.Args.
			lastArg := tt.args[len(tt.args)-1]
			gotLast := cmd.Args[len(cmd.Args)-1]
			if gotLast != lastArg {
				t.Errorf("execCmd() last arg = '%v', want = '%v'", gotLast, lastArg)
			}
		})
	}
}
