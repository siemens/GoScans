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
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/siemens/GoScans/utils"
)

// test_buildOOXMLZip creates an in-memory OOXML-shaped zip file containing a single docProps/custom.xml entry
// with the given body. It writes the zip to a temp file in the current directory and returns the file path.
// The caller is responsible for removing the file.
func test_buildOOXMLZip(t *testing.T, xmlBody []byte) string {

	// Mark as test helper so failure lines point to call sites
	t.Helper()

	// Build the zip in memory
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)
	entryWriter, errEntryWriter := zipWriter.Create(OOXMLCustomPropertiesFile)
	if errEntryWriter != nil {
		t.Fatalf("test_buildOOXMLZip() could not create zip entry: '%v'", errEntryWriter)
	}
	_, errWrite := entryWriter.Write(xmlBody)
	if errWrite != nil {
		t.Fatalf("test_buildOOXMLZip() could not write zip entry: '%v'", errWrite)
	}
	errZipClose := zipWriter.Close()
	if errZipClose != nil {
		t.Fatalf("test_buildOOXMLZip() could not close zip writer: '%v'", errZipClose)
	}

	// Write to a temp file in the current directory (already isolated by TestMain)
	tmpFile, errTmpFile := os.CreateTemp(".", "ooxml-test-*.docx")
	if errTmpFile != nil {
		t.Fatalf("test_buildOOXMLZip() could not create temp file: '%v'", errTmpFile)
	}
	_, errTmpWrite := tmpFile.Write(buf.Bytes())
	if errTmpWrite != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		t.Fatalf("test_buildOOXMLZip() could not write temp file: '%v'", errTmpWrite)
	}
	errTmpClose := tmpFile.Close()
	if errTmpClose != nil {
		_ = os.Remove(tmpFile.Name())
		t.Fatalf("test_buildOOXMLZip() could not close temp file: '%v'", errTmpClose)
	}

	// Return the temp file path as everything went fine
	return tmpFile.Name()
}

// TestGetOOXMLProperties_OversizedCustomXml_ReturnsError verifies that getOOXMLProperties returns a
// descriptive error and does not buffer beyond the cap when docProps/custom.xml decompresses to > 10 MiB.
func TestGetOOXMLProperties_OversizedCustomXml_ReturnsError(t *testing.T) {

	// Prepare unit test data — 20 MiB uncompressed; compresses to a few bytes inside the zip
	oversizedBody := bytes.Repeat([]byte("<a/>"), 5*1024*1024)
	zipPath := test_buildOOXMLZip(t, oversizedBody)
	defer func() { _ = os.Remove(zipPath) }()

	// Capture allocation baseline before the call
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Prepare and run test cases
	got, errGot := getOOXMLProperties(zipPath, utils.NewTestLogger())

	// Capture post-call allocation for the coarse memory cap guard
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	// Verify: a non-nil error must be returned
	if errGot == nil {
		t.Errorf("getOOXMLProperties() error = nil, want non-nil for oversized custom.xml")
	}

	// Verify: error message must mention the size limit
	if errGot != nil && !strings.Contains(errGot.Error(), "exceeds") {
		t.Errorf("getOOXMLProperties() error = '%v', want message containing 'exceeds'", errGot)
	}

	// Verify: nil result on error
	if got != nil {
		t.Errorf("getOOXMLProperties() = '%v', want nil on error", got)
	}

	// Verify: total allocation must stay well below what reading the full 20 MiB zip-bomb body would cause.
	// bytes.Buffer geometric growth means reading N bytes causes ~2N of TotalAlloc. Capping at 10 MiB therefore
	// yields ~32 MiB TotalAlloc, while reading the full 20 MiB body would yield ~64 MiB. Using 4× the cap (40 MiB)
	// sits clearly between the two, making this a deterministic guard without over-constraining the allocator.
	allocated := memAfter.TotalAlloc - memBefore.TotalAlloc
	const fourCaps = uint64(4 * maxCustomPropsBytes)
	if allocated > fourCaps {
		t.Errorf("getOOXMLProperties() allocated '%d' bytes, want <= '%d'", allocated, fourCaps)
	}
}

// TestGetOOXMLProperties_SmallCustomXml_ReturnsProperties verifies that getOOXMLProperties correctly
// parses custom properties from a well-formed, sub-kilobyte docProps/custom.xml.
func TestGetOOXMLProperties_SmallCustomXml_ReturnsProperties(t *testing.T) {

	// Prepare unit test data — minimal valid OOXML custom-properties XML with one string property
	const smallXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Properties>` +
		`<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="SensitivityLabel">` +
		`<lpwstr>General</lpwstr>` +
		`</property>` +
		`</Properties>`
	zipPath := test_buildOOXMLZip(t, []byte(smallXml))
	defer func() { _ = os.Remove(zipPath) }()

	// Prepare and run test cases
	got, errGot := getOOXMLProperties(zipPath, utils.NewTestLogger())

	// Verify: no error for a well-formed small file
	if errGot != nil {
		t.Fatalf("getOOXMLProperties() error = '%v', want nil", errGot)
	}

	// Verify: one property is returned with correct name and value
	if got == nil {
		t.Fatalf("getOOXMLProperties() = nil, want non-nil result")
	}
	if len(got.Properties) != 1 {
		t.Errorf("getOOXMLProperties() len(Properties) = '%d', want '1'", len(got.Properties))
	}
	if len(got.Properties) > 0 {
		prop := got.Properties[0]
		if prop.Name != "SensitivityLabel" {
			t.Errorf("getOOXMLProperties() Properties[0].Name = '%v', want 'SensitivityLabel'", prop.Name)
		}
		if prop.ValStr == nil || *prop.ValStr != "General" {
			t.Errorf("getOOXMLProperties() Properties[0].ValStr = '%v', want 'General'", prop.ValStr)
		}
	}
}
