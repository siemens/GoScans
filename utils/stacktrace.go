/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// StacktraceIndented takes the stacktrace from stack and formats it in a nicely indented way (starting with newline):
//
//	Stacktrace:
//		| goroutine 2775398 [running]:
//		| go-scans/utils.(*Requester).Get(0xc001511810, 0xc001e39740, 0x2a, 0xc0001b2460, 0x20, 0x0, 0xe, 0xc0003063a0, 0xc, 0x0, ...)
//		| 	C:/workplace/go/src/go-scans/scans/http.go:228 +0x2ac
//		| go-scans/scans/webcrawler.(*Scanner).execute(0xc0006a89a0, 0x0)
//		| 	C:/workplace/go/src/go-scans/scans/webcrawler/webcrawler.go:334 +0x5c3
//		| go-scans/scans/webcrawler.(*Scanner).Run(0xc0006a89a0, 0xd18c2e28000, 0x0)
//		| 	C:/workplace/go/src/go-scans/scans/webcrawler/webcrawler.go:230 +0x1ca
//		| go-scans/agent/core.DoWebcrawler(0xc000272240, 0xb51e8, 0xc0001b2460, 0x20, 0x50, 0xc00317b270, 0x5, 0x5, 0xc001e5bb9c, 0x4, ...)
//		| 	C:/workplace/go/src/go-scans/agent/core/core_webcrawler.go:101 +0x8ec
//		| created by go-scans/agent/core.scanTaskLauncher
//		| 	C:/workplace/go/src/go-scans/agent/core/core.go:323 +0xb28
func StacktraceIndented(indent string) string {

	// Get stacktrace
	trace := strings.Trim(string(debug.Stack()), "\n")

	// Return stacktrace formatted with indents
	return fmt.Sprintf(
		"\n%sStacktrace:\n%s\t| %s",
		indent,
		indent,
		strings.Replace(trace, "\n", "\n\t\t| ", -1),
	)
}
