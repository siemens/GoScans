/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package _test

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

var settings *Settings // Settings necessary for some unit tests
var once sync.Once     // Ensures test settings are loaded once

// Settings holds all necessary unittest settings
type Settings struct {
	PathTmpDir          string   // Path to folder used by unit tests to create temporary files and test output
	PathDataDir         string   // Path to sample data used by unit tests
	PathNmapDir         string   // Path to the Nmap executable, which one to use during unit tests
	PathNmap            string   // Path to the Nmap executable, which one to use during unit tests
	PathSslyze          string   // Path to the Sslyze executable, which one to use during unit tests
	PathPython          string   // Path to python3.7, required by SSL tests
	PathNucleiTemplates string   // Path to nuclei templates directory, which one to use during unit tests
	HttpUserAgent       string   // HTTP user agent to use during unit tests
	HttpProxy           *url.URL // HTTP Proxy to use during unit tests
}

// GetSettings returns test settings that should be used by unit tests.
// Invalid settings will be changed to empty values.
// Unit test should decide themselves which of these settings are mandatory and check their availability.
// Unit tests should always run as comprehensive as possible with the current configuration.
func GetSettings() *Settings {

	// Initialize unit test settings if not done yet
	once.Do(func() {

		// Get absolute path to bin folder
		_, filename, _, _ := runtime.Caller(0) // File path of _test.settings.go
		workingDir := filepath.Dir(filename)   // Dir path of _test

		// Initialize HTTP proxy from environment so unit tests use the same egress
		// path as `go mod download` in CI. Local dev without these vars stays direct.
		var proxy *url.URL // Nil = no proxy
		for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := os.Getenv(name); v != "" {
				if u, errU := url.Parse(v); errU == nil {
					fmt.Println(fmt.Sprintf("Using '%s' from environment variable '%s' as a proxy.", name, v))
					proxy = u
					break
				}
			}
		}

		///////////////////////////////////////////////////////////////////////
		// CONFIGURE BEFORE RUNNING UNIT TESTS TO INCREASE COVERAGE ==========>
		// EVERYTHING THAT IS NOT SET CORRECTLY WILL LEAD TO SKIPPED UNIT TESTS
		///////////////////////////////////////////////////////////////////////
		pathNmap := filepath.Join(workingDir, "tools", "nmap-7.92", "nmap.exe")                     // must be set to enable respective unit tests!
		pathSslyze := filepath.Join(workingDir, "tools", "sslyze-5.0.5", "sslyze.exe")              // must be set to enable respective unit tests!
		pathPython := "/usr/bin/python3.7"                                                          // must be set to enable respective unit tests!
		pathNucleiTemplates := filepath.Join(workingDir, "data", "nuclei-templates")                // must be set to enable respective unit tests!
		httpUserAgent := "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0" // must be set to enable respective unit tests!
		// proxy, _ = url.Parse("http://127.0.0.1:8080") // ATTENTION: Responses might look different via proxy!!
		///////////////////////////////////////////////////////////////////////
		// <========== CONFIGURE BEFORE RUNNING UNIT TESTS TO INCREASE COVERAGE
		///////////////////////////////////////////////////////////////////////

		// Changes working directory to the bin folder.
		errChdir := os.Chdir(workingDir)
		if errChdir != nil {
			panic(fmt.Sprintf("could not set working directory for unit tests: %s", errChdir))
		}

		// Unset Nmap path if incorrect
		_, errPathNmap := exec.Command(pathNmap, "-v").CombinedOutput()
		if errPathNmap != nil {
			pathNmap = ""
			fmt.Println(fmt.Sprintf("WARNING: %s", errPathNmap))
		}

		// Unset SSLyze path if incorrect
		_, errPathSslyze := exec.Command(pathSslyze).CombinedOutput()
		if errPathSslyze != nil {
			pathSslyze = ""
			fmt.Println(fmt.Sprintf("WARNING: %s", errPathSslyze))
		}

		// Unset Python path if not found
		if _, errStatPython37 := os.Stat(pathPython); errStatPython37 != nil {
			pathPython, _ = exec.LookPath("python3")
			if pathPython == "" {
				fmt.Println(fmt.Sprintf("WARNING: %s", errStatPython37))
			}
		}

		// Unset nuclei templates path if directory does not exist
		if _, errStat := os.Stat(pathNucleiTemplates); errStat != nil {
			pathNucleiTemplates = ""
		}

		// Create a new instance of the unit test settings, that might need to be adapted before running unit tests
		settings = &Settings{
			PathTmpDir:          filepath.Join(workingDir, "tmp"),
			PathDataDir:         filepath.Join(workingDir, "data"),
			PathNmapDir:         filepath.Dir(pathNmap),
			PathNmap:            pathNmap,
			PathSslyze:          pathSslyze,
			PathPython:          pathPython,
			PathNucleiTemplates: pathNucleiTemplates,
			HttpUserAgent:       httpUserAgent,
			HttpProxy:           proxy,
		}
	})

	// Return previously initialized unit test settings
	return settings
}
