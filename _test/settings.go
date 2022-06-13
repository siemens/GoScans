/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
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

// Settings necessary for some unit tests
var settings *Settings
var settingsErr error // Indicates if settings initialization failed
var once sync.Once

// Settings holds all necessary unittest settings
type Settings struct {
	PathTmpDir    string   // Path to folder used by unit tests to create temporary files and test output
	PathDataDir   string   // Path to sample data used by unit tests
	PathSslyze    string   // Path to the Sslyze executable, which one to use during unit tests
	PathNmapDir   string   // Path to the Nmap executable, which one to use during unit tests
	PathNmap      string   // Path to the Nmap executable, which one to use during unit tests
	HttpUserAgent string   // HTTP user agent to use during unit tests
	HttpProxy     *url.URL // HTTP Proxy to use during unit tests
	LdapUser      string   // Username to query Active Directory with
	LdapPassword  string   // Password to query Active Directory with
}

func GetSettings() (*Settings, error) {

	// Initialize unit test settings if not done yet
	once.Do(func() {

		// Get absolute path to bin folder
		_, filename, _, _ := runtime.Caller(0)
		workingDir := filepath.Dir(filename)
		workingDir = filepath.Join(workingDir, "../", "_test")

		// Changes working directory to the bin folder.
		err := os.Chdir(workingDir)
		if err != nil {
			fmt.Println("Error ", err.Error())
		}

		// Prepare proxy
		var proxy *url.URL
		// proxy, _ = url.Parse("http://127.0.0.1:8080") // ATTENTION: Responses might look different via proxy!!

		// Create a new instance of the unit test settings, that might need to be adapted before running unit tests
		settings = &Settings{
			PathSslyze:    filepath.Join(workingDir, "tools", "sslyze-5.0.5", "sslyze.exe"), // CONFIGURE BEFORE RUNNING UNIT TESTS
			PathNmap:      filepath.Join(workingDir, "tools", "nmap-7.91", "nmap.exe"),      // CONFIGURE BEFORE RUNNING UNIT TESTS
			HttpUserAgent: "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
			HttpProxy:     proxy,
			LdapUser:      "", // must be set to enable respective LDAP unit tests!
			LdapPassword:  "", // must be set to enable respective LDAP unit tests!
		}

		// Check if settings are valid
		_, errPathSslyze := exec.Command(settings.PathSslyze).CombinedOutput()
		if errPathSslyze != nil {
			settingsErr = fmt.Errorf("invalid SSlyze path")
			return
		}
		_, errPathNmap := exec.Command(settings.PathNmap, "-v").CombinedOutput()
		if errPathNmap != nil {
			settingsErr = fmt.Errorf("invalid Nmap path")
			return
		}

		// Set static values which should not be changed
		settings.PathNmapDir = filepath.Dir(settings.PathNmap)
		settings.PathTmpDir = filepath.Join(workingDir, "tmp")
		settings.PathDataDir = filepath.Join(workingDir, "data")
	})

	// Return previously initialized unit test settings
	return settings, settingsErr
}
