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
	"fmt"
	"github.com/siemens/GoScans/filecrawler"
	"github.com/siemens/GoScans/utils"
	"strings"
	"time"
)

const Label = "Smb"

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger) error {
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup() error {
	return nil
}

type Result struct {
	filecrawler.Result // smb result wrapped filecrawler result to allow broker distinguishing smb/nfs results by type
}

type Scanner struct {
	Label                     string
	Started                   time.Time
	Finished                  time.Time
	logger                    utils.Logger
	target                    string // Target address to be scanned (might be IPv4, IPv6 or hostname)
	crawlDepth                int
	threads                   int
	excludedShares            map[string]struct{} // faster for checking if string is contained than []string
	excludedFolders           map[string]struct{}
	excludedExtensions        map[string]struct{}
	excludedLastModifiedBelow time.Time
	excludedFileSizeBelow     int
	onlyAccessibleFiles       bool      // If true then the scanner only returns files which are readable or writeable
	smbDomain                 string    // (Optional) credentials for SMB connection
	smbUser                   string    // ...
	smbPassword               string    // ...
	deadline                  time.Time // Time when the scanner has to abort
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	crawlDepth int,
	threads int,
	excludedShares []string,
	excludedFolders []string,
	excludedExtensions []string,
	excludedLastModifiedBelow time.Time,
	excludedFileSizeBelow int,
	onlyAccessibleFiles bool,
	smbDomain string,
	smbUser string,
	smbPassword string,
) (*Scanner, error) {

	// Check whether input target is valid
	if !utils.IsValidAddress(target) {
		return nil, fmt.Errorf("invalid target '%s'", target)
	}

	// Check whether given credentials are plausible
	if !utils.ValidOrEmptyCredentials(smbDomain, smbUser, smbPassword) {
		return nil, fmt.Errorf("smb credentials incomplete")
	}

	// Define function to translate a slice into a map, because looking up values within a map is more efficient and
	// will also get rid of duplicates.
	toMap := func(slice []string) map[string]struct{} {
		lookup := make(map[string]struct{}, len(slice))
		for _, e := range slice {
			lookup[e] = struct{}{}
		}
		return lookup
	}

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		strings.TrimSpace(target),
		crawlDepth,
		threads,
		toMap(utils.TrimToLower(excludedShares)),
		toMap(utils.TrimToLower(excludedFolders)),
		toMap(utils.TrimToLower(excludedExtensions)),
		excludedLastModifiedBelow,
		excludedFileSizeBelow,
		onlyAccessibleFiles,
		smbDomain,
		smbUser,
		smbPassword,
		time.Time{}, // zero time (no deadline yet set)
	}

	// Return scan struct
	return &scan, nil
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf(fmt.Sprintf("Unexpected error: %s", r))

			// Build error status from error message and formatted stacktrace
			errMsg := fmt.Sprintf("%s%s", r, utils.StacktraceIndented("\t"))

			// Return result set indicating exception
			res = &Result{
				filecrawler.Result{
					FoldersReadable: 0,
					FilesReadable:   0,
					FilesWritable:   0,
					Data:            nil,
					Status:          errMsg,
					Exception:       true,
				},
			}
		}
	}()

	// Set scan started flag and calculate deadline
	s.Started = time.Now()
	s.deadline = time.Now().Add(timeout)
	s.logger.Infof("Started  scan of %s.", s.target)

	// Execute scan logic
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s in %fm.", s.target, duration)

	// Return result set
	return res
}

func (s *Scanner) execute() *Result {

	// Log start
	s.logger.Debugf("Crawling '%s'.", s.target)

	// Crawl SMB service
	result := s.crawl()

	// Log crawling states
	s.logger.Debugf("%d folders crawled (Files: %d, Readable: %d, Writeable: %d).",
		result.FoldersReadable,
		len(result.Data),
		result.FilesReadable,
		result.FilesWritable,
	)

	// Check whether scan timeout is reached (Timeout status already set)
	if utils.DeadlineReached(s.deadline) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			filecrawler.Result{
				FoldersReadable: result.FilesReadable,
				FilesReadable:   result.FilesReadable,
				FilesWritable:   result.FilesWritable,
				Data:            result.Data,
				Status:          utils.StatusDeadline,
				Exception:       false,
			},
		}
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result.")
	return &Result{
		filecrawler.Result{
			FoldersReadable: result.FilesReadable,
			FilesReadable:   result.FilesReadable,
			FilesWritable:   result.FilesWritable,
			Data:            result.Data,
			Status:          result.Status,
			Exception:       result.Exception,
		},
	}
}
