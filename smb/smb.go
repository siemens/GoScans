/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package smb implements a scan module for discovering and crawling SMB shares.
package smb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/siemens/GoScans/filecrawler"
	"github.com/siemens/GoScans/utils"
)

// Label identifies the scan module in logs and results
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

// Result wraps filecrawler.Result so the broker can distinguish SMB results from NFS results by type.
type Result struct {
	filecrawler.Result
}

// Scanner holds the configuration and state for a single SMB scan.
type Scanner struct {
	Label                     string
	Started                   time.Time
	Finished                  time.Time
	logger                    utils.Logger
	target                    string // Target address to be scanned (might be IPv4, IPv6 or hostname)
	crawlDepth                int
	threads                   int
	forcedShares              []string            // list of shares to try, even if they couldn't be enumerated
	excludedShares            map[string]struct{} // faster for checking if string is contained than []string
	excludedFolders           map[string]struct{}
	excludedExtensions        map[string]struct{}
	excludedLastModifiedBelow time.Time
	excludedFileSizeBelow     int
	onlyAccessibleFiles       bool   // If true then the scanner only returns files which are readable or writeable
	smbDomain                 string // (Optional) credentials for SMB connection
	smbUser                   string // ...
	smbPassword               string // ...

	contextInner       context.Context    // Context for the scan, within which the scan should execute. Might optionally wrap an outer context. If outer context is cancelled, inner one should cancel too, but not the other way around.
	contextInnerCancel context.CancelFunc // Context cancel function of inner context, not impacting optional outer one.
}

// NewScanner creates a new Scanner instance and validates all input arguments.
func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	crawlDepth int,
	threads int,
	forcedShares []string, // List of share names that should always be attempted, even if they could not be enumerated
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

	// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
	target = strings.TrimSpace(target)

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
		for _, entry := range slice {
			lookup[entry] = struct{}{}
		}
		return lookup
	}

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		target,
		crawlDepth,
		threads,
		forcedShares,
		toMap(utils.TrimToLower(excludedShares)),
		toMap(utils.TrimToLower(excludedFolders)),
		toMap(utils.TrimToLower(excludedExtensions)),
		excludedLastModifiedBelow,
		excludedFileSizeBelow,
		onlyAccessibleFiles,
		smbDomain,
		smbUser,
		smbPassword,
		nil,
		nil,
	}

	// Return scan struct
	return &scan, nil
}

// SetContext can be used to pass an existing context from outside.
// If timeout is supplied later when calling Run() the external context and the deadline context will be combined.
// Once set, the context cannot be changed anymore, because it might have been wrapped internally already.
func (s *Scanner) SetContext(ctx context.Context) {
	if s.contextInner == nil {
		s.contextInner = ctx
	}
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf("Unexpected error: %s%s", r, utils.StacktraceIndented("\t"))

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

	// Set scan started flag
	s.Started = time.Now()

	// Create initial context
	contextInner := context.Background()

	// Replace context with external one if set
	if s.contextInner != nil {
		contextInner = s.contextInner
	}

	// Add timeout to context if desired
	var contextInnerCancel context.CancelFunc
	if timeout > 0 {
		contextInner, contextInnerCancel = context.WithTimeout(contextInner, timeout)
	}

	// Set context for scan
	s.contextInner = contextInner
	s.contextInnerCancel = contextInnerCancel

	// Execute scan logic
	s.logger.Infof("Started  scan of %s.", s.target)
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s in %fm.", s.target, duration)

	// Return result set
	return res
}

// execute runs the SMB crawl and wraps the result into a package Result.
func (s *Scanner) execute() *Result {

	// Cleanup inner context if set
	if s.contextInnerCancel != nil {
		defer s.contextInnerCancel()
	}

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
	if utils.ContextExpired(s.contextInner) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			filecrawler.Result{
				FoldersReadable: result.FoldersReadable,
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
			FoldersReadable: result.FoldersReadable,
			FilesReadable:   result.FilesReadable,
			FilesWritable:   result.FilesWritable,
			Data:            result.Data,
			Status:          result.Status,
			Exception:       result.Exception,
		},
	}
}
