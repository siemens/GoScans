/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nfs

import (
	"fmt"
	"github.com/siemens/GoScans/filecrawler"
	"github.com/siemens/GoScans/utils"
	"os/exec"
	"strings"
	"time"
)

const Label = "Nfs"

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger) error {

	// Execute setup with OS specific implementation
	errOsDependant := setupOs(logger)
	if errOsDependant != nil {
		return errOsDependant
	}

	// Return nil as everything went fine
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup() error {

	// Check setup with OS specific implementation
	errOsDependant := checkSetupOs()
	if errOsDependant != nil {
		return errOsDependant
	}

	// Return nil as everything went fine
	return nil
}

type Result struct {
	filecrawler.Result // nfs result wrapped filecrawler result to allow broker distinguishing smb/nfs results by type
}

type Scanner struct {
	Label                     string
	Started                   time.Time
	Finished                  time.Time
	logger                    utils.Logger
	target                    string // Address to be scanned (might be IPv4, IPv6 or hostname)
	crawlDepth                int
	threads                   int
	excludedShares            map[string]struct{} // faster for checking if string is contained than []string
	excludedFolders           map[string]struct{}
	excludedExtensions        map[string]struct{}
	excludedLastModifiedBelow time.Time
	excludedFileSizeBelow     int
	onlyAccessibleFiles       bool      // If true then the scanner only returns files which are readable or writeable
	deadline                  time.Time // Time when the scanner has to abort
	mountTimeout              time.Duration
}

type nfsExport struct {
	name            string
	nfsRestrictions []string
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
	mountTimeout time.Duration, // Acceptable values are 0.8sec, 0.9sec and any value in the range 1-60sec
) (*Scanner, error) {

	// Check whether input target is valid
	if !utils.IsValidAddress(target) {
		return nil, fmt.Errorf("invalid target '%s'", target)
	}

	// On Linux, a base folder needs to be created
	prepareMountBase()

	// Define function to translate a slice into a map, because looking up values within a map is more efficient and
	// will also get rid of duplicates.
	toMap := func(slice []string) map[string]struct{} {
		lookup := make(map[string]struct{}, len(slice))
		for _, e := range slice {
			lookup[e] = struct{}{}
		}
		return lookup
	}

	// Check if excluded shares start with an "/" and add it if they don't
	for i, exShr := range excludedShares {
		if len(exShr) > 0 && string(exShr[0]) != "/" {
			excludedShares[i] = "/" + exShr
		}
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
		time.Time{}, // zero time (no deadline yet set)
		mountTimeout,
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

	// Crawl NFS service
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

// crawl enumerates NFS shares and crawls each of them one by one
func (s *Scanner) crawl() *filecrawler.Result {

	// Initialize result data
	result := &filecrawler.Result{
		Status: utils.StatusCompleted,
	}

	// Initialize filecrawler to crawl exports
	crawler := filecrawler.NewCrawler(
		s.logger,
		s.crawlDepth,
		s.excludedFolders,
		s.excludedExtensions,
		s.excludedLastModifiedBelow,
		int64(s.excludedFileSizeBelow),
		s.onlyAccessibleFiles,
		s.threads,
		s.deadline,
	)

	// Enumerate all Shares from the target and abort if any errors occur
	exports := s.getExports()

	// Log state
	s.logger.Debugf("Enumerated %d export(s) on '%s'.", len(exports), s.target)

	// Run as long as there are shares left to crawl
	for _, export := range exports {

		// Abort if scan deadline was reached
		if utils.DeadlineReached(s.deadline) {
			return result
		}

		// Check if export should be excluded from crawl
		if _, excluded := s.excludedShares[strings.ToLower(export.name)]; excluded {
			s.logger.Debugf("Skipping excluded export '%s'.", export.name)
			continue
		}

		// Crawl export
		shareResult, err := s.crawlExport(crawler, export)
		if err != nil {
			s.logger.Debugf(utils.TitleFirstLetter(err.Error()))
			continue
		}

		// Extract unix file permissions of the file. On Linux, this is already done by the filecrawler. On Linux
		// this must be done additionally.
		s.getUnixFlagsWindows(export.name, shareResult)

		// Update crawl result
		result.FoldersReadable += shareResult.FoldersReadable
		result.FilesWritable += shareResult.FilesWritable
		result.FilesReadable += shareResult.FilesReadable
		result.Data = append(result.Data, shareResult.Data...)
	}

	// Return result
	return result
}

// crawlExport crawls a single export
func (s *Scanner) crawlExport(crawler *filecrawler.Crawler, export nfsExport) (*filecrawler.Result, error) {

	// Initialize result data
	shareResult := &filecrawler.Result{}

	// Try mounting the export to be crawled and create mount point
	mountPoint, err := s.mountExport(export.name, "")
	if err != nil {
		return nil, fmt.Errorf("could not mount export '%s': %s", export.name, err)
	}

	// Clean up mounted exports
	defer func() {

		// Unmount export
		errUnmount := s.unmountExport(mountPoint)
		if errUnmount != nil {
			s.logger.Warningf("Could not unmount export '%s'.", mountPoint)
			return
		}

		// Delete mount point
		errDelete := deleteMountPoint(mountPoint)
		if errDelete != nil {
			s.logger.Warningf("Could not delete '%s'.", mountPoint)
		}
	}()

	// Create data for file crawler
	entryPoint := &filecrawler.EntryPoint{
		Path:    mountPoint,
		Share:   export.name,
		IsShare: true,
	}

	// Crawl with the filesystem crawler
	result := crawler.Crawl(entryPoint)

	// Subtract 1 from readable folders since we do not count them as folders
	if result.FoldersReadable > 0 {
		result.FoldersReadable -= 1
	}

	// Add NFS restrictions
	for _, file := range result.Data {
		file.NfsRestrictions = export.nfsRestrictions
	}

	// Remove the mount point from the export path
	for _, file := range result.Data {
		file.Path = strings.TrimPrefix(file.Path, mountPoint)
	}

	// Update counters
	shareResult.FoldersReadable += result.FoldersReadable
	shareResult.FilesWritable += result.FilesWritable
	shareResult.FilesReadable += result.FilesReadable
	shareResult.Data = append(shareResult.Data, result.Data...)

	// Return result
	return shareResult, nil
}

// getExports returns all exports it can find via "showmount" command and mounting the exported filesystem root (linux)
func (s *Scanner) getExports() []nfsExport {

	// Get all exports that some client mounted, this may discover NFSv3 and NFSv4 exports
	exportsMounted, errMounted := s.getExportsMounted()
	if errMounted != nil {
		s.logger.Debugf("Could not get mounted exports: %s", errMounted)
	}

	// Get all exports exported as NFSv3
	exportsV3, errV3 := s.getExportsV3()
	if errV3 != nil {
		s.logger.Debugf("Could not get NFSv3 exports: %s", errV3)
	}

	// Get all NFSv4 exports (from the NFSv4 export tree)
	exportsV4, errV4 := s.getExportsV4()
	if errV4 != nil {
		s.logger.Debugf("Could not get NFSv4 exports: %s", errV4)
	}

	// Merge NFSv4 exports, without causing duplicates
	for export := range exportsV4 {
		exportsMounted[export] = exportsV4[export]
	}

	// Merge NFSv3 exports, without causing duplicates
	// ATTENTION: Merge NFSv3 exports last, not to be replaced with similar exports from other NFS versions, because
	// they are the only ones with allowed hosts information
	for export := range exportsV3 {
		exportsMounted[export] = exportsV3[export]
	}

	// Prepare result list
	exports := make([]nfsExport, 0, len(exportsMounted))

	// Add discovered and unique exports to result list
	for exportName, allowedHosts := range exportsMounted {
		exports = append(exports, nfsExport{
			name:            exportName,
			nfsRestrictions: allowedHosts,
		})
	}

	// Return discovered exports
	return exports
}

// unmountExport unmounts the export at the mount point
func (s *Scanner) unmountExport(mountPoint string) error {

	// Unmount export
	cmd := fmt.Sprintf("%s umount %s %s", adminRights, unmountArgs, mountPoint)
	out, err := exec.Command(shellToUse, shellArg, cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf(string(out))
	}

	// Return nil as unmounting succeeded
	return nil
}

// getExportsMounted uses the "-a" option of "showmount" to get all exports of the target which are mounted by some
// client. This function can also find NFSv4 exports which are not showing with the "-e" option.
func (s *Scanner) getExportsMounted() (map[string][]string, error) {

	// Prepare memory for export results
	exports := make(map[string][]string)

	// Run command for mounted export enumeration
	cmd := fmt.Sprintf("%s showmount -a %s", adminRights, s.target)
	out, err := exec.Command(shellToUse, shellArg, cmd).CombinedOutput()
	if err != nil {
		return exports, fmt.Errorf(string(out))
	}

	// Split output to single lines
	lines := strings.Split(string(out), "\n")

	// Extract the exports
	for i, line := range lines {

		// Skip first line since it is a headline
		if i == 0 {
			continue
		}

		// Skip empty line
		if len(line) == 0 {
			continue
		}

		// Get the export after the ":" e.g. "server: /export"
		lineSplit := strings.Split(line, ":")
		if len(lineSplit) == 0 {
			continue
		}

		// Get the export of the line, trim the space and add it to exports
		export := strings.TrimSpace(lineSplit[len(lineSplit)-1])
		export = strings.ReplaceAll(export, "\\", "/") // For exports mounted by a windows nfs client (D:\export)
		exports[export] = []string{}
	}

	// Return exports
	return exports, nil
}

// getExportsV3 uses the "-e" option of "showmount" to get all exported directories and hosts with access rights
func (s *Scanner) getExportsV3() (map[string][]string, error) {

	// Prepare memory for export results
	exports := make(map[string][]string)

	// Run command for export enumeration
	cmd := fmt.Sprintf("%s showmount -e %s", adminRights, s.target)
	out, err := exec.Command(shellToUse, shellArg, cmd).CombinedOutput()
	if err != nil {
		return exports, fmt.Errorf(string(out))
	}

	// Convert the output to single lines, remove unnecessary lines and merge lines which belong together
	lines := s.sanitizeShowmountOutput(string(out))

	// Extract the export and the hosts that have an access right for every line
	for _, line := range lines {
		export, allowedHosts := s.extractLine(line)
		if export != "" {
			exports[export] = allowedHosts
		}
	}

	// Return exports
	return exports, nil
}

// The "showmount -e" command sometimes returns multiline results for certain exports. This function merges the split
// lines together for easier processing.
// E.g. for multiline output:
// /vol1/export 		192.xxx.xxx.xxx, 192.xxx.xxx.xxx,
//						192.xxx.xxx.xxx, 192.xxx.xxx.xxx
// is processed to:
// /vol1/export 192.xxx.xxx.xxx, 192.xxx.xxx.xxx, 192.xxx.xxx.xxx, 192.xxx.xxx.xxx
func (s *Scanner) sanitizeShowmountOutput(outStr string) []string {

	// Initialise result data
	var resultLines []string

	// Split the lines
	lines := strings.Split(outStr, "\n")

	// Iterate lines
	for i := 1; i < len(lines); i++ { // ignore first line since it is a headline

		// Get reference to current line processed
		line := lines[i]

		// Check for special case from Windows cmd output, where there is no space between export and allowed hosts
		// when export in the line is 35 characters long, eg. (USIRVA0005PSTO is the allowed host):
		// 	/vol/
		//	v_vf_shc_irv05p_usirva0006gsto_rootUSIRVA0005PSTO
		if !strings.Contains(line, " ") && len(line) > 35 {
			line = line[:35] + " " + line[35:]
		}

		// Replace redundant spaces and tabs with one space
		line = strings.Join(strings.Fields(line), " ")

		// Don't regard empty lines
		if line == "" {
			continue
		}

		// If the line begins with a "/" then this is either a one liner or the beginning of a multiline
		if string(line[0]) == "/" {
			resultLines = append(resultLines, line)
			continue
		}

		// Check for strange lines: If it is a continuation line at the beginning then log and append this as its
		// own line
		if resultLines == nil || len(resultLines) < 1 {
			resultLines = append(resultLines, line)
			s.logger.Errorf("Unexpected output of 'showmount -e' command: %s", line)
			continue
		}

		// Check which separator we need for line merging: "" for path continuation, " " for allowed hosts in multiline
		sep := ""
		if strings.Contains(resultLines[len(resultLines)-1], ",") {
			sep = " "
		}

		// Case where the line is a continuation of the previous line: merge with the previous line
		resultLines[len(resultLines)-1] = fmt.Sprintf("%s%s%s", resultLines[len(resultLines)-1], sep, line)
	}

	// Return unified lines
	return resultLines
}

// extractLine extracts the export name and nfs restrictions from a single line of the "showmount -e" command.
// Potentially, the "showmount" output has to be sanitized with "sanitizeShowmountOutput()" beforehand.
func (s *Scanner) extractLine(line string) (string, []string) {
	var allowedHosts []string

	// Splits the line into 2 strings (export and hosts)
	exportAndHosts := strings.SplitN(line, " ", 2)

	// Check for the special case that the line has an export but no allowed hosts
	if len(exportAndHosts) == 1 && // Normally we would expect at least two elements (an export and min. one host)
		exportAndHosts[0] != "" && // Check that the export element is not empty...
		string(exportAndHosts[0][0]) == "/" { // ... and a regular export (begins with a "/")
		return exportAndHosts[0], nil // Then return only the export (and no error)

		// Log this line otherwise, since it is unexpected
	} else if len(exportAndHosts) < 2 {
		s.logger.Errorf("Unexpected showmount output line on '%s': %s", s.target, line)
		return "", nil
	}

	// Extract export and the corresponding hosts
	exportName := exportAndHosts[0]
	hostList := strings.SplitAfter(exportAndHosts[1], ",")

	// Check if host is a special case and add it to the list of allowed hosts
	for i := 0; i < len(hostList); i++ {
		host := hostList[i]

		// If the hostname is not the last and has no "," at the end then it means that the next word belongs to it
		// So add them together and skip the next element. Eg. "Alle Computer"
		if !strings.Contains(host, ",") && i+1 < len(hostList) {
			host = fmt.Sprintf("%s %s", host, hostList[i+1])
			i++
		}

		// Save the found hosts
		allowedHosts = append(allowedHosts, strings.Trim(host, ", "))
	}
	return exportName, allowedHosts
}
