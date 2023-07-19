/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2023.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webcrawler

import (
	"fmt"
	"github.com/siemens/GoScans/utils"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Label = "Webcrawler"
const fingerprintBodySimilarity = 200

const dlFileName = "download_urls.csv"
const dlFileHeader = "Date;URL;Required Host Header"
const timestampFormat = "2006-01-02 15:04:05.123 -0700"

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
	Data      []*CrawlResult
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

// hrefInfo is a helper struct that get's sent to the appendHrefsWorker. It contains all the information needed to
// append a new entry to the href file.
type hrefInfo struct {
	downloadUrls  []string
	requiredVHost string
	timestamp     time.Time
}

// nilInfoErr is a custom error, that gives the caller of appendHrefsWorker the possibility to differentiate between
// severe and minor errors.
type nilInfoErr struct{}

func (e *nilInfoErr) Error() string {
	return fmt.Sprintf("received info is nil")
}

type Scanner struct {
	Label          string
	Started        time.Time
	Finished       time.Time
	logger         utils.Logger
	target         string // Address to be scanned (might be IPv4, IPv6 or hostname)
	port           int
	vhosts         []string
	https          bool
	depth          int
	maxThreads     int    // Amount of parallel HTTP requests
	followQS       bool   // Whether to consider URls with different query strings as different locations
	storeRoot      bool   // Whether to _always_ store first page, independent of response code
	download       bool   // Whether to download files. If download is disabled, files URLs will be stored
	outputFolder   string // Path to save download files at, respectively download URLs
	ntlmDomain     string // (Optional) credentials for NTLM authentication
	ntlmUser       string // ...
	ntlmPassword   string // ...
	userAgent      string
	proxy          *url.URL
	followTypes    []string
	downloadTypes  []string
	deadline       time.Time // Time when the scanner has to abort
	requestTimeout time.Duration

	running           bool                              // follow/download response content types can only be updated until running
	knownFingerprints map[string]*utils.HttpFingerprint // Fingerprints are used to detect redundant responses with different vhosts
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	vhosts []string,
	https bool,
	depth int,
	maxThreads int,
	followQS bool,
	storeRoot bool,
	download bool,
	outputFolder string,
	ntlmDomain string,
	ntlmUser string,
	ntlmPassword string,
	userAgent string,
	proxy string,
	requestTimeout time.Duration,
) (*Scanner, error) {

	// Check whether input target is valid
	if !utils.IsValidAddress(target) {
		return nil, fmt.Errorf("invalid target '%s'", target)
	}

	// Check whether given credentials are plausible
	if !utils.ValidOrEmptyCredentials(ntlmDomain, ntlmUser, ntlmPassword) {
		return nil, fmt.Errorf("ntlm credentials incomplete")
	}

	if download {
		// Prepare output path
		var errAbs error
		outputFolder, errAbs = filepath.Abs(outputFolder)
		if errAbs != nil {
			return nil, errAbs
		}

		// This check is also performed during unmarshal, but that only accounts for errors in the json
		if errFolder := utils.IsValidFolder(outputFolder); errFolder != nil {
			return nil, fmt.Errorf("invalid output folder '%s'", outputFolder)
		}
	} else {
		// Prepare download output file - This is not necessarily needed, because the worker will also call
		// prepareHrefsFile if needed. But it's a nice way to check up front and return an error early.
		outputFile := filepath.Join(outputFolder, dlFileName)
		errPrepare := prepareHrefsFile(outputFile, dlFileHeader)
		if errPrepare != nil {
			return nil, fmt.Errorf("could not prepare output file '%s': %s", outputFile, errPrepare)
		}
	}

	// Prepare proxy, *url.URL with appropriate scheme required
	proxyUrl, errProxy := utils.ProxyStringToUrl(proxy) // Returns nil proxy on empty input
	if errProxy != nil {
		return nil, errProxy
	}

	// Sanitize list of input vhosts
	vhosts = utils.Filter(vhosts, func(vhost string) bool { return utils.IsValidHostname(vhost) })

	// Remove current target from vhosts, it will be used first anyways
	vhosts = utils.Filter(vhosts, func(vhost string) bool { return vhost != target })

	// Remove duplicates
	vhosts = utils.UniqueStrings(vhosts)

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		strings.TrimSpace(target), // Address to be scanned (might be IPv4, IPv6 or hostname)
		port,
		vhosts,
		https,
		depth,
		maxThreads,
		followQS,
		storeRoot,
		download,
		outputFolder,
		ntlmDomain,
		ntlmUser,
		ntlmPassword,
		userAgent,
		proxyUrl,
		DefaultFollowContentTypes,
		DefaultDownloadContentTypes,
		time.Time{}, // zero time (no deadline yet set)
		requestTimeout,
		false,
		make(map[string]*utils.HttpFingerprint),
	}

	// Return scan struct
	return &scan, nil
}

// SetFollowContentTypes allows to set a custom none-default list of response content types to be followed during
// crawling a website.
func (s *Scanner) SetFollowContentTypes(responseContentTypes []string) error {
	if s.running {
		return fmt.Errorf("crawler already running")
	}
	s.followTypes = responseContentTypes
	return nil
}

// SetDownloadContentTypes allows to set a custom none-default list of response content types to be downloaded during
// crawling a website.
func (s *Scanner) SetDownloadContentTypes(responseContentTypes []string) error {
	if s.running {
		return fmt.Errorf("crawler already running")
	}
	s.downloadTypes = responseContentTypes
	return nil
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Set running flag to disallow updating follow/download content types
	s.running = true

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf(fmt.Sprintf("Unexpected error: %s", r))

			// Build error status from error message and formatted stacktrace
			errMsg := fmt.Sprintf("%s%s", r, utils.StacktraceIndented("\t"))

			// Return result set indicating exception
			res = &Result{
				nil,
				errMsg,
				true,
			}
		}
	}()

	// Set scan started flag and calculate deadline
	s.Started = time.Now()
	s.deadline = time.Now().Add(timeout)
	s.logger.Infof("Started  scan of %s:%d.", s.target, s.port)

	// Execute scan logic
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s:%d in %fm.", s.target, s.port, duration)

	// Return result set
	return res
}

func (s *Scanner) execute() *Result {

	// Declare result variable to be returned
	var results []*CrawlResult

	// Declare the variables needed for appending the hrefs to a file
	var (
		appendHrefChan     chan *hrefInfo
		appendHrefStopChan chan struct{}
		appendHrefErrChan  chan error
	)

	// Launch download handler if required
	if !s.download {

		// Actually init the variables needed for appending the hrefs to a file
		appendHrefChan = make(chan *hrefInfo, 20)
		appendHrefStopChan = make(chan struct{})
		appendHrefErrChan = make(chan error, 1)

		// Start the worker routine
		go appendHrefsWorker(
			s.logger,
			appendHrefStopChan,
			appendHrefErrChan,
			filepath.Join(s.outputFolder, dlFileName),
			appendHrefChan,
			timestampFormat,
		)

		// Stop the routine, print any remaining errors and close the channels
		defer func() {

			// Close channels
			close(appendHrefStopChan)
			close(appendHrefChan)

			// Check if there are any errors remaining. The channel will be closed by the sender (/worker)
			for errAppend := range appendHrefErrChan {
				if errAppend != nil {
					if _, ok := errAppend.(*nilInfoErr); ok {
						s.logger.Debugf("Download link info was nil")
					} else {
						s.logger.Errorf("Could not write download URLs to disk: %s", errAppend)
					}
				}
			}
		}()
	}

	// Create URL representation of target. This will be comfortable to print current URLs and does hold all necessary
	// information in one struct
	currentRequestUrl := &url.URL{}
	currentRequestUrl.Host = fmt.Sprintf("%s:%d", s.target, s.port)
	if s.https {
		currentRequestUrl.Scheme = "https"
	} else {
		currentRequestUrl.Scheme = "http"
	}

	// Add current target address as the first vhost be used
	vHosts := append([]string{s.target}, s.vhosts...)

	// Prepare memory for remaining and completed vhosts
	var vHostsRemaining = vHosts
	var vHostsCompleted []string

	// Execute scan with all vhosts. Iterate while there is something in vHosts, because the slice might shrink or
	// expand during processing.
	for len(vHostsRemaining) > 0 {

		// Reset loop data
		currentRequestUrl.Path = ""

		// Select vhost for loop cycle
		currentVhost := vHostsRemaining[0]

		// Log cycle
		s.logger.Debugf("Crawling '%s' with vhost '%s'.", currentRequestUrl.String(), currentVhost)

		// Prepare requester for this vhost. As this requester will only send a single test request, we can directly
		// set the operation mode to "reuse none", so no data or connection will be kept alive.
		vhostReq := utils.NewRequester(
			utils.ReuseNone,
			s.userAgent,
			s.ntlmDomain,
			s.ntlmUser,
			s.ntlmPassword,
			s.proxy,
			s.requestTimeout,
			utils.InsecureTransportFactory,
			utils.ClientFactory,
		)

	Start:
		// Send test request
		s.logger.Debugf("Sending test request (%s).", currentRequestUrl.Scheme)
		testResp, _, _, errTest := vhostReq.Get(currentRequestUrl.String(), currentVhost)
		if errTest != nil {
			s.logger.Debugf("Endpoint not reachable, aborting scan.")
			return &Result{
				results,
				utils.StatusNotReachable,
				false,
			}
		}

		// Read test request's body
		testHtmlBytes, _, errTestHtml := utils.ReadBody(testResp)
		if errTestHtml != nil {
			s.logger.Debugf("Could not read response body: %s", errTestHtml)
			testHtmlBytes = []byte{}
		}

		// Close body reader. Needs to happen now, cannot be done with defer statement!
		_ = testResp.Body.Close()

		// Check for wrong HTTP protocol, sometimes SSL endpoints accept HTTP requests but return an error indicator
		if utils.HttpsIndicated(testResp, testHtmlBytes) {

			// Switch to HTTPS
			s.logger.Debugf("Switching from HTTP to HTTPS due to response indicator.")
			currentRequestUrl.Scheme = "https"

			// Send test request again
			goto Start
		}

		// Check for proxy error
		if s.proxy != nil && testResp.StatusCode == 502 {
			s.logger.Debugf("Sending request via proxy failed.")
			return &Result{
				results,
				utils.StatusProxyError,
				false,
			}
		}

		// Check whether same response was previously seen with other vhost
		if seenWith := s.vhostResponseKnown(currentVhost, testResp, testHtmlBytes); seenWith != "" {
			s.logger.Debugf("Skipping vhost '%s', because response is similar to vhost '%s'.", currentVhost, seenWith)

			// Move first item from remaining (current vhost) to completed
			vHostsRemaining = vHostsRemaining[1:]
			vHostsCompleted = append(vHostsCompleted, currentVhost)

			// Proceed with next vhost
			continue
		}

		// Initiate web crawler for vhost
		// Crawler will just return current state when running into timeout. This loop will detect the timeout and
		// return temporary data with according timeout status at the end of the loop.
		crawler, errNew := NewCrawler(
			s.logger,           // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
			*currentRequestUrl, // Pass by value instead of pointer for better isolation
			currentVhost,
			s.https,
			s.depth,
			s.followQS,
			s.storeRoot,
			s.download,
			s.outputFolder,
			s.ntlmDomain,
			s.ntlmUser,
			s.ntlmPassword,
			s.userAgent,
			s.proxy,
			s.requestTimeout,
			s.followTypes,
			s.downloadTypes,
			s.maxThreads,
			s.deadline,
		)
		if errNew != nil {
			s.logger.Debugf("Initializing crawler failed.")
			return &Result{
				results,
				utils.StatusNotReachable,
				false,
			}
		}

		// Start crawling and block until results are returned
		r := crawler.Crawl()

		// Log crawling states
		s.logger.Debugf(
			"%d pages crawled with %d requests (Complete: %d, Redirect %d, Partial: %d)",
			len(r.Pages),
			r.RequestsTotal,
			r.RequestsComplete,
			r.RequestsRedirect,
			r.RequestsPartial,
		)

		// Append to result set
		results = append(results, r)

		// Add newly discovered subdomains to remaining vhosts
		for _, discoveredVhost := range r.DiscoveredVhosts {
			if !utils.StrContained(discoveredVhost, vHostsRemaining, vHostsCompleted) {
				vHostsRemaining = append(vHostsRemaining, discoveredVhost)
			}
		}

		// Write download links to output file
		if !s.download {
			appendHrefChan <- &hrefInfo{
				downloadUrls:  r.DiscoveredDownloads,
				requiredVHost: currentVhost,
				timestamp:     time.Now(),
			}
			// Check for new errors regularly
			select {
			case errAppend := <-appendHrefErrChan:
				if errAppend != nil {
					if _, ok := errAppend.(*nilInfoErr); ok {
						s.logger.Debugf("Download link info was nil")
					} else {
						s.logger.Errorf("Could not write download URLs to disk: %s", errAppend)
					}
				}
			default:
			}
		}

		// Move first item from remaining (current vhost) to completed
		vHostsRemaining = vHostsRemaining[1:]
		vHostsCompleted = append(vHostsCompleted, currentVhost)

		// Check whether scan timeout is reached
		if utils.DeadlineReached(s.deadline) {
			s.logger.Debugf("Scan ran into timeout.")

			// Log outstanding work
			left := utils.Map(vHostsRemaining, func(e string) string { return "'" + e + "'" })
			s.logger.Debugf("Aborted vhost '%s', skipping vhosts %s.", currentVhost, strings.Join(left, ","))

			// Return temporary results with timeout flag
			return &Result{
				results,
				utils.StatusDeadline,
				false,
			}
		}
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

// vhostResponseKnown checks whether a given vhost response was already seen with a previous vhost. Returns the
// previous vhost, or an empty string if a response is new.
func (s *Scanner) vhostResponseKnown(vhost string, resp *http.Response, respBody []byte) string {

	// Create fingerprint of HTTP response
	fingerprint := utils.NewHttpFingerprint(
		resp.Request.URL.String(),
		resp.StatusCode,
		utils.ExtractHtmlTitle(respBody),
		string(respBody),
	)

	// Compare if similar fingerprint was already observed
	seenWith, known := fingerprint.KnownIn(s.knownFingerprints, fingerprintBodySimilarity)

	// Return true if so
	if known {
		return seenWith
	}

	// If fingerprint is new, add it to memory
	s.knownFingerprints[vhost] = fingerprint

	// Return false as fingerprint is new
	return ""
}

func prepareHrefsFile(filePath string, header string) error {

	// Check whether path is existing and a not a directory
	info, errStat := os.Stat(filePath)
	existing := !os.IsNotExist(errStat)

	// Check validity or try to create file
	if existing {
		if info.IsDir() { // File path is existing but a folder
			return fmt.Errorf("'%s' is a directory", filePath)
		}
	} else {
		// Return on error
		file, errOpen := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0660)
		if errOpen != nil {
			return errOpen
		}

		// Make sure file gets closed on exit
		defer func() { _ = file.Close() }()

		// Write file header if necessary
		_, errWrite := file.WriteString(header + "\n")
		if errWrite != nil {
			return errWrite
		}
	}

	// Return nil as everything went fine
	return nil
}

func appendHrefsWorker(
	logger utils.Logger,
	stopCh chan struct{},
	errCh chan error,
	filePath string,
	infoQueue chan *hrefInfo,
	timestampFormat string,
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Closure that will simply drain the queue if we run into an error, so we do not block the main program
	drainFunc := func() {
		for {
			select {
			case <-stopCh:
				// Return so the routine can terminate
				return
			case _ = <-infoQueue:
			default:
				time.Sleep(time.Millisecond * 10)
			}
		}
	}

	// Make sure the routine closes the error channel and signalizes it's termination
	defer close(errCh)

	// Make sure path is not a directory
	if errDir := utils.IsValidFile(filePath); errDir != nil {

		// Try to create file with header line
		errPrepare := prepareHrefsFile(filePath, dlFileHeader)
		if errPrepare != nil {
			errCh <- fmt.Errorf("could not (re-)create output file '%s': %s", filePath, errPrepare)
			drainFunc()
			return
		}
	}

	// Open file for appending
	file, errOpen := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0660)
	if errOpen != nil {
		errCh <- fmt.Errorf("could not open output file: %s", errOpen)
		drainFunc()
		return
	}

	// Make sure file gets closed on exit
	defer func() { _ = file.Close() }()

	stop := false
	for {
		select {
		case <-stopCh:
			// Return nil as everything went fine
			stop = true
		case info, ok := <-infoQueue:
			// Exit the loop if the channel was closed (stop channel must still be closed by caller!)
			if !ok {
				stop = true
				continue
			}

			if info == nil {
				// Send a custom error, so the caller can differentiate and act accordingly
				errCh <- &nilInfoErr{}
				continue
			}

			// Write urls
			for _, downloadUrl := range info.downloadUrls {
				_, errWrite := file.WriteString(
					fmt.Sprintf("%s;%s;%s\n", info.timestamp.Format(timestampFormat), downloadUrl, info.requiredVHost))

				// On error drain the queue for the remaining time
				if errWrite != nil {
					errCh <- fmt.Errorf("cloud not write to file: %s", errWrite)
					drainFunc()
					return
				}
			}
		default:
			time.Sleep(time.Millisecond * 10)
		}
		if stop {
			break
		}
	}

	// Write any remaining urls before returning
	for info := range infoQueue {
		if info == nil {
			// Send a custom error, so the caller can differentiate and act accordingly
			errCh <- &nilInfoErr{}
			continue
		}

		// On error drain the queue for the remaining time
		for _, downloadUrl := range info.downloadUrls {
			_, errWrite := file.WriteString(
				fmt.Sprintf("%s;%s;%s\n", info.timestamp.Format(timestampFormat), downloadUrl, info.requiredVHost))
			if errWrite != nil {
				errCh <- fmt.Errorf("cloud not write to file: %s", errWrite)
				drainFunc()
				return
			}
		}
	}
}
