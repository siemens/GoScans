/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webenum

import (
	"bufio"
	"fmt"
	"go-scans/utils"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Label = "Webenum"
const fingerprintBodySimilarity = 10
const dummyUri = "notexistingdummyuri.req"

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger) error {
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup() error {
	return nil
}

type Probe struct {
	Name    string
	Path    string
	Matches []string
}

type EnumItem struct {
	Name                string
	Vhost               string
	Url                 string
	RedirectUrl         string // Final URL the request got redirected to. Might be inside or outside of original endpoint.
	RedirectCount       int    // Number of redirects that happened until the final URL was reached
	RedirectOut         bool   // Indicates whether the redirect left the original endpoint
	AuthMethod          string
	AuthSuccess         bool
	ResponseCode        int
	ResponseMessage     string
	ResponseContentType string
	ResponseHeaders     string
	ResponseEncoding    string // The encoding used to decode the response body returned by the server. Decided based on response headers, meta tags and trial and error.
	HtmlTitle           string
	HtmlContent         []byte
}

type Result struct {
	Data      []*EnumItem
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

type Scanner struct {
	Label          string
	Started        time.Time
	Finished       time.Time
	logger         utils.Logger
	target         string
	port           int
	vhosts         []string
	https          bool
	ntlmDomain     string // (Optional) credentials for NTLM authentication
	ntlmUser       string // ...
	ntlmPassword   string // ...
	probeRobots    bool   // Whether to request the robots.txt for additional probe URLs
	probes         []Probe
	userAgent      string
	proxy          *url.URL
	deadline       time.Time // Time when the scanner has to abort
	requestTimeout time.Duration
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	vhosts []string,
	https bool,
	ntlmDomain string,
	ntlmUser string,
	ntlmPassword string,
	probesFile string,
	probeRobots bool,
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

	// Prepare proxy, *url.URL with appropriate scheme required
	proxyUrl, errProxy := utils.ProxyStringToUrl(proxy) // Returns nil proxy on empty input
	if errProxy != nil {
		return nil, errProxy
	}

	// Prepare path to probes
	var errAbs error
	probesFile, errAbs = filepath.Abs(probesFile)
	if errAbs != nil {
		return nil, errAbs
	}

	// Check if path to probes is valid
	if errProbesPath := utils.IsValidFile(probesFile); errProbesPath != nil {
		return nil, errProbesPath
	}

	// Load probes
	probes, errLoad := loadProbes(probesFile)
	if errLoad != nil {
		return nil, fmt.Errorf("could not load probes: %s", errLoad)
	}

	// Sanitize list of input vhosts
	vhosts = utils.Filter(vhosts, func(vhost string) bool { return utils.IsValidHostname(vhost) })

	// Remove current target from vhosts, it will be used first anyways
	vhosts = utils.Filter(vhosts, func(vhost string) bool { return vhost != target })

	// Remove duplicates
	vhosts = utils.UniqueStrings(vhosts)

	// Initiate scan
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		strings.TrimSpace(target), // Address to be scanned (might be IPv4, IPv6 or hostname)
		port,
		vhosts,
		https,
		ntlmDomain,
		ntlmUser,
		ntlmPassword,
		probeRobots,
		probes,
		userAgent,
		proxyUrl,
		time.Time{}, // zero time (no deadline yet set)
		requestTimeout,
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
	var results []*EnumItem

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

	// Prepare storage of fingerprints. Fingerprints are used to detect redundant responses with different vhosts
	knownFingerprints := make(map[string]*utils.HttpFingerprint)

	// Execute scan with all vhosts
	for i, currentVhost := range vHosts {

		// Prepare loop cycle
		currentRequestUrl.Path = ""

		// Log step
		s.logger.Debugf("Enumerating with vhost '%s'.", currentVhost)

		// Prepare requester for crawling this vhost. Use a fresh client for each request but reuse the transport.
		// Reusing a transport layer allows to keep connection states alive and to reuse them. We do NOT want to use
		// cached application data (e.g. cookies), so we will just reuse the transport layer, not the client layer.
		vhostReq := utils.NewRequester(
			utils.ReuseTransport,
			s.userAgent,
			s.ntlmDomain,
			s.ntlmUser,
			s.ntlmPassword,
			s.proxy,
			s.requestTimeout,
			utils.InsecureTransportFactory,
			utils.ClientFactory,
		)

		// Prepare dummy request
		currentRequestUrl.Path = dummyUri

		// Send dummy request
		s.logger.Debugf("Sending dummy request.")
		dummyResp, _, _, errDummy := vhostReq.Get(currentRequestUrl.String(), currentVhost)
		if errDummy != nil {
			s.logger.Debugf("Endpoint not reachable, aborting scan.")
			return &Result{
				results,
				utils.StatusNotReachable,
				false,
			}
		}

		// Read dummy request's body
		dummyHtmlBytes, _, errDummyHtml := utils.ReadBody(dummyResp)
		if errDummyHtml != nil {
			s.logger.Debugf("Could not read response body: %s", errDummyHtml)
			dummyHtmlBytes = []byte{}
		}

		// Close body reader. Needs to happen now, cannot be done with defer statement!
		_ = dummyResp.Body.Close()

		// Check for wrong HTTP protocol, sometimes SSL endpoints accept HTTP requests but return an error indicator
		if utils.HttpsIndicated(dummyResp, dummyHtmlBytes) {

			// Switch to HTTPS
			s.logger.Debugf("Switching from HTTP to HTTPS due to response indicator.")
			currentRequestUrl.Scheme = "https"

			// Retry dummy request with https
			s.logger.Debugf("Sending dummy request (https).")
			dummyResp, _, _, errDummy = vhostReq.Get(currentRequestUrl.String(), currentVhost)
			if errDummy != nil {
				s.logger.Debugf("HTTPs endpoint not reachable, aborting scan.")
				return &Result{
					results,
					utils.StatusNotReachable,
					false,
				}
			}

			// Read https dummy request's body
			dummyHtmlBytes, _, errDummyHtml = utils.ReadBody(dummyResp)
			if errDummyHtml != nil {
				s.logger.Debugf("Could not read response body (https): %s", errDummyHtml)
				dummyHtmlBytes = []byte{}
			}

			// Close https body reader. Needs to happen now, cannot be done with defer statement!
			_ = dummyResp.Body.Close()
		}

		// Create fingerprint of website from dummy response
		fingerprint := utils.NewHttpFingerprint(
			dummyResp.Request.URL.String(),
			dummyResp.StatusCode,
			utils.ExtractHtmlTitle(dummyHtmlBytes),
			string(dummyHtmlBytes),
		)

		// Evaluate fingerprint, whether it was previously seen
		if known, seenWith := utils.HttpFingerprintKnown(knownFingerprints, fingerprint, fingerprintBodySimilarity); known {
			s.logger.Debugf("Same response as with vhost '%s', skipping '%s'.", seenWith, currentVhost)
			continue
		} else {
			knownFingerprints[currentVhost] = fingerprint
		}

		// Check for proxy error
		if s.proxy != nil && dummyResp.StatusCode == 502 {
			s.logger.Debugf("Sending request via proxy failed.")
			return &Result{
				results,
				utils.StatusProxyError,
				false,
			}
		}

		// Validate if dummy request returned 200 OK
		dummyIs200 := false
		if dummyResp.StatusCode == 200 {
			s.logger.Debugf("Target always responds 200 OK.")
			dummyIs200 = true
		}

		// Discover additional probes reading robots.txt
		var probesRobots []Probe
		var errRobots error
		if s.probeRobots {
			s.logger.Debugf("Requesting robots.txt.")
			currentRequestUrl.Path = "robots.txt"
			probesRobots, errRobots = loadProbesRobots(vhostReq, currentRequestUrl.String(), currentVhost)
			if errRobots != nil {
				s.logger.Debugf("Could not request robots.txt: %s", errRobots)
			} else {
				s.logger.Debugf("Discovered %d probes via robots.txt.", len(probesRobots))
			}
		}

		// Expand probes with robots.txt URLs
		probes := append(s.probes, probesRobots...)

		// Iterate probes
		// Do sequentially, don't overload the target host. Parallelize by target.
		for _, probe := range probes {

			// Check whether scan timeout is reached
			// Validate on top of the loop, "continue" statements might delay reaching this loop's bottom
			if utils.DeadlineReached(s.deadline) {
				s.logger.Debugf("Scan ran into timeout.")

				// Log outstanding work
				left := utils.Map(vHosts[i:], func(e string) string { return "'" + e + "'" })
				s.logger.Debugf(
					"Aborted vhost '%s', skipping vhosts %s.", currentVhost, strings.Join(left, ","))

				// Return temporary results with timeout flag
				return &Result{
					results,
					utils.StatusDeadline,
					false,
				}
			}

			// Skip probe if it can't be validated. If host always responds with 200 OK, we cannot decide based on
			// response status codes and need other measures, such as string matches. If no string matches are
			// available, we cannot validate the response without causing a lot of false-positives.
			if dummyIs200 && len(probe.Matches) == 0 {
				continue
			}

			// Update request URL path to next probe
			currentRequestUrl.Path = probe.Path

			// Log step
			s.logger.Debugf("Requesting '%s' (vhost '%s').", currentRequestUrl.String(), currentVhost)

			// Send probe request
			resp, redirects, foundAuth, errSend := vhostReq.Get(currentRequestUrl.String(), currentVhost)
			if errSend != nil {
				// Abort complete scan if request failed due to connection issue
				s.logger.Debugf("Probe failed: %s", errSend)
				continue
			}

			// Skip probe evaluation on proxy error
			if s.proxy != nil && resp.StatusCode == 502 {
				s.logger.Infof("Proxy error.", currentRequestUrl.String(), currentVhost)
				continue
			}

			// Read probe response body
			htmlBytes, htmlEncoding, errHtml := utils.ReadBody(resp)
			if errHtml != nil {
				s.logger.Infof("Could not read response body.")
				continue
			}

			// Close body reader. Needs to happen now, cannot be done with defer statement!
			_ = resp.Body.Close()

			// Check response content type
			responseType := strings.ToLower(resp.Header.Get("content-type"))
			if strings.Contains(responseType, ";") { // Content type might contain encoding declaration to be removed
				responseType = strings.Split(responseType, ";")[0]
			}

			// Check if scope changed. It's okay in case of the web enumerator, but we want to remember.
			outsideScope := !utils.SameScope(resp.Request.URL, currentRequestUrl)

			// Detect whether successful authentication took place
			authSuccess := false
			if foundAuth != "" && resp.StatusCode != http.StatusUnauthorized {
				authSuccess = true
			}

			// Validate probe response
			if !dummyIs200 && (resp.StatusCode >= 200 && resp.StatusCode <= 399) {

				// Decision can be based on status code as dummy request indicated working status codes
				s.logger.Debugf("Probe request succeeded by status code.")
				results = append(results, &EnumItem{
					Name:                probe.Name,
					Vhost:               currentVhost,
					Url:                 currentRequestUrl.String(),
					RedirectUrl:         resp.Request.URL.String(),
					RedirectCount:       redirects,
					RedirectOut:         outsideScope,
					AuthMethod:          foundAuth,
					AuthSuccess:         authSuccess,
					ResponseCode:        resp.StatusCode,
					ResponseMessage:     resp.Status,
					ResponseContentType: responseType,
					ResponseHeaders:     utils.FormattedHeader(resp.Header),
					ResponseEncoding:    htmlEncoding,
					HtmlTitle:           utils.ExtractHtmlTitle(htmlBytes),
					HtmlContent:         htmlBytes,
				})
			} else if dummyIs200 && len(probe.Matches) > 0 {

				// Decision must be based on string matches as dummy request did not indicate working status codes
				for _, stringMatch := range probe.Matches {

					// Check if string match is contained within HTML body
					probeRespContent := strings.ToLower(string(htmlBytes))
					if strings.Contains(probeRespContent, strings.ToLower(stringMatch)) {

						// Valid string match found, probe succeeded
						s.logger.Debugf("Probe request succeeded by string matching.")
						results = append(results, &EnumItem{
							Name:                probe.Name,
							Vhost:               currentVhost,
							Url:                 currentRequestUrl.String(),
							RedirectUrl:         resp.Request.URL.String(),
							RedirectCount:       redirects,
							RedirectOut:         outsideScope,
							AuthMethod:          foundAuth,
							AuthSuccess:         authSuccess,
							ResponseCode:        resp.StatusCode,
							ResponseMessage:     resp.Status,
							ResponseContentType: responseType,
							ResponseHeaders:     utils.FormattedHeader(resp.Header),
							HtmlTitle:           utils.ExtractHtmlTitle(htmlBytes),
							HtmlContent:         htmlBytes,
						})

						// Stop string matching, as first success is already enough, and continue with for loop
						break
					}
				}
			} else {
				// Probe request couldn't discover anything on this host.
				// Either no successful response status code, or no string matches
			}
		}
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result.")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

func loadProbes(path string) ([]Probe, error) {
	var probes []Probe

	// Open file
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return nil, errOpen
	}

	// Make sure probes file is closed again
	defer func() { _ = file.Close() }()

	// Create scanner for file
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Parse lines
	for i, line := range lines {

		// Trim whitespaces and trailing pipe symbols
		line = strings.Trim(line, " |")

		// Skip line if it is empty or a comment
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}

		// Split data
		data := strings.Split(line, "|")

		// Check line validity
		if len(data) < 2 {
			return nil, fmt.Errorf("invalid probe definition (line %d)", i)
		}

		// Extract string matches if available
		var matches []string
		if len(data) > 2 {
			for i := 2; i < len(data); i++ {
				if len(data[i]) > 0 {
					matches = append(matches, data[i])
				}
			}
		}

		// Append probe
		probes = append(probes, Probe{
			data[0],
			data[1],
			matches,
		})
	}

	// Return loaded probes
	return probes, nil
}

func loadProbesRobots(requester *utils.Requester, robotsUrl string, vName string) ([]Probe, error) {
	var probes []Probe
	var matches []string

	// Send robots request
	resp, _, _, errSend := requester.Get(robotsUrl, vName)
	if errSend != nil {
		return probes, errSend
	}

	// Make sure body reader gets closed on exit
	defer func() { _ = resp.Body.Close() }()

	// Get response body
	if resp.StatusCode == 200 {

		// Read body
		htmlBytes, _, errHtml := utils.ReadBody(resp)
		if errHtml != nil {
			return probes, errHtml
		}

		// Convert body to string
		body := string(htmlBytes)

		// Parse body
		for _, line := range strings.Split(body, "\n") {

			// Sanitize line
			line = strings.ToLower(strings.TrimSpace(line))

			// Detect relevant line
			var category string
			if strings.HasPrefix(line, "disallow:") {
				category = "Disallowed by robots.txt"
			} else if strings.HasPrefix(line, "sitemap:") {
				category = "Sitemap by robots.txt"
			} else {
				// Skip irrelevant line
				continue
			}

			// Extract paths from line
			paths := pathsFromRobotsLine(line)

			// Iterate paths and add them as probes
			for _, path := range paths {

				// Convert potentially absolute paths to relative ones
				relPath := utils.UrlToRelative(path)

				// Continue if path is not root
				if relPath != "/" && relPath != "" {

					// Create and add probe
					probes = append(probes, Probe{
						category,
						relPath,
						matches,
					})
				}
			}
		}
	}

	// Return discovered probes
	return probes, nil
}

func pathsFromRobotsLine(line string) []string {
	withoutKey := strings.Split(line, ":")[1:] // Split by colon and remove first element
	value := strings.Join(withoutKey, ":")     // Re-join remaining elements (might have been more)
	value = strings.TrimSpace(value)           // Sanitize path
	paths := strings.Split(value, ",")         // Separate multiple paths into slice
	for i := 0; i < len(paths); i++ {
		paths[i] = strings.TrimSpace(paths[i])
	}
	paths = utils.Filter(paths, func(path string) bool { return path != "" }) // Remove empty values
	return paths                                                              // Separate multiple paths into slice
}
