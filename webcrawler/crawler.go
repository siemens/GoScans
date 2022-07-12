/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webcrawler

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"go-scans/utils"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Constants used for the retry mechanism (currently only used for responses containing a 429 status code)
	maxRetries     = 5                               // We don't want to test the failed url indefinitely 5 times has to be enough
	minWait        = 5                               // We wan't to wait at least 15 seconds if no time is specified
	httpDateLayout = "Mon, 02 Jan 2006 15:04:05 MST" // Golang's reference date: Mon Jan 2 15:04:05 -0700 MST 2006
)

var DefaultFollowContentTypes = []string{
	"text/html", "text/plain", "text/javascript", "application/javascript", "application/json", "application/atom+xml",
	"application/rss+xml", "application/xhtml+xml", "application/x-latex", "application/xml", "application/xml-dtd",
	"application/x-sh", "application/x-tex", "application/x-texinfo", "text/cache-manifest", "text/calendar",
	"text/css", "text/csv", "text/csv-schema", "text/directory", "text/dns", "text/ecmascript", "text/encaprtp",
	"text/example", "text/fwdred", "text/grammar-ref-list", "text/jcr-cnd", "text/markdown", "text/mizar", "text/n3",
	"text/parameters", "text/provenance-notation", "text/prs.fallenstein.rst", "text/prs.lines.tag", "text/raptorfec",
	"text/RED", "text/rfc822-headers", "text/rtf", "text/rtp-enc-aescm128", "text/rtploopback", "text/rtx", "text/SGML",
	"text/t140", "text/tab-separated-values", "text/troff", "text/turtle", "text/ulpfec", "text/uri-list", "text/vcard",
	"text/vnd.abc", "text/vnd.debian.copyright", "text/vnd.DMClientScript", "text/vnd.dvb.subtitle",
	"text/vnd.esmertec.theme-descriptor", "text/vnd.fly", "text/vnd.fmi.flexstor", "text/vnd.graphviz",
	"text/vnd.in3d.3dml", "text/vnd.in3d.spot", "text/vnd.IPTC.NewsML", "text/vnd.IPTC.NITF", "text/vnd.latex-z",
	"text/vnd.motorola.reflex", "text/vnd.ms-mediapackage", "text/vnd.net2phone.commcenter.command",
	"text/vnd.radisys.msml-basic-layout", "text/vnd.si.uricatalogue", "text/vnd.sun.j2me.app-descriptor",
	"text/vnd.trolltech.linguist", "text/vnd.wap.si", "text/vnd.wap.sl", "text/vnd.wap.wmlscript", "text/vnd.wap-wml",
	"text/vnd-a", "text/vnd-curl", "text/xml", "text/xml-external-parsed-entity",
}
var DefaultDownloadContentTypes = []string{
	"application/pdf", "application/msword", "application/vnd.ms-excel", "vnd.ms-excel.addin.macroEnabled.12",
	"vnd.ms-excel.sheet.binary.macroEnabled.12", "vnd.ms-excel.sheet.macroEnabled.12",
	"vnd.ms-excel.template.macroEnabled.12", "application/vnd.ms-word.document.macroEnabled.12",
	"vnd.ms-word.template.macroEnabled.12", "application/vnd.ms-word.template.macroEnabled.12",
}

type Page struct {
	Depth               int
	Url                 *url.URL
	RedirectUrl         string // Final URL the request got redirected to. Might be inside or outside of original endpoint.
	RedirectCount       int    // Number of redirects that happened until the final URL was reached
	AuthMethod          string
	AuthSuccess         bool
	ResponseCode        int
	ResponseMessage     string
	ResponseContentType string
	ResponseHeaders     string
	ResponseEncoding    string // The encoding used to decode the response body returned by the server. Decided based on response headers, meta tags and trial and error.
	HtmlTitle           string
	HtmlContent         []byte   // Bytes array, to be converted by consumer as required
	RawLinks            []string // URLs found on that page
}

type CrawlResult struct {
	Vhost               string // The vhost this content was discovered with
	Status              string
	FaviconHash         string
	AuthMethod          string // Authentication methods seen while crawling this target
	AuthSuccess         bool   // Authentication success, if authentication-required was discovered
	RequestsTotal       int    // Amount of HTTP requests in total (except www-authenticate round-trips)
	RequestsRedirect    int    // Amount of HTTP requests, where only the headers were read
	RequestsPartial     int    // Amount of HTTP requests, where only the headers were read
	RequestsComplete    int    // Amount of HTTP requests, where the full response read
	DiscoveredVhosts    []string
	DiscoveredDownloads []string
	Pages               []*Page
}

type task struct {
	id   int32
	page *Page
}

type processResult struct {
	// Temporary data struct returned by the crawler's page processor. Depending on what values are set, the queue
	// crawler will update the crawling result accordingly. Empty values will be ignored. Therefor the result has to be
	// set if crawling the page should be retried!
	taskId             int32    // The task id corresponding to this result
	result             *Page    // Page result to be stored, filled with all data after being processed
	children           []*Page  // Discovered sub pages. Holds URL and depth first, might be crawled and filled later.
	discoveredDownload string   // Discovered download URL
	discoveredVhosts   []string // Discovered hostnames pointing to the same host
	requestsRedirect   int      // Number of requests caused by location redirects
	requestsPartial    int      // Number partial of requests executed
	requestsComplete   int      // Number complete of requests executed
	statusCode         int      // The returned HTTP status code
	retryAfter         uint64   // (optional) Number of seconds to wait if the retry flag is set. If this is smaller or equal to 0, minWaitSec will be used.
}

type Crawler struct {
	logger         utils.Logger
	baseUrl        *url.URL // Pass by value for better isolation and to avoid conflicts with other goroutines
	vhost          string   // Vhost to send along with requests to target right application
	https          bool     // Whether to initiate crawling using HTTPs or HTTP
	maxDepth       int      // Max depth of crawling. 0 = index page only, 1 = index page + direct children,...
	followQS       bool     // Whether to consider URls with different query strings as different locations
	storeRoot      bool     // Whether to _always_ store first page, independent of response code
	download       bool     // Whether to download files. Either way the files' URLs will returned in DiscoveredDownloads
	outputFolder   string   // Path to save download files at, respectively download URLs
	ntlmDomain     string   // (Optional) credentials for NTLM authentication
	ntlmUser       string   // ...
	ntlmPassword   string   // ...
	userAgent      string
	proxy          *url.URL
	requestTimeout time.Duration // Maximum seconds to wait for a request response
	deadline       time.Time     // Time at which the crawler has to abort
	followTypes    []string
	downloadTypes  []string
	targetIp       string           // Used by the crawler to match whether an URL points to the same endpoint
	targetPort     int              // Used by the crawler to match whether an URL points to the same endpoint
	maxThreads     int              // Amount of threads sending requests in parallel
	queue          []*task          // The queue holding the tasks and therefore pages that still need to be processed
	known          map[string]uint8 // A hit-map indicated pages that have already been crawled (and how often)
	nextTaskId     func() int32     // Helper function that returns the next task id
}

func NewCrawler(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	baseUrl url.URL,
	vhost string,
	https bool,
	depth int,
	followQS bool,
	storeRoot bool,
	download bool,
	outputFolder string,
	ntlmDomain string,
	ntlmUser string,
	ntlmPassword string,
	userAgent string,
	proxy *url.URL,
	requestTimeout time.Duration,
	followTypes []string,
	downloadTypes []string,
	maxThreads int,
	deadline time.Time,
) (*Crawler, error) {

	// Validate base URL
	if baseUrl.Scheme != "http" && baseUrl.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme")
	}

	// Remove duplicate follow/download content types
	followTypes = utils.UniqueStrings(followTypes)
	downloadTypes = utils.UniqueStrings(downloadTypes)

	// Make sure most basic follow content type is contained and at first position for efficiency
	basicType := "text/html"
	if len(followTypes) == 0 || followTypes[0] != basicType {
		followTypes = utils.Filter(followTypes, func(followType string) bool { return followType != basicType })
		followTypes = append([]string{basicType}, followTypes...)
	}

	// Make sure at least one crawler thread is set
	if maxThreads <= 0 {
		maxThreads = 1
	}

	// Resolve IP and port of target URL for later use
	host, port := utils.ExtractHostPort(&baseUrl)
	ips, errLookup := net.LookupIP(host)
	if errLookup != nil {
		return nil, errLookup
	}
	ip := ips[0].String()

	// Return initialized web crawler, ready to run
	return &Crawler{
		logger,
		&baseUrl,
		vhost,
		https,
		depth,
		followQS,
		storeRoot,
		download,
		outputFolder,
		ntlmDomain,
		ntlmUser,
		ntlmPassword,
		userAgent,
		proxy,
		requestTimeout,
		deadline,
		followTypes,
		downloadTypes,
		ip,
		port,
		maxThreads,
		make([]*task, 0, 500),
		make(map[string]uint8, 500), // URLs that don't need to be queued, because they were previously found or are to be ignored
		makeCounter(0),
	}, nil
}

func (c *Crawler) Crawl() *CrawlResult {

	// Initialize result data
	result := &CrawlResult{
		c.vhost,
		utils.StatusCompleted,
		"",
		"",
		false,
		0,
		0,
		0,
		0,
		[]string{},
		[]string{},
		[]*Page{},
	}

	// Prepare requester for crawling this target
	requester := utils.NewRequester(
		utils.ReuseTransportAndClient,
		c.userAgent,
		c.ntlmDomain,
		c.ntlmUser,
		c.ntlmPassword,
		c.proxy,
		c.requestTimeout,
		utils.InsecureTransportFactory,
		utils.ClientFactory,
	)

	// Query favicon hash
	c.logger.Debugf("Requesting favicon.")
	currentRequestUrl := *c.baseUrl // Create copy of base URL to avoid manipulation of original struct
	currentRequestUrl.Path = "favicon.ico"
	result.FaviconHash = requestImageHash(requester, currentRequestUrl.String(), c.vhost)
	result.RequestsComplete++

	// Initialize crawler process slots, counter and return channel
	var (
		chTasks          = make(chan *task, 1)                     // Channel over which new tasks are fed to the worker routines
		chProcessResults = make(chan *processResult, c.maxThreads) // Channel containing results returned by worker routines
		chsStop          = make([]chan struct{}, c.maxThreads)     // Slice of channels for every worker. If closed the corresponding worker will terminate
		chActive         = make(chan struct{}, c.maxThreads)       // Channel through which the workers can signal that they are currently active
		wg               sync.WaitGroup                            // Wait group to make sure all the routines have been stopped before we return from the Crawler
	)

	// Initialize the stop channels
	for i := range chsStop {
		chsStop[i] = make(chan struct{})
	}

	// Make sure channels are closed on termination
	defer close(chProcessResults) // Normally this should be closed by the worker (sender), but we have multiple sender that don't know if anybody else is still sending
	defer close(chActive)
	defer close(chTasks)

	// Helper function closing all the remaining stop channels and waiting for the workers to terminate
	// It's important that this function is called before the other defer statements (defers are executed in LIFO order)
	closeStopChs := func() {
		for i := range chsStop {
			c.logger.Debugf("Shutting down worker %d.", i)
			close(chsStop[i])
		}
		chsStop = chsStop[:0]
		// Wait until the routines actually stopped
		wg.Wait()
		c.logger.Debugf("All workers shut down.")
	}
	defer closeStopChs()

	// Set entry point
	entryUrl := *c.baseUrl // Prepare a copy, because it might get manipulated by the crawling process
	c.queue = append(c.queue, &task{
		page: &Page{
			Depth: 0,
			Url:   &entryUrl,
		},
		id: c.nextTaskId(),
	})

	// Start the worker routines
	for i := range chsStop {
		wg.Add(1)
		go c.startWorker(i, requester, chActive, chsStop[i], &wg, chTasks, chProcessResults)
	}

	// Initialize a deadline timer
	deadlineTimer := time.After(time.Until(c.deadline))

	// Counter for consecutive Too Many Requests status codes
	tmrCount := 0

	// Flag will be set when the deadline is reached
	stop := false

	// Manage crawling. Launch new tasks, listen for results and queue new URLs until done or scan timout
	for len(c.queue) > 0 || len(chActive) > 0 || len(chProcessResults) > 0 {
		select {
		case <-deadlineTimer:
			// Don't feed any more tasks and signalize the workers to stop
			closeStopChs()
			stop = true
		case procRes := <-chProcessResults:

			if procRes == nil {
				c.logger.Debugf("Process result is nil, skipping.")
				continue
			}

			// Check if a 429 status code was set in the response and re-initiate a scan of this page
			if procRes.statusCode == http.StatusTooManyRequests {

				c.logger.Debugf("Received 'too many requests' status.")

				// Determine the number of seconds to wait and calculate the time at which the waiting period is reached
				after := procRes.retryAfter
				if after <= 0 {
					after = minWait
				}
				retryTime := time.Now().Add(time.Duration(after) * time.Second)

				// Because we have a buffered channel for the tasks as well as for the results, there will most
				// likely be more TMR statuses coming after we waited for the 'retryAfter' time. Therefore we will
				// count the number of consecutive TMR statuses and wait until there is a sufficient amount of them
				// before we wait at all.
				// This way we will have to re-queue more tasks than absolutely needed, but we will not sleep as often.
				// The addition of cap(chTasks) and cap(chProcessResults) is in case the buffer size will be changed
				// to a bigger value in the future.
				tmrCount++
				if tmrCount >= 2*len(chsStop)+cap(chTasks)+cap(chProcessResults) {

					// Stop a worker if we have more than one remaining
					if len(chsStop) > 1 {
						c.logger.Debugf("Stopping one of %d worker(s).", len(chsStop))
						close(chsStop[len(chsStop)-1])
						chsStop = chsStop[:len(chsStop)-1]
					}

					// Reset the counter
					tmrCount = 0

					c.logger.Debugf("Waiting '%d' seconds.", after)
					time.Sleep(time.Until(retryTime))
				}

				// reEnqueue will only put the task in the queue if the retry time is before the crawler's deadline
				c.reEnqueue(procRes.result, retryTime, procRes.taskId)
				continue
			}

			// Reset the tmrCount as it seems like the server doesn't complain anymore and process the result
			tmrCount = 0
			c.handleResult(procRes, result)

		default:
			if len(c.queue) > 0 {
				// Feed a new task to the workers in a non blocking way and delete it from our queue
				select {
				case chTasks <- c.queue[0]:
					c.queue = c.queue[1:]
				default:
				}

				// Make sure at least one worker is active. Just in case so we don't stop prematurely
				for len(chActive) <= 0 {
					time.Sleep(time.Nanosecond * 5)
				}
			}
		}

		if stop {
			break
		}
	}

	c.logger.Debugf("Processing remaining %d result(s).", len(chActive)+len(chProcessResults))
	// Wait for remaining goroutines to finish (relevant in case of scan timeout)
	for len(chActive) > 0 || len(chProcessResults) > 0 {

		procRes := <-chProcessResults

		// At this point we don't want to requeue the failed tasks as we don't need them anymore. We might have to
		// change this if someone wants to print the remaining tasks.
		if procRes.statusCode == http.StatusTooManyRequests {
			continue
		}

		c.handleResult(procRes, result)
	}

	// Check whether the scan was ended due to the scan timeout
	if utils.DeadlineReached(c.deadline) {
		result.Status = utils.StatusDeadline
		c.logger.Debugf("Crawler finished with timeout.")
	} else {
		c.logger.Debugf("Crawler finished.")
	}

	// Print final status
	c.logger.Debugf("Crawled %d pages.", c.nextTaskId())

	// Calculate total requests
	result.RequestsTotal = result.RequestsRedirect + result.RequestsPartial + result.RequestsComplete

	// Return crawling result
	return result
}

// startWorker is supposed to be called for the worker routines. It will initialize the processing of new tasks and
// stop when the provided stop channel is closed. Furthermore the active channel is supposed to be written to before a
// new task is processed and cleared (/read from) afterwards.
func (c *Crawler) startWorker(
	id int,
	requester *utils.Requester,
	chActive chan struct{},
	chStop chan struct{},
	wg *sync.WaitGroup,
	chTasks chan *task,
	chProcessResults chan<- *processResult,
) {

	c.logger.Debugf("Starting worker %d.", id)

	// Let this routine process tasks until the stop channel gets closed (or something sent to it - not intended)
	for {
		select {
		case <-chStop:
			c.logger.Debugf("Worker %d shutting down.", id)
			wg.Done()
			return
		case target := <-chTasks:
			if target == nil {
				c.logger.Warningf("Worker %d task is nil.", id)
				continue
			}

			// Signalize that we are now starting the actual work
			chActive <- struct{}{}
			c.processTask(requester, target, chProcessResults)
			<-chActive
		}
	}
}

// processTask is the function executed by the workers. It handles the processing of one page defined in the task struct.
// The result will be sent back to the controlling goroutine over the provided channel.
func (c *Crawler) processTask(
	requester *utils.Requester,
	target *task,
	chProcessResults chan<- *processResult,
) {

	// Wrap logger again with local tag to connect log messages of this goroutine
	processLogger := utils.NewTaggedLogger(c.logger, fmt.Sprintf("t%03d", target.id))

	// Check for nil pointers
	if target == nil {

		// Log failed request and return empty result
		processLogger.Debugf("target task is nil")
		chProcessResults <- &processResult{} // Empty result set will not cause any change in the result data
		return
	}
	if requester == nil {

		// Log failed request and return empty result
		processLogger.Debugf("requester is nil")
		chProcessResults <- &processResult{taskId: target.id} // Empty result set will not cause any change in the result data
		return
	}

	// Prepare local variables
	targetPage := target.page
	requestUrl := targetPage.Url.String()
	crawlerBaseUrl := *c.baseUrl // Prepare copy for better isolation to avoid global manipulation

	// Request URL
	processLogger.Debugf("Requesting '%s' (vhost %s).", requestUrl, c.vhost)
	resp, redirects, foundAuth, errReq := requester.Get(requestUrl, c.vhost)
	if errReq != nil {

		// Log failed request and return empty result
		processLogger.Debugf("Request failed: %s", errReq)
		chProcessResults <- &processResult{taskId: target.id} // Empty result set will not cause any change in the result data
		return
	}

	// Make sure body reader gets closed on exit
	defer func() { _ = resp.Body.Close() }()

	// Abort on major issue
	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout {

		// Log request error and return empty result
		processLogger.Debugf("Proxy error.")
		chProcessResults <- &processResult{
			taskId:           target.id,
			requestsRedirect: redirects,
			requestsPartial:  1,
			statusCode:       resp.StatusCode,
		}
		return
	}

	// Check whether final response left the scope
	if !utils.SameScope(resp.Request.URL, &crawlerBaseUrl) {

		// Check if redirect to other hostname on same endpoint (vhost) might have happened
		newVhosts := make([]string, 0, 1)
		if utils.SameEndpoint(resp.Request.URL, c.targetIp, -1) {
			newVhost, _ := utils.ExtractHostPort(resp.Request.URL)
			if newVhost != "" && newVhost != c.vhost {
				newVhosts = append(newVhosts, newVhost)
				processLogger.Debugf("Response indicates other vhost (%s).", newVhosts)
			}
		} else {
			processLogger.Debugf("Response out of scope (%s).", resp.Request.URL.String())
		}

		// Return empty result
		chProcessResults <- &processResult{
			taskId:           target.id,
			discoveredVhosts: newVhosts,
			requestsRedirect: redirects,
			requestsPartial:  1,
			statusCode:       resp.StatusCode,
		}
		return
	}

	// Check response content type
	responseType := strings.ToLower(resp.Header.Get("content-type"))
	if strings.Contains(responseType, ";") { // Content type might contain encoding declaration to be removed
		responseType = strings.Split(responseType, ";")[0]
	}

	// Check if response indicates download
	contentDisposition := resp.Header.Get("content-disposition")
	if strings.Contains(contentDisposition, "attachment") || utils.StrContained(responseType, c.downloadTypes) {

		// Execute download if desired
		processLogger.Debugf("Download response.")
		var partial, complete = 1, 0
		if c.download {
			fileName := utils.SanitizeFilename(requestUrl, "_")
			errDl := streamToFile(resp.Body, c.outputFolder, fileName)
			if errDl != nil {
				processLogger.Debugf("Download failed: %s", errDl)
			} else {
				processLogger.Debugf("Download succeeded.")
			}
			partial, complete = 0, 1
		}

		// Return download result
		chProcessResults <- &processResult{
			taskId:             target.id,
			discoveredDownload: requestUrl,
			requestsRedirect:   redirects,
			requestsPartial:    partial,
			requestsComplete:   complete,
			statusCode:         resp.StatusCode,
		}
		return
	}

	// Decide whether response shall be added to the crawler results
	if resp.StatusCode == http.StatusOK && utils.StrContained(responseType, c.followTypes) {

		// Good response, store contents
		processLogger.Debugf("Valid response: %d OK to be followed.", http.StatusOK)
	} else if resp.StatusCode == http.StatusUnauthorized {

		// Good response, store contents
		processLogger.Debugf("Valid response: %d UNAUTHORIZED.", http.StatusUnauthorized)
	} else if c.storeRoot && targetPage.Depth == 0 {

		// First page should always be stored independent of content
		processLogger.Debugf("Entry point with error response.")
	} else if resp.StatusCode == http.StatusTooManyRequests {

		// We want to retry this after the waiting period
		processLogger.Debugf("Need to retry (Response code: %d, Response type: %s).", resp.StatusCode, responseType)

		// Try to get the content of the retry-after header field
		after, errParse := parseRetryAfter(&resp.Header)
		if errParse != nil {
			c.logger.Debugf("%s", errParse)
			after = 0
		}

		// Return a result with the retry flag set
		chProcessResults <- &processResult{
			taskId:     target.id,
			result:     targetPage,
			statusCode: resp.StatusCode,
			retryAfter: after,
		}
		return
	} else {

		// Log out of interest and return empty result
		processLogger.Debugf("Not of interest (Response code: %d, Response type: %s).", resp.StatusCode, responseType)
		chProcessResults <- &processResult{
			taskId:           target.id,
			requestsRedirect: redirects,
			requestsPartial:  1,
			requestsComplete: 0,
			statusCode:       resp.StatusCode,
		}
		return
	}

	// Read body stream and close it. Up til now, we just read the response headers from the server. The body will now
	// directly be streamed from the server because we need it.
	processLogger.Debugf("Reading response body.")
	htmlBytes, htmlEncoding, errHtml := utils.ReadBody(resp)
	if errHtml != nil {
		htmlBytes = []byte{}
	}

	// Release body as soon as possible to allow connection reuse by HTTP transport
	_ = resp.Body.Close()

	// Parse HTML
	processLogger.Debugf("Parsing response body.")
	doc, errParse := goquery.NewDocumentFromReader(bytes.NewReader(htmlBytes))

	// Process HTML of parsing succeeded
	var children []*Page
	if errParse != nil {
		processLogger.Warningf("Could not parse response from '%s' (vhost '%s'): %s", requestUrl, c.vhost, errParse)
	} else {

		// Extract URLs from HTML links (hrefs, src,...)
		links := extractLinks(doc)
		targetPage.RawLinks = append(targetPage.RawLinks, links...)
		processLogger.Debugf("Extracted %d URLs.", len(links))

		// Extract URLs from HTML (client-side) redirects (meta,...)
		links = extractRedirects(doc)
		targetPage.RawLinks = append(targetPage.RawLinks, links...)
		processLogger.Debugf("Extracted %d client-side redirect URLs.", len(links))

		// If max depth is not yet reached, try to generate child pages to be crawled next
		if c.maxDepth < 0 || targetPage.Depth < c.maxDepth {

			// Parse links and make them absolute
			absUrls := linksToAbsoluteUrls(targetPage.RawLinks, resp.Request.URL)

			// Create new pages for discovered links. However, do some first validation, that can be done asynchronously
			// within this goroutine. The crawler will evaluate the remaining criteria before eventually queueing this
			// pages for future crawling.
			for _, absUrl := range absUrls {

				// Skip page if it is not HTTP or HTTPs
				if absUrl.Scheme != "http" && absUrl.Scheme != "https" {
					continue
				}

				// Skip page if it would lead outside of scope
				if !utils.SameScope(absUrl, c.baseUrl) {
					continue
				}

				// Remove query strings if required. Without query strings, only the path will be requested once.
				if !c.followQS {
					absUrl.RawQuery = ""
				}

				processLogger.Debugf("Suggesting '%s'.", absUrl)
				children = append(children,
					&Page{
						Depth: targetPage.Depth + 1,
						Url:   absUrl,
					},
				)
			}
		}
	}

	// Detect whether successful authentication took place
	authSuccess := false
	if foundAuth != "" && resp.StatusCode != http.StatusUnauthorized {
		authSuccess = true
	}

	// Fill page struct with result data
	targetPage.RedirectUrl = resp.Request.URL.String()
	targetPage.RedirectCount = redirects
	targetPage.AuthMethod = foundAuth
	targetPage.AuthSuccess = authSuccess
	targetPage.ResponseCode = resp.StatusCode
	targetPage.ResponseMessage = resp.Status
	targetPage.ResponseContentType = responseType
	targetPage.ResponseHeaders = utils.FormattedHeader(resp.Header)
	targetPage.ResponseEncoding = htmlEncoding
	targetPage.HtmlTitle = utils.ExtractHtmlTitle(htmlBytes)
	targetPage.HtmlContent = htmlBytes

	// Send filled page and return
	chProcessResults <- &processResult{
		taskId:           target.id,
		result:           targetPage,
		children:         children,
		requestsRedirect: redirects,
		requestsPartial:  0,
		requestsComplete: 1,
		statusCode:       resp.StatusCode,
	}
	return
}

// handleResult checks the processResult, extracts the relevant values and adds them to the overall CrawlResult.
// This function is not thread safe!
func (c *Crawler) handleResult(procRes *processResult, result *CrawlResult) {

	// Add page to result
	if procRes.result != nil {

		// Add page to crawl results
		result.Pages = append(result.Pages, procRes.result)

		// Aggregate authentication detection into result data
		if result.AuthSuccess == false && procRes.result.AuthSuccess == true {
			result.AuthSuccess = true
			result.AuthMethod = procRes.result.AuthMethod
		} else if result.AuthMethod == "" {
			result.AuthMethod = procRes.result.AuthMethod
		}
	}

	// Validate and queue new children
	if procRes.children != nil {
		c.enqueueNewPages(procRes.children)
	}

	// Add discovered download URLs to result
	if procRes.discoveredDownload != "" {
		result.DiscoveredDownloads = append(result.DiscoveredDownloads, procRes.discoveredDownload)
	}

	// Add discovered vhosts to result
	if procRes.discoveredVhosts != nil {
		result.DiscoveredVhosts = utils.AppendUnique(result.DiscoveredVhosts, procRes.discoveredVhosts...)
	}

	// Update request counter
	result.RequestsRedirect += procRes.requestsRedirect
	result.RequestsPartial += procRes.requestsPartial
	result.RequestsComplete += procRes.requestsComplete
}

// reEnqueue adds a single page to the queue. This should only be done, when an error occurs, that can be assumed to be
// resolved within 'retryAfter' seconds. An example would be the 'TooManyRequest' status code.
// This function is not thread safe!
func (c *Crawler) reEnqueue(page *Page, retryTime time.Time, taskId int32) {

	// Check the page pointer
	if page == nil {
		c.logger.Warningf("Can't re-enqueue nil page.")
		return
	}

	pageUrl := page.Url.String()

	// Check if the target would be retried after the crawler's deadline
	if retryTime.After(c.deadline) {
		c.logger.Debugf("Skipping re-enqueue '%s' because deadline has been met.", pageUrl)
		return
	}

	// Increase the count of tries
	if retries, ok := c.known[pageUrl]; ok {
		if retries >= maxRetries {
			c.logger.Debugf("Skipping re-enqueue '%s' because maximum retries are exhausted.", pageUrl)
			return
		}
		c.known[pageUrl]++
	} else {
		// We haven't seen this task before, this should be added by 'enqueueNewPages'
		c.logger.Debugf("Skipping re-enqueue because task '%d' for target '%s' is unknown.", taskId, pageUrl)
		return
	}

	// Create a new task in order to clear all previously set fields
	newPage := &Page{
		Depth: page.Depth,
		Url:   page.Url,
	}

	// Queue page as nothing speaks against
	c.logger.Debugf("Re-queueing task '%d' for target '%s'.", taskId, pageUrl)
	c.queue = append(c.queue, &task{taskId, newPage})

	// Reorganize queue
	sortQueue(c.queue)

	return
}

// enqueueNewPages validates and appends sub pages to the queue. It might still drop pages. E.g. a page that has already
// been seen will not be enqueued once more. If appending an already crawled page is really wanted, use reEnqueue.
// This function is not thread safe!
func (c *Crawler) enqueueNewPages(newPages []*Page) {
	queued := 0
	for _, newPage := range newPages {

		// Skip page if its URL was seen previously
		pageUrl := newPage.Url.String()
		if _, ok := c.known[pageUrl]; ok {
			continue
		}

		// Add page URL to map of known ones to prevent queueing duplicates
		c.known[pageUrl] = 0

		// Queue page as nothing speaks against
		c.logger.Debugf("Queueing '%s'.", pageUrl)
		queued += 1
		c.queue = append(c.queue, &task{c.nextTaskId(), newPage}) // Null time is always before time.Now()
	}

	if queued <= 0 {
		c.logger.Debugf("No new URLs.")
		return
	}

	// Reorganize queue
	c.logger.Debugf("Queued %d new and unique URLs.", queued)
	sortQueue(c.queue)
}

// sortQueue sorts the given queue in place. The slice is sorted by page depth and the URL path's folder depth.
func sortQueue(queue []*task) {
	sort.Slice(queue, func(i, j int) bool {
		if queue[i].page.Depth < queue[j].page.Depth {
			return true

		} else if queue[i].page.Depth == queue[j].page.Depth {

			// Count folder depth indicated by URL path
			subFoldersI := strings.Count(queue[i].page.Url.Path, "/")
			subFoldersJ := strings.Count(queue[j].page.Url.Path, "/")

			// Lower folder depth first
			if subFoldersI < subFoldersJ {
				return true
			}
		}
		return false
	})
}

func extractLinks(doc *goquery.Document) []string {
	var links []string

	// Find Links
	if doc != nil {
		doc.Find("a").Each(func(i int, s *goquery.Selection) {
			href, exists := s.Attr("href")
			if exists {
				links = append(links, strings.TrimSpace(href))
			}
		})
		doc.Find("area").Each(func(i int, s *goquery.Selection) {
			href, exists := s.Attr("href")
			if exists {
				links = append(links, strings.TrimSpace(href))
			}
		})
		doc.Find("iframe").Each(func(i int, s *goquery.Selection) {
			href, exists := s.Attr("src")
			if exists {
				links = append(links, strings.TrimSpace(href))
			}
		})
		doc.Find("frame").Each(func(i int, s *goquery.Selection) {
			href, exists := s.Attr("src")
			if exists {
				links = append(links, strings.TrimSpace(href))
			}
		})

		// Remove duplicates
		links = utils.UniqueStrings(links)

		// Filter obvious garbage
		links = utils.Filter(links, func(link string) bool {
			return !strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "mailto:")
		})
	}

	// Return extracted links
	return links
}

func extractRedirects(doc *goquery.Document) []string {
	var links []string

	// Extract redirects
	if doc != nil {
		doc.Find("meta").Each(func(i int, s *goquery.Selection) {
			equiv, _ := s.Attr("http-equiv")
			content, contentExists := s.Attr("content")

			// Sample tag: <meta http-equiv="refresh" content="3; URL=http://www.example.com/">
			if equiv == "refresh" && contentExists && content != "" && strings.Contains(content, "=") {
				splits := strings.SplitN(content, "=", 2)
				u := splits[1] // Url
				if u != "" {
					links = append(links, strings.TrimSpace(u))
				}
			}
		})

		// Remove duplicates
		links = utils.UniqueStrings(links)

		// Filter obvious garbage
		links = utils.Filter(links, func(link string) bool {
			return !strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "mailto:")
		})
	}

	// Return extracted links
	return links
}

// linksToAbsoluteUrls transforms relative ULRs into absolute URLs, copying scheme, host and - depending on the link -
// the path from the reference URL. If an absolute URL is fed as input, it will remain unchanged. Other scheme/host will
// NOT transform to reference one!
func linksToAbsoluteUrls(links []string, responseUrl *url.URL) []*url.URL {

	urls := make([]*url.URL, 0, len(links))
	for _, link := range links {

		// Parse link in context of response URL. Drop links that cannot be parsed.
		u, errParse := responseUrl.Parse(link)
		if errParse == nil {
			urls = append(urls, u)
		}
	}
	return urls
}

// requestImageHash requests the given URL and calculates its MD5 checksum if the response type is "image" or "x-imag".
// An empty string is returned if the request fails or if the response content type is not as expected.
func requestImageHash(requester *utils.Requester, requestUrl string, vhost string) string {

	// Request favicon
	resp, _, _, err := requester.Get(requestUrl, vhost)
	if err != nil {
		return ""
	}

	// Make sure body reader gets closed on exit
	defer func() { _ = resp.Body.Close() }()

	// Check required response content type
	// Use resp.Header.Get() to avoid case sensitivity issues:
	// https://dhdersch.github.io/golang/2016/08/11/golang-case-sensitive-http-headers.html
	respType := strings.ToLower(resp.Header.Get("content-type"))
	if strings.Contains(respType, "image") || strings.Contains(respType, "x-icon") {
		// Read response body and store it's MD5 checksum
		respBody, _, errBody := utils.ReadBody(resp)
		if errBody == nil {
			md5Hash := md5.Sum(respBody)
			return hex.EncodeToString(md5Hash[:])
		}
	}

	// Return empty string as no favicon could be found
	return ""
}

// streamToFile downloads the content at the given URL and writes it to the given location
func streamToFile(source io.Reader, outputFolder string, outputName string) error {

	// Create tmp folder if it does not exist
	if _, err := os.Stat(outputFolder); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(outputFolder, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	// Prepare output file path
	file := filepath.Join(outputFolder, outputName)

	// Create output file
	out, errCreate := os.Create(file)
	if errCreate != nil {
		return errCreate
	}

	// Make sure file gets closed on exit
	defer func() { _ = out.Close() }()

	// Write the body to file
	_, errWrite := io.Copy(out, source)

	// Return error or nil
	return errWrite
}

// parseRetryAfter tries to get the content of the retry-after header field. This can either be a simple number
// (of seconds) or a date.
func parseRetryAfter(header *http.Header) (uint64, error) {
	if header == nil {
		return 0, fmt.Errorf("header is nil")
	}

	// Get the retry-after field from the header
	field := header.Get("Retry-After")
	if field == "" {
		return 0, fmt.Errorf("could not get the 'Retry-After' field from the header '%s'", *header)
	}

	// Try to parse the number of seconds
	after, errParse := strconv.ParseUint(field, 10, 64)
	if errParse != nil {

		// Try to parse the date and calculate the difference to now
		t, errParse := time.Parse(httpDateLayout, field)
		if errParse != nil {
			return 0, fmt.Errorf("could not parse 'Retry-After' value from '%s'", field)
		} else {
			// Check if the time has already passed
			if time.Until(t).Seconds() < 0 {
				return 0, fmt.Errorf("'Retry-After' value is already in the past for '%s'", field)
			}

			// Adding one so we won't hit the retry again because of cutting off anything small
			after = uint64(time.Until(t).Seconds()) + 1
		}
	}

	return after, nil
}

// makeCounter creates a new counter, that starts with the number provided as parameter. This function is thread safe
// but the counter can (in theory) over- or underflow.
func makeCounter(start int32) func() int32 {
	ctr := start - 1
	return func() int32 {
		return atomic.AddInt32(&ctr, 1)
	}
}
