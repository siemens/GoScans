/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"bytes"
	"fmt"
	"github.com/Azure/go-ntlmssp"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ReuseTransportAndClient = iota // Reuse client (maintaining cookies), reuse transport (keeping connections)
	ReuseTransport                 // Create new client (discarding cookies), reuse transport (keeping connections)
	ReuseNone                      // Create new client (discarding cookies) and transport (not keeping connections)
)

const maxRedirects = 10

// InsecureTransportFactory is a basic transport factory that can be passed to the requester. This transport factory
// returns a transport with insecure TLS configuration. It is intended for scanning purposes and not recommended to
// establish trusted connections!
var InsecureTransportFactory = func(proxy *url.URL, timeout time.Duration) *http.Transport {

	// Create and return fresh transport
	return &http.Transport{
		TLSClientConfig:       InsecureTlsConfigFactory(),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout * 2, // TCP connection succeeded, let's give the web app some more time
		DisableKeepAlives:     false,       // Keep-alive is required for NTLM authentication to work!
		Proxy:                 http.ProxyURL(proxy),
	}
}

// ClientFactory is a basic client factory that can be passed to the requester
var ClientFactory = func(transport *http.Transport, timeout time.Duration) *http.Client {

	// Create and return fresh client
	return &http.Client{
		Transport: transport,   // HTTP transport to use, may be a reused one with alive connections
		Timeout:   timeout * 2, // TCP connection succeeded, let's give the web app some more time
		// CheckRedirect: -> default is nil, which tells it to stop after 10 consecutive requests
	}
}

// Requester allows to comfortably initialize an HTTP requester that can be reused for multiple request and does
// automatically take care of resetting the HTTP client or transport if desired. Furthermore, it reduces the amount
// of boilerplate code and the amount of arguments that need to be passed for each HTTP request. Furthermore, this
// requester does automatically take care of NTLM authentication if credentials are provided.
// The requester's .Get() method is thread safe.
type Requester struct {
	reuseMode    int             // Whether to reuse the HTTP client (cookies) and transport (connections)
	userAgent    string          // The user agent to pretend to be
	ntlmUser     string          // (Optional) credentials for NTLM authentication
	ntlmPassword string          // ...
	proxy        *url.URL        // The proxy to apply throughout the life of this requester
	timeout      time.Duration   // Request timeout to apply throughout the life of this requester
	transport    *http.Transport // Storage of the most recently created HTTP transport for later re-use
	client       *http.Client    // Storage of the most recently created HTTP client for later re-use

	// Returning a freshly generated HTTP transport
	tFactory func(proxy *url.URL, timeout time.Duration) *http.Transport
	// Returning a freshly generated HTTP client
	cFactory func(transport *http.Transport, timeout time.Duration) *http.Client
}

// NewRequester returns a reusable and thread safe HTTP requester, which can automatically take care of reusing or
// resetting the underlying HTTP client/transport. Furthermore, the requester will automatically take care of NTLM
// authentication if required.
func NewRequester(
	reuseMode int,
	userAgent string,
	ntlmDomain string,
	ntlmUser string,
	ntlmPassword string,
	proxy *url.URL,
	timeout time.Duration,
	transportFactory func(proxy *url.URL, timeout time.Duration) *http.Transport,
	clientFactory func(transport *http.Transport, timeout time.Duration) *http.Client,
) *Requester {

	// Prepare credentials
	if ntlmDomain != "" {
		ntlmUser = ntlmDomain + "\\" + ntlmUser
	}

	// Fall back to default client/transport factories
	if transportFactory == nil {
		transportFactory = InsecureTransportFactory
	}
	if clientFactory == nil {
		clientFactory = ClientFactory
	}

	// Create initial requester
	r := Requester{
		reuseMode,
		userAgent,
		ntlmUser,
		ntlmPassword,
		proxy,
		timeout,
		nil,
		nil,
		transportFactory,
		clientFactory,
	}

	// Initialize HTTP client and transport if it will be reused
	if reuseMode == ReuseTransportAndClient {

		// Prepare transport
		transport := r.generateFreshTransport()

		// Build client with transport, configure it as required and store it for later reuse
		r.client = r.generateFreshClient(transport)
	}

	// Initialize HTTP transport if it will be reused
	if reuseMode == ReuseTransport { // Create new client but reuse transport

		// Build transport and store it for later reuse
		r.transport = r.generateFreshTransport()
	}

	// Return preconfigured requester
	return &r
}

// Get executes an HTTP GET request, following potential location redirects, watching out for authentication-required
// responses and automatically trying to authenticate if credentials are set. This method is thread safe and can be
// called from different goroutines, because the underlying *http.Client is.
// ATTENTION: The caller must take care of closing a successful response body
// ATTENTION: The transport connection can only be reused once the response body got read and closed.
func (r *Requester) Get(url_ string, vhost string) (resp *http.Response, redirects int, auth string, err error) {

	// Initial state
	nextUrl := url_ // The next URL to request, there might be a sequence of location redirects

	// Get client to use for this request (or series of redirects)
	client := r.yieldClient()

	// Build first request
	req, errNew := http.NewRequest("GET", nextUrl, nil)
	if errNew != nil {
		return nil, redirects, auth, errNew
	}

	// Set initial vhost to use
	vhostToUse := vhost

	// Loop until all redirects are followed or the max redirects are reached
	for {
		// Close the previous response's body. But read at least some of the body so if it's small the underlying
		// TCP connection will be re-used. No need to check for errors: if it fails, the Transport won't reuse it
		// anyway.
		if resp != nil {
			const maxBodySlurpSize = 2 << 10
			if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
				_, _ = io.CopyN(io.Discard, resp.Body, maxBodySlurpSize)
			}
			_ = resp.Body.Close()
		}

		// Decide host header to use for the request.
		// 	- On the first request, we want to set the host header as passed to the function.
		// 	- On subsequent requests, we need to decide. The server might redirect to another site or try to redirect
		// 	  to a correct vhost. Hence, on subsequent redirect requests, we (only) want to preserve the original host
		// 	  header in case of a relative redirect. Otherwise, we take over the new hostname.
		if redirects > 0 {
			if req.Host != req.URL.Host {
				// If the caller specified a custom Host header and the redirect location is relative, preserve the
				// Host header through the redirect. See issue #22233.
				if u, _ := url.Parse(nextUrl); u != nil && !u.IsAbs() {
					// Parse new (relative) URL in the context of the previous request to get a valid absolute URLs
					u, errParse := req.URL.Parse(nextUrl)
					if errParse != nil {
						return nil, redirects, auth, fmt.Errorf(
							"failed to parse Location header %q: %v", nextUrl, errParse)
					}
					nextUrl = u.String()
					vhostToUse = req.Host
				}
			}

			// Build subsequent request
			req, errNew = http.NewRequest("GET", nextUrl, nil)
			if errNew != nil {
				return nil, redirects, auth, errNew
			}
		}

		// Set host header for this request (might change on absolute redirects)
		req.Host = vhostToUse

		// Set request user agent
		req.Header.Set("User-Agent", r.userAgent)

		// If www-authenticate was seen in a previous request, set request credentials. NTLM negotiator will jump in
		// and try to execute authentication, IF credentials are set.
		// Some possible outcomes:
		//		- auth = ""								=> no www-authenticate seen
		//		- auth = "...." && response code == 401	=> www-authenticate seen, authentication not successful
		//		- auth = "...." && response code != 401 => www-authenticate seen and successful
		if auth != "" {
			if r.ntlmUser != "" && r.ntlmPassword != "" {
				req.SetBasicAuth(r.ntlmUser, r.ntlmPassword)
			}
		}

		// Send request (Redirects will not be followed automatically)
		var errDo error
		resp, errDo = client.Do(req)
		if errDo != nil {
			return nil, redirects, auth, errDo
		}

		// Detect required authentication. If detected, retry and remember for future requests.
		if auth == "" {

			// Check requested authentication mode
			auth = resp.Header.Get("WWW-Authenticate")
			if strings.HasPrefix(auth, "Digest") {
				auth = "Digest" // Digest comes with a bunch of data
			}

			// If detected, retry with credentials and do so for future requests.
			if auth != "" {
				continue
			}
		}

		// Detect redirect and handle
		nextUrl = resp.Header.Get("Location")
		if nextUrl != "" {

			// Follow redirect or exit redirect loop
			if redirects <= maxRedirects {
				redirects++
				continue
			} else {
				_ = resp.Body.Close() // Close latest response body as it will not be used anymore
				return nil, redirects, auth, fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
		}

		// Return final response (after potential redirects and authentication requests). The response includes an open
		// response body IO reader, which needs to be closed by the caller once done with it.
		return resp, redirects, auth, nil
	}
}

// GetCookies returns the cookies currently stored in a reusable HTTP client. This does only return cookies, if the
// requester's operation mode is reusing clients and if the used client has an initialized cookie jar.
func (r *Requester) GetCookies(url_ string) []*http.Cookie {
	if r.client != nil {
		if r.client.Jar != nil {
			u, _ := url.Parse(url_)
			return r.client.Jar.Cookies(u)
		}
	}
	return []*http.Cookie{}
}

// yieldClient prepares and returns an HTTP client to use for a request. Depending on the configuration, the
// client reuses an existing client/transport or re-initializes one or both of these components. Furthermore, it is
// made sure, that the applied transport is wrapped by an NTLM negotiator if NTLM credentials are set.
func (r *Requester) yieldClient() *http.Client {

	// Be cautious with operation modes!
	// 	 OLD client + OLD transport		=> Returns a reference to same old client with a reference to the old transport.
	// 	 								   http.Client and http.Transport are thread safe, so is this mode.
	// 	 NEW client + OLD transport 	=> Returns a reference to a fresh new client with a reference to the old
	// 	 								   transport. http.Transport is thread safe, so is this mode.
	// 	 NEW client + NEW transport		=> Returns a reference to a fresh new client with a reference to a fresh
	// 	 								   transport. No conflicts at all.
	// 	 OLD client + NEW transport 	=> This operation mode is NOT possible in a thread safe way, without locking
	// 	 								   the complete request-response cycle! The reused client includes the
	// 	 								   reference to the transport. If this reference is changes, it would for
	// 	 								   all threads. If you do not want to re-use connections, you can create a
	//									   transport with disabled HTTP keep-alive.

	// Return reusable client including reusable transport
	if r.reuseMode == ReuseTransportAndClient {

		// Client was created in constructor, so we just return the pointer
		return r.client
	}

	// Return fresh client reusing the existing transport
	if r.reuseMode == ReuseTransport {

		// Build client with transport, configure it as required and store it for later reuse
		client := r.generateFreshClient(r.transport)

		// Return fresh client with reused transport
		return client
	}

	// By default, return fresh client with fresh transport (r.reuseMode == ReuseNone || invalid mode int)
	// Prepare fresh transport
	transport := r.generateFreshTransport()

	// Build client with transport, configure it as required and store it for later reuse
	client := r.generateFreshClient(transport)

	// Return fresh client including a fresh transport
	return client
}

// generateFreshTransport constructs a fresh transport based on the configured factory function (which might be changed
// by the developer) and makes sure that some settings required by the Requester are always applied.
func (r *Requester) generateFreshTransport() *http.Transport {

	// Build transport
	transport := r.tFactory(r.proxy, r.timeout)

	// If NTLM shall be used, make sure keep-alive is enabled as it is a requirement for NTLM authentication
	if r.ntlmUser != "" && r.ntlmPassword != "" {
		transport.DisableKeepAlives = false
	}

	// Return a fresh pre-configured transport
	return transport
}

// generateFreshClient constructs a fresh client based on the configured factory function (which might be changed by
// the developer) and makes sure that some settings required by the Requester are always applied.
func (r *Requester) generateFreshClient(transport *http.Transport) *http.Client {

	// Build client
	client := r.cFactory(transport, r.timeout)

	// Patch redirect function to not automatically handle location redirects. We will take care of this manually
	// to give us more insight into what's happening, e.g. to count redirects and detect www-authenticate responses.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Return first response directly. Might contain location redirect.
	}

	// Wrap client's transport by NTLM negotiator if desired
	if r.ntlmUser != "" && r.ntlmPassword != "" {
		negotiatedTransport := ntlmssp.Negotiator{
			RoundTripper: client.Transport,
		}
		client.Transport = negotiatedTransport
	}

	// Add cookie jar to client, if client re-use is intended. Why would it, if not for the cookies?
	if r.reuseMode == ReuseTransportAndClient {
		jar, _ := cookiejar.New(nil)
		client.Jar = jar
	}

	// Return a fresh pre-configured client
	return client
}

// FormattedHeader iterates HTTP response headers, sorts them and joins them to a newline separated string
func FormattedHeader(headers http.Header) string {

	respHeaders := ""

	// Read available headers
	var keys []string
	for k := range headers {
		keys = append(keys, k)
	}

	// Sort headers alphabetically
	sort.Strings(keys)

	// Join headers to a single string
	for _, key := range keys {
		respHeaders += key + ": " + strings.Join(headers[key], ",") + "\r\n"
	}

	// Remove trailing newlines
	respHeaders = strings.Trim(respHeaders, " \r\n")

	// Return crated string
	return respHeaders
}

// ExtractHtmlTitle parses HTML content and extracts the HTML title
func ExtractHtmlTitle(body []byte) string {

	// IoReader required, so transform string into one
	ioReader := bytes.NewReader(body)

	// Create HTML tokenizer that can be iterated
	tokenizer := html.NewTokenizer(ioReader)

	// Crawl HTML content until title is discovered or end is reached
	for {
		// Get next element
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken: // Return if end or error is reached
			return ""
		case html.StartTagToken: // Investigate start token, might be title
			// Take current token
			t := tokenizer.Token()

			// Check if if token is title
			if t.Data == "title" {

				// Get next element
				tt = tokenizer.Next()

				// Expecting text if token really was the title element
				if tt == html.TextToken {

					// Get current token and read its data, which should be the title
					t = tokenizer.Token()
					title := t.Data

					// Before returning the title, get the next element (we want to find the title's end token)
					tt = tokenizer.Next()

					// Expecting end token to terminate the title
					if tt == html.EndTagToken {

						// Check if end token actually is closing the title element
						t := tokenizer.Token()
						if t.Data == "title" {
							return title
						} else {
							return ""
						}
					}
				}
			}
		}
	}
}

// HttpsIndicated indicates whether the wrong HTTP protocol (HTTP over HTTPS) might have been used. There are some
// web servers that allow HTTP connections to HTTPS ports, but indicate an error.
func HttpsIndicated(resp *http.Response, respBody []byte) bool {
	if resp.Request.URL.Scheme == "http" {

		// Common byte sequence indicating wrong HTTP protocol
		if bytes.HasPrefix(respBody, []byte{21, 3}) {
			return true
		}

		// Common response body indicating wrong HTTP protocol
		if bytes.Contains(respBody, []byte("The page must be viewed over a secure channel")) {
			return true
		}

		// Common response body indicating wrong HTTP protocol
		if bytes.Contains(respBody, []byte("You're speaking plain HTTP to an SSL-enabled server port")) {
			return true
		}

		// Common response style indicating wrong HTTP protocol
		if len(resp.Header) == 0 && len(respBody) == 0 {
			return true
		}
	}

	// Return false by default as no wrong protocol was discovered
	return false
}

func ProxyStringToUrl(proxy string) (*url.URL, error) {
	var proxyUrl *url.URL // nil = No proxy
	if proxy != "" {
		proxy = strings.ToLower(proxy)

		// Check proxy scheme
		if !strings.HasPrefix(proxy, "http://") &&
			!strings.HasPrefix(proxy, "https://") &&
			!strings.HasPrefix(proxy, "socks5://") {
			return nil, fmt.Errorf("invalid proxy scheme in '%s'", proxy)
		}

		// Convert proxy string to proxy URL
		var errParse error
		proxyUrl, errParse = url.Parse(proxy)
		if errParse != nil {
			return nil, fmt.Errorf("invalid proxy URL '%s'", proxy)
		}
	}

	// Return converted proxy
	return proxyUrl, nil
}

// UrlToRelative can be fed with a relative, absolute or garbage path and will try to convert it into a relative one
// An absolute path will be converted into a relative one. A relative path will be returned but without leading slash.
// Garbage input is interpreted as a relative path and be returned the same way without leading slash.
func UrlToRelative(path string) string {

	// Prepare base to remove
	u, err := url.Parse(path)
	if err != nil {
		// Return input if it could not be parsed as an URL
		return strings.TrimLeft(path, "/")
	}
	base := u.Scheme + "://" + u.Host

	// Remove absolute URL from path or return sanitized relative input
	if strings.HasPrefix(path, base) {
		// Remove base in order to return a relative path including optional query string and fragment
		relPath := strings.Replace(path, base, "", 1)

		// Sanitize relative path
		relPath = strings.TrimLeft(relPath, "/")

		// Return relative path
		return relPath

	} else {
		return strings.TrimLeft(path, "/")
	}
}

// ExtractHostPort extracts host and port from a given URL. If no port is specified the protocol defaults are returned.
func ExtractHostPort(target *url.URL) (string, int) {

	if target == nil {
		return "", -1
	}

	// Prepare variables
	var host string
	var port int

	// Split port from URL's host. If it did not contain a port (implicit port), fall back to decision based on scheme
	h, p, errSplit := net.SplitHostPort(target.Host)
	if errSplit != nil { // Could not split port from URL's host, so probably there was no port
		host = target.Host
		if target.Scheme == "http" {
			port = 80
		} else if target.Scheme == "https" {
			port = 443
		}
	} else {
		host = h
		port, _ = strconv.Atoi(p)
	}

	// Return host and port
	return host, port
}

// SameScope detects whether a given URL has the same endpoint (host + port) as the given reference URL. SameScope will
// always return true as long as it is pointing to the same host/port as the reference URL.
func SameScope(urlToCheck *url.URL, referenceUrl *url.URL) bool {

	// Extract original host and port
	origHost, origPort := ExtractHostPort(referenceUrl)

	// Extract response host and port
	finalHost, finalPort := ExtractHostPort(urlToCheck)

	// Return false if host differs
	if origHost != finalHost {
		return false
	}

	// Return false if port differs
	if origPort != finalPort {
		return false
	}

	// Return true if host and port is the same
	return true
}

// SameEndpoint detects whether a given URL is pointing to the given IP and port. SameEndpoint will return true as long
// as it is resolving to the given host/port.
// If the endpointIp is empty or endpointPort is -1 the respective value will not be checked.
func SameEndpoint(url *url.URL, endpointIp string, endpointPort int) bool {

	if url == nil {
		return false
	}

	// Extract hostname from URL
	host, port := ExtractHostPort(url)

	// Return false if port is already different from expected one
	if endpointPort > -1 && port != endpointPort {
		return false
	}

	if endpointIp != "" {

		// Resolve URL's IP
		ips, err := net.LookupIP(host)
		if err != nil {
			return false
		}

		// Check if one of the resolved IPs matches the expected one
		for _, ip := range ips {
			if ip.String() == endpointIp {
				return true
			}
		}

		// Return false as IP is different
		return false
	}

	// Return true if both endpointIp and endpointPort are supposed to not be checked
	return true
}

// HttpFingerprint holds defining attributes of an HTTP response. These attributes can be used to compare different
// HTTP responses for being equal
type HttpFingerprint struct {
	RespUrl      string
	ResponseCode int
	HtmlTitle    string
	HtmlLen      int
}

// NewHttpFingerprint creates a new HTTP fingerprint definition
func NewHttpFingerprint(respUrl string, responseCode int, htmlTitle string, htmlContent string) *HttpFingerprint {
	return &HttpFingerprint{
		respUrl,
		responseCode,
		htmlTitle,
		len(htmlContent),
	}
}

// Similar compares two HTTP fingerprints for being similar. Response URL, code and HTML title must match, while
// HTML content length need to be close by the defined threshold
func (f *HttpFingerprint) Similar(f2 *HttpFingerprint, lengthVariability int) bool {
	if f.RespUrl == f2.RespUrl &&
		f.ResponseCode == f2.ResponseCode &&
		f.HtmlTitle == f2.HtmlTitle &&
		(-lengthVariability/2 <= f.HtmlLen-f2.HtmlLen && f.HtmlLen-f2.HtmlLen <= lengthVariability/2) {
		return true
	}
	return false
}

// String converts a fingerprint to its string representation
func (f *HttpFingerprint) String() string {
	return f.RespUrl + "|" + strconv.Itoa(f.ResponseCode) + "|" + f.HtmlTitle + "|~" + strconv.Itoa(f.HtmlLen)
}

// KnownIn checks whether the fingerprint is already part of a list of fingerprints
func (f *HttpFingerprint) KnownIn(knownFingerprints map[string]*HttpFingerprint, lengthVariability int) (string, bool) {
	for k, v := range knownFingerprints {
		if v.Similar(f, lengthVariability) {
			return k, true
		}
	}
	return "", false
}

// ReadBody detects the response's content encoding and returns accordingly decoded response body bytes. The response
// body might arrive arbitrary encoding. The response's encoding is detected from different sources (Content-Type
// response header, BOMs, HTML meta tag, RFC defaults,...)
func ReadBody(response *http.Response) (body []byte, encoding string, err error) {

	// Get content type header content. It might indicate encoding like "text/html; charset=UTF-8". The
	// charset value can be extracted by charset.DetermineEncoding(), if passed.
	contentType := response.Header.Get("Content-Type")

	// Read raw bytes and close stream
	raw, errRead := io.ReadAll(response.Body)
	if errRead != nil {
		return nil, "", errRead
	}

	// Try to detect encoding
	e, eName, _ := charset.DetermineEncoding(raw, contentType)

	// Prepare reader for actual encoding
	decoded, errUtf := e.NewDecoder().Bytes(raw)
	if errUtf != nil {

		// Return raw bytes, if they couldn't be decoded
		return raw, "", nil
	}

	// Return reader
	return decoded, eName, nil
}
