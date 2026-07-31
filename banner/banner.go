/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package banner implements a scan module for banner grabbing over TCP/TLS connections.
package banner

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/siemens/GoScans/utils"
	"github.com/ziutek/telnet"
)

const Label = "Banner"                                   // Scan-module label
const receiveSize = 2048                                 // Maximum bytes read from a banner response
const tagPlain = "Plain"                                 // Plain TCP result tag
const tagSsl = "Ssl"                                     // TLS result tag
const tagTelnet = "Telnet"                               // Telnet result tag
const tagHttp = "Http"                                   // HTTP result tag
const tagHttps = "Https"                                 // HTTPS result tag
const triggerWindows = "\r\n"                            // Line feed to use. However, Linux systems often don't like it and don't respond to it
const triggerLinux = "\n"                                // Line feed that makes Linux systems happy to respond
const triggerHttp = "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" // GET request that makes HTTP servers to respond. They usually don't care about the used line feed, independent of the underlying OS

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger) error {
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup() error {
	return nil
}

// ResultData holds the raw banner bytes captured from each protocol probe.
type ResultData struct {
	Plain  []byte
	Ssl    []byte
	Telnet []byte
	Http   []byte
	Https  []byte
}

// Result wraps ResultData with a scan status and an exception flag for the caller to inspect.
type Result struct {
	Data      *ResultData // Bytes array, to be converted by consumer as required
	Status    string      // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool        // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

// Scanner holds the target configuration and timeouts for a single banner grabbing session.
type Scanner struct {
	Label          string
	Started        time.Time
	Finished       time.Time
	logger         utils.Logger
	target         string
	port           int
	protocol       string
	dialTimeout    time.Duration
	receiveTimeout time.Duration
}

// NewScanner validates and initialises a Scanner for the given target, port, and protocol.
func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	protocol string,
	dialTimeout time.Duration,
	receiveTimeout time.Duration,
) (*Scanner, error) {

	// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
	target = strings.TrimSpace(target)

	// Check whether input target is valid
	if !utils.IsValidAddress(target) {
		return nil, fmt.Errorf("invalid target '%s'", target)
	}

	// Check whether input protocol is valid
	if !(protocol == "tcp" || protocol == "udp") {
		return nil, fmt.Errorf("invalid protocol '%s'", protocol)
	}

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		target, // Address to be scanned (might be IPv4, IPv6 or hostname)
		port,
		protocol,
		dialTimeout,
		receiveTimeout,
	}

	// Return scan struct
	return &scan, nil
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run() (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception
			s.logger.Errorf("Unexpected error: %s", r)

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

	// Set scan started flag
	s.Started = time.Now()
	s.logger.Infof("Started  scan of %s:%d (%s).", s.target, s.port, s.protocol)

	// Execute scan logic
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s:%d (%s) in %fm.", s.target, s.port, s.protocol, duration)

	// Return result set
	return res
}

// execute runs all protocol probes in order and returns the aggregated banner results.
func (s *Scanner) execute() *Result {

	// Declare temporary results variable collecting intermediate results
	tmpResults := make(map[string][]byte)

	// Try plain socket trigger for Windows
	s.logger.Debugf("Sending plain socket trigger (Windows).")
	respPlainWin, errRespPlainWin := sendPlain(s.target, s.port, s.protocol, triggerWindows, s.dialTimeout, s.receiveTimeout)

	// Check first error response for connection timeout. Don't proceed if host/port is not reachable at all
	if socketErrorType(errRespPlainWin) == "dial" {
		s.logger.Debugf("Endpoint not reachable, aborting scan.")
		return &Result{
			&ResultData{},
			utils.StatusNotReachable,
			false,
		}
	}

	// Store result if not empty
	s.updateResultMap(tmpResults, tagPlain, respPlainWin, errRespPlainWin)

	// Try Linux line feed if Windows line feed did not work (wrong line feed might cause read timeout)
	if _, ok := tmpResults[tagPlain]; !ok {
		s.logger.Debugf("Sending plain socket trigger (Linux).")
		respPlainLin, errRespPlainLin := sendPlain(s.target, s.port, s.protocol, triggerLinux, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagPlain, respPlainLin, errRespPlainLin) // Store result if not empty
	}

	// Continue with triggers only working on TCP
	if s.protocol == "tcp" {

		// Try SSL socket trigger for Windows
		s.logger.Debugf("Sending SSL socket trigger (Windows).")
		respSslWin, errRespSslWin := sendSsl(s.target, s.port, triggerWindows, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagSsl, respSslWin, errRespSslWin) // Store result if not empty

		// Try Linux line feed if Windows line feed did not work (wrong line feed might cause read timeout)
		if _, ok := tmpResults[tagSsl]; !ok {
			// Try SSL socket trigger for Linux
			s.logger.Debugf("Sending SSL socket trigger (Linux).")
			respSslLin, errRespSslLin := sendSsl(s.target, s.port, triggerLinux, s.dialTimeout, s.receiveTimeout)
			s.updateResultMap(tmpResults, tagSsl, respSslLin, errRespSslLin) // Store result if not empty
		}

		// Try telnet trigger for Windows
		s.logger.Debugf("Sending telnet trigger (Windows).")
		respTelnetWin, errRespTelnetWin := sendTelnet(s.target, s.port, true, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagTelnet, respTelnetWin, errRespTelnetWin) // Store result if not empty

		// Try Linux line feed if Windows line feed did not work (wrong line feed might cause read timeout)
		if _, ok := tmpResults[tagTelnet]; !ok {
			// Try telnet trigger for Linux
			s.logger.Debugf("Sending telnet trigger (Linux).")
			respTelnetLin, errRespTelnetLin := sendTelnet(s.target, s.port, false, s.dialTimeout, s.receiveTimeout)
			s.updateResultMap(tmpResults, tagTelnet, respTelnetLin, errRespTelnetLin) // Store result if not empty
		}

		// Prepare HTTP request
		req := fmt.Sprintf(triggerHttp, net.JoinHostPort(s.target, strconv.Itoa(s.port)))

		// Try HTTP trigger
		s.logger.Debugf("Sending HTTP trigger.")
		respHttp, errRespHttp := sendPlain(s.target, s.port, "tcp", req, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagHttp, respHttp, errRespHttp) // Store result if not empty

		// Try HTTPs trigger
		s.logger.Debugf("Sending HTTPS trigger.")
		respHttps, errRespHttps := sendSsl(s.target, s.port, req, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagHttps, respHttps, errRespHttps) // Store result if not empty
	}

	// Prepare results data
	results := &ResultData{
		Plain:  tmpResults[tagPlain],  // Returns result bytes or empty bytes
		Ssl:    tmpResults[tagSsl],    // Returns result bytes or empty bytes
		Telnet: tmpResults[tagTelnet], // Returns result bytes or empty bytes
		Http:   tmpResults[tagHttp],   // Returns result bytes or empty bytes
		Https:  tmpResults[tagHttps],  // Returns result bytes or empty bytes
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result.")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

// updateResultMap trims the response and stores it in res under triggerName, logging and skipping empty or errored responses.
func (s *Scanner) updateResultMap(res map[string][]byte, triggerName string, response []byte, err error) {

	// Get rid of whitespaces
	response = bytes.TrimSpace(response)

	// Log error or store valid response
	if err != nil {
		s.logger.Debugf("Trigger '%s' failed: %s", triggerName, err)
	} else if len(response) == 0 {
		s.logger.Debugf("Trigger response '%s' was empty.", triggerName)
	} else {
		res[triggerName] = response
	}
}

// sendPlain opens a raw TCP or UDP connection, writes trigger, and returns the first response bytes.
func sendPlain(
	address string,
	port int,
	protocol string,
	trigger string,
	dialTimeout time.Duration,
	receiveTimeout time.Duration,
) ([]byte, error) {

	// Establish TCP/UDP connection
	conn, errConn := net.DialTimeout(protocol, net.JoinHostPort(address, strconv.Itoa(port)), dialTimeout)

	// Return error if TCP/UDP connection failed
	if errConn != nil {
		return []byte{}, errConn
	}

	// Make sure connection gets closed on exit
	defer func() { _ = conn.Close() }()

	// Set maximum time to wait. Go sockets require timestamp to timeout, not int (seconds)
	errSet := conn.SetDeadline(time.Now().Add(receiveTimeout))
	if errSet != nil {
		return []byte{}, errSet
	}

	// Send trigger
	_, errWrite := conn.Write([]byte(trigger))
	if errWrite != nil {
		return []byte{}, errWrite
	}

	// Receive response
	responseBuffer := make([]byte, receiveSize)
	_, errRead := conn.Read(responseBuffer)
	if errRead != nil && !errors.Is(errRead, io.EOF) {
		return []byte{}, errRead
	}

	// Slice the buffer up until first null byte if a null byte exists at all
	n := bytes.IndexByte(responseBuffer, 0)
	if n >= 0 {
		responseBuffer = responseBuffer[:n]
	}

	// Return response
	return responseBuffer, nil
}

// sendSsl opens a TLS connection with certificate verification disabled, writes trigger, and returns the first response bytes.
func sendSsl(address string, port int, trigger string, dialTimeout, receiveTimeout time.Duration) ([]byte, error) {

	// Connect to address
	conn, errConn := tls.DialWithDialer(
		&net.Dialer{Timeout: dialTimeout},
		"tcp",
		net.JoinHostPort(address, strconv.Itoa(port)),
		utils.InsecureTlsConfigFactory(),
	)
	if errConn != nil {
		return []byte{}, errConn
	}

	// Make sure connection gets closed on exit
	defer func() { _ = conn.Close() }()

	// Set maximum time to wait. Go sockets require timestamp to timeout, not int (seconds)
	errSet := conn.SetDeadline(time.Now().Add(receiveTimeout))
	if errSet != nil {
		return []byte{}, errSet
	}

	// Send trigger
	_, errWrite := conn.Write([]byte(trigger))
	if errWrite != nil {
		return []byte{}, errWrite
	}

	// Receive response
	responseBuffer := make([]byte, receiveSize)
	_, errRead := conn.Read(responseBuffer)
	if errRead != nil && !errors.Is(errRead, io.EOF) {
		return []byte{}, errRead
	}

	// Slice the buffer up until first null byte if a null byte exists at all
	n := bytes.IndexByte(responseBuffer, 0)
	if n >= 0 {
		responseBuffer = responseBuffer[:n]
	}

	// Return response
	return responseBuffer, nil
}

// sendTelnet opens a Telnet connection, writes a newline trigger, and returns the first response bytes.
func sendTelnet(address string, port int, isWindows bool, dialTimeout, receiveTimeout time.Duration) ([]byte, error) {

	// Connect to address
	conn, errConn := telnet.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), dialTimeout)
	if errConn != nil {
		return []byte{}, errConn
	}

	// Make sure connection gets closed on exit
	defer func() { _ = conn.Close() }()

	// Set maximum time to wait. Go sockets require timestamp to timeout, not int (seconds)
	errSet := conn.SetDeadline(time.Now().Add(receiveTimeout))
	if errSet != nil {
		return []byte{}, errSet
	}

	// If connection is to Linux, set Unix write mode
	if !isWindows {
		conn.SetUnixWriteMode(true)
	}

	// Send trigger
	_, errWrite := conn.Write([]byte("\n"))
	if errWrite != nil {
		return []byte{}, errWrite
	}

	// Receive response
	responseBuffer := make([]byte, receiveSize)
	_, errRead := conn.Read(responseBuffer)
	if errRead != nil && !errors.Is(errRead, io.EOF) {
		return []byte{}, errRead
	}

	// Slice the buffer up until first null byte if a null byte exists at all
	n := bytes.IndexByte(responseBuffer, 0)
	if n >= 0 {
		responseBuffer = responseBuffer[:n]
	}

	// Return response
	return responseBuffer, nil
}

// socketErrorType Digging deep to find out which kind of socket error happened. Because Golang is too stupid to give you an error code
// or a certain error type. Just an error string, which might be different on different OS/languages.
// Returns empty string if error is not a socket issue
func socketErrorType(err error) string {
	var t *net.OpError
	switch {
	case errors.As(err, &t):
		return t.Op // Might be "dial", "read", "write",...
	}
	return "" // Empty if not a socket error
}
