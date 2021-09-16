/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package banner

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/ziutek/telnet"
	"go-scans/utils"
	"net"
	"strings"
	"time"
)

const Label = "Banner"
const receiveSize = 2048
const tagPlain = "Plain"
const tagSsl = "Ssl"
const tagTelnet = "Telnet"
const tagHttp = "Http"
const tagHttps = "Https"
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

type ResultData struct {
	Plain  []byte
	Ssl    []byte
	Telnet []byte
	Http   []byte
	Https  []byte
}

type Result struct {
	Data      *ResultData // Bytes array, to be converted by consumer as required
	Status    string      // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool        // Indicates if something went wrong badly and results shall be discarded. This should never be
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
	protocol       string
	dialTimeout    time.Duration
	receiveTimeout time.Duration
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	protocol string,
	dialTimeout time.Duration,
	receiveTimeout time.Duration,
) (*Scanner, error) {

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
		strings.TrimSpace(target), // Address to be scanned (might be IPv4, IPv6 or hostname)
		port,
		strings.TrimSpace(protocol),
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

func (s *Scanner) execute() *Result {

	// Declare temporary results variable collecting intermediate results
	tmpResults := make(map[string][]byte)

	// Try plain socket trigger for Windows
	s.logger.Debugf("Sending plain socket trigger (Windows).")
	respPlainWin, errPlainWin := sendPlain(s.target, s.port, s.protocol, triggerWindows, s.dialTimeout, s.receiveTimeout)

	// Check first error response for connection timeout. Don't proceed if host/port ist not reachable at all
	if socketErrorType(errPlainWin) == "dial" {
		s.logger.Debugf("Endpoint not reachable, aborting scan.")
		return &Result{
			&ResultData{},
			utils.StatusNotReachable,
			false,
		}
	}

	// Store result if not empty
	s.updateResultMap(tmpResults, tagPlain, respPlainWin, errPlainWin)

	// Try Linux line feed if Windows line feed did not work (wrong line feed might cause read timeout)
	if _, ok := tmpResults[tagPlain]; !ok {
		s.logger.Debugf("Sending plain socket trigger (Linux).")
		respPlainLin, errPlainLin := sendPlain(s.target, s.port, s.protocol, triggerLinux, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagPlain, respPlainLin, errPlainLin) // Store result if not empty
	}

	// Continue with triggers only working on TCP
	if s.protocol == "tcp" {

		// Try SSL socket trigger for Windows
		s.logger.Debugf("Sending SSL socket trigger (Windows).")
		respSslWin, errSslWin := sendSsl(s.target, s.port, triggerWindows, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagSsl, respSslWin, errSslWin) // Store result if not empty

		// Try Linux line feed if Windows line feed did not work (wrong line feed might cause read timeout)
		if _, ok := tmpResults[tagSsl]; !ok {
			// Try SSL socket trigger for Linux
			s.logger.Debugf("Sending SSL socket trigger (Linux).")
			respSslLin, errSslLin := sendSsl(s.target, s.port, triggerLinux, s.dialTimeout, s.receiveTimeout)
			s.updateResultMap(tmpResults, tagSsl, respSslLin, errSslLin) // Store result if not empty
		}

		// Try telnet trigger for Windows
		s.logger.Debugf("Sending telnet trigger (Windows).")
		respTelnetWin, errTelWin := sendTelnet(s.target, s.port, true, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagTelnet, respTelnetWin, errTelWin) // Store result if not empty

		// Try Linux line feed if Windows line feed did not work (wrong line feed might cause read timeout)
		if _, ok := tmpResults[tagTelnet]; !ok {
			// Try telnet trigger for Linux
			s.logger.Debugf("Sending telnet trigger (Linux).")
			respTelnetLin, errTelLin := sendTelnet(s.target, s.port, false, s.dialTimeout, s.receiveTimeout)
			s.updateResultMap(tmpResults, tagTelnet, respTelnetLin, errTelLin) // Store result if not empty
		}

		// Prepare HTTP request
		req := fmt.Sprintf(triggerHttp, s.target)

		// Try HTTP trigger
		s.logger.Debugf("Sending HTTP trigger.")
		respHttp, errHttp := sendPlain(s.target, s.port, "tcp", req, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagHttp, respHttp, errHttp) // Store result if not empty

		// Try HTTPs trigger
		s.logger.Debugf("Sending HTTPS trigger.")
		respHttps, errHttps := sendSsl(s.target, s.port, req, s.dialTimeout, s.receiveTimeout)
		s.updateResultMap(tmpResults, tagHttps, respHttps, errHttps) // Store result if not empty
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
	s.logger.Debugf("Returning scan result")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

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

func sendPlain(
	address string,
	port int,
	protocol string,
	trigger string,
	dialTimeout time.Duration,
	receiveTimeout time.Duration,
) ([]byte, error) {

	// Establish TCP/UDP connection
	conn, errCon := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", address, port), dialTimeout)

	// Return error if TCP/UDP connection failed
	if errCon != nil {
		return []byte{}, errCon
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
	n, errRead := conn.Read(responseBuffer)
	if errRead != nil && errRead.Error() != "EOF" {
		return []byte{}, errRead
	}

	// Slice the buffer up until first null byte if a null byte exists at all
	n = bytes.IndexByte(responseBuffer, 0)
	if n >= 0 {
		responseBuffer = responseBuffer[:n]
	}

	// Return response
	return responseBuffer, nil
}

func sendSsl(address string, port int, trigger string, dialTimeout, receiveTimeout time.Duration) ([]byte, error) {

	// Connect to address
	conn, errDial := tls.DialWithDialer(
		&net.Dialer{Timeout: dialTimeout},
		"tcp",
		fmt.Sprintf("%s:%d", address, port),
		utils.InsecureTlsConfigFactory(),
	)
	if errDial != nil {
		return []byte{}, errDial
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
	n, errRead := conn.Read(responseBuffer)
	if errRead != nil && errRead.Error() != "EOF" {
		return []byte{}, errRead
	}

	// Slice the buffer up until first null byte if a null byte exists at all
	n = bytes.IndexByte(responseBuffer, 0)
	if n >= 0 {
		responseBuffer = responseBuffer[:n]
	}

	// Return response
	return responseBuffer, nil
}

func sendTelnet(address string, port int, isWindows bool, dialTimeout, receiveTimeout time.Duration) ([]byte, error) {

	// Connect to address
	conn, errDial := telnet.DialTimeout("tcp", fmt.Sprintf("%s:%d", address, port), dialTimeout)
	if errDial != nil {
		return []byte{}, errDial
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
	n, errRead := conn.Read(responseBuffer)
	if errRead != nil && errRead.Error() != "EOF" {
		return []byte{}, errRead
	}

	// Slice the buffer up until first null byte if a null byte exists at all
	n = bytes.IndexByte(responseBuffer, 0)
	if n >= 0 {
		responseBuffer = responseBuffer[:n]
	}

	// Return response
	return responseBuffer, nil
}

// Digging deep to find out which kind of socket error happened. Because Golang is too stupid to give you an error code
// or a certain error type. Just an error string, which might be different on different OS/languages.
// Returns empty string if error is not a socket issue
func socketErrorType(err error) string {
	switch t := err.(type) {
	case *net.OpError:
		return t.Op // Might be "dial", "read", "write",...
	}
	return "" // Empty if not a socket error
}
