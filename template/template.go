/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package template

import (
	"fmt"
	"go-scans/utils"
	"strings"
	"time"
)

const label = "Template"

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger) error {

	// Execute setup routines required for the scanner
	// TODO

	// Return nil as everything went fine
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup() error {

	// Check scanner prerequisites
	// TODO

	// Return nil as everything went fine
	return nil
}

// TODO adapt type as necessary
type Result struct {
	Data      map[string]string
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

// TODO adapt parameters as necessary
type Scanner struct {
	Label    string
	Started  time.Time
	Finished time.Time
	logger   utils.Logger
	target   string // Address to be scanned (might be IPv4, IPv6 or hostname)
	port     int
	protocol string
	deadline time.Time // Time when the scanner has to abort
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	protocol string,
) (*Scanner, error) {

	// Check whether input target is valid
	if !utils.IsValidAddress(target) {
		return nil, fmt.Errorf("invalid target '%s'", target)
	}
	// TODO validate arguments as necessary

	// Initiate scanner with sanitized input values
	// TODO adapt parameters and sanitize as required
	scan := Scanner{
		Label:    label,
		logger:   logger,
		target:   strings.TrimSpace(target),
		port:     port,
		protocol: strings.TrimSpace(protocol),
		deadline: time.Time{},
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

	// Declare variables
	// TODO adapt type as necessary
	results := map[string]string{}

	// Execute scan
	// TODO implement scan

	// Check whether scan timeout is reached
	// TODO regularly check if scan time frame is reached
	if utils.DeadlineReached(s.deadline) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			results,
			utils.StatusDeadline,
			false,
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
