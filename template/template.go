/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package template provides a reference skeleton for implementing GoScans scan modules.
package template

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/siemens/GoScans/utils"
)

// label identifies the template scanner
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

// Result holds the scan output data.
type Result struct {
	Data      map[string]string
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

// Scanner implements the template scan module.
type Scanner struct {
	Label    string
	Started  time.Time
	Finished time.Time
	logger   utils.Logger
	target   string // Address to be scanned (might be IPv4, IPv6 or hostname)
	port     int
	protocol string

	contextInner       context.Context    // Context for the scan, within which the scan should execute. Might optionally wrap an outer context. If outer context is cancelled, inner one should cancel too, but not the other way around.
	contextInnerCancel context.CancelFunc // Context cancel function of inner context, not impacting optional outer one.
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	protocol string,
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

	// TODO validate arguments as necessary

	// Initiate scanner with sanitized input values
	// TODO adapt parameters and sanitize as required
	scan := Scanner{
		Label:              label,
		logger:             logger,
		target:             target,
		port:               port,
		protocol:           protocol,
		contextInner:       nil,
		contextInnerCancel: nil,
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
	s.logger.Infof("Started  scan of %s:%d.", s.target, s.port)
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s:%d in %fm.", s.target, s.port, duration)

	// Return result set
	return res
}

func (s *Scanner) execute() *Result {

	// Cleanup inner context if set
	if s.contextInnerCancel != nil {
		defer s.contextInnerCancel()
	}

	// Declare variables
	// TODO adapt type as necessary
	results := map[string]string{}

	// Execute scan
	// TODO implement scan

	// Check whether scan timeout is reached
	// TODO regularly check if scan time frame is reached
	if utils.ContextExpired(s.contextInner) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			results,
			utils.StatusDeadline,
			false,
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
