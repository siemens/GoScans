/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"log"
	"os"
)

// Logger defines a minimum logger interface. This way the maximum flexibility in supported loggers can be offered.
// If your chosen logger does not implement one of the functions required by this interface, you can wrap it and
// append the missing exported function, redirecting to the original loggers suitable one.
type Logger interface {
	Debugf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Warningf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}

// TaggedLogger wraps a logger and allows to add a tag before every message.
// It should mainly be used to group information from different goroutines.
type TaggedLogger struct {
	Logger
	tag string
}

// Debugf prepends the tag to the format string and delegates to the wrapped logger.
func (l *TaggedLogger) Debugf(format string, v ...interface{}) {
	l.Logger.Debugf("["+l.tag+"] "+format, v...)
}

// Infof prepends the tag to the format string and delegates to the wrapped logger.
func (l *TaggedLogger) Infof(format string, v ...interface{}) {
	l.Logger.Infof("["+l.tag+"] "+format, v...)
}

// Warningf prepends the tag to the format string and delegates to the wrapped logger.
func (l *TaggedLogger) Warningf(format string, v ...interface{}) {
	l.Logger.Warningf("["+l.tag+"] "+format, v...)
}

// Errorf prepends the tag to the format string and delegates to the wrapped logger.
func (l *TaggedLogger) Errorf(format string, v ...interface{}) {
	l.Logger.Errorf("["+l.tag+"] "+format, v...)
}

// NewTaggedLogger wraps a logger with a tag that is prepended to every log message.
func NewTaggedLogger(logger Logger, tag string) *TaggedLogger {
	return &TaggedLogger{
		logger,
		tag,
	}
}

// TestLogger wraps the default golang logger and implements the required Logger interface
type TestLogger struct {
	*log.Logger
	tag string
}

// Debugf logs a debug-level message via the underlying standard logger.
func (l *TestLogger) Debugf(format string, v ...interface{}) {
	l.Printf(format+"\n", v...)
}

// Infof logs an info-level message via the underlying standard logger.
func (l *TestLogger) Infof(format string, v ...interface{}) {
	l.Printf(format+"\n", v...)
}

// Warningf logs a warning-level message via the underlying standard logger.
func (l *TestLogger) Warningf(format string, v ...interface{}) {
	l.Printf(format+"\n", v...)
}

// Errorf logs an error-level message via the underlying standard logger.
func (l *TestLogger) Errorf(format string, v ...interface{}) {
	l.Printf(format+"\n", v...)
}

// NewTestLogger returns a new standard golang logger compliant with the Logger interface
func NewTestLogger() *TestLogger {
	stdLogger := log.New(os.Stdout, "", log.LstdFlags)
	return &TestLogger{
		stdLogger,
		"",
	}
}
