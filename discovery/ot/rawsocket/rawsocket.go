/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package rawsocket provides platform-specific raw socket implementations for OT protocol scanning.
package rawsocket

import (
	"net"
	"time"
)

// Conn abstracts a raw Ethernet socket. Both the Linux AF_PACKET and the Windows Npcap
// implementations satisfy this interface. Timeout errors returned by Read satisfy net.Error
// with Timeout() == true so callers can break receive loops with a single type assertion.
type Conn interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// OpenEthernetSocket opens a platform-specific raw Ethernet socket bound to the given
// interface and EtherType. On Linux this uses AF_PACKET; on Windows it uses Npcap/pcap.
func OpenEthernetSocket(ifi *net.Interface, etherType uint16) (Conn, error) {
	return openEthernetSocket(ifi, etherType)
}

// timeoutError signals that a read deadline has elapsed. It wraps an underlying error so
// callers can use errors.Is / errors.As to inspect the root cause (e.g. syscall.EAGAIN on Linux).
type timeoutError struct{ cause error }

// Error returns the underlying error message.
func (e *timeoutError) Error() string { return e.cause.Error() }

// Timeout returns true, marking this as a deadline-driven error.
func (e *timeoutError) Timeout() bool { return true }

// Temporary returns true for backwards compatibility with pre-Go-1.18 callers.
func (e *timeoutError) Temporary() bool { return true }

// Unwrap returns the underlying error for use with errors.Is and errors.As.
func (e *timeoutError) Unwrap() error { return e.cause }

// Ensure timeoutError satisfies net.Error at compile time.
var _ net.Error = (*timeoutError)(nil)
