//go:build linux

/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package rawsocket

import (
	"net"
	"syscall"
	"time"
)

// conn wraps a Linux AF_PACKET socket for sending/receiving raw Ethernet frames.
type conn struct {
	fd    int
	ifIdx int
}

// openEthernetSocket opens a raw Ethernet socket bound to the given interface and EtherType.
func openEthernetSocket(ifi *net.Interface, etherType uint16) (*conn, error) {

	// Create AF_PACKET raw socket for the requested EtherType
	fd, errFd := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherType)))
	if errFd != nil {
		return nil, errFd
	}

	// Bind the socket to the network interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  ifi.Index,
	}
	if errBind := syscall.Bind(fd, &addr); errBind != nil {
		_ = syscall.Close(fd)
		return nil, errBind
	}

	// Return nil as everything went fine
	return &conn{fd: fd, ifIdx: ifi.Index}, nil
}

// Write sends raw bytes to the bound interface.
func (c *conn) Write(b []byte) (int, error) {

	// Send bytes via AF_PACKET sendto; return 0 bytes written on any failure
	addr := syscall.SockaddrLinklayer{
		Ifindex: c.ifIdx,
	}
	if errSend := syscall.Sendto(c.fd, b, 0, &addr); errSend != nil {
		return 0, errSend
	}

	// Return nil as everything went fine
	return len(b), nil
}

// Read receives raw bytes from the socket. When the SO_RCVTIMEO deadline fires, it returns a
// net.Error with Timeout() == true so callers can break their receive loop with a single type check.
func (c *conn) Read(b []byte) (int, error) {

	// Receive a frame; wrap EAGAIN/EWOULDBLOCK as a timeout net.Error
	n, _, errRecv := syscall.Recvfrom(c.fd, b, 0)
	if errRecv == syscall.EAGAIN || errRecv == syscall.EWOULDBLOCK {
		return 0, &timeoutError{cause: errRecv}
	}

	// Return nil as everything went fine
	return n, errRecv
}

// SetReadDeadline sets a timeout for read operations using SO_RCVTIMEO.
func (c *conn) SetReadDeadline(t time.Time) error {

	// Convert the absolute deadline to a relative duration clamped to zero
	d := time.Until(t)
	if d < 0 {
		d = 0
	}

	// Apply the socket option
	tv := syscall.Timeval{
		Sec:  int64(d / time.Second),
		Usec: int64((d % time.Second) / time.Microsecond),
	}
	return syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// Close closes the raw socket.
func (c *conn) Close() error {
	return syscall.Close(c.fd)
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
