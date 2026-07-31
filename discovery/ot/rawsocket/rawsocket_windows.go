//go:build windows

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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// pcapPollInterval is the read timeout passed to pcap.OpenLive. The handle will return
// NextErrorTimeoutExpired after this interval so the Read loop can check its deadline without
// blocking indefinitely inside the C library.
const pcapPollInterval = 10 * time.Millisecond

// conn wraps an Npcap pcap.Handle for sending/receiving raw Ethernet frames on Windows.
type conn struct {
	handle   *pcap.Handle
	mu       sync.Mutex
	deadline time.Time
}

// openEthernetSocket opens an Npcap handle bound to the given interface, filtered to the
// requested EtherType. Npcap must be installed (shipped with Nmap on Windows).
func openEthernetSocket(ifi *net.Interface, etherType uint16) (*conn, error) {

	// Find the Npcap device that corresponds to the Go net.Interface by matching IPv4 addresses
	device, errDevice := FindPcapDevice(ifi)
	if errDevice != nil {
		return nil, fmt.Errorf("could not find Npcap device for interface '%s': %w", ifi.Name, errDevice)
	}

	// Open the device in promiscuous mode with a short poll timeout so Read can honour deadlines
	handle, errHandle := pcap.OpenLive(device, 1518, true, pcapPollInterval)
	if errHandle != nil {
		return nil, fmt.Errorf("could not open Npcap device '%s': %w", device, errHandle)
	}

	// Restrict captured frames to the requested EtherType to avoid processing noise
	filter := fmt.Sprintf("ether proto 0x%04x", etherType)
	if errFilter := handle.SetBPFFilter(filter); errFilter != nil {
		handle.Close()
		return nil, fmt.Errorf("could not set BPF filter '%s': %w", filter, errFilter)
	}

	// Return nil as everything went fine
	return &conn{handle: handle}, nil
}

// Write injects a raw Ethernet frame onto the wire.
func (c *conn) Write(b []byte) (int, error) {

	// Transmit the frame via Npcap and map any error to the expected (0, err) signature
	if errSend := c.handle.WritePacketData(b); errSend != nil {
		return 0, errSend
	}

	// Return nil as everything went fine
	return len(b), nil
}

// Read receives the next raw Ethernet frame. It polls the Npcap handle at pcapPollInterval
// intervals and returns a net.Error with Timeout() == true when the read deadline elapses.
func (c *conn) Read(b []byte) (int, error) {

	for {
		// Check whether the deadline has already passed before attempting a read
		c.mu.Lock()
		dl := c.deadline
		c.mu.Unlock()
		if !dl.IsZero() && time.Now().After(dl) {
			return 0, &timeoutError{cause: errors.New("read deadline exceeded")}
		}

		// Attempt to read the next frame from the Npcap handle
		data, _, errRead := c.handle.ReadPacketData()
		if errors.Is(errRead, pcap.NextErrorTimeoutExpired) {
			continue // poll interval elapsed, re-check deadline and try again
		}
		if errRead != nil {
			return 0, errRead
		}

		// Copy as many bytes as the caller's buffer can hold
		n := copy(b, data)

		// Return nil as everything went fine
		return n, nil
	}
}

// SetReadDeadline sets the absolute time after which Read returns a timeout error.
func (c *conn) SetReadDeadline(t time.Time) error {

	// Store the deadline for the polling loop in Read to check
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()

	// Return nil as everything went fine
	return nil
}

// Close closes the Npcap handle, which also unblocks any in-progress Read call.
func (c *conn) Close() error {

	// pcap.Handle.Close signals the internal stop flag and releases the C handle
	c.handle.Close()

	// Return nil as everything went fine
	return nil
}

// FindPcapDevice returns the Npcap device name (e.g. \Device\NPF_{GUID}) whose address list
// contains an IPv4 address that matches one of the addresses assigned to ifi.
func FindPcapDevice(ifi *net.Interface) (string, error) {

	// Collect the IPv4 addresses assigned to the Go interface for matching
	addrs, errAddrs := ifi.Addrs()
	if errAddrs != nil {
		return "", fmt.Errorf("could not list addresses for '%s': %w", ifi.Name, errAddrs)
	}
	ifaceIps := make(map[string]struct{})
	for _, addr := range addrs {
		var ip net.IP
		switch addr := addr.(type) {
		case *net.IPNet:
			ip = addr.IP
		case *net.IPAddr:
			ip = addr.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			ifaceIps[ip4.String()] = struct{}{}
		}
	}

	// Enumerate all Npcap devices and find the one whose addresses overlap
	devices, errDevices := pcap.FindAllDevs()
	if errDevices != nil {
		return "", fmt.Errorf("could not enumerate Npcap devices: %w", errDevices)
	}
	for _, dev := range devices {
		for _, devAddr := range dev.Addresses {
			if ip4 := devAddr.IP.To4(); ip4 != nil {
				if _, ok := ifaceIps[ip4.String()]; ok {
					return dev.Name, nil
				}
			}
		}
	}

	// Return error if no Npcap device is found
	return "", fmt.Errorf("no Npcap device found for interface '%s'", ifi.Name)
}
