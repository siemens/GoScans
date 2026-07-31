//go:build linux

/*
* Large-Scale Discovery, a network scanning solution for information gathering in large IT/OT network environments.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ot

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/siemens/GoScans/discovery/ot/rawsocket"
	"github.com/siemens/GoScans/utils"
)

// listenMdns joins the mDNS multicast group on iface and continuously captures unsolicited
// mDNS announcements, emitting each discovered host as a Host to ch. It returns when ctx is cancelled.
func listenMdns(ctx context.Context, logger utils.Logger, iface string, ch chan<- Host) error {

	// Look up the network interface to pass to the multicast listener
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Resolve the mDNS multicast group address
	mcastAddr, errMcastAddr := net.ResolveUDPAddr("udp4", mdnsAddr)
	if errMcastAddr != nil {
		return fmt.Errorf("could not resolve mDNS multicast address: %w", errMcastAddr)
	}

	// Join the mDNS multicast group so upstream switches deliver multicast to this interface.
	// We do not read from this socket; frame capture happens on the raw socket below.
	udpConn, errUdpConn := net.ListenMulticastUDP("udp4", ifi, mcastAddr)
	if errUdpConn != nil {
		return fmt.Errorf("could not join mDNS multicast group on '%s': %w", iface, errUdpConn)
	}
	defer func() { _ = udpConn.Close() }()

	// Bind the UDP socket to this interface so IGMP joins are scoped correctly and the socket
	// buffer does not accumulate multicast frames arriving on other interfaces.
	rawUdp, errRawUdp := udpConn.SyscallConn()
	if errRawUdp != nil {
		return fmt.Errorf("could not get raw connection for mDNS socket: %w", errRawUdp)
	}
	var errDevice error
	errControl := rawUdp.Control(func(fd uintptr) {
		errDevice = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	})
	if errControl != nil {
		return fmt.Errorf("could not set device binding on mDNS socket: %w", errControl)
	}
	if errDevice != nil {
		return fmt.Errorf("could not bind mDNS socket to interface '%s': %w", iface, errDevice)
	}

	// Open a raw IPv4 socket to capture mDNS frames with their Ethernet headers for the source MAC
	conn, errConn := rawsocket.OpenEthernetSocket(ifi, ipV4EtherType)
	if errConn != nil {
		return fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Close the raw socket when the context is cancelled so the blocked Read returns immediately
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// Read IPv4 frames forever; parseUdpFrame filters to mDNS in software
	buf := make([]byte, 1500)
	for {
		n, errN := conn.Read(buf)
		if errN != nil {
			return nil // context cancelled or socket closed — clean exit
		}

		// Extract source MAC, source IP, and UDP payload from the raw Ethernet frame
		srcMac, ip, payload := parseUdpFrame(buf[:n], mdnsDstIp, mdnsPort)
		if ip == "" {
			continue
		}

		// Minimum DNS header is 12 bytes
		if len(payload) < 12 {
			continue
		}

		// Decode the mDNS response name and forward the host to the caller
		hostname := extractMdnsName(payload)
		//logger.Debugf("mDNS passive: announcement from '%s': MAC '%s', hostname '%s'.", ip, srcMac, hostname)
		host := Host{MacAddress: srcMac, Ips: []string{ip}}
		if hostname != "" {
			host.DnsNames = []string{hostname}
		}
		ch <- host
	}
}

// listenSsdp joins the SSDP multicast group on iface and continuously captures unsolicited
// SSDP NOTIFY announcements, emitting each discovered device as a Host to ch. It returns when ctx is cancelled.
func listenSsdp(ctx context.Context, logger utils.Logger, iface string, ch chan<- Host) error {

	// Look up the network interface to pass to the multicast listener
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Resolve the SSDP multicast group address
	mcastAddr, errMcastAddr := net.ResolveUDPAddr("udp4", ssdpAddr)
	if errMcastAddr != nil {
		return fmt.Errorf("could not resolve SSDP multicast address: %w", errMcastAddr)
	}

	// Join the SSDP multicast group so upstream switches deliver multicast to this interface.
	// We do not read from this socket; frame capture happens on the raw socket below.
	udpConn, errUdpConn := net.ListenMulticastUDP("udp4", ifi, mcastAddr)
	if errUdpConn != nil {
		return fmt.Errorf("could not join SSDP multicast group on '%s': %w", iface, errUdpConn)
	}
	defer func() { _ = udpConn.Close() }()

	// Bind the UDP socket to this interface so IGMP joins are scoped correctly and the socket
	// buffer does not accumulate multicast frames arriving on other interfaces.
	rawUdp, errRawUdp := udpConn.SyscallConn()
	if errRawUdp != nil {
		return fmt.Errorf("could not get raw connection for SSDP socket: %w", errRawUdp)
	}
	var errDevice error
	errControl := rawUdp.Control(func(fd uintptr) {
		errDevice = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	})
	if errControl != nil {
		return fmt.Errorf("could not set device binding on SSDP socket: %w", errControl)
	}
	if errDevice != nil {
		return fmt.Errorf("could not bind SSDP socket to interface '%s': %w", iface, errDevice)
	}

	// Open a raw IPv4 socket to capture SSDP frames with their Ethernet headers for the source MAC
	conn, errConn := rawsocket.OpenEthernetSocket(ifi, ipV4EtherType)
	if errConn != nil {
		return fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Close the raw socket when the context is cancelled so the blocked Read returns immediately
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// Read IPv4 frames forever; parseUdpFrame filters to SSDP in software
	buf := make([]byte, 1500)
	for {
		n, errN := conn.Read(buf)
		if errN != nil {
			return nil // context cancelled or socket closed — clean exit
		}

		// Extract source MAC, source IP, and UDP payload from the raw Ethernet frame
		srcMac, ip, payload := parseUdpFrame(buf[:n], ssdpDstIp, ssdpPort)
		if ip == "" {
			continue
		}

		// Extract the SERVER header and forward the device to the caller
		serverInfo := extractSsdpServer(string(payload))
		//logger.Debugf("SSDP passive: announcement from '%s': MAC '%s', server '%s'.", ip, srcMac, serverInfo)
		host := Host{MacAddress: srcMac, Ips: []string{ip}}
		if serverInfo != "" {
			host.OsGuesses = []string{serverInfo}
		}
		ch <- host
	}
}
