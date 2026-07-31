//go:build windows

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
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/siemens/GoScans/discovery/ot/rawsocket"
	"github.com/siemens/GoScans/utils"
)

// pcapPollInterval is the read timeout used when opening a pcap handle for passive listeners.
// The handle returns after this interval so the Read loop can check for context cancellation.
const pcapPollInterval = 10 * time.Millisecond

// listenMdns opens a pcap handle on iface filtered to inbound UDP traffic destined for the mDNS
// multicast group (224.0.0.251:5353) and continuously captures unsolicited mDNS announcements,
// emitting each discovered host as a Host to ch. It returns when ctx is cancelled.
func listenMdns(ctx context.Context, logger utils.Logger, iface string, ch chan<- Host) error {

	// Look up the network interface so we can find the matching Npcap device
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Map the Go interface to the Npcap device name
	device, errDevice := rawsocket.FindPcapDevice(ifi)
	if errDevice != nil {
		return fmt.Errorf("could not find Npcap device for '%s': %w", iface, errDevice)
	}

	// Open the Npcap handle; a short poll interval lets us check context cancellation promptly
	handle, errHandle := pcap.OpenLive(device, 1518, true, pcapPollInterval)
	if errHandle != nil {
		return fmt.Errorf("could not open mDNS passive socket on '%s': %w", iface, errHandle)
	}
	defer func() { handle.Close() }()

	// BPF filter: capture only UDP packets destined for the mDNS multicast address and port
	if errFilter := handle.SetBPFFilter("udp and dst host 224.0.0.251 and dst port 5353"); errFilter != nil {
		return fmt.Errorf("could not set mDNS BPF filter on '%s': %w", iface, errFilter)
	}

	// Read frames forever; check for context cancellation on each poll timeout
	for {
		// Check whether the context has been cancelled before blocking on the next read
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Attempt to read the next matching frame from Npcap
		data, _, errRead := handle.ReadPacketData()
		if errors.Is(errRead, pcap.NextErrorTimeoutExpired) {
			continue // poll interval elapsed — re-check context and try again
		}
		if errRead != nil {
			return nil // handle closed or unrecoverable error — clean exit
		}

		// Extract source MAC, source IP, and UDP payload from the raw Ethernet frame
		srcMac, ip, payload := parseUdpFrame(data, mdnsDstIp, mdnsPort)
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

// listenSsdp opens a pcap handle on iface filtered to inbound UDP traffic destined for the SSDP
// multicast group (239.255.255.250:1900) and continuously captures unsolicited SSDP NOTIFY
// announcements, emitting each discovered device as a Host to ch. It returns when ctx is cancelled.
func listenSsdp(ctx context.Context, logger utils.Logger, iface string, ch chan<- Host) error {

	// Look up the network interface so we can find the matching Npcap device
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Map the Go interface to the Npcap device name
	device, errDevice := rawsocket.FindPcapDevice(ifi)
	if errDevice != nil {
		return fmt.Errorf("could not find Npcap device for '%s': %w", iface, errDevice)
	}

	// Open the Npcap handle; a short poll interval lets us check context cancellation promptly
	handle, errHandle := pcap.OpenLive(device, 1518, true, pcapPollInterval)
	if errHandle != nil {
		return fmt.Errorf("could not open SSDP passive socket on '%s': %w", iface, errHandle)
	}
	defer func() { handle.Close() }()

	// BPF filter: capture only UDP packets destined for the SSDP multicast address and port
	if errFilter := handle.SetBPFFilter("udp and dst host 239.255.255.250 and dst port 1900"); errFilter != nil {
		return fmt.Errorf("could not set SSDP BPF filter on '%s': %w", iface, errFilter)
	}

	// Read frames forever; check for context cancellation on each poll timeout
	for {
		// Check whether the context has been cancelled before blocking on the next read
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Attempt to read the next matching frame from Npcap
		data, _, errRead := handle.ReadPacketData()
		if errors.Is(errRead, pcap.NextErrorTimeoutExpired) {
			continue // poll interval elapsed — re-check context and try again
		}
		if errRead != nil {
			return nil // handle closed or unrecoverable error — clean exit
		}

		// Extract source MAC, source IP, and UDP payload from the raw Ethernet frame
		srcMac, ip, payload := parseUdpFrame(data, ssdpDstIp, ssdpPort)
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
