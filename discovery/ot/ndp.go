/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ot

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/siemens/GoScans/utils"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// ndpListenTimeout limits how long NDP discovery waits for responses
const ndpListenTimeout = 5 * time.Second

// ScanNdp sends an ICMPv6 Neighbor Solicitation to ff02::1 and collects Neighbor Advertisements.
func ScanNdp(logger utils.Logger, iface string) ([]Host, error) {

	// Look up the interface by name
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Open an ICMPv6 raw socket
	conn, errConn := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if errConn != nil {
		return nil, fmt.Errorf("could not open ICMPv6 socket: %w", errConn)
	}
	defer func() { _ = conn.Close() }()

	// Join the all-nodes multicast group on the interface
	p := conn.IPv6PacketConn()
	allNodes := net.ParseIP("ff02::1")
	errJoin := p.JoinGroup(ifi, &net.IPAddr{IP: allNodes})
	if errJoin != nil {
		return nil, fmt.Errorf("could not join multicast group: %w", errJoin)
	}

	// Build and send a Neighbor Solicitation to the all-nodes multicast address
	msg := icmp.Message{
		Type: ipv6.ICMPTypeNeighborSolicitation,
		Code: 0,
		Body: &icmp.RawBody{Data: make([]byte, 20)},
	}
	msgBytes, errMsgBytes := msg.Marshal(nil)
	if errMsgBytes != nil {
		return nil, fmt.Errorf("could not marshal NDP solicitation: %w", errMsgBytes)
	}

	// Address the solicitation to the all-nodes multicast group, scoped to the interface
	dst := &net.IPAddr{IP: allNodes, Zone: iface}
	_, errSend := conn.WriteTo(msgBytes, dst)
	if errSend != nil {
		logger.Warningf("Could not send NDP solicitation: %s", errSend)
	}

	// Collect Neighbor Advertisements until the deadline, deduplicating by source IP
	var hosts []Host
	var seen = make(map[string]bool)
	var deadline = time.Now().Add(ndpListenTimeout)
	_ = conn.SetReadDeadline(deadline)

	// Receive loop: read ICMPv6 messages until the deadline elapses
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, peer, errRead := conn.ReadFrom(buf)
		if errRead != nil {
			break
		}

		// Minimum ICMPv6 message is 4 bytes
		if n < 4 {
			continue
		}

		// Parse the ICMPv6 message and filter to Neighbor Advertisements only
		parsed, errParsed := icmp.ParseMessage(58, buf[:n])
		if errParsed != nil {
			continue
		}
		if parsed.Type != ipv6.ICMPTypeNeighborAdvertisement {
			continue
		}

		// Deduplicate by source IP
		ip := peer.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true

		// Extract the Target Link-Layer Address option (type 2) from the advertisement body
		mac := extractNdpMac(buf[:n])

		// Prepare and append host struct
		host := Host{
			Ips:        []string{ip},
			MacAddress: mac,
		}
		logger.Debugf("NDP response from '%s': MAC '%s'.", ip, mac)
		hosts = append(hosts, host)
	}

	// Return nil as everything went fine
	return hosts, nil
}

// extractNdpMac extracts the MAC address from a Neighbor Advertisement's Target Link-Layer Address
// option (ICMPv6 option type 2). Returns an empty string when the option is absent or malformed.
func extractNdpMac(buf []byte) string {

	// Require at least a 28-byte buffer (4-byte ICMPv6 header + 24-byte advertisement body)
	if len(buf) < 28 {
		return ""
	}

	// The advertisement body starts at byte 4 (after the 4-byte ICMPv6 header)
	body := buf[4:]
	if len(body) < 24 {
		return ""
	}

	// Options begin after flags (4 bytes) + target address (16 bytes)
	optOffset := 20
	for optOffset+2 <= len(body) {
		optType := body[optOffset]
		optLen := int(body[optOffset+1]) * 8
		if optLen == 0 {
			break
		}

		// Option type 2 = Target Link-Layer Address (6-byte MAC at offset +2)
		if optType == 2 && optLen >= 8 && optOffset+8 <= len(body) {
			return strings.ToUpper(net.HardwareAddr(body[optOffset+2 : optOffset+8]).String())
		}
		optOffset += optLen
	}
	return ""
}
