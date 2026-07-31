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
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/siemens/GoScans/discovery/ot/rawsocket"
	"github.com/siemens/GoScans/utils"
)

const arpEtherType = 0x0806                // Ethernet protocol type for ARP
const arpMaxCidr = 20                      // Largest IPv4 subnet accepted for an ARP scan
const arpSendPace = 200 * time.Microsecond // Delay between ARP requests
const arpTimeoutBase = 5 * time.Second     // Base time allowed for ARP responses

// arpBroadcast stores the Ethernet broadcast address used for ARP discovery
var arpBroadcast = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// ScanArp sends ARP requests to every host in the subnet of the given interface and collects replies.
func ScanArp(logger utils.Logger, iface string) ([]Host, error) {

	// Resolve the interface IPv4 address and its subnet
	eth, ethIp, ethNet, errEth := interfaceIpV4Net(iface)
	if errEth != nil {
		return nil, errEth
	}

	// Check if subnet size can be processed
	ones, _ := ethNet.Mask.Size()
	if ones < arpMaxCidr { // ones are reversely proportional compared to subnet size
		return nil, fmt.Errorf("subnet /%d on '%s' is too large for ARP scan (maximum is /%d)", ones, iface, arpMaxCidr)
	}

	// Enumerate all usable host addresses before opening the socket so we can size the result buffer
	targets := subnetHosts(ethNet)

	// Open a raw Ethernet socket for ARP frames on the interface
	conn, errConn := rawsocket.OpenEthernetSocket(eth, arpEtherType)
	if errConn != nil {
		return nil, fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Buffer sized to the total number of targets: the receiver goroutine can never produce more
	// replies than there are hosts, and the buffer prevents it from blocking while sends are in flight
	type arpResult struct{ mac, ip string }
	chResults := make(chan arpResult, len(targets)+1)

	// Start the receiver goroutine before the first request is sent so fast responders are not missed.
	// The deadline is set later, after sends complete, so fast replies during sending are captured
	// and the full listen window applies after the last request leaves the wire.
	ready := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)

		// Signal to the main goroutine that we are now blocked on Read()
		// and guaranteed to receive any frame that arrives from this point on
		close(ready)

		for {
			n, errN := conn.Read(buf)
			if errN != nil {
				if netErr, ok := errN.(net.Error); ok && netErr.Timeout() {
					break // deadline hit, exit
				}
				continue
			}
			mac, ip := parseArpReply(buf[:n])
			if mac != "" {
				chResults <- arpResult{mac: mac, ip: ip}
			}
		}
		close(chResults)
	}()

	// Block here until the listener signals it is ready so zero frames are sent before the listener is on Read()
	<-ready

	// Send ARP requests to all target addresses while the receiver is already listening
	logger.Infof("Sending ARP requests for %d addresses on '%s' (timeout %s).", len(targets), iface, arpTimeout(len(targets)))
	for _, target := range targets {
		frame := buildArpRequestFrame(eth.HardwareAddr, ethIp, target)
		_, errSend := conn.Write(frame)
		if errSend != nil {
			logger.Debugf("Could not send ARP request to '%s': %s", target, errSend)
		}
		time.Sleep(arpSendPace)
	}

	// Arm the read deadline now that all requests have been sent, giving late responders the full
	// listen window from this point on
	timeout := arpTimeout(len(targets))
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Collect and deduplicate results until the receiver closes the channel at the deadline
	var hosts []Host
	var seen = make(map[string]struct{})
	for result := range chResults {
		if _, ok := seen[result.mac]; ok {
			continue
		}
		seen[result.mac] = struct{}{}
		logger.Debugf("ARP reply from '%s': MAC '%s'.", result.ip, result.mac)
		hosts = append(hosts, Host{MacAddress: result.mac, Ips: []string{result.ip}})
	}

	// Return nil as everything went fine
	return hosts, nil
}

// listenArp continuously captures gratuitous ARP frames on iface and emits discovered hosts
// to ch. Gratuitous ARP frames are ARP requests or replies where the sender IP equals the target IP,
// typically emitted by devices coming online or refreshing their L2 presence.
func listenArp(ctx context.Context, logger utils.Logger, iface string, ch chan<- Host) error {

	// Look up the named interface
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Open a raw Ethernet socket for ARP frames
	conn, errConn := rawsocket.OpenEthernetSocket(ifi, arpEtherType)
	if errConn != nil {
		return fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Close the socket when the context is canceled so the blocked Read() below returns immediately
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// Read ARP frames forever; exit when the socket is closed by the watcher goroutine above
	buf := make([]byte, 1500)
	for {
		n, errN := conn.Read(buf)
		if errN != nil {
			return nil // context cancelled or socket closed, clean exit
		}

		// Parse only gratuitous ARP frames; regular request/reply traffic is discarded
		mac, ip := parseGratuitousArp(buf[:n])
		if mac == "" {
			continue
		}

		// logger.Debugf("ARP passive: gratuitous ARP from '%s': MAC '%s'.", ip, mac)
		ch <- Host{MacAddress: mac, Ips: []string{ip}}
	}
}

// arpTimeout returns a listen duration scaled to the number of target hosts.
func arpTimeout(hostCount int) time.Duration {
	return arpTimeoutBase + time.Duration(hostCount/256)*time.Second
}

// interfaceIpV4Net returns the IPv4 address and its network for the named interface.
func interfaceIpV4Net(iface string) (*net.Interface, net.IP, *net.IPNet, error) {

	// Look up the interface by name
	eth, errEth := net.InterfaceByName(iface)
	if errEth != nil {
		return nil, nil, nil, fmt.Errorf("could not find interface '%s': %w", iface, errEth)
	}

	// Iterate all assigned addresses looking for the first IPv4 one
	addrs, errAddrs := eth.Addrs()
	if errAddrs != nil {
		return nil, nil, nil, fmt.Errorf("could not list addresses on '%s': %w", iface, errAddrs)
	}
	for _, addr := range addrs {
		ethNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ethIp := ethNet.IP.To4(); ethIp != nil {
			return eth, ethIp, &net.IPNet{IP: ethIp.Mask(ethNet.Mask), Mask: ethNet.Mask}, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("no IPv4 address on interface '%s'", iface)
}

// subnetHosts returns all usable host addresses in the given IPv4 network,
// excluding the network address and the broadcast address.
func subnetHosts(ipNet *net.IPNet) []net.IP {

	// Compute the numeric start (network address) and end (broadcast) of the range
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil
	}
	start := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32([]byte(ipNet.Mask))
	broadcast := start | ^mask

	// Enumerate every address between network+1 and broadcast-1 inclusive
	var hosts []net.IP
	for addr := start + 1; addr < broadcast; addr++ {
		b := make(net.IP, 4)
		binary.BigEndian.PutUint32(b, addr)
		hosts = append(hosts, b)
	}

	// Return the hosts
	return hosts
}

// buildArpRequestFrame constructs an ARP request Ethernet frame asking "who has targetIp?"
func buildArpRequestFrame(srcMac net.HardwareAddr, srcIp, targetIp net.IP) []byte {

	// Allocate and build the 42-byte ARP request frame (14 Ethernet + 28 ARP)
	frame := make([]byte, 42)

	// Ethernet header: dst=broadcast, src=srcMac, EtherType=0x0806
	copy(frame[0:6], arpBroadcast)
	copy(frame[6:12], srcMac)
	binary.BigEndian.PutUint16(frame[12:14], arpEtherType)

	// ARP payload: HTYPE=Ethernet(1), PTYPE=IPv4(0x0800), HLEN=6, PLEN=4
	binary.BigEndian.PutUint16(frame[14:16], 1)      // HTYPE
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // PTYPE
	frame[18] = 6                                    // HLEN
	frame[19] = 4                                    // PLEN
	binary.BigEndian.PutUint16(frame[20:22], 1)      // OPER = request

	// Sender hardware address and sender protocol address
	copy(frame[22:28], srcMac)
	copy(frame[28:32], srcIp.To4())

	// Target hardware address (zeroed for request) and target protocol address
	copy(frame[32:38], make([]byte, 6))
	copy(frame[38:42], targetIp.To4())

	// Return the constructed frame
	return frame
}

// parseArpReply extracts the sender MAC and IP from an ARP reply Ethernet frame.
// Returns empty strings when the frame is not a valid ARP reply.
func parseArpReply(buf []byte) (mac, ip string) {

	// Require a full ARP frame: 14-byte Ethernet header + 28-byte ARP payload
	if len(buf) < 42 {
		return "", ""
	}

	// Filter by EtherType
	if binary.BigEndian.Uint16(buf[12:14]) != arpEtherType {
		return "", ""
	}

	// OPER must be 2 (reply)
	if binary.BigEndian.Uint16(buf[20:22]) != 2 {
		return "", ""
	}

	// Extract sender MAC and sender IP from the ARP payload
	senderMac := net.HardwareAddr(buf[22:28]).String()
	senderIp := net.IP(buf[28:32]).String()

	// Return the extracted MAC and IP
	return strings.ToUpper(senderMac), senderIp
}

// parseGratuitousArp extracts the sender MAC and IP from a gratuitous ARP frame.
// A gratuitous ARP is identified by the sender IP equalling the target IP, which devices send to
// announce themselves on the network. Returns empty strings for any other ARP frame type.
func parseGratuitousArp(buf []byte) (mac, ip string) {

	// Require a full ARP frame: 14-byte Ethernet header + 28-byte ARP payload
	if len(buf) < 42 {
		return "", ""
	}

	// Filter by EtherType
	if binary.BigEndian.Uint16(buf[12:14]) != arpEtherType {
		return "", ""
	}

	// OPER must be 1 (request) or 2 (reply); gratuitous ARPs appear as both
	oper := binary.BigEndian.Uint16(buf[20:22])
	if oper != 1 && oper != 2 {
		return "", ""
	}

	// A gratuitous ARP has identical sender IP and target IP
	senderIp := net.IP(buf[28:32])
	targetIp := net.IP(buf[38:42])
	if !senderIp.Equal(targetIp) {
		return "", ""
	}

	// All-zero sender IP is not meaningful
	if senderIp.Equal(net.IPv4zero) {
		return "", ""
	}

	// Extract sender MAC and sender IP from the ARP payload
	senderMac := net.HardwareAddr(buf[22:28]).String()
	return strings.ToUpper(senderMac), senderIp.String()
}
