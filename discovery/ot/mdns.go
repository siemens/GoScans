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
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/siemens/GoScans/discovery/ot/rawsocket"
	"github.com/siemens/GoScans/utils"
)

const mdnsAddr = "224.0.0.251:5353"       // mDNS multicast endpoint
const ssdpAddr = "239.255.255.250:1900"   // SSDP multicast endpoint
const mdnsListenTimeout = 5 * time.Second // Time allowed for multicast responses
const ipV4EtherType = uint16(0x0800)      // EtherType for IPv4 frames
const mdnsPort = uint16(5353)             // mDNS destination UDP port
const ssdpPort = uint16(1900)             // SSDP destination UDP port

var mdnsDstIp = net.IP{224, 0, 0, 251}     // mDNS multicast group address
var ssdpDstIp = net.IP{239, 255, 255, 250} // SSDP multicast group address

// ScanMdnsSsdp queries mDNS and SSDP multicast groups to discover devices on the given interface.
func ScanMdnsSsdp(logger utils.Logger, iface string) ([]Host, error) {

	// Resolve the interface object and its IPv4 address for binding the outgoing socket
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}
	localIp, errLocalIp := getInterfaceIpV4(iface)
	if errLocalIp != nil {
		return nil, errLocalIp
	}

	// Accumulate results from both sub-protocols
	var allHosts []Host

	// mDNS discovery
	mdnsHosts, errMdnsHosts := queryMdns(logger, ifi, localIp)
	if errMdnsHosts != nil {
		logger.Warningf("Could not execute mDNS discovery: %s", errMdnsHosts)
	} else {
		allHosts = append(allHosts, mdnsHosts...)
	}

	// SSDP discovery
	ssdpHosts, errSsdpHosts := querySsdp(logger, ifi, localIp)
	if errSsdpHosts != nil {
		logger.Warningf("Could not execute SSDP discovery: %s", errSsdpHosts)
	} else {
		allHosts = append(allHosts, ssdpHosts...)
	}

	// Return nil as everything went fine
	return allHosts, nil
}

// getInterfaceIpV4 returns the first IPv4 address assigned to the named interface.
func getInterfaceIpV4(iface string) (net.IP, error) {

	// Look up the interface by name
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Iterate addresses and return the first IPv4 one
	addrs, errAddrs := ifi.Addrs()
	if errAddrs != nil {
		return nil, fmt.Errorf("could not get addresses for '%s': %w", iface, errAddrs)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipV4 := ipNet.IP.To4(); ipV4 != nil {
			return ipV4, nil
		}
	}

	// Return nil as everything went fine
	return nil, fmt.Errorf("no IPv4 address on interface '%s'", iface)
}

// queryMdns sends an mDNS service-discovery query and collects responders. It opens a raw
// Ethernet socket for receiving so that the source MAC is extracted from every response frame.
func queryMdns(logger utils.Logger, ifi *net.Interface, localIp net.IP) ([]Host, error) {

	// Open a raw IPv4 socket for capturing mDNS response frames with their Ethernet headers
	raw, errRaw := rawsocket.OpenEthernetSocket(ifi, ipV4EtherType)
	if errRaw != nil {
		return nil, fmt.Errorf("could not open raw socket on '%s': %w", ifi.Name, errRaw)
	}
	defer func() { _ = raw.Close() }()

	// Resolve the mDNS multicast address and open a UDP socket bound to the local IP for sending
	addr, errAddr := net.ResolveUDPAddr("udp4", mdnsAddr)
	if errAddr != nil {
		return nil, errAddr
	}
	udp, errUdp := net.ListenUDP("udp4", &net.UDPAddr{IP: localIp, Port: 0})
	if errUdp != nil {
		return nil, errUdp
	}
	defer func() { _ = udp.Close() }()

	// Send the mDNS PTR query for _services._dns-sd._udp.local
	query := buildMdnsQuery("_services._dns-sd._udp.local")
	_, errSend := udp.WriteToUDP(query, addr)
	if errSend != nil {
		logger.Debugf("Could not send mDNS query: %s", errSend)
	}

	// Collect unique responders until the read deadline fires; mDNS responses are multicast
	var hosts []Host
	var seen = make(map[string]bool)
	_ = raw.SetReadDeadline(time.Now().Add(mdnsListenTimeout))

	// Receive loop: read raw frames until the deadline fires
	buf := make([]byte, 1500)
	for {
		n, errN := raw.Read(buf)
		if errN != nil {
			break
		}

		// Extract source MAC, source IP, and UDP payload; filters for mDNS destination
		srcMac, ip, payload := parseUdpFrame(buf[:n], mdnsDstIp, mdnsPort)
		if ip == "" {
			continue
		}

		// Record each unique source IP once
		if seen[ip] {
			continue
		}
		seen[ip] = true

		// Minimum DNS header is 12 bytes
		if len(payload) < 12 {
			continue
		}

		// Decode the mDNS response name and build a Host record
		hostname := extractMdnsName(payload)
		host := Host{MacAddress: srcMac, Ips: []string{ip}}
		if hostname != "" {
			host.DnsNames = []string{hostname}
		}
		logger.Debugf("mDNS response from '%s': MAC '%s', hostname '%s'.", ip, srcMac, hostname)
		hosts = append(hosts, host)
	}

	// Return nil as everything went fine
	return hosts, nil
}

// querySsdp sends an SSDP M-SEARCH request and collects responders. It opens a raw Ethernet
// socket for receiving so that the source MAC is extracted from every unicast response frame.
func querySsdp(logger utils.Logger, ifi *net.Interface, localIp net.IP) ([]Host, error) {

	// Open a raw IPv4 socket for capturing SSDP response frames with their Ethernet headers
	raw, errRaw := rawsocket.OpenEthernetSocket(ifi, ipV4EtherType)
	if errRaw != nil {
		return nil, fmt.Errorf("could not open raw socket on '%s': %w", ifi.Name, errRaw)
	}
	defer func() { _ = raw.Close() }()

	// Resolve the SSDP multicast address and open a UDP socket bound to the local IP for sending
	addr, errAddr := net.ResolveUDPAddr("udp4", ssdpAddr)
	if errAddr != nil {
		return nil, errAddr
	}
	udp, errUdp := net.ListenUDP("udp4", &net.UDPAddr{IP: localIp, Port: 0})
	if errUdp != nil {
		return nil, errUdp
	}
	defer func() { _ = udp.Close() }()

	// Read back the ephemeral port the OS assigned so we can filter incoming unicast responses
	localPort := uint16(udp.LocalAddr().(*net.UDPAddr).Port)

	// Send the SSDP M-SEARCH request to the multicast group
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"
	_, errSend := udp.WriteToUDP([]byte(msearch), addr)
	if errSend != nil {
		logger.Debugf("Could not send SSDP M-SEARCH: %s", errSend)
	}

	// Collect unique responders until the read deadline fires. SSDP responses are unicast to our
	// ephemeral port so we filter on localIp:localPort rather than the multicast destination.
	var hosts []Host
	var seen = make(map[string]bool)
	_ = raw.SetReadDeadline(time.Now().Add(mdnsListenTimeout))

	// Receive loop: read raw frames until the deadline fires
	buf := make([]byte, 1500)
	for {
		n, errN := raw.Read(buf)
		if errN != nil {
			break
		}

		// Extract source MAC, source IP, and UDP payload; filters for our unicast destination
		srcMac, ip, payload := parseUdpFrame(buf[:n], localIp, localPort)
		if ip == "" {
			continue
		}

		// Record each unique source IP once
		if seen[ip] {
			continue
		}
		seen[ip] = true

		// Extract the SERVER header and build a Host record
		serverInfo := extractSsdpServer(string(payload))
		host := Host{MacAddress: srcMac, Ips: []string{ip}}
		if serverInfo != "" {
			host.OsGuesses = []string{serverInfo}
		}
		logger.Debugf("SSDP response from '%s': MAC '%s', server '%s'.", ip, srcMac, serverInfo)
		hosts = append(hosts, host)
	}

	// Return nil as everything went fine
	return hosts, nil
}

// buildMdnsQuery constructs a minimal mDNS/DNS-SD PTR query packet for the given name.
func buildMdnsQuery(name string) []byte {

	// Build a minimal DNS query packet for the given name
	var pkt []byte

	// DNS header: ID=0, Flags=0 (standard query), QD=1, AN/NS/AR=0
	pkt = append(pkt, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)

	// Encode the query name as DNS labels
	for _, part := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, []byte(part)...)
	}
	pkt = append(pkt, 0) // root label terminator

	// QTYPE=PTR (12), QCLASS=IN (1)
	pkt = append(pkt, 0, 12, 0, 1)

	// Return the completed DNS PTR query packet
	return pkt
}

// extractMdnsName scans the answer records of an mDNS packet and returns the hostname from the
// first A record (Type 1). In an A record the owner NAME is "hostname.local", making it the only
// record type where the NAME field directly identifies the device. PTR records are intentionally
// excluded: their NAME is the query being answered (e.g. a reverse IPv6 arpa address or a service
// type like "_http._tcp.local"), not the device hostname — the hostname lives in their RDATA.
// Returns an empty string when no A record is present (e.g. queries, probes, service-only responses).
func extractMdnsName(data []byte) string {

	// Require at least a 12-byte DNS header
	if len(data) < 12 {
		return ""
	}

	// Skip past all question records to reach the answer section
	offset := 12
	qdCount := int(data[4])<<8 | int(data[5])
	for i := 0; i < qdCount && offset < len(data); i++ {
		offset = skipDnsName(data, offset)
		offset += 4 // QTYPE + QCLASS
	}

	// Iterate answer records looking for the first A record (Type 1)
	anCount := int(data[6])<<8 | int(data[7])
	for i := 0; i < anCount && offset < len(data); i++ {

		// Record the start of this record's name so we can decode it if the type matches
		nameOffset := offset
		offset = skipDnsName(data, offset)

		// Need at least type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes after the name
		if offset+10 > len(data) {
			break
		}

		// Read the record type and rdlength, then advance past the rdata
		rrType := int(data[offset])<<8 | int(data[offset+1])
		rdLength := int(data[offset+8])<<8 | int(data[offset+9])
		offset += 10 + rdLength

		// Only A records carry the device hostname as their owner NAME
		if rrType != 1 {
			continue
		}

		// Decode, strip .local suffix, and return the hostname
		name := decodeDnsName(data, nameOffset)
		name = strings.TrimSuffix(name, ".local.")
		name = strings.TrimSuffix(name, ".local")
		return name
	}

	// No A record found in the answer section
	return ""
}

// skipDnsName advances offset past a DNS wire-format name (labels or compression pointer) and
// returns the new offset positioned immediately after the name terminator.
func skipDnsName(data []byte, offset int) int {

	// Walk labels and pointers until the root label or end of data
	for offset < len(data) {
		if data[offset]&0xC0 == 0xC0 {
			return offset + 2 // compression pointer is always 2 bytes
		}
		if data[offset] == 0 {
			return offset + 1 // root label terminator
		}
		offset += int(data[offset]) + 1
	}

	// Return offset as-is if data ran out
	return offset
}

// decodeDnsName iteratively decodes a DNS wire-format name starting at offset.
// It follows compression pointers and guards against infinite pointer cycles.
func decodeDnsName(data []byte, offset int) string {

	// Accumulate decoded labels; joined with "." on return
	var parts []string

	// Guard against pointer loops: each byte offset may be visited at most once
	visited := make(map[int]bool)

	// Iteratively decode labels and follow compression pointers
	for offset < len(data) {
		if visited[offset] {
			break // pointer cycle detected — terminate
		}
		visited[offset] = true

		// Read the next label length or compression-pointer marker
		length := int(data[offset])
		if length == 0 {
			break
		}

		// Follow a DNS compression pointer (top two bits set)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			ptr := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			offset = ptr // jump; continue the same loop rather than recursing
			continue
		}

		// Read a plain label
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	// Return the assembled domain name
	return strings.Join(parts, ".")
}

// parseUdpFrame extracts the source MAC, source IP, and UDP payload from a raw Ethernet frame,
// verifying that the destination IP and destination UDP port match the given values. Returns empty
// strings and nil payload when the frame does not match. Works for both multicast and unicast destinations.
func parseUdpFrame(frame []byte, dstIp net.IP, dstPort uint16) (srcMac, srcIp string, payload []byte) {

	// Require at least a 14-byte Ethernet header + 20-byte IPv4 header + 8-byte UDP header
	if len(frame) < 42 {
		return "", "", nil
	}

	// Only handle IPv4 frames (EtherType 0x0800)
	if binary.BigEndian.Uint16(frame[12:14]) != ipV4EtherType {
		return "", "", nil
	}

	// Only handle UDP (IP protocol 17)
	ipHeader := frame[14:]
	if ipHeader[9] != 17 {
		return "", "", nil
	}

	// Verify the destination IP matches the expected multicast group
	if !net.IP(ipHeader[16:20]).Equal(dstIp) {
		return "", "", nil
	}

	// Compute the IPv4 header length from the IHL field (lower nibble, in 32-bit words)
	ihl := int(ipHeader[0]&0x0F) * 4
	if len(ipHeader) < ihl+8 {
		return "", "", nil
	}

	// Verify the destination UDP port matches
	udpHeader := ipHeader[ihl:]
	if binary.BigEndian.Uint16(udpHeader[2:4]) != dstPort {
		return "", "", nil
	}

	// Extract source MAC from Ethernet header bytes 6–11
	mac := strings.ToUpper(net.HardwareAddr(frame[6:12]).String())

	// Extract source IP from the IPv4 header
	ip := net.IP(ipHeader[12:16]).String()

	// Return source MAC, source IP, and UDP payload (after the 8-byte UDP header)
	return mac, ip, udpHeader[8:]
}

// extractSsdpServer extracts the value of the SERVER header from an SSDP response.
// Returns an empty string when no SERVER header is present.
func extractSsdpServer(response string) string {

	// Scan header lines for the SERVER field
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}
