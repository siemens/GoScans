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

// profinetEtherType identifies PROFINET DCP Ethernet frames
const profinetEtherType = 0x8892

// profinetDcpIdentify and profinetDcpResponse share the value 0x05 because the PROFINET DCP spec
// assigns ServiceID=5 ("Identify") to both the request and its response; the ServiceType byte
// (Request=0x00, Response=0x01) distinguishes the two directions.
const profinetDcpIdentify = 0x05              // ServiceID for DCP Identify request
const profinetDcpResponse = 0x05              // ServiceID for DCP Identify response (same value by spec design)
const profinetDcpServiceReq = 0x00            // Request service type
const profinetDcpServiceRes = 0x01            // Response service type
const profinetListenTimeout = 5 * time.Second // profinetListenTimeout limits how long discovery waits for PROFINET responses

const dcpOptionDeviceProperties = 0x02 // Device-properties DCP option
const dcpSubOptionVendor = 0x01        // Device-vendor suboption
const dcpSubOptionNameOfStation = 0x02 // Station-name suboption
const dcpSubOptionDeviceId = 0x03      // Device-ID suboption

const dcpOptionIp = 0x01          // IP DCP option
const dcpSubOptionIpParams = 0x02 // IP-parameters suboption

// profinetMulticast stores the Profinet multicast destination
var profinetMulticast = net.HardwareAddr{0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00}

// ScanProfinetDcp sends a PROFINET DCP Identify multicast and collects responses.
func ScanProfinetDcp(logger utils.Logger, iface string) ([]Host, error) {

	// Open raw socket on the interface
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Bind an Ethernet raw socket for the PROFINET EtherType on the found interface
	conn, errConn := rawsocket.OpenEthernetSocket(ifi, profinetEtherType)
	if errConn != nil {
		return nil, fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Build DCP Identify Request frame and send multicast
	frame := buildDcpIdentifyFrame(ifi.HardwareAddr)
	logger.Debugf("Sending PROFINET DCP Identify multicast on '%s'.", iface)
	_, errSend := conn.Write(frame)
	if errSend != nil {
		return nil, fmt.Errorf("could not send DCP frame: %w", errSend)
	}

	// Listen for responses until the deadline
	var hosts []Host
	var deadline = time.Now().Add(profinetListenTimeout)
	_ = conn.SetReadDeadline(deadline)

	// Receive loop: read raw Ethernet frames until the deadline elapses
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, errN := conn.Read(buf)
		if errN != nil {
			if netErr, ok := errN.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}

		// Discard frames that are too short to contain an Ethernet header
		if n < 14 {
			continue
		}

		// Filter to PROFINET EtherType only
		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType != profinetEtherType {
			continue
		}

		// Parse source MAC and DCP response payload after the 14-byte Ethernet header
		srcMac := net.HardwareAddr(buf[6:12]).String()
		host := parseDcpResponse(buf[14:n], srcMac)
		if host != nil {
			logger.Debugf("PROFINET DCP response from '%s': hostname '%s', IP '%s'.", srcMac, strings.Join(host.DnsNames, ", "), strings.Join(host.Ips, ", "))
			hosts = append(hosts, *host)
		}
	}

	// Return nil as everything went fine
	return hosts, nil
}

// buildDcpIdentifyFrame constructs a PROFINET DCP Identify Request Ethernet frame.
func buildDcpIdentifyFrame(srcMac net.HardwareAddr) []byte {

	// Allocate the frame buffer with capacity for a minimum-size Ethernet frame
	frame := make([]byte, 0, 64)

	// Ethernet header: dst=PROFINET multicast, src=caller MAC, EtherType=0x8892
	frame = append(frame, profinetMulticast...)
	frame = append(frame, srcMac...)
	frame = append(frame, 0x88, 0x92)

	// PROFINET FrameID for DCP Identify Multicast request
	frame = append(frame, 0xFE, 0xFE)

	// DCP header: ServiceID, ServiceType, Xid, ResponseDelay, DCPDataLength
	frame = append(frame, profinetDcpIdentify)    // ServiceID
	frame = append(frame, profinetDcpServiceReq)  // ServiceType (Request)
	frame = append(frame, 0x00, 0x00, 0x00, 0x01) // Xid
	frame = append(frame, 0x00, 0x04)             // ResponseDelay factor
	frame = append(frame, 0x00, 0x04)             // DCPDataLength

	// DCP Block: Identify All (Option=0xFF, SubOption=0xFF, BlockLength=0)
	frame = append(frame, 0xFF, 0xFF)
	frame = append(frame, 0x00, 0x00)

	// Pad to the minimum Ethernet frame size of 64 bytes
	for len(frame) < 64 {
		frame = append(frame, 0x00)
	}

	// Return the completed DCP Identify Request frame
	return frame
}

// parseDcpResponse parses a PROFINET DCP Identify Response payload and returns a Host.
// Returns nil if the frame is invalid or not a DCP Identify Response.
func parseDcpResponse(data []byte, srcMac string) *Host {

	// Require at least a 12-byte DCP header
	if len(data) < 12 {
		return nil
	}

	// Check FrameID — DCP Identify Response is 0xFE, 0xFF
	if data[0] != 0xFE || data[1] != 0xFF {
		return nil
	}

	// Validate ServiceID and ServiceType
	serviceId := data[2]
	serviceType := data[3]
	if serviceId != profinetDcpResponse || serviceType != profinetDcpServiceRes {
		return nil
	}

	// Determine payload bounds from the DCPDataLength field
	dcpDataLen := int(binary.BigEndian.Uint16(data[10:12]))
	payload := data[12:]
	if len(payload) < dcpDataLen {
		dcpDataLen = len(payload)
	}

	// Initialise the Host record with the source MAC; DCP block parsing fills the remaining fields
	host := &Host{
		MacAddress: strings.ToUpper(srcMac),
	}

	// Iterate over DCP blocks and extract device properties and IP parameters
	offset := 0
	for offset+4 <= dcpDataLen {
		option := payload[offset]
		subOption := payload[offset+1]
		blockLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		// Stop if the block claims more data than is available
		if offset+blockLen > dcpDataLen {
			break
		}

		// Slice the block data bytes; the CTO list flagged each of these as needing a comment
		blockData := payload[offset : offset+blockLen]

		// Dispatch on the DCP block option to extract device-properties or IP fields
		switch option {
		case dcpOptionDeviceProperties:
			if len(blockData) < 2 {
				break
			}

			// First 2 bytes are BlockInfo; the actual value follows
			value := strings.TrimRight(string(blockData[2:]), "\x00")

			// Dispatch on sub-option to set the corresponding Host field
			switch subOption {
			case dcpSubOptionNameOfStation:
				if value != "" {
					host.DnsNames = utils.AppendUnique(host.DnsNames, value)
				}
			case dcpSubOptionVendor:
				host.OsGuesses = utils.AppendUnique(host.OsGuesses, "PROFINET - "+value)
			case dcpSubOptionDeviceId:
				if len(host.OsGuesses) == 0 {
					host.OsGuesses = utils.AppendUnique(host.OsGuesses, "PROFINET IO Device")
				}
			}

		case dcpOptionIp:
			// IP block: 2 bytes BlockInfo + IP(4) + Subnet(4) + Gateway(4)
			if subOption == dcpSubOptionIpParams && len(blockData) >= 14 {
				ip := net.IP(blockData[2:6])
				if !ip.Equal(net.IPv4zero) {
					host.Ips = utils.AppendUnique(host.Ips, ip.String())
				}
			}
		}

		// Blocks are padded to even byte boundaries
		offset += blockLen
		if blockLen%2 != 0 {
			offset++
		}
	}

	// Return nil as everything went fine
	return host
}

// listenProfinetDcp continuously captures PROFINET DCP Identify Response frames on iface and
// emits discovered hosts to ch. It only observes responses already present on the wire (e.g. from
// other controllers' broadcasts) without sending any probe itself. It returns when ctx is cancelled.
func listenProfinetDcp(ctx context.Context, logger utils.Logger, iface string, ch chan<- Host) error {

	// Look up the named interface
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Open a raw Ethernet socket for PROFINET frames
	conn, errConn := rawsocket.OpenEthernetSocket(ifi, profinetEtherType)
	if errConn != nil {
		return fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Close the socket when the context is cancelled so the blocked Read() below returns immediately
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// Read PROFINET frames forever; exit when the socket is closed by the watcher goroutine above
	buf := make([]byte, 1500)
	for {
		n, errN := conn.Read(buf)
		if errN != nil {
			return nil // context cancelled or socket closed — clean exit
		}

		// Discard frames too short for an Ethernet header
		if n < 14 {
			continue
		}

		// Filter to PROFINET EtherType only
		if binary.BigEndian.Uint16(buf[12:14]) != profinetEtherType {
			continue
		}

		// Parse source MAC and DCP response payload after the 14-byte Ethernet header
		srcMac := net.HardwareAddr(buf[6:12]).String()
		host := parseDcpResponse(buf[14:n], srcMac)
		if host != nil {
			//logger.Debugf("PROFINET DCP passive: response from '%s': hostname '%s', IP '%s'.", srcMac, strings.Join(host.DnsNames, ", "), strings.Join(host.Ips, ", "))
			ch <- *host
		}
	}
}
