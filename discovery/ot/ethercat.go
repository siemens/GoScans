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

const ethercatEtherType = 0x88A4              // Ethernet protocol type for EtherCAT
const ethercatBrdCommand = 0x07               // BRD — Broadcast Read
const ethercatListenTimeout = 5 * time.Second // Time allowed for EtherCAT responses

// ethercatBroadcast stores the Ethernet broadcast address used for EtherCAT discovery
var ethercatBroadcast = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// ScanEthercat sends an EtherCAT broadcast read and collects responding slaves.
func ScanEthercat(logger utils.Logger, iface string) ([]Host, error) {

	// Open raw socket on the interface
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Bind an Ethernet raw socket for the EtherCAT EtherType on the found interface
	conn, errConn := rawsocket.OpenEthernetSocket(ifi, ethercatEtherType)
	if errConn != nil {
		return nil, fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Build EtherCAT BRD frame and send broadcast to read DL Status register (ADO 0x0110)
	frame := buildEthercatBrdFrame(ifi.HardwareAddr, 0x0110, 2)

	// Log action
	logger.Debugf("Sending EtherCAT BRD frame on '%s'.", iface)
	_, errSend := conn.Write(frame)
	if errSend != nil {
		return nil, fmt.Errorf("could not send EtherCAT frame: %w", errSend)
	}

	// Listen for responses until the deadline, deduplicating by source MAC
	var hosts []Host
	var seen = make(map[string]bool)
	var deadline = time.Now().Add(ethercatListenTimeout)
	_ = conn.SetReadDeadline(deadline)

	// Receive loop: read raw frames until the deadline elapses
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

		// Filter to EtherCAT EtherType only
		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType != ethercatEtherType {
			continue
		}

		// Record each unique source MAC as an EtherCAT slave
		srcMac := strings.ToUpper(net.HardwareAddr(buf[6:12]).String())
		if seen[srcMac] {
			continue
		}
		seen[srcMac] = true

		// Record the EtherCAT slave with its source MAC
		host := Host{
			MacAddress: srcMac,
			OsGuesses:  []string{"EtherCAT Slave"},
		}
		logger.Debugf("EtherCAT response: MAC '%s'.", srcMac)
		hosts = append(hosts, host)
	}

	// Return nil as everything went fine
	return hosts, nil
}

// buildEthercatBrdFrame constructs an EtherCAT BRD (Broadcast Read) Ethernet frame.
// ado is the physical memory address to read; length is the number of data bytes requested.
func buildEthercatBrdFrame(srcMac net.HardwareAddr, ado uint16, length uint16) []byte {

	// Allocate the frame buffer with capacity for a minimum-size Ethernet frame
	frame := make([]byte, 0, 64)

	// Ethernet header: dst=broadcast, src=caller MAC, EtherType=0x88A4
	frame = append(frame, ethercatBroadcast...)
	frame = append(frame, srcMac...)
	frame = append(frame, 0x88, 0xA4)

	// EtherCAT header (2 bytes): 11-bit payload length + 4-bit type (1=commands) + reserved
	ecatHeaderLen := uint16(10)                // datagram size in bytes
	ecatHeader := ecatHeaderLen | (0x01 << 12) // type 1 = EtherCAT commands
	frame = append(frame, byte(ecatHeader), byte(ecatHeader>>8))

	// EtherCAT datagram header: command, index, ADP, ADO, length+flags, IRQ
	frame = append(frame, ethercatBrdCommand)            // Command: BRD
	frame = append(frame, 0x00)                          // Index
	frame = append(frame, 0x00, 0x00)                    // ADP (auto-increment address, 0 = first slave)
	frame = append(frame, byte(ado), byte(ado>>8))       // ADO (physical memory address, little-endian)
	frame = append(frame, byte(length), byte(length>>8)) // Length + flags
	frame = append(frame, 0x00, 0x00)                    // IRQ

	// Data payload (zeroed for read) followed by working counter
	for i := uint16(0); i < length; i++ {
		frame = append(frame, 0x00)
	}
	frame = append(frame, 0x00, 0x00) // Working counter

	// Pad to the minimum Ethernet frame size of 64 bytes
	for len(frame) < 64 {
		frame = append(frame, 0x00)
	}

	// Return the completed EtherCAT BRD frame
	return frame
}
