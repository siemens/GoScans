/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package ot implements operational technology protocol scanners including PROFINET, EtherCAT, and mDNS.
package ot

import (
	"fmt"
	"net"
	"strings"

	"github.com/siemens/GoScans/utils"
)

// Host represents a host discovered via L2/OT protocols.
type Host struct {
	MacAddress string
	Ips        []string
	DnsNames   []string
	OsGuesses  []string
}

// Scanner defines the settings required by the OT discovery scan.
type Scanner struct {
	NetworkInterface string       // The network interface to run the OT scans on, e.g. "eth0"
	logger           utils.Logger // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
}

// NewScanner creates an OT discovery scanner for the given network interface.
// Returns an error if the interface name is empty or cannot be found on the host.
func NewScanner(logger utils.Logger, nwInterface string) (*Scanner, error) {

	// Check if network interface is provided
	if nwInterface == "" {
		return nil, fmt.Errorf("network interface is empty")
	}

	// Read local interfaces
	interfaces, errInterfaces := net.Interfaces()
	if errInterfaces != nil {
		return nil, fmt.Errorf("could not enumerate network interfaces: %w", errInterfaces)
	}

	// Check if provided network interface name exists
	found := false
	for _, iface := range interfaces {
		if iface.Name == nwInterface {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("network interface '%s' does not exist", nwInterface)
	}

	// Return OT discovery scanner
	return &Scanner{
		logger:           logger,
		NetworkInterface: nwInterface,
	}, nil
}

// Run runs all L2 OT discovery methods and collects results.
func (s *Scanner) Run() []Host {

	// Prepare memory for result data
	var allHosts []Host

	// PROFINET DCP Discovery
	s.logger.Infof("Executing discovery via PROFINET DCP on '%s'.", s.NetworkInterface)
	pnHosts, errPnHosts := ScanProfinetDcp(s.logger, s.NetworkInterface)
	if errPnHosts != nil {
		s.logger.Warningf("Could not execute discovery via PROFINET DCP: %s", errPnHosts)
	} else {
		s.logger.Infof("Discovered %d devices via PROFINET DCP.", len(pnHosts))
		allHosts = append(allHosts, pnHosts...)
	}

	// EtherCAT Discovery
	s.logger.Infof("Executing discovery via EtherCAT on '%s'.", s.NetworkInterface)
	ecHosts, errEcHosts := ScanEthercat(s.logger, s.NetworkInterface)
	if errEcHosts != nil {
		s.logger.Warningf("Could not execute discovery via EtherCAT: %s", errEcHosts)
	} else {
		s.logger.Infof("Discovered %d devices via EtherCAT.", len(ecHosts))
		allHosts = append(allHosts, ecHosts...)
	}

	// LLDP Passive Listening
	s.logger.Infof("Executing discovery via LLDP listener on '%s'.", s.NetworkInterface)
	lldpHosts, errLldpHosts := ListenLldp(s.logger, s.NetworkInterface)
	if errLldpHosts != nil {
		s.logger.Warningf("Could not execute discovery via LLDP listener: %s", errLldpHosts)
	} else {
		s.logger.Infof("Discovered %d devices via LLDP listener.", len(lldpHosts))
		allHosts = append(allHosts, lldpHosts...)
	}

	// IPv6 Neighbor Discovery
	s.logger.Infof("Executing discovery via IPv6 NDP on '%s'.", s.NetworkInterface)
	ndpHosts, errNdpHosts := ScanNdp(s.logger, s.NetworkInterface)
	if errNdpHosts != nil {
		s.logger.Warningf("Could not execute discovery via IPv6 NDP: %s", errNdpHosts)
	} else {
		s.logger.Infof("Discovered %d devices via IPv6 NDP.", len(ndpHosts))
		allHosts = append(allHosts, ndpHosts...)
	}

	// mDNS/SSDP Discovery
	s.logger.Infof("Executing discovery via mDNS/SSDP on '%s'.", s.NetworkInterface)
	mdnsHosts, errMdnsHosts := ScanMdnsSsdp(s.logger, s.NetworkInterface)
	if errMdnsHosts != nil {
		s.logger.Warningf("Could not execute discovery via mDNS/SSDP: %s", errMdnsHosts)
	} else {
		s.logger.Infof("Discovered %d devices via mDNS/SSDP.", len(mdnsHosts))
		allHosts = append(allHosts, mdnsHosts...)
	}

	// ARP Discovery
	s.logger.Infof("Executing discovery via ARP on '%s'.", s.NetworkInterface)
	arpHosts, errArpHosts := ScanArp(s.logger, s.NetworkInterface)
	if errArpHosts != nil {
		s.logger.Warningf("Could not execute discovery via ARP: %s", errArpHosts)
	} else {
		s.logger.Infof("Discovered %d devices via ARP.", len(arpHosts))
		allHosts = append(allHosts, arpHosts...)
	}

	// Drain passively discovered hosts from the background listener (if running)
	if passiveListener != nil {
		passiveHosts := passiveListener.Drain(s.NetworkInterface)
		if len(passiveHosts) > 0 {
			s.logger.Infof("Collected %d passively discovered host(s) on '%s'.", len(passiveHosts), s.NetworkInterface)
			allHosts = append(allHosts, passiveHosts...)
		}
	}

	// Return merged results
	return mergeResults(allHosts)
}

// mergeResults deduplicates a slice of hosts using two passes. Each pass folds every entry into
// an accumulator by MAC equality (when both sides have a MAC) or by shared IP (when at least one
// side is MAC-less). The second pass resolves transitivity gaps left by the first: a multi-IP
// entry can bridge two already-committed entries that were recorded separately, absorbing only the
// first match in the first pass and leaving the second stranded. After the first pass every entry
// carries the full union of its group's IPs, so the second pass finds and collapses any remaining
// overlap. Two entries that both carry MACs are never merged on a shared IP alone — differing MACs
// identify distinct physical devices and a shared IP is treated as noise (e.g. DHCP lease reuse).
func mergeResults(hosts []Host) []Host {

	// fold runs a single deduplication pass over the input slice
	fold := func(input []Host) []Host {
		var acc []Host
		for _, incoming := range input {

			// Build a set of the incoming host's IPs for fast overlap checking
			incomingIps := make(map[string]struct{}, len(incoming.Ips))
			for _, ip := range incoming.Ips {
				incomingIps[ip] = struct{}{}
			}

			// Search for an existing entry that matches by MAC or shared IP
			incomingMac := strings.ToUpper(incoming.MacAddress)
			matched := false
			for i := range acc {
				existing := &acc[i]
				existingMac := strings.ToUpper(existing.MacAddress)

				// Match by MAC when both sides have one
				macMatch := incomingMac != "" && existingMac != "" && incomingMac == existingMac

				// Match by shared IP only when at least one side has no MAC. If both sides
				// have MACs that differ they are definitively different physical devices, so
				// a shared IP (e.g. from DHCP lease reuse across the scan window) must not
				// cause a merge.
				ipMatch := false
				if !macMatch && (incomingMac == "" || existingMac == "") {
					for _, ip := range existing.Ips {
						if _, ok := incomingIps[ip]; ok {
							ipMatch = true
							break
						}
					}
				}

				if !macMatch && !ipMatch {
					continue
				}

				// Union IPs, DNS names, OS guesses; copy MAC if the existing entry is missing one
				existing.Ips = utils.AppendUnique(existing.Ips, incoming.Ips...)
				existing.DnsNames = utils.AppendUnique(existing.DnsNames, incoming.DnsNames...)
				existing.OsGuesses = utils.AppendUnique(existing.OsGuesses, incoming.OsGuesses...)
				if existing.MacAddress == "" && incoming.MacAddress != "" {
					existing.MacAddress = incoming.MacAddress
				}
				matched = true
				break
			}

			// No match found — append as a new entry
			if !matched {
				acc = append(acc, incoming)
			}
		}
		return acc
	}

	// First pass collapses direct matches; second pass resolves transitivity gaps
	return fold(fold(hosts))
}
