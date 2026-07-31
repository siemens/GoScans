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
	"fmt"
	"net"
	"sync"

	"github.com/siemens/GoScans/utils"
)

// passiveListener is the package-level singleton used by Scanner.Run() to collect passively
// discovered hosts. It is initialized by StartPassiveListener and read by drainPassiveHosts.
var passiveListener *Listener

// Listener passively captures unsolicited OT broadcast frames on one or more network interfaces
// and accumulates discovered hosts in an internal cache, organized by interface name. Unlike
// Scanner, it holds its sockets open for the lifetime of the provided context and requires no
// active probes to surface results. Hosts are retrieved via Drain, which atomically returns and
// clears the cache for a given interface.
type Listener struct {
	logger     utils.Logger
	interfaces []string
	mu         sync.Mutex
	hosts      map[string][]Host // keyed by interface name
}

// NewListener creates a passive OT listener for the given network interfaces. If no interface
// names are provided, all non-loopback interfaces with an IPv4 address are used.
func NewListener(logger utils.Logger, interfaces ...string) (*Listener, error) {

	// Get local interfaces
	allInterfaces, errAllInterfaces := net.Interfaces()
	if errAllInterfaces != nil {
		return nil, fmt.Errorf("could not enumerate network interfaces: %w", errAllInterfaces)
	}

	// Build lookup
	known := make(map[string]struct{}, len(allInterfaces))
	for _, iface := range allInterfaces {
		known[iface.Name] = struct{}{}
	}

	// Validate that every requested interface exists on this host
	for _, name := range interfaces {
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("network interface '%s' does not exist", name)
		}
	}

	// Return the listener with an initialized host cache
	return &Listener{
		interfaces: interfaces,
		logger:     logger,
		hosts:      make(map[string][]Host),
	}, nil
}

// Listen starts all passive protocol listeners on every configured interface and accumulates
// discovered hosts in the internal cache. It blocks until ctx is cancelled, at which point all
// listeners shut down and the method returns.
func (l *Listener) Listen(ctx context.Context) {

	// Top-level WaitGroup tracks per-interface goroutine groups
	var wgInterfaces sync.WaitGroup

	// Launch one goroutine group per interface
	for _, iface := range l.interfaces {
		wgInterfaces.Add(1)
		go func(iface string) {
			defer wgInterfaces.Done()
			l.listenOnInterface(ctx, iface)
		}(iface)
	}

	// Block until all interface groups have exited
	wgInterfaces.Wait()
}

// Drain returns all hosts accumulated on the given interface since the last drain and resets
// that interface's cache to empty. Safe for concurrent use by multiple scanners.
func (l *Listener) Drain(iface string) []Host {

	// Swap the slice under the lock and return the old one to the caller
	l.mu.Lock()
	hosts := l.hosts[iface]
	l.hosts[iface] = nil
	l.mu.Unlock()

	// Return collected hosts
	return hosts
}

// listenOnInterface starts the protocol listeners for a single interface and forwards discovered
// hosts into the internal cache.
func (l *Listener) listenOnInterface(ctx context.Context, iface string) {

	// Allocate a buffered channel the protocol goroutines write into; capacity absorbs bursts
	ch := make(chan Host, 256)

	// Forward hosts from the channel into the cache in a dedicated goroutine so that the
	// protocol goroutines are never blocked by a slow mutex acquisition
	go func() {
		for host := range ch {
			l.mu.Lock()
			l.hosts[iface] = mergeResults(append(l.hosts[iface], host))
			l.mu.Unlock()
		}
	}()

	// Launch one goroutine per protocol; all share the same context and output channel
	var wg sync.WaitGroup

	// LLDP passive listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.logger.Debugf("Starting LLDP passive listener on '%s'.", iface)
		if errListen := listenLldp(ctx, l.logger, iface, ch); errListen != nil {
			l.logger.Warningf("LLDP passive listener on '%s' stopped: %s", iface, errListen)
		}
	}()

	// PROFINET DCP passive listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.logger.Debugf("Starting PROFINET DCP passive listener on '%s'.", iface)
		if errListen := listenProfinetDcp(ctx, l.logger, iface, ch); errListen != nil {
			l.logger.Warningf("PROFINET DCP passive listener on '%s' stopped: %s", iface, errListen)
		}
	}()

	// ARP gratuitous broadcast listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.logger.Debugf("Starting ARP passive listener on '%s'.", iface)
		if errListen := listenArp(ctx, l.logger, iface, ch); errListen != nil {
			l.logger.Warningf("ARP passive listener on '%s' stopped: %s", iface, errListen)
		}
	}()

	// mDNS passive listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.logger.Debugf("Starting mDNS passive listener on '%s'.", iface)
		if errListen := listenMdns(ctx, l.logger, iface, ch); errListen != nil {
			l.logger.Warningf("mDNS passive listener on '%s' stopped: %s", iface, errListen)
		}
	}()

	// SSDP passive listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.logger.Debugf("Starting SSDP passive listener on '%s'.", iface)
		if errListen := listenSsdp(ctx, l.logger, iface, ch); errListen != nil {
			l.logger.Warningf("SSDP passive listener on '%s' stopped: %s", iface, errListen)
		}
	}()

	// Block until all protocol listeners have exited, then close the forwarding channel
	wg.Wait()
	close(ch)
}

// StartPassiveListener creates the global passive listener and starts it in a background
// goroutine. If no interface names are provided, all suitable interfaces are auto-discovered.
// This function is intended to be called once at agent startup.
func StartPassiveListener(ctx context.Context, logger utils.Logger, interfaces ...string) error {

	// Create the listener
	listener, errListener := NewListener(logger, interfaces...)
	if errListener != nil {
		return errListener
	}

	// Store the global reference and start listening in the background
	passiveListener = listener

	// Launch passive listener
	go passiveListener.Listen(ctx)

	// Return nil as everything went fine
	return nil
}
