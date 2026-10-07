// names.go
//
// Finds a human-readable name for each IP. Two methods, tried in order:
//  1. mDNS: devices announce their own name on the local network
//     (works well for Apple devices and some printers/TVs).
//  2. Reverse DNS: ask a DNS server "what is the name of this IP?"
//     (our Jio router answers for itself, but rarely for other devices).
//
// If both fail the name stays "unknown". That is normal: many phones never
// announce a name, and phones with a Private Wi-Fi Address hide on purpose.
package main

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

// discoverMDNS asks the network for devices offering common mDNS services.
// mDNS = multicast DNS: instead of asking a DNS server, devices on the
// local network announce themselves, e.g. "I'm Chinmays-iPhone.local and I
// offer AirPlay". Each service type below is a kind of announcement.
func discoverMDNS() {
	services := []string{
		"_workstation._tcp", // computers
		"_http._tcp",        // anything with a web page (printers, NAS...)
		"_airplay._tcp",     // Apple AirPlay devices
		"_smb._tcp",         // file sharing
	}

	// One after another, ~1 second each. (Could run in parallel later.)
	for _, service := range services {
		browseMDNSService(service)
	}
}

// browseMDNSService listens for ONE kind of mDNS announcement for 1 second
// and saves any IP -> hostname pairs it hears into `mdnsNames`.
func browseMDNSService(service string) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return // can't do mDNS, just skip
	}

	// Found devices arrive on this channel (a pipe between goroutines).
	entries := make(chan *zeroconf.ServiceEntry)

	// context.WithTimeout = "stop after 1 second". It's how Go prevents a
	// network call from waiting forever.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Background goroutine: reads each found device off the channel and
	// saves its name. It ends when the channel is closed after the timeout.
	go func() {
		for entry := range entries {
			// Hostnames end with a dot ("name.local."), remove it.
			name := strings.TrimSuffix(entry.HostName, ".")

			// A device can have several IPs; save the name for each.
			for _, ip := range entry.AddrIPv4 {
				mu.Lock()
				mdnsNames[ip.String()] = name
				mu.Unlock()
			}
		}
	}()

	// Start browsing, then wait here until the 1-second timer runs out.
	resolver.Browse(ctx, service, "local.", entries)
	<-ctx.Done()
}

// lookupName does a reverse DNS lookup: "what is the name of this IP?".
// Waits at most 1 second, and returns "unknown" if nothing comes back.
func lookupName(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "unknown"
	}

	// DNS names end with a trailing dot, remove it.
	return strings.TrimSuffix(names[0], ".")
}

// getName returns the best known name for an IP:
// mDNS first (usually friendlier), then reverse DNS, else "unknown".
func getName(ip string) string {
	mu.Lock()
	name := mdnsNames[ip]
	mu.Unlock()

	if name != "" {
		return name
	}

	return lookupName(ip)
}
