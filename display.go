// display.go
//
// Prints the final results as a table: NAME, IP, MAC.
package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// printTable sorts the devices by IP and prints one row per device.
func printTable(myIP net.IP) {
	// Copy the IPs out of the map into a slice, so we can sort them.
	// (Maps have no order in Go.) Lock while reading the map.
	mu.Lock()
	ips := make([]string, 0, len(devices))
	for ip := range devices {
		ips = append(ips, ip)
	}
	mu.Unlock()

	// Sort numerically so .80 comes before .141.
	// (Sorting as plain text would put "141" before "80".)
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(
			net.ParseIP(ips[i]).To4(),
			net.ParseIP(ips[j]).To4(),
		) < 0
	})

	// This Mac's own hostname, to label our own row.
	selfName, _ := os.Hostname()

	fmt.Printf("\n%-33s %-16s %s\n", "NAME", "IP", "MAC")
	fmt.Println(strings.Repeat("-", 68))

	for _, ip := range ips {
		name := getName(ip) // mDNS, then reverse DNS, else "unknown"

		// Always label our device clearly.
		if ip == myIP.String() {
			name = selfName + " (this Mac)"
		}

		mu.Lock()
		mac := devices[ip]
		mu.Unlock()

		fmt.Printf("%-33s %-16s %s\n", name, ip, mac)
	}

	fmt.Println("\ndevices found:", len(ips))
}
