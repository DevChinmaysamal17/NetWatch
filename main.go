package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	// devices maps IP -> MAC for every device that answered our ARP scan.
	devices = map[string]string{}

	// mu protects the map above.
	mu sync.Mutex
)

func main() {
	if err := loadOUI("oui.csv"); err != nil {
		log.Fatal("loadOUI: ", err)
	}

	conn, err := connectDB()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(context.Background())

	// Open the interface ONCE and start ONE listener for the whole run.
	iface, myIP, network := getInterface("en0")
	handle := openHandle("en0")
	defer handle.Close()
	go listenForReplies(handle)

	// One scan round: returns hosts, saves nothing. runCycle does the DB work.
	scanFn := func() ([]Host, error) {
		// Reset, otherwise last cycle's devices stay in the map forever
		// and nothing would ever look offline.
		mu.Lock()
		devices = map[string]string{}
		mu.Unlock()

		scanNetwork(handle, iface, myIP, network) // scan.go
		addSelf(iface, myIP)                      // scan.go

		mu.Lock()
		snapshot := make(map[string]string, len(devices))
		for ip, mac := range devices {
			snapshot[ip] = mac
		}
		mu.Unlock()

		hosts := make([]Host, 0, len(snapshot))
		for ip, mac := range snapshot {
			name := getName(ip) // names.go
			if name == "unknown" {
				name = Vendor(mac) // oui.go
			}
			hosts = append(hosts, Host{
				MAC:      strings.ToLower(mac),
				IP:       ip,
				Hostname: name,
			})
		}
		return hosts, nil
	}

	monitor(conn, scanFn, 5*time.Second) // monitor.go, loops forever
}
